"""Parent-process lazy lookup: resolve the parent process behind an EDR alert.

The polling path (``services.connectors`` connector's ``fetch_alerts`` /
``process_lookup`` with a semaphore) never reaches this code. Parent-process
lineage is only looked up when the alert detail view renders: a single
one-shot EDR HTTP call through the stateless connectors microservice, with a
read-through cache and best-effort persistence. A failure must never block an
analyst from reading an alert, so every failure path resolves to
``unavailable`` and never raises.

Ground truth (do not re-derive):

* ``Alert`` has ``connector_id`` / ``connector_type`` (nullable),
  ``raw_event`` (JSONB), ``enrichment_data`` (JSONB), ``event_time`` and
  ``created_at`` (tz-aware datetimes). No migration: everything touched is a
  JSONB key or a datetime.
* The connectors service owns the EDR credentials; the API must NOT call EDR
  directly. It POSTs to ``{CONNECTORS_SERVICE_URL}/api/v1/internal/edr/
  process-lookup`` with the shared service token and a tenant assertion,
  exactly as :func:`app.api.v1.endpoints.connectors._catalog_headers` does.
* ``edrserver.process_lookup`` returns
  ``{"status": "found" | "not_found" | "unavailable",
     "entity_id": str, "process": {...}|None}``.

No polling path is touched; this module performs the one-shot lookup only.
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Redis key namespace. Versioned on purpose so a schema change to the cached
#: payload means a different key and the old data is never served.
CACHE_NAMESPACE = "parent-proc:v1"

#: Status reported on success (parent resolved and cached).
STATUS_RESOLVED = "resolved"
#: Status when the parent entity_id was looked up and the EDR did not find it.
STATUS_NOT_FOUND = "not_found"
#: Status when we could not determine the parent (EDR error, unreachable, etc.).
STATUS_UNAVAILABLE = "unavailable"

#: The raw connectors/edrserver status for a clean lookup miss.
_EDR_NOT_FOUND = "not_found"
_EDR_UNAVAILABLE = "unavailable"

#: TTLs (seconds) resolved from settings.
_TTL_RESOLVED = 3600
_TTL_NOT_FOUND = 300

#: When an alert is younger than this many minutes, a not_found miss is rechecked sooner.
_NOT_FOUND_COOLDOWN_ALERT_AGE_MINUTES = 10
_NOT_FOUND_COOLDOWN_TTL = 60

#: ASCII control chars plus Bidi/zero-width marks. Stripped from name,
#: executable and entity_id before caching, logging or persisting so a malicious
#: process name cannot smuggle a Bidi override or zero-width reorder.
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f\u061C\u070F\u180E\u200A-\u200F\u2028-\u202F\u205F-\u206F\uFEFF\u2060-\u2065\u2066-\u2069\u200B-\u200D]")


def _strip_control_chars(value: str) -> str:
    """Return *value* with ASCII control characters removed, safe for log/cache."""
    return _CTRL_RE.sub("", value)


# ---------------------------------------------------------------------------
# Eligibility
# ---------------------------------------------------------------------------


def compute_eligibility(alert: Any) -> bool:
    """Decide whether an alert can have a parent process looked up.

    An alert is eligible when:

    * its connector is an EDR (``connector_type == "edrserver"``);
    * there is process context — the alert's ``raw_event`` carries a
      ``process`` object, either with a ``parent`` node or nested enough to
      expose a parent entity_id; and
    * that parent has a real, non-empty, non-self entity_id.

    Self-referencing parents (``parent.entity_id == process.entity_id``) are
    filtered out: they mean there is no independent ancestor, only an
    incomplete record, which is the ``no_parent`` case, not an eligible one.

    No polling path is touched here or anywhere else in this module.
    """
    connector_type = getattr(alert, "connector_type", None)
    if connector_type != "edrserver":
        return False

    raw_event = getattr(alert, "raw_event", None)
    if not isinstance(raw_event, dict):
        return False

    parent_entity_id = _extract_parent_entity_id(raw_event)
    if not parent_entity_id:
        return False

    # Non-self-ref: the parent must be a different entity from the process.
    process = raw_event.get("process")
    process_entity_id = process.get("entity_id") if isinstance(process, dict) else None
    if process_entity_id and parent_entity_id.strip() == process_entity_id.strip():
        return False

    return True


def _extract_parent_entity_id(raw_event: dict[str, Any]) -> str:
    """Pull the parent process entity_id out of ``raw_event``.

    Handles three shapes EDR connectors have been observed to emit:

    * ``raw_event.process.parent.entity_id`` — the flat ECS layout;
    * ``raw_data.process.parent.entity_id`` — ``raw_data`` already parsed;
    * ``raw_data.raw_event.process.parent.entity_id`` — ``raw_data`` is a JSON
      string carrying its own nested ``raw_event`` (the shape produced by the
      EDR connector today, where ``raw_data`` is a serialized object).

    ``raw_data`` may be a dict or a JSON string; both are accepted.
    Empty/whitespace values return "".
    """
    parent_id = ""

    process = raw_event.get("process")
    if isinstance(process, dict):
        parent = process.get("parent")
        if isinstance(parent, dict):
            parent_id = _nonempty(parent.get("entity_id"))

    if not parent_id:
        raw_data = _coerce_raw_data(raw_event.get("raw_data"))
        if isinstance(raw_data, dict):
            inner = raw_data.get("raw_event")
            if not isinstance(inner, dict):
                inner = raw_data
            proc = inner.get("process")
            if isinstance(proc, dict):
                parent = proc.get("parent")
                if isinstance(parent, dict):
                    parent_id = _nonempty(parent.get("entity_id"))

    return parent_id


def _nonempty(value: Any) -> str:
    """Return a stripped non-empty string, else ""."""
    if isinstance(value, str):
        stripped = value.strip()
        return _strip_control_chars(stripped)
    if isinstance(value, uuid.UUID):
        return value.hex


def _coerce_raw_data(value: Any) -> Any:
    """Return a dict from ``raw_data`` whether it is a dict or JSON string.

    The EDR connector today stores ``raw_data`` as a serialized JSON object;
    a few sources pass a dict directly. This accepts both so callers can walk
    ``raw_data`` without repeating the JSON parse.
    """
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return None
        return parsed if isinstance(parsed, dict) else None
    return None

def classify_parent_lookup(alert: Any) -> Optional[str]:
    """Classify an alert's parent-process lookup outcome for the API response.

    Derived purely from the alert row (no live lookup), this mirrors
    :func:`compute_eligibility` for the ``eligible`` case but extends it to
    the three states the alert-detail response exposes:

    * ``None`` -- not an EDR connector; parent-process lineage is out of scope
      (the alert-detail ``parent_lookup`` stays ``None``).
    * ``"not_applicable"`` -- EDR connector but no process context at all.
    * ``"no_parent"`` -- EDR connector with process context but no usable,
      non-self parent entity_id (missing or self-referencing parent).
    * ``"eligible"`` -- EDR connector with a real, non-self parent entity_id
      (see :func:`compute_eligibility`).

    Accepts the ORM model or a plain dict (``Any``) so it is usable both in
    tests and when mapping the persisted snapshot in the view layer.
    """
    connector_type = getattr(alert, "connector_type", None)
    if connector_type != "edrserver":
        return None

    raw_event = getattr(alert, "raw_event", None)
    if not isinstance(raw_event, dict):
        return "not_applicable"

    parent_entity_id = _extract_parent_entity_id(raw_event)
    if not parent_entity_id:
        return "no_parent"

    # Non-self-ref: a parent equal to the process itself means there is no
    # independent ancestor (the ``no_parent`` case), not an eligible one.
    process = raw_event.get("process")
    process_entity_id = process.get("entity_id") if isinstance(process, dict) else None
    if process_entity_id and parent_entity_id.strip() == process_entity_id.strip():
        return "no_parent"

    return "eligible"



# ---------------------------------------------------------------------------
# Redis read-through
# ---------------------------------------------------------------------------


async def _get_redis_client() -> Optional[Any]:
    """Return a redis asyncio client, or None when no URL is configured."""
    try:
        from redis.asyncio import from_url
    except Exception:  # pragma: no cover - redis not installed
        return None
    url = getattr(settings, "REDIS_URL", "") or ""
    if not url:
        return None
    try:
        return from_url(url, decode_responses=True)
    except Exception:  # pragma: no cover - connection failure
        return None


def _cache_key(tenant_id: uuid.UUID, connector_id: str, entity_id: str) -> str:
    """Build the per-(tenant, connector, entity) cache key."""
    tid = _strip_control_chars(str(tenant_id))
    cid = _strip_control_chars(connector_id or "")
    eid = _strip_control_chars(entity_id or "")
    return f"{CACHE_NAMESPACE}:{tid}:{cid}:{eid}"


async def _read_cache(
    tenant_id: uuid.UUID,
    connector_id: str,
    entity_id: str,
) -> Optional[dict[str, Any]]:
    """Return a cached parent-process snapshot, or None on miss/failure."""
    client = await _get_redis_client()
    if client is None:
        return None
    key = _cache_key(tenant_id, connector_id, entity_id)
    try:
        raw = await client.get(key)
    except Exception:  # pragma: no cover - transient redis error
        return None
    finally:
        try:
            await client.aclose()
        except Exception:  # pragma: no cover - best effort close
            pass
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


async def _write_cache(
    tenant_id: uuid.UUID,
    connector_id: str,
    entity_id: str,
    snapshot: dict[str, Any],
    ttl: Optional[int] = _TTL_RESOLVED,
) -> None:
    """Persist a snapshot under the cache key. Best-effort; never raises."""
    client = await _get_redis_client()
    if client is None:
        return
    key = _cache_key(tenant_id, connector_id, entity_id)
    try:
        if ttl is None:
            await client.set(key, json.dumps(snapshot))
        else:
            await client.set(key, json.dumps(snapshot), ex=ttl)
    except Exception:  # pragma: no cover - best effort write
        logger.warning("parent_process_cache.write_failed", exc_info=True)
    finally:
        try:
            await client.aclose()
        except Exception:  # pragma: no cover - best effort close
            pass


# ---------------------------------------------------------------------------
# Connector HTTP call
# ---------------------------------------------------------------------------


def _connector_service_headers(tenant_id: uuid.UUID | str | None) -> dict[str, str]:
    """Credential + tenant assertion for a connectors-service call.

    Mirrors :func:`app.api.v1.endpoints.connectors._catalog_headers` exactly,
    so the parent-process request is authorised the same way as the catalog
    and test-connection calls. If that import is available we reuse it verbatim;
    otherwise we replicate the small function here. A bearer credential is
    mandatory on every connectors route, and a service token must additionally
    declare the tenant it acts for.
    """
    try:
        from app.api.v1.endpoints.connectors import _catalog_headers

        return dict(_catalog_headers(tenant_id))
    except Exception:
        # Replicate the upstream behaviour: no fallback to session credentials,
        # and an unconfigured deployment sends no bearer (the connectors route
        # then refuses with 401, which maps to ``unavailable`` here).
        headers: dict[str, str] = {}
        token = _connectors_service_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if tenant_id is not None:
            headers["X-AiSOC-Tenant-ID"] = str(tenant_id)
        return headers


def _connectors_service_token() -> str:
    specific = (os.getenv("AISOC_CONNECTORS_SERVICE_TOKEN") or "").strip()
    return specific or (os.getenv("AISOC_SERVICE_TOKEN") or "").strip()


def _connector_service_url(path: str) -> str:
    base = settings.CONNECTORS_SERVICE_URL.rstrip("/")
    suffix = path if path.startswith("/") else f"/{path}"
    return f"{base}/api/v1{suffix}"


async def _call_connector_process_lookup(
    tenant_id: uuid.UUID,
    connector_id: str,
    entity_id: str,
    from_ts: str,
    to_ts: str,
) -> dict[str, Any]:
    """POST one-shot parent-process lookup to the connectors microservice.

    Returns a normalised snapshot keyed by ``status`` (``resolved`` /
    ``not_found`` / ``unavailable``). Never raises: any transport failure,
    decode failure, or non-JSON response resolves to ``unavailable``.
    """
    url = _connector_service_url("/internal/edr/process-lookup")
    payload = {
        "entity_id": entity_id,
        "connector_id": connector_id,
        "from_ts": from_ts,
        "to_ts": to_ts,
    }
    headers = _connector_service_headers(tenant_id)
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
    except httpx.HTTPError as exc:
        logger.warning(
            "parent_process_lookup.unreachable",
            exc_info=True,
        )
        return _map_status(_EDR_UNAVAILABLE, entity_id, None)
    if resp.status_code not in (200,):
        logger.warning(
            "parent_process_lookup.unexpected_status status=%s",
            resp.status_code,
        )
        return _map_status(_EDR_UNAVAILABLE, entity_id, None)
    try:
        body = resp.json()
    except ValueError:
        logger.warning("parent_process_lookup.invalid_json")
        return _map_status(_EDR_UNAVAILABLE, entity_id, None)
    if not isinstance(body, dict):
        logger.warning("parent_process_lookup.invalid_body")
        return _map_status(_EDR_UNAVAILABLE, entity_id, None)
    return _map_status(body.get("status"), entity_id, body.get("process"))


def _map_status(edr_status: Any, entity_id: str, process: Any) -> dict[str, Any]:
    """Map an edrserver/process-lookup status onto the API response payload.

    Found -> resolved with the process fields flattened (name, pid, executable,
    started_at) plus source "edr_lookup" and fetched_at. not_found -> not_found
    with null fields. Anything else (including unavailable and unknown values) ->
    unavailable with retryable true. This is the single status-mapping function
    for the module, covered by tests.
    """
    fetched_at = _now_iso()
    if edr_status == "found":
        proc = process if isinstance(process, dict) else {}
        return {
            "status": STATUS_RESOLVED,
            "entity_id": str(proc.get("entity_id")) if proc else entity_id,
            "name": _strip_control_chars(proc["name"]) if isinstance(proc.get("name"), str) else proc.get("name"),
            "pid": proc.get("pid"),
            "executable": _strip_control_chars(proc["executable"]) if isinstance(proc.get("executable"), str) else proc.get("executable"),
            "started_at": proc.get("started_at"),
            "source": "edr_lookup",
            "cached": False,
            "fetched_at": fetched_at,
        }
    if edr_status == _EDR_NOT_FOUND:
        return {
            "status": STATUS_NOT_FOUND,
            "entity_id": entity_id,
            "name": None,
            "pid": None,
            "executable": None,
            "started_at": None,
            "source": "edr_lookup",
            "cached": False,
            "fetched_at": fetched_at,
        }
    # unavailable (and any unknown status): retryable, no data
    return {
        "status": STATUS_UNAVAILABLE,
        "entity_id": entity_id,
        "name": None,
        "pid": None,
        "executable": None,
        "started_at": None,
        "source": "edr_lookup",
        "cached": False,
        "fetched_at": fetched_at,
        "retryable": True,
    }


# ---------------------------------------------------------------------------
# Build response
# ---------------------------------------------------------------------------


async def build_parent_process_response(
    db: AsyncSession,
    alert: Any,
    tenant_id: uuid.UUID,
) -> dict[str, Any]:
    """Return the parent-process lookup payload for one alert.

    Read-through semantics:

    1. Look at the cached snapshot first (Redis). A resolved snapshot short-
       circuits; a not_found snapshot is returned as-is (the alert view's own
       retry path decides when to re-check); an unavailable snapshot is
       reported without a re-lookup.
    2. Otherwise call the connectors service one-shot lookup, write the
       resolved snapshot back to Redis, persist it to Postgres (best-effort),
       and return the snapshot.

    Persistence and the cache are both best-effort: a failure in either is
    logged and swallowed so the response still reaches the analyst.

    No polling path is touched.
    """
    connector_id = getattr(alert, "connector_id", None)
    connector_id_str = str(connector_id) if connector_id is not None else ""
    alert_raw = getattr(alert, "raw_event", None) or {}
    entity_id = getattr(alert, "parent_process_entity_id", None) or _extract_parent_entity_id(alert_raw)

    cached = await _read_cache(tenant_id, connector_id_str, entity_id)
    if isinstance(cached, dict):
        return {**cached, "cached": True}

    # Not cached: perform the one-shot lookup through the connectors service.
    from_ts, to_ts = _lookup_window(alert)
    resp = await _call_connector_process_lookup(
        tenant_id,
        connector_id_str,
        entity_id,
        from_ts,
        to_ts,
    )
    snapshot = {**resp, "cached": False}
    ttl = resolve_ttl(snapshot["status"], _alert_age_minutes(alert))
    await _write_cache(tenant_id, connector_id_str, entity_id, snapshot, ttl=ttl)
    if snapshot["status"] == STATUS_RESOLVED:
        await persist_snapshot(db, alert, snapshot)
    return snapshot





# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


async def persist_snapshot(db: AsyncSession, alert: Any, snapshot: dict[str, Any]) -> None:
    """Atomically merge ``snapshot`` into ``enrichment_data.parent_process``.

    A single conditional UPDATE:

        SET enrichment_data = enrichment_data || jsonb_build_object(
            'parent_process', :snapshot
        )
        WHERE id = :id AND NOT (enrichment_data ? 'parent_process')

    so a concurrent Fusion/Alert-Rail update to another enrichment key cannot
    clobber a parent_process snapshot we are about to write, and vice versa.
    The ``WHERE`` clause means an already-persisted snapshot is left untouched
    (idempotent). ``updated_at`` is intentionally NOT touched: the UPDATE does
    not set it. Best-effort — a failure is logged and swallowed so the response
    is never blocked.
    """
    if not settings.alert_parent_process_persist:
        return
    alert_id = getattr(alert, "id", None)
    if alert_id is None:
        return
    try:
        await db.execute(
            text(
                "UPDATE alerts "
                "SET enrichment_data = enrichment_data || jsonb_build_object("
                "'parent_process', CAST(:snapshot AS jsonb)) "
                "WHERE id = :id AND NOT (enrichment_data ? 'parent_process')"
            ),
            {"snapshot": json.dumps(snapshot), "id": str(alert_id)},
        )
    except Exception:  # noqa: BLE001 - best effort, never blocks the response
        logger.warning("parent_process_snapshot.persist_failed", exc_info=True)
    finally:
        try:
            await db.commit()
        except Exception:  # pragma: no cover - best effort flush
            try:
                await db.rollback()
            except Exception:  # pragma: no cover
                pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _alert_age_minutes(alert: Any) -> float:
    """Minutes between the alert's creation time and now."""
    created_at = getattr(alert, "created_at", None)
    if created_at is None:
        return float("inf")
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    seconds = (now - created_at).total_seconds()
    return seconds / 60.0


def resolve_ttl(status: str, alert_age_minutes: float) -> Optional[int]:
    """Return the Redis TTL for one lookup result.

    resolved -> 3600s. not_found -> 60s while the alert is still fresh
    (younger than _NOT_FOUND_COOLDOWN_ALERT_AGE_MINUTES) else 300s, so a brand
    new alert with an incomplete index is rechecked sooner. unavailable ->
    None (do not cache). Never raises.
    """
    if status == STATUS_NOT_FOUND and alert_age_minutes < (
        _NOT_FOUND_COOLDOWN_ALERT_AGE_MINUTES
    ):
        return _NOT_FOUND_COOLDOWN_TTL
    if status == STATUS_NOT_FOUND:
        return _TTL_NOT_FOUND
    if status == STATUS_RESOLVED:
        return _TTL_RESOLVED
    return None


def _rfc3339_ms(dt: datetime) -> str:
    """Format a datetime as EDR expects: RFC 3339 UTC, millisecond
    precision, ``Z`` suffix (per LLM-REST-API spec rule 4 and the
    ``process-detail-v1`` testdata). Python's ``isoformat()`` emits
    microsecond precision with a ``+00:00`` offset, which the EDR process
    endpoint rejects with 400.
    """
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"

def _lookup_window(alert: Any) -> tuple[str, str]:
    """Return ``(from_ts, to_ts)`` as RFC3339 UTC for the EDR lookup.

    Past-anchored window: ``to = event_time`` (the child alert's event time) and
    ``from = to - PARENT_LOOKUP_WINDOW_MINUTES`` (default 1 day). Because the
    entire window lies in the past relative to any EDR server clock, the EDR's
    ``to <= now + 60s`` validation can never fail on a host/EDR clock skew.
    When the alert has no ``event_time``, ``to`` falls back to the current UTC
    time.
    """
    window = getattr(settings, "PARENT_LOOKUP_WINDOW_MINUTES", 1440)
    try:
        window = float(window)
    except (TypeError, ValueError):
        window = 1440.0
    window = max(window, 0.0)

    event_time = getattr(alert, "event_time", None)
    if event_time is None:
        to = datetime.now(timezone.utc)
    else:
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)
        to = event_time
    frm = to - timedelta(minutes=window)
    return _rfc3339_ms(frm), _rfc3339_ms(to)
