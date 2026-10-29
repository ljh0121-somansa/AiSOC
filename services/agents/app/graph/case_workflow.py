"""Case Investigation — EDR collection node (plan U9, spec §4, §5 stages 0-9, §5.1).

Wires the U2/U3 ``EdrClient`` case methods to the U8 pure-logic rules and
records ``edr_call`` ledger events + ``tool_input``/``tool_output`` artifacts
(spec §5 stage 11). ``edr_collect_node`` replaces the U7 ``_case_edr_collect``
skeleton inside ``build_case_investigation_graph``.

Invariant reminders (plan §4):
- No synthetic/dummy results. Budget exhaustion / LLM failure are recorded as
  "incomplete" / limitation; the run is explicit-failed with a reason code.
- "unavailable" is admitted ONLY via the source_kind pre-decision (static
  timeline/graph) or ``error.code`` (``feature_disabled`` / ``unsupported_source``).
- ``external_id`` is split at the FIRST colon only; colons inside ``event_id``
  are preserved (spec §4).
- ``<redacted>`` masked values are never restored (AGENTS.md §10).
- The case/Alert content is loaded server-side by the U4 context API when
  absent from state — the UI request body is never trusted.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timedelta
from typing import Any

import httpx
import structlog
from langchain_core.runnables.config import RunnableConfig

from app.core.service_token import service_token
import app.investigator.ledger as ledger
from app.edr.client import (
    EdrApiError,
    EdrClient,
    EdrClientError,
    EdrPermissionDeniedError,
    EdrServerUnavailableError,
)
from app.investigation_rules import (
    AlertRef,
    chunk_observables,
    classify_stage_outcome,
    collection_budget,
    group_alerts_by_time_window,
    select_alerts,
)

logger = structlog.get_logger()

_API_URL = os.getenv("API_SERVICE_URL", "http://api:8000")
_API_TIMEOUT_S = float(os.getenv("AGENTS_API_TIMEOUT", "10.0"))

#: observable type priority for hunt chunking (spec §5.1): sha256 > ip > url/domain > other.
_OBSERVABLE_TYPE_ORDER = {"sha256": 0, "ip": 1, "url": 2, "domain": 3}

# ISO 8601 durations used for the per-alert timeline window (spec §5.1:
# PT10M before + PT5M after = 15 min <= 60 min cap).
_TIMELINE_BEFORE = "PT10M"
_TIMELINE_AFTER = "PT5M"


class CaseContextLoadError(Exception):
    """U4 context load failed — spec stage 1: run fails closed (``load_error``)."""

    def __init__(self, message: str = "") -> None:
        super().__init__(f"load_error{(' ' + message[:120]) if message else ''}")


class CaseCollectionError(Exception):
    """Fatal collection failure that must fail the run (spec stage 0: 401/403)."""

    def __init__(self, reason_code: str, message: str = "") -> None:
        self.reason_code = reason_code
        suffix = f" ({message[:120]})" if message else ""
        super().__init__(reason_code + suffix)


# ---------------------------------------------------------------------------
# external_id parsing (spec §4)
# ---------------------------------------------------------------------------


def parse_external_id(external_id: str | None) -> tuple[str, str] | None:
    """Split ``external_id`` at the FIRST colon only (spec §4).

    ``external_id = "{source_kind}:{event_id}"``; colons inside ``event_id``
    are preserved. Returns ``None`` when the value is missing/unparseable.
    """
    if not external_id or ":" not in external_id:
        return None
    source_kind, event_id = external_id.split(":", 1)
    if not source_kind or not event_id:
        return None
    return source_kind, event_id


# ---------------------------------------------------------------------------
# U4 context API client (spec §2, §4)
# ---------------------------------------------------------------------------


def _service_token() -> str:
    """Service token for the api-service graph routes (delegated to app.core.service_token)."""
    return service_token()


async def fetch_case_investigation_context(case_id: str, tenant_ref: str) -> dict[str, Any]:
    """GET /api/v1/graph/case-investigation-context/{case_id} (U4 endpoint).

    The tenant comes from the caller's session ref, never the request body
    (spec §2). Raises :class:`CaseContextLoadError` (fail-closed).
    """
    url = f"{_API_URL}/api/v1/graph/case-investigation-context/{case_id}"
    headers = {"X-AiSOC-Tenant-ID": tenant_ref}
    token = _service_token()
    if token:
        headers["X-AiSOC-Service-Token"] = token
    try:
        async with httpx.AsyncClient(timeout=_API_TIMEOUT_S) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            return resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise CaseContextLoadError(str(exc)) from exc


# ---------------------------------------------------------------------------
# Ledger recorder (U7b config injection; Q3 state-accumulation fallback)
# ---------------------------------------------------------------------------


def _get_recorder(config: RunnableConfig | None) -> tuple[Any, Any, Any] | None:
    """Return ``(run_id, tenant_id, seq_issuer)`` from ``config["configurable"]``.

    When the runner did not inject the recorder (direct node call), returns
    ``None`` and the node accumulates events in
    ``state["_pending_ledger_events"]`` (Q3 fallback: the runner flushes it
    at tier boundaries).
    """
    if not config:
        return None
    cfg = (config or {}).get("configurable") or {}
    run_id = cfg.get("run_id")
    tenant_id = cfg.get("tenant_id")
    issuer = cfg.get("seq_issuer")
    if run_id is None or tenant_id is None or issuer is None:
        return None
    return run_id, tenant_id, issuer


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


async def _record_edr_call(
    state: dict,
    recorder,
    *,
    stage: str,
    endpoint: str,
    input_json: str,
    output: dict[str, Any] | None,
    error: EdrApiError | EdrClientError | None,
    retries: int,
    classification: str,
    duration_ms: int,
    params_ref: str,
) -> None:
    """Record one ``edr_call`` event + ``tool_input``/``tool_output`` artifacts
    linked via ``event_id`` (spec §5 stage 11)."""
    request_id = None
    error_code = None
    status_code = 200
    if isinstance(error, EdrApiError):
        request_id = error.request_id
        error_code = error.code
        status_code = error.status
    elif error is not None:
        status_code = 0
    if output is not None:
        request_id = request_id or output.get("request_id")

    payload = {
        "stage": stage,
        "endpoint": endpoint,
        "status_code": status_code,
        "error_code": error_code,
        "request_id": request_id,
        "retries": retries,
        "classification": classification,
        "params_ref": params_ref,
    }
    summary = f"{stage}: {endpoint} {classification} ({params_ref})"
    input_hash = _sha256(input_json)
    output_text = json.dumps(output, ensure_ascii=False) if output is not None else (str(error) if error is not None else "")
    output_hash = _sha256(output_text)

    if recorder is None:
        state.setdefault("_pending_ledger_events", []).append(
            {
                "kind": "edr_call",
                "agent": "edr_collect",
                "summary": summary,
                "payload": payload,
                "input_hash": input_hash,
                "output_hash": output_hash,
                "duration_ms": duration_ms,
            }
        )
        return

    run_id, tenant_id, issuer = recorder
    event_id = await ledger.record_event(
        run_id=run_id,
        tenant_id=tenant_id,
        seq=await issuer.next(),
        kind="edr_call",
        agent="edr_collect",
        summary=summary[:8000],
        payload=payload,
        input_hash=input_hash,
        output_hash=output_hash,
        duration_ms=duration_ms,
    )
    if event_id is None:
        return
    await ledger.record_artifact(
        run_id=run_id,
        tenant_id=tenant_id,
        kind="tool_input",
        content=input_json,
        event_id=event_id,
    )
    await ledger.record_artifact(
        run_id=run_id,
        tenant_id=tenant_id,
        kind="tool_output",
        content=output_text,
        event_id=event_id,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_edr_client() -> EdrClient:
    """Factory so tests can inject a stub client (existing convention: tools.py:184)."""
    return EdrClient()


def _iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _rfc3339(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _dur_min(dur: str) -> int:
    """Parse an ISO 8601 duration ("PT10M" / "PT2H") into minutes."""
    value = float(dur[2:-1])
    return int(value * 60) if dur.endswith("H") else int(value)


def _group_window(group: list[AlertRef], before: str = _TIMELINE_BEFORE, after: str = _TIMELINE_AFTER) -> tuple[str, str]:
    """Per-group time window (spec §5.1): min(@timestamp)−before ~ max(@timestamp)+after."""
    ts = [_iso(a.event_time) for a in group]
    from_ts = _rfc3339(min(ts) - timedelta(minutes=_dur_min(before)))
    to_ts = _rfc3339(max(ts) + timedelta(minutes=_dur_min(after)))
    return from_ts, to_ts


def _observables_from(item: dict[str, Any] | None, raw_event: dict[str, Any] | None) -> list[dict[str, str]]:
    """Collect candidate observables from a detection detail item and raw_event."""
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _add(otype: str, value: Any) -> None:
        if value is None:
            return
        v = str(value)
        key = (otype, v)
        if key in seen:
            return
        seen.add(key)
        found.append({"type": otype, "value": v})

    item = ((item or {}).get("item") or {})
    edr = item.get("edr") or {}
    for obs in edr.get("observables") or []:
        if isinstance(obs, dict) and obs.get("value"):
            _add(str(obs.get("type", "other")), obs["value"])
    raw_event = raw_event or {}
    fh = (raw_event.get("file") or {}).get("hash") or {}
    if fh.get("sha256"):
        _add("sha256", fh["sha256"])
    for ip in ((raw_event.get("host") or {}).get("ip") or []):
        _add("ip", ip)
    file_item = item.get("file") or {}
    url_val = file_item.get("url")
    if isinstance(url_val, str):
        _add("url", url_val)
    elif isinstance(url_val, list):
        for u in url_val:
            _add("url", u)

    found.sort(key=lambda o: _OBSERVABLE_TYPE_ORDER.get(o.get("type", ""), 99))
    return found


def _evidence_assessment_from_item(item: dict[str, Any]) -> str:
    """Evidence-level assessment only from observed data (no rule-based verdicts, spec §1)."""
    behavior = (item or {}).get("behavior") or {}
    verdict = behavior.get("verdict")
    if verdict in ("malicious_indicator", "benign_indicator"):
        return verdict
    return "not_determined"


# ---------------------------------------------------------------------------
# The edr_collect node
# ---------------------------------------------------------------------------


async def edr_collect_node(state: dict, config: RunnableConfig | None = None) -> dict:
    """Case EDR collection node (plan U9, spec §5 stages 0-9).

    - Loads case/Alert context server-side via the U4 endpoint when absent
      from state (UI payload untrusted, spec §2/§4).
    - Parses ``external_id`` (first-colon split), classifies stage outcomes
      via U8, calls U2/U3 client methods under the U8 collection budget.
    - Records one ``edr_call`` event + ``tool_input``/``tool_output``
      artifacts per EDR call (spec §5 stage 11), seq from the shared
      RunSequence (U6).
    - On 401/403 raises :class:`CaseCollectionError` (fail-closed, run fails
      with ``unauthorized`` / ``forbidden_scope`` — spec stage 0).
    """
    case_id = str(state.get("case_id", ""))
    tenant_ref = str(state.get("tenant_ref", "default"))

    # Stage 1: case/Alert context — from state or the U4 endpoint (spec §2).
    alerts = state.get("alerts")
    case_context = state.get("case_context")
    if alerts is None:
        case_context = await fetch_case_investigation_context(case_id, tenant_ref)
        alerts = case_context.get("alerts") or []
    if not case_context:
        case_context = {
            "case_id": case_id,
            "status": state.get("case_status", "open"),
            "severity": state.get("case_severity", "info"),
            "alert_ids": [str(a.get("id")) for a in (alerts or [])],
        }
    alerts = alerts or []

    # U8 alert cap (default 20; excess -> alerts_truncated).
    refs = [
        AlertRef(alert_id=a.get("id"), event_time=str(a.get("event_time", "1970-01-01T00:00:00Z")), severity=str(a.get("severity", "info")))
        for a in alerts
    ]
    selected, cap_lim = select_alerts(refs)
    limitations: list[str] = list(state.get("limitations") or [])
    if cap_lim:
        limitations.append(cap_lim)

    # Budget (U8): wall-clock is enforced by the runner timeout; call cap here.
    # The capabilities call itself is counted against the cap (spec §5.4:
    # pagination/retries included in the total).
    alert_count = int(state.get("alert_count", len(alerts)))
    budget = collection_budget(alert_count)
    calls = 0
    budget_exhausted = False

    def budget_left() -> bool:
        nonlocal calls, budget_exhausted
        if calls >= budget.max_calls:
            if not budget_exhausted:
                budget_exhausted = True
                limitations.append("collection_budget_exceeded")
            return False
        return True

    # Stage 0: capabilities (feature gates). Failure -> capabilities_unchecked.
    client = state.get("edr_client") or make_edr_client()
    capabilities: dict[str, Any] = {}
    try:
        if not budget_left():
            limitations.append("collection_budget_exceeded")
        else:
            calls += 1
            capabilities = await client.get_capabilities()
    except EdrPermissionDeniedError as exc:
        reason = "forbidden_scope" if "(403)" in str(exc) else "unauthorized"
        raise CaseCollectionError(reason, str(exc)) from exc
    except (EdrClientError, httpx.HTTPError) as exc:
        limitations.append("capabilities_unchecked")
        logger.warning("case_edr_collect.capabilities_unchecked", error=str(exc)[:200])
    features: dict[str, Any] = capabilities.get("features") or {}
    limits: dict[str, Any] = capabilities.get("limits") or {}

    recorder = _get_recorder(config)
    stage_results: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    edr_evidence: dict[str, Any] = {}
    ev_seq = 0

    def add_evidence(**kw: Any) -> str:
        nonlocal ev_seq
        ev_seq += 1
        kw.setdefault("id", f"ev-{ev_seq}")
        evidence.append(kw)
        return kw["id"]

    def add_stage(alert_ext: str, stage: str, source_kind: str, outcome: str) -> None:
        stage_results.append(
            {"alert_external_id": alert_ext, "stage": stage, "source_kind": source_kind, "outcome": outcome}
        )

    async def call(
        stage: str,
        endpoint: str,
        coro,
        params: Any = None,
        retries: int = 0,
        params_ref: str = "?",
    ) -> tuple[dict[str, Any] | None, EdrApiError | EdrClientError | None, str]:
        """Run one EDR call, count it against the call budget, record ledger
        event + artifacts (spec §5 stage 11)."""
        nonlocal calls
        if not budget_left():
            return None, None, "incomplete"
        calls += 1
        input_json = json.dumps(params if params is not None else {}, ensure_ascii=False, sort_keys=True)
        t0 = time.monotonic()
        try:
            result = await coro
            # Pre-decision "unavailable" (e.g. static timeline/graph): the
            # client skipped the HTTP call, so it is NOT counted as a call
            # and no edr_call event/artifacts are recorded (spec §5: the
            # call was never made, so no request_id/hash exist).
            if isinstance(result, dict) and result.get("status") == "unavailable":
                return result, None, "unavailable"
            duration_ms = int((time.monotonic() - t0) * 1000)
            await _record_edr_call(
                state, recorder,
                stage=stage, endpoint=endpoint, input_json=input_json,
                output=result, error=None, retries=retries,
                classification="completed", duration_ms=duration_ms,
                params_ref=params_ref,
            )
            return result, None, "completed"
        except EdrApiError as exc:
            duration_ms = int((time.monotonic() - t0) * 1000)
            cls = classify_stage_outcome(exc.code, "dynamic", stage)
            await _record_edr_call(
                state, recorder,
                stage=stage, endpoint=endpoint, input_json=input_json,
                output=None, error=exc, retries=retries,
                classification=cls, duration_ms=duration_ms,
                params_ref=params_ref,
            )
            if cls == "unavailable":
                limitations.append(f"{stage}_unavailable({params_ref})")
            else:
                code = exc.code or f"http_{exc.status}"
                limitations.append(f"{stage}_incomplete({params_ref}: {code})")
            return None, exc, cls
        except EdrPermissionDeniedError as exc:
            reason = "forbidden_scope" if "(403)" in str(exc) else "unauthorized"
            raise CaseCollectionError(reason, str(exc)) from exc
        except (EdrServerUnavailableError, httpx.HTTPError) as exc:
            duration_ms = int((time.monotonic() - t0) * 1000)
            await _record_edr_call(
                state, recorder,
                stage=stage, endpoint=endpoint, input_json=input_json,
                output=None, error=exc, retries=retries,
                classification="incomplete", duration_ms=duration_ms,
                params_ref=params_ref,
            )
            reason = "transport_error" if isinstance(exc, httpx.HTTPError) else "unavailable_error"
            limitations.append(f"{stage}_incomplete({params_ref}: {reason})")
            return None, exc, "incomplete"

    # ------------------------------------------------------------------
    # Priority 1 (spec §5.4): stage 2 detail for EVERY selected alert first.
    # ------------------------------------------------------------------
    alert_by_id = {str(a.get("id")): a for a in alerts}
    details: dict[str, dict[str, Any]] = {}
    for ref in selected:
        alert = alert_by_id.get(str(ref.alert_id)) or {}
        params_ref = str(alert.get("external_id", "?"))
        parsed = parse_external_id(params_ref)
        if parsed is None:
            limitations.append(f"unsupported_source_kind({params_ref})")
            add_stage(params_ref, "detail", "unknown", "incomplete")
            continue
        kind, event_id = parsed
        raw_event = alert.get("raw_event") or {}
        lookup_hint = ((raw_event.get("edr") or {}).get("links") or {}).get("lookup_hint")
        endpoint = f"/detections/{kind}/{event_id}"
        detail, err, cls = await call(
            "detail", endpoint,
            client.fetch_detection_detail(kind, event_id, lookup_hint),
            {"source_kind": kind, "event_id": event_id, "lookup_hint": lookup_hint},
            retries=0,
            params_ref=params_ref,
        )
        if isinstance(detail, dict) and detail.get("status") == "unavailable":
            limitations.append(detail.get("reason_code", f"{kind}_unavailable"))
            add_stage(params_ref, "detail", kind, "unavailable")
        elif detail:
            details[params_ref] = detail
            edr_evidence[f"detail:{params_ref}"] = detail
            item = detail.get("item") or {}
            add_evidence(
                alert_external_id=params_ref,
                stage="detail",
                kind="detection_detail",
                observed=True,
                assessment=_evidence_assessment_from_item(item),
            )
            add_stage(params_ref, "detail", kind, "completed")
        else:
            add_stage(params_ref, "detail", kind, cls if cls != "incomplete" else "incomplete")

    # ------------------------------------------------------------------
    # Group stages (U8 grouping) for hunt (6), file-ingress (7), event-search (9).
    # Group-call incompleteness is attributed to ALL alerts of the group (spec §5.1).
    # ------------------------------------------------------------------
    groups, group_lims = group_alerts_by_time_window(selected)
    limitations.extend(group_lims)

    group_from_ts, group_to_ts = _group_window(selected) if selected else ("", "")

    if selected:
        for group in groups:
            if budget_exhausted:
                break
            ext_ids = [str(a.alert_id) for a in group]
            from_ts, to_ts = _group_window(group)

            # Stage 6: IOC hunt per group (observables chunked, U8).
            if features.get("hunt") is False:
                for ext in ext_ids:
                    limitations.append(f"hunt_unavailable({ext})")
                    add_stage(ext, "hunt", "dynamic", "unavailable")
                continue
            obs: list[dict[str, str]] = []
            for a in group:
                alert = alert_by_id.get(str(a.alert_id)) or {}
                detail = details.get(str(alert.get("external_id")))
                obs.extend(_observables_from(detail, alert.get("raw_event")))
            chunks, trunc_lim = chunk_observables(obs)
            if trunc_lim:
                limitations.append(trunc_lim)
            # Spec §5.1: even when the excess observables are truncated, up to
            # 3 calls (3x20) are still made; the group's stage 6 is
            # "incomplete" when truncated (excess not sent) or a chunk failed.
            group_hunt_incomplete = bool(trunc_lim)
            for chunk in chunks:
                if not budget_left():
                    group_hunt_incomplete = True
                    break
                result, err, cls = await call(
                    "hunt", "/hunt",
                    client.hunt(from_ts, to_ts, chunk),
                    {"from": from_ts, "to": to_ts, "observables": chunk},
                    retries=0,
                    params_ref=ext_ids[0],
                )
                if result is not None:
                    edr_evidence[f"hunt:{ext_ids[0]}"] = result
                    if result.get("has_more"):
                        limitations.append("hunt_truncated")
                    for it in result.get("items") or []:
                        # Re-observation on other hosts/users = concrete spread evidence.
                        add_evidence(
                            alert_external_id=ext_ids[0],
                            stage="hunt",
                            kind="hunt_reobserved",
                            observed=True,
                            assessment="malicious_indicator",
                        )
                elif err is not None:
                    group_hunt_incomplete = True
            for ext in ext_ids:
                outcome = "incomplete" if group_hunt_incomplete else "completed"
                add_stage(ext, "hunt", "dynamic", outcome)

            # Stage 7: file ingress per group.
            sha256: str | None = None
            for a in group:
                alert = alert_by_id.get(str(a.alert_id)) or {}
                detail = details.get(str(alert.get("external_id"))) or {}
                sha256 = sha256 or (((detail.get("item") or {}).get("file") or {}).get("hash") or {}).get("sha256")
                if not sha256:
                    sha256 = (((alert.get("raw_event") or {}).get("file") or {}).get("hash") or {}).get("sha256")
                if sha256:
                    break
            if features.get("file_ingress") is False:
                for ext in ext_ids:
                    limitations.append(f"file_ingress_unavailable({ext})")
                    add_stage(ext, "file_ingress", "dynamic", "unavailable")
            elif not sha256:
                for ext in ext_ids:
                    add_stage(ext, "file_ingress", "dynamic", "incomplete")
            elif budget_left():
                result, err, cls = await call(
                    "file_ingress", "/investigations/file-ingress",
                    client.check_file_ingress(from_ts, to_ts, sha256),
                    {"sha256": sha256, "from": from_ts, "to": to_ts},
                    params_ref=ext_ids[0],
                )
                if result is not None:
                    edr_evidence[f"file_ingress:{ext_ids[0]}"] = result
                    if result.get("truncated") or result.get("warnings"):
                        limitations.append("file_ingress_truncated")
                    for obs_item in result.get("observed") or []:
                        add_evidence(
                            alert_external_id=ext_ids[0],
                            stage="file_ingress",
                            kind="file_ingress_observed",
                            observed=True,
                            assessment=_evidence_assessment_from_item(obs_item),
                        )
                    if result.get("inferred"):
                        limitations.append("file_ingress_inferred_candidates_present")
                    for ext in ext_ids:
                        add_stage(ext, "file_ingress", "dynamic", "completed")
                else:
                    for ext in ext_ids:
                        add_stage(ext, "file_ingress", "dynamic", "incomplete")
            if budget_exhausted:
                break

    # ------------------------------------------------------------------
    # Priority 3 (spec §5.4): timeline (3) + graph (4) per alert.
    # static source_kind: skipped pre-decision (client returns unavailable dict).
    # ------------------------------------------------------------------
    for ref in selected:
        if budget_exhausted:
            break
        alert = alert_by_id.get(str(ref.alert_id)) or {}
        ext_id = str(alert.get("external_id"))
        parsed = parse_external_id(ext_id)
        kind = parsed[0] if parsed else "unknown"
        event_id = parsed[1] if parsed else ""

        # Stage 3: timeline.
        tl_result, tl_err, tl_cls = await call(
            "timeline", f"/investigations/{kind}/{event_id}/timeline",
            client.fetch_case_timeline(kind, event_id),
            {"source_kind": kind, "event_id": event_id},
            params_ref=ext_id,
        )
        if isinstance(tl_result, dict) and tl_result.get("status") == "unavailable":
            edr_evidence[f"timeline:{ext_id}"] = tl_result
            limitations.append(tl_result.get("reason_code", "timeline_unavailable"))
            add_stage(ext_id, "timeline", kind, "unavailable")
        elif tl_result is not None:
            # Pagination (spec §16): has_more -> next_cursor only; each page is
            # one counted call. Accumulate items across all pages so the
            # evidence count reflects the full timeline.
            tl_items: list[dict[str, Any]] = list(tl_result.get("items") or [])
            cursor = tl_result.get("next_cursor")
            while tl_result.get("has_more") and cursor and budget_left():
                page, err, cls = await call(
                    "timeline", f"/investigations/{kind}/{event_id}/timeline",
                    client.fetch_case_timeline(kind, event_id, cursor=cursor),
                    {"cursor": cursor},
                    params_ref=ext_id,
                )
                if page is None:
                    tl_cls = "incomplete"
                    break
                tl_items.extend(page.get("items") or [])
                tl_result = page
                cursor = page.get("next_cursor")
                if page.get("has_more") and cursor:
                    limitations.append("timeline_truncated")
            edr_evidence[f"timeline:{ext_id}"] = {
                "items": tl_items,
                "has_more": bool(tl_result.get("has_more")),
            }
            if tl_cls == "completed":
                add_evidence(
                    alert_external_id=ext_id,
                    stage="timeline",
                    kind="timeline_sample",
                    observed=True,
                    assessment="not_determined",
                    timeline_events=len(tl_items),
                )
            add_stage(ext_id, "timeline", kind, tl_cls)
        else:
            add_stage(ext_id, "timeline", kind, tl_cls)

        # Stage 4: graph (client retries once on truncated internally;
        # static -> unavailable pre-decision, no HTTP call made).
        g_result, g_err, g_cls = await call(
            "graph", f"/investigations/{kind}/{event_id}/graph",
            client.fetch_case_graph(kind, event_id),
            {"source_kind": kind, "event_id": event_id},
            retries=0,
            params_ref=ext_id,
        )
        if isinstance(g_result, dict) and g_result.get("status") == "unavailable":
            edr_evidence[f"graph:{ext_id}"] = g_result
            limitations.append(g_result.get("reason_code", "graph_unavailable"))
            add_stage(ext_id, "graph", kind, "unavailable")
        elif g_result is not None:
            edr_evidence[f"graph:{ext_id}"] = g_result
            if g_result.get("truncated"):
                limitations.append(f"graph_truncated({ext_id})")
                add_stage(ext_id, "graph", kind, "incomplete")
            else:
                add_stage(ext_id, "graph", kind, "completed")
        else:
            add_stage(ext_id, "graph", kind, g_cls)

    # ------------------------------------------------------------------
    # Priority 4 (spec §5.4): host inventory (dedup by agent_id) +
    # optional stages 8 (process detail) / 9 (event search).
    # ------------------------------------------------------------------
    agent_ids: list[str] = []
    process_ids: list[str] = []
    for ref in selected:
        alert = alert_by_id.get(str(ref.alert_id)) or {}
        agent_id = ((alert.get("raw_event") or {}).get("agent") or {}).get("id")
        if agent_id and str(agent_id) not in agent_ids:
            agent_ids.append(str(agent_id))
        pid = ((alert.get("raw_event") or {}).get("process") or {}).get("entity_id")
        if pid and str(pid) not in process_ids:
            process_ids.append(str(pid))

    for agent_id in agent_ids:
        if budget_exhausted:
            break
        result, err, cls = await call(
            "host_inventory", f"/hosts/{agent_id}",
            client.host_inventory_by_agent(agent_id),
            {"agent_id": agent_id},
            params_ref=agent_id,
        )
        if result is not None:
            edr_evidence[f"host_inventory:{agent_id}"] = result

    for pid in process_ids:
        if budget_exhausted:
            break
        result, err, cls = await call(
            "process_detail", f"/processes/{pid}",
            client.lookup_process_range(pid, from_ts=group_from_ts, to_ts=group_to_ts),
            {"process_id": pid, "from": group_from_ts, "to": group_to_ts},
            params_ref=pid,
        )
        if result is not None:
            edr_evidence[f"process_detail:{pid}"] = result

    # Optional stage 9: broad event search within the group window (spec §5.1:
    # unfiltered broad search stays <= event_search_broad_max_minutes).
    broad_limit = int(limits.get("event_search_broad_max_minutes", 60))
    span_min = (
        int((_iso(selected[-1].event_time) - _iso(selected[0].event_time)).total_seconds() / 60)
        if len(selected) > 1
        else _dur_min(_TIMELINE_BEFORE) + _dur_min(_TIMELINE_AFTER)
    ) if selected else 0
    if selected and features.get("event_search") and not budget_exhausted and span_min <= broad_limit:
        result, err, cls = await call(
            "event_search", "/events/search",
            client.search_case_events(group_from_ts, group_to_ts),
            {"from": group_from_ts, "to": group_to_ts},
            params_ref="case",
        )
        if result is not None:
            edr_evidence["event_search"] = result
            if (result.get("coverage") or {}).get("consistency") == "eventual" or result.get("warnings"):
                limitations.append("event_search_recent_data_may_change")

    # ------------------------------------------------------------------
    # Build the LLM bundle (spec §5.2) + entities + mitre (spec §4, §6.1).
    # Raw responses stay in the artifacts only; the bundle carries summaries.
    # ------------------------------------------------------------------
    def _j(data: Any) -> str:
        return json.dumps(data, ensure_ascii=False)

    process_chain: list[dict[str, Any]] = []
    for key, val in edr_evidence.items():
        if key.startswith("graph:") and isinstance(val, dict):
            for node in val.get("nodes") or []:
                if node.get("kind") == "process":
                    process_chain.append({"id": node.get("id"), "label": node.get("label")})

    timeline_samples: list[dict[str, Any]] = []
    for key, val in edr_evidence.items():
        if key.startswith("timeline:") and isinstance(val, dict):
            items = val.get("items") or []
            # Time-ordered sampling with first/last (spec §5.2 drop-priority 4).
            timeline_samples.extend(items[:2] + (items[-2:] if len(items) > 4 else []))

    first_alert = alert_by_id.get(str(selected[0].alert_id)) if selected else None
    raw0 = (first_alert or {}).get("raw_event") or {}
    entities = {
        "agent_id": str((raw0.get("agent") or {}).get("id") or ""),
        "pc_name": ((raw0.get("host") or {}).get("name") or ""),
        "pc_ip": ((raw0.get("host") or {}).get("ip") or []),
        "user": ((raw0.get("user") or {}).get("name") or ""),
        "process": {
            "entity_id": ((raw0.get("process") or {}).get("entity_id") or ""),
            "name": ((raw0.get("process") or {}).get("name") or ""),
            "pid": ((raw0.get("process") or {}).get("pid")),
            "creation_time": ((raw0.get("process") or {}).get("created_at") or ""),
        },
    }
    mitre = list(case_context.get("mitre_techniques") or [])

    bundle = {
        "case_context": _j(case_context),
        "alerts": _j([
            {
                "id": str(r.alert_id),
                "external_id": (alert_by_id.get(str(r.alert_id)) or {}).get("external_id"),
                "severity": r.severity,
                "event_time": r.event_time,
            }
            for r in selected
        ]),
        "evidence": _j(evidence),
        "process_chain": _j(process_chain),
        "timeline": _j(timeline_samples),
        "host_inventory": _j([edr_evidence[k] for k in edr_evidence if k.startswith("host_inventory:") and isinstance(edr_evidence[k], dict)],),
        "optional_stages": _j({
            "process_detail": [edr_evidence[k] for k in edr_evidence if k.startswith("process_detail:") and isinstance(edr_evidence[k], dict)],
            "event_search": edr_evidence.get("event_search"),
            "limitations": limitations,
        }),
    }

    state.update(
        {
            "edr_evidence": edr_evidence,
            "stage_results": stage_results,
            "evidence": evidence,
            "bundle": bundle,
            "limitations": limitations,
            "entities": entities,
            "mitre_techniques": mitre,
            "case_context": case_context,
            "alerts": alerts,
        }
    )
    return state


# Exposed for the graph wiring (U7b: node signature (state, config)).
case_edr_collect_node = edr_collect_node
