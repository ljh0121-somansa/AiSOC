"""Hot-reload consumer for the live detection engine (Phase 2).

The API compiles Sigma/YAML rules on save and publishes ``rules:reload`` events
to Redis (see ``services/api/app/services/detections/compiler.py``). This
module subscribes to that channel and applies each event to the *live*
:class:`~app.services.detection_engine.DetectionEngine` instance via its
Copy-on-Write :meth:`~app.services.detection_engine.DetectionEngine.apply_reload`.

Two responsibilities:

* :func:`listen_detection_reload` — background Pub/Sub listener. Applied inline
  on the event loop, non-blocking with respect to evaluation: the engine swap
  is a single pointer assignment, and the Kafka consumer resolves the map at
  event dispatch, so in-flight evaluation is never affected. Fail-soft by
  design: a bad broadcast is logged and skipped, never wedges the service.
* :func:`reconcile_from_postgres` — one-time startup reconciliation. On boot the
  engine has only the JSON-seeded corpus; the PostgreSQL ``detection_rules`` table
  is the durable source of truth, so every ``status='active'`` + ``compile_status='compiled'`` rule is loaded
  (best-effort, retrying) so console-authored rules are live from the first event.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import asyncpg
import structlog

logger = structlog.get_logger()

# Redis channel the API publishes ``rules:reload`` events on.
# Kept here so API and fusion can never drift (Section 0 guardrail A-4).
CHANNEL = "rules:reload"


# API broadcasts ENABLE/DISABLE/UPSERT (see api/compiler.py). The engine's
# Copy-on-Write swap speaks CREATE/UPDATE/DISABLE, so translate on the way in.
_ACTION_MAP = {
    "ENABLE": "CREATE",
    "UPSERT": "UPDATE",
    "DISABLE": "DISABLE",
}


def _map_action(api_action: str | None) -> str:
    """Translate a broadcast ``action`` to the engine's COW action.

    Raises ``ValueError`` for anything unknown so an invalid broadcast can't be
    silently dropped by the matcher.
    """
    try:
        return _ACTION_MAP[api_action]
    except (KeyError, TypeError):
        raise ValueError(f"unknown reload action: {api_action!r}")


async def listen_detection_reload(
    redis_client: Any,
    detector: Any,
    channel: str = CHANNEL,
) -> None:
    """Consume ``rules:reload`` broadcasts and hot-reload ``detector``.

    Runs forever (until cancelled) and reconnects if Redis drops. Unknown
    actions / missing specs raise from :meth:`apply_reload`; the inner handler
    catches and logs them so one bad broadcast can't kill the listener.
    """
    while True:
        pubsub = redis_client.pubsub()
        try:
            await pubsub.subscribe(channel)
            async for message in pubsub.listen():
                if message is None or message.get("type") != "message":
                    continue
                try:
                    payload = json.loads(message["data"])
                    action = _map_action(payload.get("action"))
                    rule_id = str(payload["rule_id"])
                    # API emits match_when both at root and under compiled_rule;
                    # tolerate either (and old broadcasts that only send one).
                    mw = payload.get("match_when")
                    if not mw:
                        cr = payload.get("compiled_rule") or {}
                        mw = cr.get("match_when")
                    match_when = mw if isinstance(mw, dict) else json.loads(mw)
                    metadata = {
                        "name": (payload.get("compiled_rule") or {}).get("name"),
                        "severity": (payload.get("compiled_rule") or {}).get("severity"),
                        "category": (payload.get("compiled_rule") or {}).get("category"),
                    }
                    detector.apply_reload(action, rule_id, match_when, metadata=metadata)
                    logger.info("detection_reload.applied", action=action, rule_id=rule_id)
                except ValueError as exc:
                    logger.error(
                        "detection_reload.invalid_reload",
                        action=str(payload.get("action")),
                        rule_id=payload.get("rule_id"),
                        error=str(exc),
                    )
                except Exception as exc:  # noqa: BLE001 — one bad message must not wedge the listener
                    logger.error("detection_reload.message_failed", error=str(exc))
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — reconnect loop, never exit
            logger.error("detection_reload.listener_error", error=str(exc))
        await asyncio.sleep(1.0)


async def reconcile_from_postgres(database_url: str, detector: Any) -> None:
    """Load ``status='compiled'`` rules from PostgreSQL into the live engine.

    Best-effort with bounded retries (mirrors ``run_migrations.py``'s backoff
    so a Postgres autostop/boot-race doesn't block startup): once Postgres is
    reachable every compiled rule is applied as UPDATE, then we stop
    listening to the table (the Pub/Sub listener handles subsequent changes).
    """
    dsn = database_url.replace("postgresql+asyncpg://", "postgresql://")
    attempts = 6
    for attempt in range(1, attempts + 1):
        try:
            conn = await asyncpg.connect(dsn)
            try:
                rows = await conn.fetch(
                    "SELECT id, name, severity, category, compiled_spec "
                    "FROM detection_rules WHERE status = 'active' AND compile_status = 'compiled'"
                )
                for row in rows:
                    mw = row["compiled_spec"]
                    match_when = mw if isinstance(mw, dict) else json.loads(mw)
                    detector.apply_reload(
                        "UPDATE",
                        str(row["id"]),
                        match_when,
                        metadata={
                            "name": row["name"],
                            "severity": row["severity"],
                            "category": row["category"],
                        },
                    )
                logger.info("detection_reload.reconciled", applied=len(rows))
            finally:
                await conn.close()
            return
        except Exception as exc:  # noqa: BLE001 — retry, then give up soft
            delay = min(2**attempt * 0.1, 2.0)
            logger.warning("detection_reload.reconcile_retry", attempt=attempt, error=str(exc))
            await asyncio.sleep(delay)
    # Postgres never came reachable within the budget. This is awaited
    # synchronously before the Kafka worker starts consuming (see main.py), so
    # raising here crash-restarts the service rather than booting with a silent
    # 0-rule map — the fail-fast contract for the "Postgres down" case (distinct
    # from a slow-to-connect Postgres, which the bounded retry handles).
    raise RuntimeError("Fusion startup aborted: Unable to load detection rules from database")
