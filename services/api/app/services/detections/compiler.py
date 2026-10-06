"""Compile-on-save helper for the live detection hot-reload path (Phase 2).

The console edits Sigma/YAML rule bodies in :mod:`services.api.app.api.v1.endpoints`.
This module turns a saved body into the flat ``match_when`` DSL the fusion
matcher runs (see :mod:`sigma_match_when`), records the result on the rule row
(``compiled_spec`` / ``compile_status`` / ``compile_error``), and publishes a
``rules:reload`` event to fusion so its in-memory registry swaps the rule in,
out, or up without a restart.

The endpoints call :func:`apply_compile_and_reload` *after* their own commit and
only for ``sigma`` / ``yaml`` rules; nothing here touches Redis/DB from inside
the fusion hot path and nothing here rolls back a committed rule.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from redis.asyncio import Redis, from_url

from app.services.detections.native_match_when import compile_native_to_match_when
from app.services.detections.sigma_match_when import (
    CompileResult,
    compile_sigma_to_match_when,
)

if TYPE_CHECKING:
    from app.models.detection_rule import DetectionRule
    from app.db.database import DBSession

logger = logging.getLogger(__name__)

# Only these languages reach the fusion matcher; other rule languages (kql/eql/
# yara/…) are evaluated elsewhere and must never be published for hot-reload.
_RELOAD_LANGUAGES = frozenset({"sigma", "yaml"})

_redis_client: Redis | None = None


async def _get_redis_client() -> Redis:
    from app.core.config import settings

    global _redis_client
    if _redis_client is None:
        _redis_client = from_url(str(settings.REDIS_URL), decode_responses=True)
    return _redis_client


async def compile_rule(rule: DetectionRule, db: DBSession) -> CompileResult:
    """Compile ``rule.rule_body`` and persist the result to the rule row.

    Sets ``compiled_spec`` (the compiled ``match_when`` or ``None``),
    ``compile_status`` and ``compile_error`` from :class:`CompileResult`, then
    commits. ``version`` is owned by the caller (already bumped in the update
    endpoint) and is deliberately left untouched here. A compile error is
    recorded on the row and returned, never raised.
    """
    if getattr(rule, "rule_type", None) == "native":
        result = compile_native_to_match_when(rule.rule_body or "")
    else:
        result = compile_sigma_to_match_when(rule.rule_body or "")
    rule.compiled_spec = result.match_when
    rule.compile_status = result.status
    rule.compile_error = result.error
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return result


def decide_reload_action(
    rule: DetectionRule,
    result: CompileResult,
    *,
    prev_status: str | None,
    prev_body_changed: bool,
) -> str | None:
    """Return the reload ``action`` to broadcast, or ``None`` for no-op.

    ``was_active`` is derived from ``prev_status`` (``None`` for a fresh create).
    The semantics mirror the plan: activate when newly active + compiles,
    disable when going inactive or losing compileability, upsert on a live
    body change, and stay silent otherwise (e.g. ``testing`` status or an
    inactive rule that never ran).
    """
    was_active = prev_status == "active"
    now_active = rule.status == "active"
    compilable = result.status == "compiled"
    if compilable:
        if not now_active:
            return "DISABLE" if was_active else None
        if now_active and was_active and not prev_body_changed:
            return None  # active, unchanged -> nothing to reload
        return "ENABLE" if not was_active else "UPSERT"
    # No longer compilable: drop it from fusion only if it was live there.
    return "DISABLE" if was_active else None


async def broadcast_rule_reload(rule: DetectionRule, action: str) -> None:
    """Publish a ``rules:reload`` event to fusion.

    Fail-soft: a Redis failure is logged and swallowed so a live reload never
    rolls back an already-persisted rule row.
    """
    try:
        client = await _get_redis_client()
        payload = {
            "event_type": "RULE_STATE_CHANGED",
            "rule_id": str(rule.id),
            "action": action,
            "version": rule.version or 1,
            "match_when": rule.compiled_spec,
            "compiled_rule": {
                "id": str(rule.id),
                "name": rule.name,
                "severity": rule.severity,
                "category": rule.category,
                "match_when": rule.compiled_spec,
            },
        }
        await client.publish("rules:reload", json.dumps(payload))
    except Exception as exc:  # noqa: BLE001 — never fail the caller on a reload
        logger.warning("detection_rule.reload_publish_failed", error=str(exc))


async def apply_compile_and_reload(
    rule: DetectionRule,
    db: DBSession,
    *,
    prev_status: str | None = None,
    prev_body_changed: bool = False,
) -> None:
    """Compile a saved Sigma/YAML rule, persist it, and broadcast if needed.

    No-op for non-Sigma rule languages and for rules whose change is not
    observable by fusion. All I/O is non-blocking with respect to the caller's
    response.
    """
    lang = getattr(rule, "rule_language", "")
    if lang not in _RELOAD_LANGUAGES:
        return
    result = await compile_rule(rule, db)
    action = decide_reload_action(
        rule,
        result,
        prev_status=prev_status,
        prev_body_changed=prev_body_changed,
    )
    if action is not None:
        await broadcast_rule_reload(rule, action)
