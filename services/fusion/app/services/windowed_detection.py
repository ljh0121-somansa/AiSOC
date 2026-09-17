"""Stateful / windowed detection engine (Wave 2).

The live :class:`app.services.detection_engine.DetectionEngine` is stateless: it
matches one event at a time. Whole classes of real attacks are only visible
across MULTIPLE events in a time window — brute force, password spray, port
scans, data-staging bursts. This engine adds sliding-window threshold detection:
count events matching a rule, grouped by an entity, and fire once when the count
crosses a threshold inside the window.

State lives in Redis sorted sets (member = event id, score = epoch seconds) so
the window is a cheap ``ZREMRANGEBYSCORE`` + ``ZCARD``, and a short-lived
"fired" marker suppresses duplicate alerts for the same window. Everything is
fail-soft: a Redis outage degrades to "windowed detections are skipped for the
outage", never crashing the fusion pipeline.

Only security-relevant bursts fire — a benign event that doesn't match a rule's
``match_when`` never even touches Redis.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

import structlog

from app.models.alert import AlertSeverity, RawAlert
from app.services.detection_engine import DetectionHit
from app.services.detection_matcher import format_match_condition, matches
from app.services.provenance import extract_provenance

logger = structlog.get_logger()

_SEVERITY_MAP = {
    "critical": AlertSeverity.CRITICAL,
    "high": AlertSeverity.HIGH,
    "medium": AlertSeverity.MEDIUM,
    "low": AlertSeverity.LOW,
    "info": AlertSeverity.INFO,
}


@dataclass(frozen=True)
class WindowRule:
    id: str
    name: str
    severity: str
    category: str
    mitre: list[str]
    # Selects the events this rule counts (evaluated against recovered flat fields).
    match_when: dict[str, Any]
    # Flat field whose value is the entity the count is grouped by.
    group_by: str
    threshold: int
    window_seconds: int
    # Distinct-value cardinality gate. For each named field, the count of distinct
    # values seen in-window must reach distinct_threshold before the rule fires.
    # Guards against single-category floods (e.g. SSH brute-force = one dst_port)
    # masquerading as multi-target scans. Empty tuple => no gate.
    cardinality_fields: tuple[str, ...] = ()
    distinct_threshold: int = 0


# Built-in windowed rules. Intentionally small + high-signal; the corpus can grow
# via the same JSON export path as the stateless engine later.
_BUILTIN_RULES: tuple[WindowRule, ...] = (
    WindowRule(
        id="wd-bruteforce-auth",
        name="Brute-force: repeated authentication failures",
        severity="high",
        category="identity",
        mitre=["T1110"],
        # Un-suffixed fields are plain-equality clauses in the matcher DSL.
        match_when={"event_type": "authentication", "outcome": "failure"},
        group_by="user",
        threshold=5,
        window_seconds=600,
    ),
    WindowRule(
        id="wd-password-spray",
        name="Password spray: auth failures across many accounts from one source",
        severity="high",
        category="identity",
        mitre=["T1110.003"],
        match_when={"event_type": "authentication", "outcome": "failure"},
        group_by="src_ip",
        threshold=10,
        window_seconds=600,
    ),
    WindowRule(
        id="wd-port-scan",
        name="Port scan: many distinct connections from one source",
        severity="medium",
        category="network",
        mitre=["T1046"],
        # Un-suffixed fields are plain-equality clauses in the matcher DSL.
        match_when={"event_type": "network"},
        group_by="src_ip",
        threshold=50,
        window_seconds=120,
        # Only fire when the traffic spans many distinct ports. Repeated hits on a
        # single port (e.g. SSH brute-force) share one dst_port and must NOT be
        # labelled a scan; that is caught by wd-firewall-ssh-abuse instead.
        cardinality_fields=("dst_port",),
        distinct_threshold=15,
    ),
    WindowRule(
        id="wd-firewall-ssh-abuse",
        name="Repetitive firewall SSH drops: SSH brute-force / abuse",
        severity="high",
        category="firewall",
        mitre=["T1110.001", "T1078"],
        # Firewall logs preserve L4 packet semantics (event_type=network), not an
        # authentication failure, so a single-port flood of SSH drop events matches
        # here instead of wd-bruteforce (which requires event_type=authentication).
        match_when={
            "event_type": "network",
            "dst_port": 22,
            "event_action": "drop",
        },
        group_by="src_ip",
        threshold=30,
        window_seconds=120,
    ),
)


class WindowedDetectionEngine:
    """Redis-backed sliding-window threshold detections."""

    def __init__(self, redis: Any, rules: tuple[WindowRule, ...] = _BUILTIN_RULES, *, key_prefix: str = "aisoc:wd") -> None:
        self._redis = redis
        self._rules = rules
        self._prefix = key_prefix

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    @staticmethod
    def _fields(message: dict[str, Any]) -> dict[str, Any]:
        ocsf = message.get("ocsf_event")
        if not isinstance(ocsf, dict):
            return {}
        raw = ocsf.get("raw_data")
        if isinstance(raw, str) and raw.strip():
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    return parsed
            except (ValueError, TypeError):
                pass
        return ocsf

    async def evaluate(self, message: dict[str, Any]) -> list[DetectionHit]:
        """Count this event into any matching window; return threshold-crossing hits."""
        ocsf = message.get("ocsf_event")
        if not isinstance(ocsf, dict):
            return []
        tenant = str(message.get("tenant_id") or ocsf.get("tenant_uid") or "")
        if not tenant:
            return []
        fields = self._fields(message)
        now = time.time()
        hits: list[DetectionHit] = []
        for rule in self._rules:
            try:
                if not matches(rule.match_when, fields):
                    continue
                entity = fields.get(rule.group_by)
                if not entity:
                    continue
                fired, count = await self._observe_and_check(rule, tenant, str(entity), now, fields)
                if not fired:
                    continue
                hits.append(
                    DetectionHit(
                        rule_id=rule.id,
                        name=rule.name,
                        severity=rule.severity,
                        category=rule.category,
                        mitre=list(rule.mitre),
                        match_count=count,
                        entity_key=str(entity),
                    )
                )
            except Exception as exc:  # noqa: BLE001 — one rule/Redis error must not wedge detection
                logger.debug("windowed_detection.rule_error", rule=rule.id, error=str(exc))
        return hits

    async def _observe_and_check(
        self,
        rule: WindowRule,
        tenant: str,
        entity: str,
        now: float,
        fields: dict[str, Any],
    ) -> tuple[bool, int]:
        key = f"{self._prefix}:{tenant}:{rule.id}:{entity}"
        member = uuid.uuid4().hex
        await self._redis.zadd(key, {member: now})
        # Track distinct values of each cardinality field as a sorted set:
        # member=value, score=now. Re-adding the same value refreshes its score
        # (single dedup) while keeping the latest in-window timestamp.
        for cfield in rule.cardinality_fields:
            value = fields.get(cfield)
            if value is None:
                continue
            ckey = f"{key}:card:{cfield}"
            await self._redis.zadd(ckey, {str(value): now})
            await self._redis.zremrangebyscore(
                ckey, 0, now - rule.window_seconds,
            )
        # Expire member and per-cardinality sets a window after their last event.
        await self._redis.expire(key, rule.window_seconds + 60)
        for cfield in rule.cardinality_fields:
            await self._redis.expire(
                f"{key}:card:{cfield}", rule.window_seconds + 60,
            )
        count = await self._redis.zcard(key)
        # Cardinality gate: distinct window-count per field. Members outside the
        # window were pruned above, so ZCARD equals distinct values in-window.
        for cfield in rule.cardinality_fields:
            distinct = await self._redis.zcard(f"{key}:card:{cfield}")
            if distinct < rule.distinct_threshold:
                return False, count
        if count < rule.threshold:
            return False, count
        # Fire once per window: a short-lived marker suppresses re-firing on every
        # subsequent event until the window rolls.
        fired_key = f"{key}:fired"
        already = await self._redis.set(fired_key, "1", nx=True, ex=rule.window_seconds)
        return bool(already), count

    def build_alert(self, message: dict[str, Any], hit: DetectionHit) -> RawAlert | None:
        ocsf = message.get("ocsf_event") or {}
        tenant_raw = message.get("tenant_id") or ocsf.get("tenant_uid")
        try:
            tenant_id = uuid.UUID(str(tenant_raw))
        except (ValueError, TypeError):
            return None
        fields = self._fields(message)
        matched_rule = next(
            (r for r in self._rules if r.id == hit.rule_id), None
        )
        cond = format_match_condition(
            matched_rule.match_when if matched_rule is not None else {}, fields
        )
        # Resolve rule attributes statically, dynamic metrics at runtime (defensive).
        if matched_rule is not None:
            threshold = matched_rule.threshold
            window = matched_rule.window_seconds
            group_by = matched_rule.group_by
        else:
            threshold = "N"
            window = "N"
            group_by = "entity"
        count = getattr(hit, "match_count", None) or getattr(hit, "count", None) or f">={threshold}"
        entity = getattr(hit, "entity_key", None) or getattr(hit, "group_key", None) or group_by
        description = (
            f"{hit.name} ({hit.severity}): "
            f"{entity} exceeded threshold ({count}/{threshold} in {window}s). "
            f"Condition: {cond}."
        )
        connector_id, connector_type, class_uid = extract_provenance(message, ocsf)
        return RawAlert(
            tenant_id=tenant_id,
            source=f"detection:{hit.rule_id}",
            title=hit.name,
            description=description,
            severity=_SEVERITY_MAP.get(hit.severity, AlertSeverity.MEDIUM),
            src_ip=fields.get("src_ip"),
            hostname=fields.get("hostname") or fields.get("host"),
            username=fields.get("user"),
            mitre_techniques=hit.mitre,
            raw_event=ocsf,
            connector_id=connector_id,
            connector_type=connector_type,
            ocsf_class_uid=class_uid,
            rule_id=hit.rule_id,
            rule_name=hit.name,
        )
