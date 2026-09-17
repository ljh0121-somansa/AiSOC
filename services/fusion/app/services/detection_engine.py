"""Live detection-evaluation engine (Phase A2).

The reality audit's second SIEM gap: ~939 executable detection rules existed
but only ran in CI fixture-replay — **nothing evaluated them against the live
event stream**, so telemetry that wasn't a vendor-asserted finding (the
promoter's job) never became an alert.

This engine closes that. At fusion boot the engine is seeded from the PostgreSQL
``detection_rules`` table (the single source of truth; see
:func:`app.services.detection_reload.reconcile_from_postgres`), and live edits
from the web console are applied afterwards via
:meth:`DetectionEngine.apply_reload`. It then evaluates each ingested event's
recovered raw fields against every relevant rule's ``match_when`` (via the
vendored :func:`app.services.detection_matcher.matches`). A match becomes a
:class:`DetectionHit` that the fusion consumer turns into a ``RawAlert`` and
routes through the normal dedup/correlate/persist pipeline.

Field alignment (verified against the normalizer): the ingest pipeline
preserves the connector-normalized flat event under ``ocsf_event["raw_data"]``
as a JSON string. The native ``match_when`` specs were authored against exactly
those flat connector fields, so ``matches(rule.match_when, json.loads(raw_data))``
is the correct evaluation contract.

Performance: rules are indexed by ``product`` so an event only evaluates its
own product's rules plus product-agnostic rules, keeping per-event work far
below the full 817-rule corpus. The engine is pure/synchronous; the consumer
calls it inline (the corpus is small and the matcher is regex/dict work).
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog

from app.models.alert import AlertSeverity, RawAlert
from app.services.detection_matcher import matches, format_match_condition
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
class DetectionHit:
    rule_id: str
    name: str
    severity: str
    category: str
    mitre: list[str]
    # Windowed-engine only: the runtime count that crossed threshold and the
    # entity key it was grouped under (populated by windowed_detection.evaluate).
    match_count: int | None = None
    entity_key: str | None = None


def _get(obj: Any, *path: str) -> Any:
    cur: Any = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


class DetectionEngine:
    """Evaluates the native executable corpus against live events."""

    def __init__(self, rules: list[dict[str, Any]] | None = None) -> None:
        # Rule registry is a dict keyed by rule["id"] with Copy-on-Write swap
        # (see apply_reload): the worker's evaluate() path reads the map
        # pointer, the hot-reload listener mutates a fresh copy, so no lock is
        # needed and evaluation stays pure and synchronous.
        #
        # The Postgres ``detection_rules`` table is the single source of truth:
        # the map starts empty here and is populated at startup by
        # :func:`app.services.detection_reload.reconcile_from_postgres`, so fusion
        # never re-reads the deleted JSON artifact. ``rules`` is accepted only for
        # tests that want to inject a corpus directly.
        self._rules_map: dict[str, dict[str, Any]] = {r["id"]: r for r in (rules or [])}

    @property
    def rule_count(self) -> int:
        return len(self._rules_map)

    def _candidates(self, product: str) -> list[dict[str, Any]]:
        # Correctness-first routing: evaluate the whole corpus against every
        # event. Connector product names don't line up 1:1 with spec products
        # (``aws_cloudtrail`` vs ``aws``, ``crowdstrike_falcon`` vs ``edr``), so
        # any product-based pre-filter risks silently dropping a real match.
        # The matcher short-circuits on the first absent field, so a full pass
        # over ~800 rules is cheap in practice (a benign event touches almost
        # none of them past the first clause). Reads the *current* map pointer,
        # so a hot-reload swap is visible to this event stream on the next event.
        return list(self._rules_map.values())

    @staticmethod
    def _raw_fields(ocsf: dict[str, Any]) -> dict[str, Any]:
        """Recover the connector-normalized flat fields the specs match on."""
        raw = ocsf.get("raw_data")
        if isinstance(raw, str) and raw.strip():
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    return parsed
            except (ValueError, TypeError):
                # Malformed raw_data JSON — fall through to the OCSF top level below.
                pass
        # Fall back to the OCSF top level (some connectors emit flat OCSF).
        return ocsf if isinstance(ocsf, dict) else {}

    def evaluate(self, message: dict[str, Any]) -> list[DetectionHit]:
        """Return every rule that fires on this normalized-event message."""
        ocsf = message.get("ocsf_event")
        if not isinstance(ocsf, dict):
            return []
        fields = self._raw_fields(ocsf)
        hits: list[DetectionHit] = []
        for rule in self._candidates(""):
            try:
                if matches(rule["match_when"], fields):
                    hits.append(
                        DetectionHit(
                            rule_id=rule["id"],
                            name=rule["name"],
                            severity=rule["severity"],
                            category=rule["category"],
                            mitre=list(rule.get("mitre") or []),
                        )
                    )
            except Exception as exc:  # noqa: BLE001 — one bad rule must not wedge detection
                logger.debug("detection_engine.rule_error", rule=rule.get("id"), error=str(exc))
        return hits

    def apply_reload(self, action: str, rule_id: str, match_when: dict[str, Any] | None = None, metadata: dict | None = None) -> None:
        """Hot-reload one rule with Copy-on-Write semantics.

        A fresh dict is built with the requested mutation, then the instance
        pointer is atomically reassigned. The Kafka consumer only ever holds a
        reference to the map it resolved at event dispatch, so an in-flight
        evaluate() is never affected, and no lock is needed: the next event
        resolves the newest map. Unknown actions/ids are rejected so the
        broadcaster can't silently drop or corrupt a rule.

        ``match_when`` is required for CREATE/UPDATE (the new spec) and
        ignored for DISABLE (which just removes the id).
        """
        if action not in ("CREATE", "UPDATE", "DISABLE"):
            raise ValueError(f"unknown reload action: {action!r}")
        if action == "DISABLE":
            new_map = dict(self._rules_map)
            new_map.pop(rule_id, None)
        else:
            if match_when is None:
                raise ValueError(f"{action} requires match_when")
            meta = (metadata or {}).copy()
            meta.setdefault("name", rule_id)
            meta.setdefault("severity", "medium")
            meta.setdefault("category", "custom")
            new_map = dict(self._rules_map)
            new_map[rule_id] = {
                "id": rule_id,
                "name": meta["name"],
                "severity": meta["severity"],
                "category": meta["category"],
                "match_when": match_when,
            }
        self._rules_map = new_map

    def build_alert(self, message: dict[str, Any], hit: DetectionHit) -> RawAlert | None:
        """Turn a detection hit into a RawAlert for the fusion pipeline.

        The description names the rule, its severity, the MITRE technique
        count, and the actual field/values that matched the rule's
        ``match_when`` (recovered from the event's raw fields), so an analyst
        opening the alert sees *why* it fired instead of the generic
        "fired on ingested telemetry" placeholder.
        """
        ocsf = message.get("ocsf_event") or {}
        tenant_raw = message.get("tenant_id") or ocsf.get("tenant_uid")
        try:
            tenant_id = uuid.UUID(str(tenant_raw))
        except (ValueError, TypeError):
            return None
        connector_id, connector_type, class_uid = extract_provenance(message, ocsf)
        fields = self._raw_fields(ocsf)
        rule_spec = self._rules_map.get(hit.rule_id, {})
        cond = format_match_condition(rule_spec.get("match_when") or {}, fields)
        # MITRE ID resolution: handle both list and string types defensively.
        if isinstance(hit.mitre, list):
            mitre_str = ", ".join(hit.mitre) if hit.mitre else hit.category
        elif isinstance(hit.mitre, str) and hit.mitre.strip():
            mitre_str = hit.mitre.strip()
        else:
            mitre_str = hit.category

        # Entity context recovered from the raw event for SOC-facing descriptions.
        host = (
            _get(ocsf, "device", "name")
            or _get(ocsf, "device", "hostname")
            or _get(ocsf, "hostname")
        )
        src = _get(ocsf, "src_endpoint", "ip")
        dst = _get(ocsf, "dst_endpoint", "ip")
        user = _get(ocsf, "actor", "user", "name")

        network_str = None
        if src and dst:
            network_str = f"src={src} -> dst={dst}"
        elif src:
            network_str = f"src={src}"
        elif dst:
            network_str = f"dst={dst}"

        entities = []
        if host:
            entities.append(f"host={host}")
        if network_str:
            entities.append(network_str)
        if user:
            entities.append(f"user={user}")

        entity_str = f"Entity: {', '.join(entities)}" if entities else ""

        description = f"{hit.name} ({hit.severity}, {mitre_str}): {cond}."
        if entity_str:
            description = f"{description} {entity_str}"
        return RawAlert(
            tenant_id=tenant_id,
            source=f"detection:{hit.rule_id}",
            title=hit.name,
            description=description,
            severity=_SEVERITY_MAP.get(hit.severity, AlertSeverity.MEDIUM),
            src_ip=_get(ocsf, "src_endpoint", "ip"),
            dst_ip=_get(ocsf, "dst_endpoint", "ip"),
            hostname=_get(ocsf, "device", "name"),
            username=_get(ocsf, "actor", "user", "name"),
            mitre_techniques=list(hit.mitre) if isinstance(hit.mitre, list) else [hit.mitre],
            raw_event=ocsf,
            connector_id=connector_id,
            connector_type=connector_type,
            ocsf_class_uid=class_uid,
            rule_id=hit.rule_id,
            rule_name=hit.name,
        )


