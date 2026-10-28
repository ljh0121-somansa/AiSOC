"""Case Investigation — pure-logic rules (plan U8, spec §5, §5.1, §5.4).

Pure functions for stage outcome classification, time-window grouping,
observables chunking, and collection budget. No I/O, no SQL, no EDR calls —
U9 wires these to the U2/U3 client methods.

Invariant reminders honoured here (plan §4):
- "unavailable" is admitted ONLY via the ``source_kind`` pre-decision or an
  explicit ``error.code`` (``feature_disabled`` / ``unsupported_source``). A
  bare 404 (``code=None`` / unknown code) is "incomplete", never "unavailable".
- Budget exhaustion is recorded as "incomplete(collection_budget_exceeded)" —
  no synthetic results, no arbitrary budget increase.
- This module is brand-new and unhooked, so existing code is untouched.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any

# ---------------------------------------------------------------------------
# Stage outcome classification (spec §5 "unavailable" strict rule)
# ---------------------------------------------------------------------------

#: Only these error codes mark a stage "unavailable" (spec §5, §9.1).
STAGE_UNAVAILABLE_CODES = frozenset({"feature_disabled", "unsupported_source"})

#: Stages that are unavailable for ``static`` source_kind — the call is
#: skipped before it happens (spec §5 stages 3/4: static timeline/graph).
STATIC_UNAVAILABLE_STAGES = frozenset({"timeline", "graph"})


def classify_stage_outcome(
    error_code: str | None,
    source_kind: str,
    stage: str,
) -> str:
    """Classify a stage outcome as ``"unavailable"`` or ``"incomplete"``.

    Spec §5: "unavailable" is admitted ONLY via the pre-decision on
    ``source_kind`` (static timeline/graph) or an explicit ``error.code`` in
    ``STAGE_UNAVAILABLE_CODES``. A bare 404 (``code=None`` or an unknown
    code) is "incomplete", never "unavailable".
    """
    if error_code is not None and error_code in STAGE_UNAVAILABLE_CODES:
        return "unavailable"
    if source_kind == "static" and stage in STATIC_UNAVAILABLE_STAGES:
        return "unavailable"
    return "incomplete"


# ---------------------------------------------------------------------------
# Time-window grouping (spec §5.1)
# ---------------------------------------------------------------------------

@dataclass
class AlertRef:
    """Minimal alert shape needed by the grouping logic."""
    alert_id: Any
    event_time: str  # ISO-8601 UTC
    severity: str = "info"


def group_alerts_by_time_window(
    alerts: list[AlertRef],
    *,
    gap_hours: float = 24.0,
    max_span_minutes: int = 10080,
    before: str = "PT10M",
    after: str = "PT5M",
) -> tuple[list[list[AlertRef]], list[str]]:
    """Group alerts into time-window groups (spec §5.1).

    1. Sort by ``event_time``; start a new group when the gap between
       adjacent alerts exceeds ``gap_hours`` (24h).
    2. Group span cap: ``(max_ts − min_ts) + before + after ≤
       max_span_minutes`` (168h). When a group's span exceeds the cap, split
       at the largest adjacent gap and recurse.
    3. If a single alert's window itself exceeds the cap, the group is kept
       as-is and ``time_window_exceeds_limit`` is returned as a limitation
       (U9 marks the affected stage as incomplete).

    Returns ``(groups, limitations)`` where ``limitations`` lists any
    ``time_window_exceeds_limit`` markers.
    """
    def _ts(a: AlertRef) -> datetime:
        return datetime.fromisoformat(a.event_time.replace("Z", "+00:00"))

    def _dur_min(dur: str) -> int:
        # "PT10M" / "PT5M" → 10 / 5 minutes; "PT100H" → 6000 minutes.
        value = float(dur[2:-1])
        return int(value * 60) if dur.endswith("H") else int(value)

    margin_min = _dur_min(before) + _dur_min(after)
    sorted_alerts = sorted(alerts, key=lambda a: _ts(a))

    # Step 1: split by 24h gap
    groups: list[list[AlertRef]] = []
    current: list[AlertRef] = []
    for alert in sorted_alerts:
        if current:
            gap_h = (_ts(alert) - _ts(current[-1])).total_seconds() / 3600
            if gap_h > gap_hours:
                groups.append(current)
                current = []
        current.append(alert)
    if current:
        groups.append(current)

    limitations: list[str] = []

    def _split(group: list[AlertRef]) -> list[list[AlertRef]]:
        """Recursively split at the largest adjacent gap until the span fits
        the cap; if the window itself exceeds the cap, keep the group and
        record ``time_window_exceeds_limit``."""
        ts = [_ts(a) for a in group]
        span_min = (ts[-1] - ts[0]).total_seconds() / 60 + margin_min
        if span_min <= max_span_minutes:
            return [group]
        if len(group) <= 1:
            limitations.append("time_window_exceeds_limit")
            return [group]
        gaps = [
            ((ts[i + 1] - ts[i]).total_seconds() / 60, i)
            for i in range(len(ts) - 1)
        ]
        max_gap_min, split_idx = max(gaps, key=lambda x: x[0])
        if max_gap_min < margin_min:
            # The largest gap is too small to split — keep the group, mark it.
            limitations.append("time_window_exceeds_limit")
            return [group]
        left = group[: split_idx + 1]
        right = group[split_idx + 1 :]
        result: list[list[AlertRef]] = []
        result.extend(_split(left))
        result.extend(_split(right))
        return result

    result: list[list[AlertRef]] = []
    for group in groups:
        result.extend(_split(group))
    return result, limitations


# ---------------------------------------------------------------------------
# Observables chunking (spec §5.1, stage 6)
# ---------------------------------------------------------------------------

def chunk_observables(
    observables: list[dict[str, str]],
    *,
    per_call: int = 20,
    max_calls: int = 3,
) -> tuple[list[list[dict[str, str]]], str | None]:
    """Chunk observables into per-call batches (spec §5.1, stage 6).

    Returns ``(chunks, truncation_limitation)``. If ``len(observables) >
    per_call * max_calls`` (60), the excess is NOT sent and
    ``observables_truncated(<count>)`` is returned as the limitation code.
    """
    total = len(observables)
    usable = min(total, per_call * max_calls)
    chunks = [
        observables[i : i + per_call]
        for i in range(0, usable, per_call)
    ]
    if total > usable:
        return chunks, f"observables_truncated({total - usable})"
    return chunks, None


# ---------------------------------------------------------------------------
# Collection budget (spec §5.4)
# ---------------------------------------------------------------------------

@dataclass
class CollectionBudget:
    """Deterministic collection budget (spec §5.4): wall-clock cap + call cap.

    Defaults come from env: ``EDR_COLLECTION_MAX_SECONDS`` (600s) and
    ``EDR_COLLECTION_MAX_CALLS`` (``min(200, 10 + 15*N)``); when the env var
    is set it overrides the formula.
    """
    max_seconds: float
    max_calls: int


def collection_budget(alert_count: int) -> CollectionBudget:
    """Compute the collection budget for a case with ``alert_count`` alerts."""
    max_seconds = float(os.getenv("EDR_COLLECTION_MAX_SECONDS", "600"))
    env_calls = os.getenv("EDR_COLLECTION_MAX_CALLS")
    if env_calls:
        max_calls = int(env_calls)
    else:
        max_calls = min(200, 10 + 15 * alert_count)
    return CollectionBudget(max_seconds=max_seconds, max_calls=max_calls)


# ---------------------------------------------------------------------------
# Alert cap (spec §5.1)
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def select_alerts(
    alerts: list[AlertRef],
    *,
    cap: int = 20,
) -> tuple[list[AlertRef], str | None]:
    """Select up to ``cap`` alerts for investigation (spec §5.1).

    Sort by severity descending (critical > high > medium > low > info), ties
    broken by ``event_time`` ascending. When the case has more than ``cap``
    alerts, the excess is not investigated and
    ``alerts_truncated(<count>)`` is returned.
    """
    if len(alerts) <= cap:
        return alerts, None
    ordered = sorted(
        alerts,
        key=lambda a: (
            _SEVERITY_ORDER.get(a.severity.lower(), 99),
            a.event_time,
        ),
    )
    selected = ordered[:cap]
    truncated_count = len(alerts) - cap
    return selected, f"alerts_truncated({truncated_count})"


# ---------------------------------------------------------------------------
# Verdict / confidence cap / report validation (spec §6.1, §6.2)
# ---------------------------------------------------------------------------

VERDICTS = ("true_positive", "false_positive", "insufficient")

# Core stages per source_kind (spec §6.2(a)): gate-off stages are excluded
# from the core set; unavailable stages are dropped, incomplete stages stay.
CORE_STAGES = {
    "dynamic": frozenset({"detail", "timeline", "graph", "hunt", "file_ingress"}),
    "static": frozenset({"detail", "hunt", "file_ingress"}),
}


def core_stages_for(source_kind: str) -> frozenset:
    return CORE_STAGES.get(source_kind, CORE_STAGES["static"])


@dataclass
class StageResult:
    """Outcome of one (alert, stage) collection (spec §5, §6.2)."""
    alert_external_id: str
    stage: str
    source_kind: str
    outcome: str  # "completed" | "incomplete" | "unavailable"


@dataclass
class EvidenceRef:
    """A single collected evidence item (spec §6.1)."""
    id: str
    alert_external_id: str
    stage: str
    assessment: str  # "malicious_indicator" | "benign_indicator" | "not_determined"
    observed: bool


def _completed_non_detail_count(stage_results: list[StageResult]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in stage_results:
        if r.stage in core_stages_for(r.source_kind) and r.outcome == "completed" and r.stage != "detail":
            counts[r.alert_external_id] = counts.get(r.alert_external_id, 0) + 1
    return counts


def _all_core_completed(stage_results: list[StageResult]) -> bool:
    """Spec §6.2(a) ② for false_positive: every core stage of every alert
    must be completed (unavailable excluded, any 'incomplete' fails)."""
    for r in stage_results:
        if r.stage in core_stages_for(r.source_kind) and r.outcome == "incomplete":
            return False
    return True


def _per_alert_min_stages_ok(stage_results: list[StageResult], min_besides_detail: int = 2) -> bool:
    """Spec §6.2(a) ③: per alert, ≥ ``min_besides_detail`` completed core
    stages besides detail(2)."""
    alerts: dict[str, list[StageResult]] = {}
    for r in stage_results:
        if r.stage in core_stages_for(r.source_kind):
            alerts.setdefault(r.alert_external_id, []).append(r)
    for rs in alerts.values():
        completed_non_detail = [r for r in rs if r.outcome == "completed" and r.stage != "detail"]
        if len(completed_non_detail) < min_besides_detail:
            return False
    return True


def compute_verdict(
    stage_results: list[StageResult],
    evidence: list[EvidenceRef],
    limitations: list[str],
) -> str:
    """Compute the Case verdict (spec §6.2): ``true_positive`` / ``false_positive``
    / ``insufficient``.

    ``true_positive`` needs (a) ① an ``observed`` ``malicious_indicator`` and ②
    the supporting stage completed. ``false_positive`` needs (a) ①-④: an
    ``observed`` ``benign_indicator``, all core stages completed (②), per-alert
    completed non-detail core stages ≥ 2 (③), and no ``alerts_truncated`` (④).
    Anything else is ``insufficient`` (no synthetic verdicts, AGENTS.md §5).
    """
    lim_set = set(limitations)
    has_alerts_truncated = any(l.startswith("alerts_truncated") for l in lim_set)

    malicious_observed = [e for e in evidence if e.assessment == "malicious_indicator" and e.observed]
    benign_observed = [e for e in evidence if e.assessment == "benign_indicator" and e.observed]

    if malicious_observed:
        ev = malicious_observed[0]
        supporting = [
            r for r in stage_results
            if r.alert_external_id == ev.alert_external_id and r.stage == ev.stage
        ]
        if supporting and all(r.outcome == "completed" for r in supporting):
            return "true_positive"

    if benign_observed and not has_alerts_truncated:
        if _all_core_completed(stage_results) and _per_alert_min_stages_ok(stage_results):
            return "false_positive"

    return "insufficient"


def compute_confidence_cap(
    stage_results: list[StageResult],
    limitations: list[str],
) -> tuple[float, list[str]]:
    """Compute the confidence cap (spec §6.2(d)): the MIN of all applicable
    caps, with the applied reasons.

    Caps: no limitation -> 1.0; non-supporting incomplete stage or an
    unavailable core stage -> 0.8; ``capabilities_unchecked`` / ``alerts_truncated``
    -> 0.8; ``context_truncated`` -> 0.7; ≥2 distinct (alert, stage) core pairs
    that are incomplete-or-unavailable -> 0.6.
    """
    cap = 1.0
    reasons: list[str] = []

    bad_pairs = set()
    has_unavailable = False
    has_incomplete_core = False
    for r in stage_results:
        if r.stage in core_stages_for(r.source_kind) and r.outcome in ("incomplete", "unavailable"):
            bad_pairs.add((r.alert_external_id, r.stage))
            if r.outcome == "unavailable":
                has_unavailable = True
            if r.outcome == "incomplete":
                has_incomplete_core = True

    lim_set = set(limitations)
    if "capabilities_unchecked" in lim_set:
        cap = min(cap, 0.8)
        reasons.append("capabilities_unchecked")
    if any(l.startswith("alerts_truncated") for l in lim_set):
        cap = min(cap, 0.8)
        reasons.append("alerts_truncated")
    if any(l.startswith("context_truncated") for l in lim_set):
        cap = min(cap, 0.7)
        reasons.append("context_truncated")

    if has_unavailable:
        cap = min(cap, 0.8)
        reasons.append("stage_unavailable")
    if len(bad_pairs) >= 2:
        cap = min(cap, 0.6)
        reasons.append("core_stage_degraded")
    elif has_incomplete_core:
        cap = min(cap, 0.8)
        reasons.append("stage_incomplete_non_supporting")

    return cap, reasons


def clamp_confidence(llm_reported: float, cap: float) -> float:
    """``confidence = min(llm_reported, cap)`` (spec §6.2(d), server clamp)."""
    return min(llm_reported, cap)


REPORT_REQUIRED_KEYS = (
    "case_id", "case_number", "run_id", "verdict", "synthesis_performed",
    "confidence", "confidence_source", "evidence", "counter_evidence",
    "limitations", "entities", "mitre_techniques", "narrative",
)


def validate_case_report(report: dict[str, Any]) -> tuple[bool, str | None]:
    """Validate the LLM-produced Case report (spec §5.3, §6.1).

    Reject (return ``("llm_output_invalid")``) when: a required key is missing,
    ``verdict`` is not one of the 3-value enum, ``synthesis_performed`` is false
    but ``verdict`` is not ``insufficient``, an evidence ID is cited that does
    not exist in ``evidence``, or a masked value was restored (``<redacted>``
    replaced by a real command line / secret). Returns ``(True, None)`` when valid.
    """
    for key in REPORT_REQUIRED_KEYS:
        if key not in report:
            return False, "llm_output_invalid"

    verdict = report.get("verdict")
    if verdict not in VERDICTS:
        return False, "llm_output_invalid"

    if report.get("synthesis_performed") is False and verdict != "insufficient":
        return False, "llm_output_invalid"

    confidence = report.get("confidence")
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not (0 <= confidence <= 1):
        return False, "llm_output_invalid"

    # Evidence ID references must exist in the report's own evidence array.
    evidence_ids = {e.get("id") for e in report.get("evidence") or [] if isinstance(e, dict)}
    for e in report.get("evidence") or []:
        if isinstance(e, dict) and "id" not in e:
            return False, "llm_output_invalid"
    # narrative / counter_evidence must not cite a non-existent evidence ID.
    narrative = str(report.get("narrative", ""))
    for e in report.get("counter_evidence") or []:
        ref = e.get("evidence_id") if isinstance(e, dict) else None
        if ref is not None and ref not in evidence_ids:
            return False, "llm_output_invalid"

    # Masked-value restoration guard (spec §5.3 / AGENTS.md §10): the process
    # command line arrives ``<redacted>`` from EDR; the LLM must not restore it.
    entities = report.get("entities") or {}
    process = entities.get("process") or {}
    command_line = process.get("command_line")
    if command_line is not None and command_line != "<redacted>":
        return False, "llm_output_invalid"

    return True, None
