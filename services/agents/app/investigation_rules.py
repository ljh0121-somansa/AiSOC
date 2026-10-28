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
