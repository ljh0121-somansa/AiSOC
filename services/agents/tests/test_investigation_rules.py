"""U8: Case-investigation pure-logic rules (plan U8, spec §5, §5.1, §5.4).

Covers §9.1 scenarios: stage classification (404 vs feature_disabled),
time-window grouping (span cap + time_window_exceeds_limit), observables
chunking (20/call, 3-call cap), alert cap (20 + alerts_truncated), and
§9.2 "collection budget exhaustion" (incomplete, no synthesis).
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta

import pytest

from app.investigation_rules import (
    AlertRef,
    chunk_observables,
    classify_stage_outcome,
    collection_budget,
    group_alerts_by_time_window,
    select_alerts,
)

BASE_TS = "2026-01-01T00:00:00Z"


def _ts(hours_after: float) -> str:
    return (datetime(2026, 1, 1) + timedelta(hours=hours_after)).isoformat() + "Z"


# ---------------------------------------------------------------------------
# Stage classification (spec §5 "unavailable" strict rule, §9.1)
# ---------------------------------------------------------------------------

def test_bare_404_is_incomplete_not_unavailable():
    """Spec §9.1: 404 with unparseable/None code -> incomplete (not_found),
    never 'unavailable'."""
    assert classify_stage_outcome(None, "static", "detail") == "incomplete"
    assert classify_stage_outcome("not_found", "static", "detail") == "incomplete"
    # unknown code -> incomplete
    assert classify_stage_outcome("bad_request", "dynamic", "detail") == "incomplete"


def test_feature_disabled_is_unavailable():
    assert classify_stage_outcome("feature_disabled", "dynamic", "detail") == "unavailable"


def test_unsupported_source_is_unavailable():
    assert classify_stage_outcome("unsupported_source", "unknown", "detail") == "unavailable"


def test_static_timeline_graph_pre_decision():
    """Spec §5: for static source_kind, timeline/graph stages are skipped
    before the call — pre-decision unavailable."""
    assert classify_stage_outcome(None, "static", "timeline") == "unavailable"
    assert classify_stage_outcome(None, "static", "graph") == "unavailable"
    # other stages on static are still attempted
    assert classify_stage_outcome(None, "static", "detail") == "incomplete"
    # dynamic: no pre-decision
    assert classify_stage_outcome(None, "dynamic", "timeline") == "incomplete"


# ---------------------------------------------------------------------------
# Time-window grouping (spec §5.1, §9.1 "group span exceeded")
# ---------------------------------------------------------------------------

def test_grouping_23h_gap_eight_alerts_example():
    """Spec §9.1 example: 8 alerts at 23h gaps -> span = 7*23h = 161h,
    +15min margin = 9675min <= 10080min -> single group, no limitations."""
    alerts = [
        AlertRef(alert_id=f"al-{i}", event_time=_ts(i * 23), severity="high")
        for i in range(8)
    ]
    groups, limitations = group_alerts_by_time_window(alerts)
    assert len(groups) == 1
    assert len(groups[0]) == 8
    assert limitations == []


def test_group_span_exceeded_splits_at_largest_gap():
    """Span = 8*22h = 176h (+15min margin) > 168h cap.
    All gaps are 22h (≤24h, so the 24h-gap rule does NOT pre-fragment).
    The span-cap split triggers: largest gap (22h, all equal → first index 0)
    splits [al-0] | [al-1..al-8]; right span 7*22h=154h fits the cap."""
    gaps = [22, 22, 22, 22, 22, 22, 22, 22]
    ts = [0.0]
    for g in gaps:
        ts.append(ts[-1] + g)
    alerts = [AlertRef(alert_id=f"al-{i}", event_time=_ts(ts[i]), severity="high") for i in range(9)]
    groups, limitations = group_alerts_by_time_window(alerts)
    assert len(groups) == 2
    assert len(groups[0]) == 1
    assert len(groups[1]) == 8
    assert limitations == []


def test_single_alert_window_exceeds_limit():
    """A single alert's window exceeds the cap (before+after margin can't
    be split) -> group kept, time_window_exceeds_limit recorded."""
    # A single alert: span = 0, but the spec says if the *window* itself
    # exceeds the cap, the stage is incomplete. Simulate a very wide
    # before/after: margin alone > cap.
    alerts = [AlertRef(alert_id="al-1", event_time=_ts(0))]
    groups, limitations = group_alerts_by_time_window(
        alerts, before="PT60H", after="PT60H"  # margin 120h
    )
    # margin (720min) + span(0) = 720min <= 10080? No — 120h < 168h, so it
    # fits. Use an even wider margin to exceed the cap.
    groups, limitations = group_alerts_by_time_window(alerts, before="PT100H", after="PT100H")
    assert limitations == ["time_window_exceeds_limit"]
    assert len(groups) == 1


def test_grouping_gap_split_24h():
    """Adjacent gap > 24h starts a new group (spec §5.1 rule 1)."""
    alerts = [
        AlertRef(alert_id="al-1", event_time=_ts(0), severity="high"),
        AlertRef(alert_id="al-2", event_time=_ts(10), severity="high"),
        AlertRef(alert_id="al-3", event_time=_ts(40), severity="high"),  # 30h gap
    ]
    groups, limitations = group_alerts_by_time_window(alerts)
    assert [len(g) for g in groups] == [2, 1]
    assert limitations == []


# ---------------------------------------------------------------------------
# Observables chunking (spec §5.1, §9.1 "observables 20/60 exceeded")
# ---------------------------------------------------------------------------

def test_chunk_observables_21_items():
    """21 observables -> 2 chunks (20 + 1), no truncation."""
    obs = [{"type": "sha256", "value": f"ab{i:032}"} for i in range(21)]
    chunks, limitation = chunk_observables(obs)
    assert [len(c) for c in chunks] == [20, 1]
    assert limitation is None


def test_chunk_observables_61_items():
    """61 observables -> 3 calls (60), excess 1 -> observables_truncated(1)."""
    obs = [{"type": "sha256", "value": f"ab{i:032}"} for i in range(61)]
    chunks, limitation = chunk_observables(obs)
    assert len(chunks) == 3
    assert [len(c) for c in chunks] == [20, 20, 20]
    assert limitation == "observables_truncated(1)"


def test_chunk_observables_within_limit():
    obs = [{"type": "ip", "value": f"10.0.0.{i}"} for i in range(20)]
    chunks, limitation = chunk_observables(obs)
    assert len(chunks) == 1
    assert len(chunks[0]) == 20
    assert limitation is None


# ---------------------------------------------------------------------------
# Alert cap (spec §5.1, §9.1 "Case with 21+ alerts")
# ---------------------------------------------------------------------------

def test_select_alerts_over_cap():
    """21 alerts -> top 20 by severity desc, then event_time asc;
    alerts_truncated(1) returned (spec §6.2(b): false_positive impossible)."""
    alerts = []
    for i in range(21):
        sev = ["critical", "high", "medium", "low", "info"][i % 5]
        alerts.append(AlertRef(alert_id=f"al-{i}", event_time=_ts(i * 2), severity=sev))
    selected, limitation = select_alerts(alerts)
    assert len(selected) == 20
    assert limitation == "alerts_truncated(1)"
    # severity ordering: all 5 criticals come first (al-0,5,10,15,20)
    assert [a.severity for a in selected[:5]] == ["critical"] * 5
    # the excluded alert is al-19 (info, latest info at t=38h)
    assert "al-19" not in [a.alert_id for a in selected]


def test_select_alerts_within_cap():
    alerts = [AlertRef(alert_id="al-1", event_time=_ts(0), severity="high")]
    selected, limitation = select_alerts(alerts)
    assert len(selected) == 1
    assert limitation is None


def test_select_alerts_severity_tie_break():
    """Cap exceeded: same severity -> earlier event_time first (spec §5.1)."""
    alerts = [
        AlertRef(alert_id=f"al-{i}", event_time=_ts(i * 2), severity="high")
        for i in range(21)
    ]
    selected, limitation = select_alerts(alerts)
    # 21 alerts -> top 20 by (severity, event_time asc)
    assert [a.alert_id for a in selected] == [f"al-{i}" for i in range(20)]
    assert limitation == "alerts_truncated(1)"


# ---------------------------------------------------------------------------
# Collection budget (spec §5.4, §9.2 "collection budget exhaustion")
# ---------------------------------------------------------------------------

def test_collection_budget_formula(monkeypatch):
    """Default: total time 600s, calls = min(200, 10 + 15*N)."""
    b = collection_budget(5)
    assert b.max_seconds == 600.0
    assert b.max_calls == 85  # 10 + 15*5


def test_collection_budget_formula_cap_at_200(monkeypatch):
    """13 alerts -> min(200, 10+195)=200."""
    b = collection_budget(13)
    assert b.max_calls == 200


def test_collection_budget_env_override(monkeypatch):
    monkeypatch.setenv("EDR_COLLECTION_MAX_SECONDS", "900")
    monkeypatch.setenv("EDR_COLLECTION_MAX_CALLS", "300")
    b = collection_budget(2)
    assert b.max_seconds == 900.0
    assert b.max_calls == 300
