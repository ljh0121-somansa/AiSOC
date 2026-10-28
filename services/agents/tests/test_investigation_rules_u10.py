"""U10: Case-investigation verdict/cap/report-validation rules (plan U10, spec §6.1, §6.2).

Covers §9.2 scenarios: supporting-stage truncation -> insufficient downgrade,
static-only + file_ingress disabled -> false_positive impossible (③ floor),
LLM over-cap confidence (0.92 -> 0.8 clamp, NOT rejected), group-call
incompleteness attribution, collection budget exhaustion (incomplete, no
synthesis), and report schema / verdict-enum / evidence-citation /
`<redacted>`-restoration rejection (llm_output_invalid).
"""
from __future__ import annotations

from app.investigation_rules import (
    EvidenceRef,
    StageResult,
    clamp_confidence,
    compute_confidence_cap,
    compute_verdict,
    validate_case_report,
)

# ---------------------------------------------------------------------------
# Helpers to build stage results compactly
# ---------------------------------------------------------------------------

def _sr(alert: str, stage: str, outcome: str, source_kind: str = "dynamic") -> StageResult:
    return StageResult(alert_external_id=alert, stage=stage, source_kind=source_kind, outcome=outcome)


DYN = "dynamic:af093445-28a3-40c0-9481-e6397c0c1a56"
STA = "static:15ae9697-9b04-48e5-a883-06db71e76d33"


# ---------------------------------------------------------------------------
# compute_verdict (spec §6.2(a) ①-④)
# ---------------------------------------------------------------------------

def test_true_positive_supported_by_completed_hunt():
    """§9.2: non-supporting stage truncated (graph truncated on dynamic) +
    observed malicious evidence from a COMPLETED supporting stage (hunt) ->
    verdict stays true_positive, only cap 0.8 (no downgrade)."""
    results = [
        _sr(DYN, "detail", "completed"),
        _sr(DYN, "timeline", "completed"),
        _sr(DYN, "graph", "incomplete"),  # non-supporting truncation
        _sr(DYN, "hunt", "completed"),
        _sr(DYN, "file_ingress", "completed"),
        _sr(STA, "detail", "completed", "static"),
        _sr(STA, "hunt", "completed", "static"),
        _sr(STA, "file_ingress", "unavailable", "static"),  # feature off
    ]
    evidence = [
        EvidenceRef(id="ev-1", alert_external_id=DYN, stage="hunt",
                     assessment="malicious_indicator", observed=True),
    ]
    assert compute_verdict(results, evidence, ["graph_truncated(%s)" % DYN]) == "true_positive"


def test_downgrade_when_supporting_stage_incomplete():
    """§9.2: the stage that produced the verdict-supporting evidence is
    incomplete -> downgrade to insufficient."""
    results = [
        _sr(DYN, "detail", "completed"),
        _sr(DYN, "hunt", "incomplete"),  # supporting stage incomplete
    ]
    evidence = [
        EvidenceRef(id="ev-1", alert_external_id=DYN, stage="hunt",
                     assessment="malicious_indicator", observed=True),
    ]
    assert compute_verdict(results, evidence, []) == "insufficient"


def test_false_positive_all_conditions():
    """§9.2: dynamic alert with core stages (2,3,4,6) all completed +
    observed benign evidence -> false_positive allowed."""
    results = [
        _sr(DYN, "detail", "completed"),
        _sr(DYN, "timeline", "completed"),
        _sr(DYN, "graph", "completed"),
        _sr(DYN, "hunt", "completed"),
    ]
    evidence = [
        EvidenceRef(id="ev-1", alert_external_id=DYN, stage="hunt",
                     assessment="benign_indicator", observed=True),
    ]
    assert compute_verdict(results, evidence, []) == "false_positive"


def test_false_positive_blocked_by_alerts_truncated():
    """④: alerts_truncated present -> false_positive impossible (uninvestigated
    alerts remain) -> insufficient."""
    results = [
        _sr(DYN, "detail", "completed"),
        _sr(DYN, "hunt", "completed"),
    ]
    evidence = [
        EvidenceRef(id="ev-1", alert_external_id=DYN, stage="hunt",
                     assessment="benign_indicator", observed=True),
    ]
    assert compute_verdict(results, evidence, ["alerts_truncated(5)"]) == "insufficient"


def test_false_positive_blocked_by_min_stages_floor():
    """§9.2 (③ floor): static-only case with file_ingress disabled -> core
    stages are {detail, hunt}; completed non-detail core stages = 1 (hunt only)
    < 2 -> false_positive impossible -> insufficient."""
    results = [
        _sr(STA, "detail", "completed", "static"),
        _sr(STA, "hunt", "completed", "static"),
        _sr(STA, "file_ingress", "unavailable", "static"),
    ]
    evidence = [
        EvidenceRef(id="ev-1", alert_external_id=STA, stage="hunt",
                     assessment="benign_indicator", observed=True),
    ]
    assert compute_verdict(results, evidence, ["file_ingress_unavailable(%s)" % STA]) == "insufficient"


def test_false_positive_requires_observed_benign():
    """benign evidence that is only `inferred`/`not_determined` ->
    false_positive impossible -> insufficient."""
    results = [
        _sr(DYN, "detail", "completed"),
        _sr(DYN, "hunt", "completed"),
    ]
    evidence = [
        EvidenceRef(id="ev-1", alert_external_id=DYN, stage="hunt",
                     assessment="benign_indicator", observed=False),
    ]
    assert compute_verdict(results, evidence, []) == "insufficient"


def test_incomplete_group_call_attributed_to_all_alerts():
    """§9.2: a group hunt call is incomplete -> every alert in the group has
    its stage-6 marked incomplete. If the supporting evidence came from hunt,
    the verdict downgrades to insufficient."""
    results = [
        _sr(DYN, "detail", "completed"),
        _sr(DYN, "hunt", "incomplete"),  # group hunt call incomplete
    ]
    evidence = [
        EvidenceRef(id="ev-1", alert_external_id=DYN, stage="hunt",
                     assessment="malicious_indicator", observed=True),
    ]
    assert compute_verdict(results, evidence, []) == "insufficient"


def test_no_malicious_or_benign_is_insufficient():
    """§9.2: incomplete collection with no malicious evidence -> insufficient."""
    results = [
        _sr(DYN, "detail", "incomplete"),
        _sr(DYN, "hunt", "incomplete"),
    ]
    assert compute_verdict(results, [], []) == "insufficient"


# ---------------------------------------------------------------------------
# compute_confidence_cap (spec §6.2(d))
# ---------------------------------------------------------------------------

def test_cap_unchanged_when_no_limitation():
    cap, reasons = compute_confidence_cap([], [])
    assert cap == 1.0
    assert reasons == []


def test_cap_08_on_non_supporting_incomplete_or_unavailable():
    """A non-supporting stage incomplete, or an unavailable stage -> cap 0.8."""
    results = [
        _sr(DYN, "graph", "incomplete"),
    ]
    cap, reasons = compute_confidence_cap(results, [])
    assert cap == 0.8
    assert "stage_incomplete_non_supporting" in reasons


def test_cap_08_on_unavailable_core_stage():
    results = [
        _sr(STA, "file_ingress", "unavailable", "static"),
    ]
    cap, reasons = compute_confidence_cap(results, [])
    assert cap == 0.8
    assert "stage_unavailable" in reasons


def test_cap_06_on_two_or_more_bad_core_pairs():
    """Two or more distinct (alert, stage) core pairs that are incomplete or
    unavailable -> cap 0.6."""
    results = [
        _sr(DYN, "graph", "incomplete"),
        _sr(DYN, "timeline", "unavailable"),
    ]
    cap, reasons = compute_confidence_cap(results, [])
    assert cap == 0.6
    assert "core_stage_degraded" in reasons


def test_cap_07_on_context_truncated():
    cap, reasons = compute_confidence_cap([], ["context_truncated(evidence,graph)"])
    assert cap == 0.7
    assert "context_truncated" in reasons


def test_cap_08_on_alerts_truncated():
    cap, reasons = compute_confidence_cap([], ["alerts_truncated(5)"])
    assert cap == 0.8
    assert "alerts_truncated" in reasons


def test_cap_08_on_capabilities_unchecked():
    cap, reasons = compute_confidence_cap([], ["capabilities_unchecked"])
    assert cap == 0.8
    assert "capabilities_unchecked" in reasons


def test_cap_min_of_multiple_reasons():
    """When several caps apply, the MINIMUM wins (0.6 < 0.7 < 0.8)."""
    results = [
        _sr(DYN, "graph", "incomplete"),
        _sr(DYN, "timeline", "unavailable"),
        _sr(DYN, "hunt", "unavailable"),
    ]
    cap, reasons = compute_confidence_cap(results, ["context_truncated(evidence)"])
    assert cap == 0.6  # min(0.6, 0.7, 0.8)
    assert "core_stage_degraded" in reasons
    assert "context_truncated" in reasons


def test_clamp_confidence():
    """LLM reports 0.92 with cap 0.8 -> clamped to 0.8 (valid, not rejected)."""
    assert clamp_confidence(0.92, 0.8) == 0.8
    assert clamp_confidence(0.5, 0.8) == 0.5
    assert clamp_confidence(1.0, 0.6) == 0.6


# ---------------------------------------------------------------------------
# validate_case_report (spec §5.3, §6.1)
# ---------------------------------------------------------------------------

def _report(**overrides):
    r = {
        "case_id": "3f2a9c1e-0000-0000-0000-000000000000",
        "case_number": "CASE-2026-00421",
        "run_id": "run-0001",
        "verdict": "true_positive",
        "synthesis_performed": True,
        "confidence": 0.8,
        "confidence_source": {"llm_reported": 0.92, "cap": 0.8, "cap_reasons": ["stage_incomplete_non_supporting(graph, %s)" % DYN]},
        "evidence": [
            {"id": "ev-1", "alert_external_id": DYN, "stage": "hunt", "kind": "hunt_reobserved", "observed": True, "assessment": "malicious_indicator"},
            {"id": "ev-2", "alert_external_id": STA, "stage": "detail", "kind": "static_detection", "observed": True, "assessment": "not_determined"},
        ],
        "counter_evidence": [],
        "limitations": ["graph_truncated(%s)" % DYN, "timeline_unavailable(%s)" % STA, "graph_unavailable(%s)" % STA],
        "entities": {"agent_id": "0f75dd1c-65d9-4e40-8472-8eca6f48e92d", "pc_name": "host-01", "pc_ip": "192.0.2.10", "user": "Analyst", "process": {"name": "sample.exe", "pid": 4120, "creation_time": "2026-07-07T00:44:12.114Z"}},
        "mitre_techniques": ["T1036.005", "TA005"],
        "narrative": "확인된 사실: sample.exe가 payload.dll 생성. 동일 hash가 hunt에서 재관측.",
    }
    r.update(overrides)
    return r


def test_valid_report_passes():
    ok, err = validate_case_report(_report())
    assert ok is True
    assert err is None


def test_missing_required_key_rejected():
    r = _report()
    del r["confidence"]
    ok, err = validate_case_report(r)
    assert ok is False
    assert err == "llm_output_invalid"


def test_bad_verdict_enum_rejected():
    ok, err = validate_case_report(_report(verdict="maybe"))
    assert ok is False
    assert err == "llm_output_invalid"


def test_synthesis_false_requires_insufficient():
    """synthesis_performed=false but verdict != insufficient -> rejected."""
    ok, err = validate_case_report(_report(synthesis_performed=False, verdict="true_positive"))
    assert ok is False
    assert err == "llm_output_invalid"


def test_confidence_out_of_range_rejected():
    ok, err = validate_case_report(_report(confidence=1.4))
    assert ok is False
    assert err == "llm_output_invalid"


def test_missing_evidence_id_rejected():
    r = _report()
    r["evidence"] = [{"id": "ev-1", "alert_external_id": DYN, "stage": "hunt", "observed": True, "assessment": "malicious_indicator"}]
    del r["evidence"][0]["id"]
    ok, err = validate_case_report(r)
    assert ok is False
    assert err == "llm_output_invalid"


def test_counter_evidence_citing_missing_id_rejected():
    r = _report()
    r["counter_evidence"] = [{"evidence_id": "ev-99", "note": "maintenance window"}]
    ok, err = validate_case_report(r)
    assert ok is False
    assert err == "llm_output_invalid"


def test_redacted_restoration_rejected():
    """Process command_line must stay `<redacted>`; any real value = restoration
    attempt -> rejected (spec §5.3, AGENTS.md §10)."""
    r = _report()
    r["entities"]["process"]["command_line"] = "C:\\temp\\sample.exe -m"
    ok, err = validate_case_report(r)
    assert ok is False
    assert err == "llm_output_invalid"


def test_redacted_kept_is_valid():
    r = _report()
    r["entities"]["process"]["command_line"] = "<redacted>"
    ok, err = validate_case_report(r)
    assert ok is True
    assert err is None
