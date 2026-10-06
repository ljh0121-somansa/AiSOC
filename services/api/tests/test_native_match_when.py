"""Round-trip tests for the native infix DSL compiler (Step 2).

``compile_native_to_match_when`` turns the human-readable ``detection.condition``
string from a native ``detections/`` rule into the flat ``match_when`` grammar the
vendored fusion matcher (:mod:`app._vendor.detection_matcher`) evaluates. The
grammar is authored by hand against a copy of that matcher, so this suite proves
two contracts:

1. **Grammar shape** - a fixed set of conditions compiles to the exact ``match_when``
   dict the matcher understands (guardrail: the operator never sees an opaque
   compiler bug).
2. **Verdict parity** - ``matches(mw, event)`` returns the expected boolean for
   positive/negative events, i.e. the emitted grammar actually means what the
   human-readable condition says.

A full corpus sweep (``test_native_corpus_round_trip``) additionally checks every
committed native rule: every non-stateful rule round-trips with no parse error.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from app._vendor.detection_matcher import matches
from app.services.detections.native_match_when import compile_native_to_match_when

_REPO = Path(__file__).resolve().parents[3]
_NATIVE_CORPUS = _REPO / "detections"


def test_A_eq_and_numeric_emit_flat_membership():
    body = (
        'id: det-cloud-001\n'
        'detection:\n'
        '  condition: |\n'
        '    event_name == "UpdateDistribution"\n'
        '    AND origin_changed == true\n'
        '    AND distribution_age_days > 30\n'
    )
    result = compile_native_to_match_when(body)
    assert result.status == "compiled"
    assert result.match_when == {
        "event_name": "UpdateDistribution",
        "origin_changed": True,
        "distribution_age_days_gt": 30,
    }
    assert matches(result.match_when, {"event_name": "UpdateDistribution", "origin_changed": True, "distribution_age_days": 41}) is True
    assert matches(result.match_when, {"event_name": "UpdateDistribution", "origin_changed": False, "distribution_age_days": 41}) is False
    assert matches(result.match_when, {"event_name": "UpdateDistribution", "origin_changed": True, "distribution_age_days": 5}) is False


def test_A_isnull_and_not_in_and_in():
    body = (
        'id: det-test-001\n'
        'detection:\n'
        '  condition: |\n'
        '    status IS NULL\n'
        '    AND src NOT IN ["approved", "whitelisted"]\n'
        '    AND dst IN ["host-a", "host-b"]\n'
    )
    result = compile_native_to_match_when(body)
    assert result.status == "compiled"
    assert result.match_when == {
        "status": None,
        "src_not_in": ["approved", "whitelisted"],
        "dst_in": ["host-a", "host-b"],
    }
    # Flat AND-merge: the event must supply every field the rule mentions.
    assert matches(result.match_when, {"status": None, "src": "evil", "dst": "host-a"}) is True
    # An approved source is dropped by NOT IN.
    assert matches(result.match_when, {"status": None, "src": "approved", "dst": "host-a"}) is False
    # A non-listed destination fails IN.
    assert matches(result.match_when, {"status": None, "src": "evil", "dst": "host-z"}) is False


def test_A_grouped_or_and_and():
    body = (
        'id: det-cloud-002\n'
        'detection:\n'
        '  condition: |\n'
        '    finding_type == "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"\n'
        '    OR (finding_type STARTSWITH "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"\n'
        '        AND finding_severity >= 7)\n'
    )
    result = compile_native_to_match_when(body)
    assert result.status == "compiled"
    assert result.match_when == {
        "any_of": [
            {"finding_type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"},
            {
                "finding_type_startswith": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
                "finding_severity_gte": 7,
            },
        ]
    }
    first = {"finding_type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"}
    assert matches(result.match_when, first) is True
    second = {"finding_type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAzure", "finding_severity": 8.5}
    assert matches(result.match_when, second) is True
    third = {"finding_type": "Unrelated", "finding_severity": 8.5}
    assert matches(result.match_when, third) is False


def test_A_contains_and_contains_any():
    body = (
        'id: det-endpoint-001\n'
        'detection:\n'
        '  condition: |\n'
        '    (image_basename == "logman.exe" AND command_line CONTAINS "stop")\n'
        '    OR (image_basename == "wevtutil.exe" AND command_line CONTAINS_ANY ["sl", "/e:false"])\n'
    )
    result = compile_native_to_match_when(body)
    assert result.status == "compiled"
    assert matches(result.match_when, {"image_basename": "logman.exe", "command_line": "logman.exe stop"}) is True
    assert matches(result.match_when, {"image_basename": "logman.exe", "command_line": "logman.exe start"}) is False
    assert matches(result.match_when, {"image_basename": "wevtutil.exe", "command_line": "wevtutil.exe sl"}) is True
    assert matches(result.match_when, {"image_basename": "wevtutil.exe", "command_line": "wevtutil.exe run"}) is False


def test_A_stateful_rule_reports_unsupported():
    body = (
        'id: det-app-001\n'
        'detection:\n'
        '  condition: |\n'
        '    distinct_ports_per_src > 50\n'
        '    AND interval_consistency > 0.85\n'
    )
    result = compile_native_to_match_when(body)
    assert result.status == "unsupported_stateful"
    assert result.match_when is None
    assert result.error


def test_A_no_condition_and_parse_error_are_errors():
    empty = "id: det-test-002\ndetection:\n  condition:\n"
    bad = "id: det-test-003\ndetection:\n  condition: | event_name =="
    assert compile_native_to_match_when(empty).status == "error"
    assert compile_native_to_match_when(bad).status == "error"


@pytest.mark.parametrize("category", ["cloud", "identity", "endpoint", "network", "application", "data-exfil"])
def test_native_corpus_round_trip(category):
    """Every committed rule in a category round-trips with no parse error."""
    if not _NATIVE_CORPUS.is_dir():
        pytest.skip("native corpus not present")
    n = 0
    for f in sorted((_NATIVE_CORPUS / category).glob("*.yaml")):
        raw = f.read_text(encoding="utf-8")
        result = compile_native_to_match_when(raw)
        if result.status == "error":
            pytest.fail(f"{f.name}: unexpected parse error - {result.error}")
        n += 1
    assert n >= 10, f"expected a non-trivial corpus in {category}, got {n}"


def test_native_full_corpus_has_no_parse_errors():
    total = 0
    error = 0
    for category in ["cloud", "identity", "endpoint", "network", "application", "data-exfil"]:
        if not _NATIVE_CORPUS.is_dir():
            continue
        for f in sorted((_NATIVE_CORPUS / category).glob("*.yaml")):
            try:
                raw = f.read_text(encoding="utf-8")
            except OSError:
                continue
            result = compile_native_to_match_when(raw)
            total += 1
            if result.status == "error":
                error += 1
    assert error == 0, f"{error}/{total} native rules failed to parse"
    assert total >= 800
