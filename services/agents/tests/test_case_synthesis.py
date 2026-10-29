"""U11: LLM synthesis node fail-closed logic (plan U11, spec §5.2, §5.3, §9.3).

Covers the §9.3 scenarios: LLM unconfigured (insufficient + llm_unavailable),
LLM call failure (llm_call_failed), output schema violation (llm_output_invalid
rejection), context truncation (context_truncated) and budget exceeded (budget_exceeded,
LLM not called). LLM is granted no tools, so instruction text in evidence can't
trigger extra API calls.
"""
from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest

import app.graph.case_synthesis as cs
from app.graph.case_synthesis import (
    SYNTHESIS_ROLE,
    CaseSynthesisResult,
    bundle_token_cost,
    build_synthesis_prompt,
    case_synthesis,
    reduce_bundle,
)
from app.llm.factory import resolve_model_alias

VALID_REPORT = {
    "case_id": "c1",
    "case_number": "CASE-2026-00001",
    "run_id": "run-1",
    "verdict": "true_positive",
    "synthesis_performed": True,
    "confidence": 0.8,
    "confidence_source": {"llm_reported": 0.92, "cap": 0.8, "cap_reasons": ["stage_incomplete_non_supporting"]},
    "evidence": [{"id": "ev-1", "alert_external_id": "dynamic:aa", "stage": "hunt", "kind": "hunt_reobserved", "observed": True, "assessment": "malicious_indicator"}],
    "counter_evidence": [],
    "limitations": [],
    "entities": {"pc_name": "host-01", "process": {"name": "sample.exe", "command_line": "<redacted>"}},
    "mitre_techniques": ["T1036.005"],
    "narrative": "Confirmed facts: sample.exe created payload.dll; same hash re-observed on another host.",
}


def _valid_report() -> dict:
    return copy.deepcopy(VALID_REPORT)


def _fake_llm(report: dict, fail: Exception | None = None, tokens: int = 1234):
    """A stub LLM whose ainvoke returns ``report`` as JSON content."""

    class _FakeLLM:
        async def ainvoke(self, messages, **kwargs):
            if fail is not None:
                raise fail
            return SimpleNamespace(
                content=json.dumps(report),
                response_metadata={"token_usage": {"total_tokens": tokens}},
            )

    return _FakeLLM()


def _stub(monkeypatch, report: dict, fail: Exception | None = None, tokens: int = 1234):
    """Patch the LLM constructor in the case_synthesis module namespace."""
    monkeypatch.setattr(cs, "_make_llm", lambda max_tokens, **kw: _fake_llm(report, fail, tokens))


def _patch_config(monkeypatch, configured: bool):
    """Patch ``resolve_api_key`` as bound in the case_synthesis module (it is
    imported by name, so the function object itself is not the right target)."""
    monkeypatch.setattr(cs, "resolve_api_key",
                         lambda model=None: ("sk-test" if configured else None))


@pytest.mark.asyncio
async def test_llm_unconfigured(monkeypatch):
    """§9.3: LLM unconfigured -> run completed, verdict insufficient,
    synthesis_performed false, limitation llm_unavailable."""
    _patch_config(monkeypatch, configured=False)
    res = await case_synthesis({"case_context": "case c1", "evidence": "ev-1"})
    assert isinstance(res, CaseSynthesisResult)
    assert res.verdict == "insufficient"
    assert res.synthesis_performed is False
    assert res.confidence == 0.0
    assert res.limitations == ["llm_unavailable"]
    assert res.report is None


@pytest.mark.asyncio
async def test_llm_call_failed(monkeypatch):
    """§9.3: gateway 5xx / timeout -> llm_call_failed, fail-closed."""
    _patch_config(monkeypatch, configured=True)
    _stub(monkeypatch, {}, fail=TimeoutError("gateway timeout"))
    res = await case_synthesis({"case_context": "case c1", "evidence": "ev-1"})
    assert res.verdict == "insufficient"
    assert res.synthesis_performed is False
    assert res.limitations == ["llm_call_failed"]
    assert "TimeoutError" in res.error


@pytest.mark.asyncio
async def test_schema_violation_rejected(monkeypatch):
    """§9.3: LLM returns a verdict outside the 3-value enum -> rejected,
    llm_output_invalid (fail-closed, not a clamp)."""
    _patch_config(monkeypatch, configured=True)
    bad = _valid_report()
    bad["verdict"] = "maybe"  # not in the 3-value enum
    _stub(monkeypatch, bad)
    res = await case_synthesis({"case_context": "case c1", "evidence": "ev-1"})
    assert res.verdict == "insufficient"
    assert res.synthesis_performed is False
    assert res.limitations[0] == "llm_output_invalid"


@pytest.mark.asyncio
async def test_redacted_restoration_rejected(monkeypatch):
    """§9.3: LLM restored a <redacted> command line -> rejected."""
    _patch_config(monkeypatch, configured=True)
    bad = _valid_report()
    bad["entities"]["process"]["command_line"] = "C:\\temp\\sample.exe -m"
    _stub(monkeypatch, bad)
    res = await case_synthesis({"case_context": "case c1", "evidence": "ev-1"})
    assert res.limitations[0] == "llm_output_invalid"


@pytest.mark.asyncio
async def test_valid_report_adopted_and_clamped(monkeypatch):
    """§9.2: LLM reports 0.92, cap 0.8 -> clamped to 0.8 (valid, adopted)."""
    _patch_config(monkeypatch, configured=True)
    _stub(monkeypatch, _valid_report())
    res = await case_synthesis({"case_context": "case c1", "evidence": "ev-1"})
    assert res.synthesis_performed is True
    assert res.verdict == "true_positive"
    assert res.confidence == 0.8  # min(0.92, 0.8)
    assert res.report["confidence"] == 0.8
    assert res.confidence_source["llm_reported"] == 0.92


@pytest.mark.asyncio
async def test_context_truncated(monkeypatch):
    """§9.3: input bundle exceeds the input budget -> lower-priority sections
    dropped, context_truncated recorded, LLM still called with the reduced bundle."""
    _patch_config(monkeypatch, configured=True)
    monkeypatch.setenv(cs.CASE_INVESTIGATION_MAX_TOKENS_ENV, "500")  # input budget = 100 tokens
    bundle = {
        "case_context": "x" * 400,  # 100 tokens -> fits exactly in 100
        "evidence": "y" * 400,      # 100 tokens
        "timeline": "z" * 400,      # 100 tokens
        "host_inventory": "w" * 400,  # 100 tokens
        "optional_stages": "v" * 400,  # 100 tokens
    }
    _stub(monkeypatch, _valid_report())
    res = await case_synthesis(bundle)
    assert res.synthesis_performed is True
    assert any(l.startswith("context_truncated") for l in res.limitations)


@pytest.mark.asyncio
async def test_budget_exceeded_no_llm_call(monkeypatch):
    """§9.3: the top-priority section alone exceeds the input budget -> LLM
    NOT called, insufficient + budget_exceeded (no arbitrary increase)."""
    _patch_config(monkeypatch, configured=True)
    monkeypatch.setenv(cs.CASE_INVESTIGATION_MAX_TOKENS_ENV, "100")  # input budget = 20 tokens
    bundle = {"case_context": "x" * 200}  # 50 tokens > 20; case_context can't be dropped
    called = []

    def _make_llm(max_tokens, **kw):
        called.append(max_tokens)
        return _fake_llm(_valid_report())

    monkeypatch.setattr(cs, "_make_llm", _make_llm)
    res = await case_synthesis(bundle)
    assert res.verdict == "insufficient"
    assert res.synthesis_performed is False
    assert res.limitations == ["budget_exceeded"]
    assert called == []  # LLM was NOT called


def test_reduce_bundle_drops_low_priority():
    bundle = {
        "case_context": "a" * 400,  # 100 tokens
        "alerts": "b" * 400,
        "evidence": "c" * 400,
        "process_chain": "d" * 100,  # 25 tokens
        "timeline": "e" * 400,
        "host_inventory": "f" * 400,
        "optional_stages": "g" * 400,
    }
    reduced, dropped = reduce_bundle(bundle, max_input_tokens=200)
    assert "host_inventory" in dropped or "optional_stages" in dropped
    assert reduced.get("case_context") is not None
    assert bundle_token_cost(reduced) <= 200


def test_prompt_fences_data_domain():
    system, user = build_synthesis_prompt({"evidence": "hash=abc user=root cmd=<redacted>"})
    assert "not instructions" in system or "not instructions" in user
    assert "<evidence>" in user
    assert "true_positive" in user
