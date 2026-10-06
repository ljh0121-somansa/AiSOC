"""Synthetic output must never be indistinguishable from real output.

Two endpoints returned generated content as an ordinary 200 with nothing on the
wire to mark it:

  * ``POST /api/v1/hunt/search`` always returns ``_synthetic_hits`` — it does
    not query the lake at all — and the console read the 200 as success and
    rendered a green "Live backend" pill over fabricated CrowdStrike events.
  * ``POST /api/v1/copilot/chat`` falls back to a canned paragraph whenever
    ``OPENAI_API_KEY`` is unset or the call raises, so an analyst read generic
    claims as analysis of their own environment.

These tests pin the provenance fields that let a caller tell the difference.
They are deliberately about the contract, not the prose: the fixtures may
change, but a consumer must always be able to ask "did a model produce this?"
and "is this my data?" and get a truthful answer.
"""

from __future__ import annotations

import pytest
from app.api import copilot as copilot_mod
from app.api import hunt_search as hunt_mod


class TestHuntSearchProvenance:
    @pytest.mark.asyncio
    async def test_search_declares_itself_as_sample(self):
        res = await hunt_mod.hunt_search(hunt_mod.HuntQuery(query="process_name:powershell"))
        assert res.source == "sample", (
            "the search handler generates events rather than querying telemetry; it must not present them as live"
        )
        assert res.notice, "a sample response must carry a human-readable reason"
        assert "not results from your telemetry" in res.notice

    @pytest.mark.asyncio
    async def test_hits_are_still_returned(self):
        """Labelling the data must not empty the workbench."""
        res = await hunt_mod.hunt_search(hunt_mod.HuntQuery(query="anything", limit=5))
        assert res.hits, "sample mode should still populate the UI"
        assert res.total == len(res.hits)


class TestCopilotProvenance:
    @pytest.mark.asyncio
    async def test_no_api_key_is_reported_as_template(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        text, source = await copilot_mod._get_openai_reply({"messages": []}, "what happened?")
        assert source == "template"
        assert text, "the fallback should still say something useful"

    @pytest.mark.asyncio
    async def test_llm_failure_is_reported_as_template(self, monkeypatch: pytest.MonkeyPatch):
        """A provider error must degrade visibly, not silently."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-a-real-key")

        async def _boom(*args, **kwargs):
            raise RuntimeError("provider unreachable")

        monkeypatch.setattr("app.llm.contract.safe_chat_completions_request", _boom, raising=False)
        _text, source = await copilot_mod._get_openai_reply({"messages": []}, "hello")
        assert source == "template"

    def test_response_model_defaults_to_llm_but_can_carry_template(self):
        """The field must exist on the wire, not just in the handler."""
        fields = copilot_mod.CopilotChatResponse.model_fields
        assert "source" in fields
        assert "notice" in fields
        msg = copilot_mod.CopilotMessage(id="m1", role="assistant", content="hi", timestamp="2026-01-01T00:00:00Z")
        templated = copilot_mod.CopilotChatResponse(conversationId="c1", reply=msg, source="template", notice="canned")
        assert templated.source == "template"

    @pytest.mark.asyncio
    async def test_stream_no_api_key_yields_template(self, monkeypatch: pytest.MonkeyPatch):
        import json
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        resp = await copilot_mod.chat_stream(copilot_mod.CopilotChatRequest(message="hello"))
        frames = []
        async for chunk in resp.body_iterator:
            for line in chunk.decode().splitlines():
                if line.strip():
                    frames.append(json.loads(line))
        assert len(frames) >= 2
        assert frames[0]["source"] == "template"
        assert frames[-1]["done"] is True

    @pytest.mark.asyncio
    async def test_stream_llm_success_yields_deltas(self, monkeypatch: pytest.MonkeyPatch):
        import json
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
        monkeypatch.setenv("LLM_GATEWAY_URL", "http://litellm:4000")
        async def _mock_stream(*args, **kwargs):
            yield "Hello "
            yield "analyst!"

        monkeypatch.setattr("app.llm.contract.safe_chat_completions_stream", _mock_stream, raising=False)
        resp = await copilot_mod.chat_stream(copilot_mod.CopilotChatRequest(message="hi"))
        frames = []
        async for chunk in resp.body_iterator:
            for line in chunk.decode().splitlines():
                if line.strip():
                    frames.append(json.loads(line))
        assert frames[0]["source"] == "llm"
        deltas = [f.get("delta") for f in frames if "delta" in f]
        assert "Hello " in deltas
        assert "analyst!" in deltas
        assert frames[-1]["done"] is True
