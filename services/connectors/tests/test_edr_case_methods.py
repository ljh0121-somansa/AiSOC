"""U2: Case-investigation EDR call methods on EdrServerConnector (plan U2, spec §5 stages 0-5, §7).

New methods use distinct names; existing connector methods and their
callers are untouched.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from app.connectors.edrserver import EdrServerConnector

BASE = "https://edrserver.internal:7601"


def _connector() -> EdrServerConnector:
    return EdrServerConnector(base_url=BASE, token="aisoc.id.secret")


def _detail_json(event_id: str) -> dict:
    event = {"id": event_id}
    item = {"event": event}
    return {"item": item}


def _not_found_body():
    error = {"code": "not_found", "message": "detection not found"}
    body = {"error": error, "request_id": "req-1"}
    return body


def _feature_disabled_body():
    error = {"code": "feature_disabled", "message": "feature off"}
    return {"error": error}


@pytest.mark.asyncio
async def test_fetch_detection_detail_sends_lookup_hint():
    connector = _connector()
    with respx.mock(base_url=BASE) as m:
        route = m.get("/api/v2/ai-soc/detections/dynamic/ev-9").respond(200, json=_detail_json("ev-9"))
        data = await connector.fetch_detection_detail("dynamic", "ev-9", lookup_hint="hint-9")
        assert data["item"]["event"]["id"] == "ev-9"
        sent_params = route.calls.last.request.url.params
        assert sent_params["lookup_hint"] == "hint-9"


@pytest.mark.asyncio
async def test_fetch_detection_detail_404_error_code_preserved():
    """Bare 404 is NOT 'unavailable' — error.code distinguishes not_found
    (incomplete) from feature_disabled (unavailable) (spec §5)."""
    connector = _connector()
    with respx.mock(base_url=BASE) as m:
        m.get("/api/v2/ai-soc/detections/static/ev-404").respond(404, json=_not_found_body())
        with pytest.raises(Exception) as exc_info:
            await connector.fetch_detection_detail("static", "ev-404")
        assert "not_found" in str(exc_info.value)

        m.get("/api/v2/ai-soc/detections/static/ev-404b").respond(404, json=_feature_disabled_body())
        with pytest.raises(Exception) as exc_info2:
            await connector.fetch_detection_detail("static", "ev-404b")
        assert "feature_disabled" in str(exc_info2.value)


@pytest.mark.asyncio
async def test_fetch_case_graph_truncated_retry_once():
    connector = _connector()
    with respx.mock(base_url=BASE) as m:
        route = m.get("/api/v2/ai-soc/investigations/dynamic/ev-9/graph")
        route.side_effect = [
            httpx.Response(200, json={"nodes": [1, 2], "truncated": True}),
            httpx.Response(200, json={"nodes": [1, 2, 3], "truncated": False}),
        ]
        data = await connector.fetch_case_graph("dynamic", "ev-9")
        assert data["truncated"] is False
        assert route.calls.last.request.url.params["max_nodes"] == "500"


@pytest.mark.asyncio
async def test_fetch_case_timeline_static_skipped_without_call():
    connector = _connector()
    result = await connector.fetch_case_timeline("static", "ev-9")
    assert result == {"status": "unavailable", "reason_code": "timeline_unavailable(static)"}


@pytest.mark.asyncio
async def test_fetch_case_graph_static_skipped_without_call():
    connector = _connector()
    result = await connector.fetch_case_graph("static", "ev-9")
    assert result == {"status": "unavailable", "reason_code": "graph_unavailable(static)"}


@pytest.mark.asyncio
async def test_fetch_case_timeline_dynamic_sends_window_params():
    connector = _connector()
    with respx.mock(base_url=BASE) as m:
        items = [{"code": 6700}]
        route = m.get("/api/v2/ai-soc/investigations/dynamic/ev-9/timeline").respond(
            200, json={"items": items, "has_more": False}
        )
        data = await connector.fetch_case_timeline("dynamic", "ev-9", categories=["process", "file"], action_types=[1, 2])
        p = route.calls.last.request.url.params
        assert p["before"] == "PT10M"
        assert p["after"] == "PT5M"
        assert p["limit"] == "100"
        assert p["categories"] == "process,file"
        assert p["action_types"] == "1,2"


@pytest.mark.asyncio
async def test_host_inventory_by_agent():
    connector = _connector()
    with respx.mock(base_url=BASE) as m:
        host = {"agent_id": "agent-001", "observed_at": "2026-10-28T00:00:00Z"}
        route = m.get("/api/v2/ai-soc/hosts/agent-001").respond(
            200, json={"host": host, "inventory": []}
        )
        data = await connector.host_inventory_by_agent("agent-001")
        assert data["host"]["agent_id"] == "agent-001"


@pytest.mark.asyncio
async def test_detail_503_retry_after_backoff():
    """503 detail_not_ready: backoff via Retry-After, then success (spec §5 stage 2)."""
    connector = _connector()
    with respx.mock(base_url=BASE) as m:
        error = {"code": "detail_not_ready", "retryable": True}
        body = {"error": error}
        route = m.get("/api/v2/ai-soc/detections/dynamic/ev-9")
        route.side_effect = [
            httpx.Response(503, json=body, headers={"Retry-After": "0.01"}),
            httpx.Response(200, json=_detail_json("ev-9")),
        ]
        data = await connector.fetch_detection_detail("dynamic", "ev-9")
        assert data["item"]["event"]["id"] == "ev-9"
        assert len(route.calls) == 2
