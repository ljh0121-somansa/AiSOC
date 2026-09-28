"""Splunk connector: saved-search dispatch (#525), normalize-once (#528), and
checkpointed pagination + deterministic identity (#529)."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx
from app.connectors.splunk import SplunkConnector

BASE = "https://splunk.test:8089"


def _conn(**kw) -> SplunkConnector:
    return SplunkConnector(base_url=BASE, token="tok", **kw)


# --------------------------------------------------------------------------
# normalize: idempotent + deterministic identity (#528 / #529)
# --------------------------------------------------------------------------


def test_normalize_is_idempotent():
    c = _conn()
    row = {
        "event_id": "E1",
        "search_name": "Brute Force Detected",
        "urgency": "high",
        "_time": "2026-08-01T00:00:00Z",
        "src": "1.2.3.4",
        "host": "h1",
    }
    once = c.normalize(row)
    twice = c.normalize(once)
    # Re-normalizing a canonical envelope must be a no-op (no blanked
    # external_id, no title -> "splunk", no severity reset, no double nesting).
    assert twice == once
    assert once["external_id"] == "E1"
    assert once["title"] == "Brute Force Detected"
    assert once["severity"] == "high"
    assert once["hostname"] == "h1"
    assert once["raw_event"] == row


def test_normalize_deterministic_external_id():
    c = _conn()
    assert c.normalize({"_cd": "1:99", "urgency": "low"})["external_id"] == "1:99"
    assert c.normalize({"event_id": "E7"})["external_id"] == c.normalize({"event_id": "E7"})["external_id"]


# --------------------------------------------------------------------------
# ordering + checkpoint (#529)
# --------------------------------------------------------------------------


def test_order_and_checkpoint_filters_seen_and_advances():
    c = _conn()
    c.set_checkpoint({"time": "2026-08-01T00:00:10Z", "id": "E10"})
    rows = [
        {"event_id": "E09", "_time": "2026-08-01T00:00:09Z"},  # before checkpoint -> dropped
        {"event_id": "E10", "_time": "2026-08-01T00:00:10Z"},  # == checkpoint -> dropped
        {"event_id": "E12", "_time": "2026-08-01T00:00:12Z"},
        {"event_id": "E11", "_time": "2026-08-01T00:00:11Z"},
    ]
    fresh = c._order_and_checkpoint(rows)
    assert [r["event_id"] for r in fresh] == ["E11", "E12"]  # stable order restored
    assert c.get_checkpoint() == {"time": "2026-08-01T00:00:12Z", "id": "E12"}


def test_checkpoint_not_advanced_when_nothing_new():
    c = _conn()
    c.set_checkpoint({"time": "2026-08-01T00:00:99Z", "id": "Z"})
    assert c._order_and_checkpoint([{"event_id": "E1", "_time": "2026-08-01T00:00:01Z"}]) == []
    assert c.get_checkpoint() is None


def test_same_timestamp_distinct_ids_both_kept():
    c = _conn()
    rows = [
        {"event_id": "A", "_time": "2026-08-01T00:00:10Z"},
        {"event_id": "B", "_time": "2026-08-01T00:00:10Z"},
    ]
    assert {r["event_id"] for r in c._order_and_checkpoint(rows)} == {"A", "B"}


# --------------------------------------------------------------------------
# saved-search dispatch vs notable fallback (#525) + pagination (#529)
# --------------------------------------------------------------------------


def _done_status() -> httpx.Response:
    return httpx.Response(200, json={"entry": [{"content": {"dispatchState": "DONE"}}]})


@respx.mock
@pytest.mark.asyncio
async def test_fetch_alerts_dispatches_configured_saved_search():
    c = _conn(saved_search="My Search")
    # Name is URL-encoded into the dispatch path, never injected into SPL.
    dispatch = respx.post(url__regex=r".+/services/saved/searches/My%20Search/dispatch").mock(
        return_value=httpx.Response(201, json={"sid": "SID1"})
    )
    respx.get(url__regex=r".+/services/search/jobs/SID1/results").mock(
        return_value=httpx.Response(200, json={"results": [{"event_id": "E1", "urgency": "high", "_time": "2026-08-01T00:00:00Z"}]})
    )
    respx.get(url__regex=r".+/services/search/jobs/SID1(\?.*)?$").mock(return_value=_done_status())

    out = await c.fetch_alerts(since_seconds=300)
    assert dispatch.called, "configured saved_search was not dispatched (#525)"
    assert len(out) == 1
    assert out[0]["external_id"] == "E1"
    assert out[0]["severity"] == "high"


@respx.mock
@pytest.mark.asyncio
async def test_fetch_alerts_falls_back_to_notable_index_when_unset():
    c = _conn(saved_search="")
    jobs = respx.post(url__regex=r".+/services/search/jobs$").mock(return_value=httpx.Response(201, json={"sid": "SID2"}))
    respx.get(url__regex=r".+/services/search/jobs/SID2/results").mock(return_value=httpx.Response(200, json={"results": []}))
    respx.get(url__regex=r".+/services/search/jobs/SID2(\?.*)?$").mock(return_value=_done_status())

    await c.fetch_alerts()
    assert jobs.called
    assert "notable" in jobs.calls[0].request.content.decode()



@respx.mock
@pytest.mark.asyncio
async def test_fetch_alerts_falls_back_to_notable_on_404_legacy_saved_search():
    c = _conn(saved_search="AiSOC_Alerts")
    respx.post(url__regex=r".+/services/saved/searches/AiSOC_Alerts/dispatch").mock(
        return_value=httpx.Response(404, text="Saved search does not exist")
    )
    jobs = respx.post(url__regex=r".+/services/search/jobs$").mock(return_value=httpx.Response(201, json={"sid": "SID_FALLBACK"}))
    respx.get(url__regex=r".+/services/search/jobs/SID_FALLBACK/results").mock(return_value=httpx.Response(200, json={"results": []}))
    respx.get(url__regex=r".+/services/search/jobs/SID_FALLBACK(\?.*)?$").mock(return_value=_done_status())

    out = await c.fetch_alerts()
    assert jobs.called
    assert "notable" in jobs.calls[0].request.content.decode()
    assert out == []


@respx.mock
@pytest.mark.asyncio
async def test_fetch_alerts_dispatches_existing_aisoc_alerts_saved_search():
    c = _conn(saved_search="AiSOC_Alerts")
    dispatch = respx.post(url__regex=r".+/services/saved/searches/AiSOC_Alerts/dispatch").mock(
        return_value=httpx.Response(201, json={"sid": "SID_REAL"})
    )
    respx.get(url__regex=r".+/services/search/jobs/SID_REAL/results").mock(
        return_value=httpx.Response(200, json={"results": [{"event_id": "E_REAL", "_time": "2026-08-01T00:00:00Z"}]})
    )
    respx.get(url__regex=r".+/services/search/jobs/SID_REAL(\?.*)?$").mock(return_value=_done_status())

    out = await c.fetch_alerts()
    assert dispatch.called
    assert len(out) == 1
    assert out[0]["external_id"] == "E_REAL"


@respx.mock
@pytest.mark.asyncio
async def test_fetch_alerts_raises_on_404_for_custom_saved_search():
    c = _conn(saved_search="Custom_Security_Search")
    respx.post(url__regex=r".+/services/saved/searches/Custom_Security_Search/dispatch").mock(
        return_value=httpx.Response(404, text="Saved search does not exist")
    )
    with pytest.raises(httpx.HTTPStatusError):
        await c.fetch_alerts()


@respx.mock
@pytest.mark.asyncio
async def test_fetch_alerts_raises_when_job_not_done():
    c = _conn(saved_search="")
    respx.post(url__regex=r".+/services/search/jobs$").mock(return_value=httpx.Response(201, json={"sid": "SID_FAIL"}))
    respx.get(url__regex=r".+/services/search/jobs/SID_FAIL(\?.*)?$").mock(
        return_value=httpx.Response(200, json={"entry": [{"content": {"dispatchState": "FAILED"}}]})
    )
    with pytest.raises(RuntimeError, match="state: FAILED"):
        await c.fetch_alerts()


@respx.mock
@pytest.mark.asyncio
async def test_query_strips_index_prefix_for_federated_spl():
    from app.federated.query import UnifiedQuery
    c = _conn(saved_search="index=firewall")
    captured = {}

    def _mock_jobs(request: httpx.Request) -> httpx.Response:
        captured["search"] = request.read().decode()
        return httpx.Response(200, json={"results": []})

    respx.post(url__regex=r".+/services/search/jobs$").mock(side_effect=_mock_jobs)
    await c.query(UnifiedQuery(free_text="blocked"))
    assert "search=search+index%3Dfirewall" in captured["search"]
    assert "index%3Dindex%3D" not in captured["search"]

@respx.mock
@pytest.mark.asyncio
async def test_pagination_collects_all_results_no_head_cap():
    c = _conn(saved_search="", page_size=100)
    total = 250
    respx.post(url__regex=r".+/services/search/jobs$").mock(return_value=httpx.Response(201, json={"sid": "S"}))
    respx.get(url__regex=r".+/services/search/jobs/S(\?.*)?$").mock(return_value=_done_status())

    def _results(request: httpx.Request) -> httpx.Response:
        qs = parse_qs(urlparse(str(request.url)).query)
        offset = int(qs.get("offset", ["0"])[0])
        count = int(qs.get("count", ["100"])[0])
        page = [
            {"event_id": f"E{i}", "_time": f"2026-08-01T00:{(i // 60) % 60:02d}:{i % 60:02d}Z"}
            for i in range(offset, min(offset + count, total))
        ]
        return httpx.Response(200, json={"results": page})

    respx.get(url__regex=r".+/services/search/jobs/S/results").mock(side_effect=_results)

    out = await c.fetch_alerts()
    # All 250 survive — the old `head 100` / count=100 cap silently dropped 150.
    assert len(out) == total
    assert len({e["external_id"] for e in out}) == total


# --------------------------------------------------------------------------
# regression tests: 422 fix, kwargs acceptance, token/url norm, API endpoint
# --------------------------------------------------------------------------


def test_splunk_connector_init_with_poll_interval_and_extra_kwargs():
    c = SplunkConnector(
        base_url="splunk.test:8089",
        token="tok",
        poll_interval_seconds=300,
        extra_kw="ignored",
        page_size=200,
    )
    assert c._base_url == "https://splunk.test:8089"
    assert c._page_size == 200


def test_splunk_headers_token_normalization():
    c_plain = SplunkConnector(base_url=BASE, token="raw-token")
    assert c_plain._headers()["Authorization"] == "Bearer raw-token"

    c_bearer = SplunkConnector(base_url=BASE, token="Bearer bearer-token")
    assert c_bearer._headers()["Authorization"] == "Bearer bearer-token"

    c_splunk = SplunkConnector(base_url=BASE, token="Splunk hec-token")
    assert c_splunk._headers()["Authorization"] == "Splunk hec-token"


@respx.mock
@pytest.mark.asyncio
async def test_splunk_test_connection_success():
    c = _conn()
    respx.get(f"{BASE}/services/server/info").mock(
        return_value=httpx.Response(200, json={"entry": [{"content": {"version": "9.1.0"}}]})
    )
    res = await c.test_connection()
    assert res == {"success": True, "connector": "splunk", "version": "9.1.0"}


@respx.mock
@pytest.mark.asyncio
async def test_splunk_test_connection_http_error():
    c = _conn()
    respx.get(f"{BASE}/services/server/info").mock(
        return_value=httpx.Response(401)
    )
    res = await c.test_connection()
    assert res["success"] is False
    assert "HTTP 401" in res["error"]


@respx.mock
def test_splunk_test_endpoint_fastapi_client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.api.router import router

    test_app = FastAPI()
    test_app.include_router(router, prefix="/api/v1")

    respx.get(f"{BASE}/services/server/info").mock(
        return_value=httpx.Response(200, json={"entry": [{"content": {"version": "9.1.0"}}]})
    )

    client = TestClient(test_app)
    resp = client.post(
        "/api/v1/connectors/splunk/test",
        json={
            "auth_config": {"token": "test-token"},
            "connector_config": {
                "base_url": BASE,
                "saved_search": "AiSOC_Alerts",
                "page_size": 500,
                "ssl_verify": True,
                "poll_interval_seconds": 300,
            },
        },
    )
    assert resp.status_code == 200
    assert resp.json() == {"success": True, "connector": "splunk", "version": "9.1.0"}

    # Missing required argument returns 422 with descriptive error
    bad_resp = client.post(
        "/api/v1/connectors/splunk/test",
        json={"auth_config": {}, "connector_config": {}},
    )
    assert bad_resp.status_code == 422
    assert "connector config does not match schema" in bad_resp.json()["detail"]
