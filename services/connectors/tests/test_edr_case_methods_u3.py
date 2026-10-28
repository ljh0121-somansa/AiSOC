"""U3: Case-investigation EDR call methods 2 on EdrServerConnector (plan U3, spec §5 stages 6-9, §7).

New methods use distinct names (search_case_events vs legacy search_events,
lookup_process_range vs legacy lookup_process, check_file_ingress vs legacy
check_ingress); legacy methods and their callers are untouched.
"""
from __future__ import annotations

import json

import httpx
import pytest
import respx

from app.connectors.edrserver import EdrApiError, EdrServerConnector, parse_edr_error_body

BASE = "https://edrserver.internal:7601"


def _connector() -> EdrServerConnector:
    return EdrServerConnector(base_url=BASE, token="aisoc.id.secret")


def _observables(n: int) -> list[dict[str, str]]:
    return [{"type": "sha256", "value": f"ab{i:032}"} for i in range(n)]


@pytest.mark.asyncio
async def test_hunt_sends_observables():
    """Spec §5 stage 6: POST /hunt with exact-match observables; chunking
    (20/call, max 3 calls/case) is enforced by the caller (U8)."""
    connector = _connector()
    with respx.mock(base_url=BASE) as m:
        route = m.post("/api/v2/ai-soc/hunt").respond(
            200, json={"items": [{"host": "host-02", "user": "Attacker"}], "total": 1}
        )
        data = await connector.hunt("2026-10-01T00:00:00Z", "2026-10-28T00:00:00Z", _observables(2), sources=["edr"])
        assert data["total"] == 1
        body = json.loads(route.calls.last.request.content)
        assert body["observables"] == _observables(2)
        assert body["sources"] == ["edr"]


@pytest.mark.asyncio
async def test_hunt_503_retryable_backoff():
    """503 with retryable=True gets a Retry-After backoff inside _edr_post."""
    connector = _connector()
    with respx.mock(base_url=BASE) as m:
        error = {"code": "detail_not_ready", "message": "not ready", "retryable": True}
        route = m.post("/api/v2/ai-soc/hunt")
        route.side_effect = [
            httpx.Response(503, json={"error": error, "request_id": "req-9"}, headers={"Retry-After": "0.01"}),
            httpx.Response(200, json={"items": [], "total": 0}),
        ]
        data = await connector.hunt("t0", "t1", _observables(1))
        assert data["total"] == 0
        assert len(route.calls) == 2


def test_hunt_404_code_preserved():
    """Spec §5 strict rule: 404 alone is NOT 'unavailable' — only error.code
    (feature_disabled / unsupported_source) marks a stage unavailable."""
    err = parse_edr_error_body(
        '{"error": {"code": "feature_disabled", "message": "hunt disabled"}, "request_id": "req-1"}',
        404,
    )
    assert err.code == "feature_disabled"
    assert isinstance(err, EdrApiError)


@pytest.mark.asyncio
async def test_search_case_events_sends_filters():
    """Spec §5 stage 9: POST /events/search with typed filters; distinct from
    legacy GET search_events (single query param), which stays untouched."""
    connector = _connector()
    with respx.mock(base_url=BASE) as m:
        route = m.post("/api/v2/ai-soc/events/search").respond(
            200, json={"items": [{"category": "process"}], "coverage": "complete"}
        )
        data = await connector.search_case_events(
            "t0", "t1",
            categories=["process", "network"],
            action_types=[1, 3],
            observables=[{"type": "ip", "value": "192.0.2.10"}],
            file_paths=["C:\\Windows\\System32\\x.dll"],
            limit=500,
        )
        assert data["coverage"] == "complete"
        body = json.loads(route.calls.last.request.content)
        assert body["categories"] == ["process", "network"]
        assert body["action_types"] == [1, 3]
        assert body["observables"] == [{"type": "ip", "value": "192.0.2.10"}]
        assert body["file_paths"] == ["C:\\Windows\\System32\\x.dll"]
        assert body["limit"] == 500


@pytest.mark.asyncio
async def test_check_file_ingress_sends_params():
    """Spec §5 stage 7: hops <= 2, evidence <= 200 (caller U8 enforces ceilings);
    observed vs inferred distinction stays with the caller."""
    connector = _connector()
    with respx.mock(base_url=BASE) as m:
        route = m.post("/api/v2/ai-soc/investigations/file-ingress").respond(
            200, json={"observed": ["dl-1"], "inferred": ["dl-2"], "truncated": False}
        )
        data = await connector.check_file_ingress("t0", "t1", "sha-1", host_names=["host-01"])
        assert data["observed"] == ["dl-1"]
        body = json.loads(route.calls.last.request.content)
        assert body["sha256"] == "sha-1"
        assert body["host_names"] == ["host-01"]
        assert body["max_process_hops"] == 2
        assert body["max_evidence"] == 200


def test_file_ingress_404_feature_disabled():
    """Spec §9.1: 404 + feature_disabled on file-ingress -> unavailable."""
    err = parse_edr_error_body(
        '{"error": {"code": "feature_disabled", "message": "file_ingress disabled"}, "request_id": "req-7"}',
        404,
    )
    assert err.code == "feature_disabled"


@pytest.mark.asyncio
async def test_lookup_process_range_sends_time_range():
    """Spec §5 stage 8: time range selects the index partition (<= 10080 min);
    distinct from legacy lookup_process (no range), which stays untouched."""
    connector = _connector()
    with respx.mock(base_url=BASE) as m:
        route = m.get("/api/v2/ai-soc/processes/proc-1").respond(
            200, json={"process": {"pid": 4120, "command_line": "<redacted>"}}
        )
        data = await connector.lookup_process_range("proc-1", from_ts="t0", to_ts="t1")
        assert data["process"]["pid"] == 4120
        p = route.calls.last.request.url.params
        assert p["from"] == "t0"
        assert p["to"] == "t1"
