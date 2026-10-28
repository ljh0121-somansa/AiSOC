"""U3: Case-investigation EDR call methods 2 on EdrClient (plan U3, spec §5 stages 6-9, §7).

New methods use distinct names (search_case_events vs legacy search_events,
lookup_process_range vs legacy lookup_process, check_file_ingress vs legacy
check_ingress); legacy methods and their callers (tools.py, forensic_agent.py)
are untouched.
"""
from __future__ import annotations

import json

import httpx
import pytest
import respx

from app.edr.client import EdrApiError, EdrClient, EdrClientError

BASE = "http://127.0.0.1:7601"


def _client(max_retries: int = 3) -> EdrClient:
    return EdrClient(base_url=BASE, api_token="case-token", max_retries=max_retries)


def _observables(n: int) -> list[dict[str, str]]:
    return [{"type": "sha256", "value": f"ab{i:032}"} for i in range(n)]


@pytest.mark.asyncio
async def test_hunt_sends_observables():
    """Spec §5 stage 6: POST /hunt — exact-match observables, chunking is U8's job."""
    client = _client()
    with respx.mock(base_url=BASE) as m:
        route = m.post("/api/v2/ai-soc/hunt").respond(
            200, json={"items": [{"host": "host-02", "user": "Attacker"}], "total": 1}
        )
        data = await client.hunt("2026-10-01T00:00:00Z", "2026-10-28T00:00:00Z", _observables(2), sources=["edr"])
        assert data["total"] == 1
        body = json.loads(route.calls.last.request.content)
        assert body["observables"] == _observables(2)
        assert body["sources"] == ["edr"]
        assert body["limit"] == 100


@pytest.mark.asyncio
async def test_hunt_429_retryable_backoff():
    """429 (retryable) gets Retry-After backoff inside _request, then succeeds."""
    client = _client()
    with respx.mock(base_url=BASE) as m:
        error = {"code": "rate_limit_exceeded", "message": "too many requests", "retryable": True}
        route = m.post("/api/v2/ai-soc/hunt")
        route.side_effect = [
            httpx.Response(429, json={"error": error, "request_id": "req-9"}, headers={"Retry-After": "0.01"}),
            httpx.Response(200, json={"items": [], "total": 0}),
        ]
        data = await client.hunt("t0", "t1", _observables(1))
        assert data["total"] == 0


def test_hunt_404_code_preserved():
    """Spec §5 strict rule: 404 alone is NOT 'unavailable' — only error.code
    (feature_disabled / unsupported_source) marks a stage unavailable."""
    from app.edr.client import parse_edr_error_body
    err = parse_edr_error_body(
        '{"error": {"code": "feature_disabled", "message": "hunt disabled"}, "request_id": "req-1"}',
        404,
    )
    assert err.code == "feature_disabled"


@pytest.mark.asyncio
async def test_search_case_events_sends_filters():
    """Spec §5 stage 9: POST /events/search with typed filters; distinct from legacy GET search_events."""
    client = _client()
    with respx.mock(base_url=BASE) as m:
        route = m.post("/api/v2/ai-soc/events/search").respond(
            200, json={"items": [{"category": "process"}], "coverage": "complete"}
        )
        data = await client.search_case_events(
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
    """Spec §5 stage 7: hops <= 2, evidence <= 200 — caller (U8) enforces the
    ceilings; observed vs inferred distinction stays with the caller."""
    client = _client()
    with respx.mock(base_url=BASE) as m:
        route = m.post("/api/v2/ai-soc/investigations/file-ingress").respond(
            200, json={"observed": ["dl-1"], "inferred": ["dl-2"], "truncated": False}
        )
        data = await client.check_file_ingress("t0", "t1", "sha-1", host_names=["host-01"])
        assert data["observed"] == ["dl-1"]
        body = json.loads(route.calls.last.request.content)
        assert body["sha256"] == "sha-1"
        assert body["host_names"] == ["host-01"]
        assert body["max_process_hops"] == 2
        assert body["max_evidence"] == 200


def test_file_ingress_404_feature_disabled():
    """Spec §9.1: 404 + feature_disabled on file-ingress -> unavailable."""
    from app.edr.client import parse_edr_error_body
    err = parse_edr_error_body(
        '{"error": {"code": "feature_disabled", "message": "file_ingress disabled"}, "request_id": "req-7"}',
        404,
    )
    assert err.code == "feature_disabled"


@pytest.mark.asyncio
async def test_lookup_process_range_sends_time_range():
    """Spec §5 stage 8: time range selects the index partition (<= 10080 min);
    distinct from legacy lookup_process (no range)."""
    client = _client()
    with respx.mock(base_url=BASE) as m:
        route = m.get("/api/v2/ai-soc/processes/proc-1").respond(
            200, json={"process": {"pid": 4120, "command_line": "<redacted>"}}
        )
        data = await client.lookup_process_range("proc-1", from_ts="t0", to_ts="t1")
        assert data["process"]["pid"] == 4120
        p = route.calls.last.request.url.params
        assert p["from"] == "t0"
        assert p["to"] == "t1"
