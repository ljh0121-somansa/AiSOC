"""U14: testdata-based E2E integration (plan U14, spec §9.1–9.4).

Drives the real Case graph (U7 skeleton + U9 EDR collect + U11 LLM synthesis)
against the committed ``tests/testdata/edr/*.json`` fixtures served through
``respx``. The LLM is deliberately left unconfigured so the run exercises the
fail-closed path (acceptance 2: insufficient + llm_unavailable) while the EDR
collection path is exercised end-to-end (acceptance 7: the collection budget is
separate from the LLM budget and must not abort the run).

The merged state exposes the node outputs (verdict, synthesis_performed,
limitations, edr_evidence, bundle). The run's terminal status lives in the
Ledger (``complete_run``), which requires a database and is out of scope for
the DB-less unit suite — so these tests assert the observable node results.

Test file only — no production code is touched (merge-safe, plan U14).
"""

from __future__ import annotations

import json
import os
from typing import Any
from unittest import mock

import httpx
import pytest
import respx

import app.graph.runner as runner
import app.graph.case_synthesis as case_synthesis
import app.investigator.ledger as case_ledger
from app.edr.client import EdrClient

EDR_BASE = "http://127.0.0.1:7601"
DATA_DIR = os.path.join(os.path.dirname(__file__), "testdata", "edr")


def _load(name: str) -> Any:
    with open(os.path.join(DATA_DIR, name), encoding="utf-8") as fh:
        return json.load(fh)


def _caps() -> dict:
    """Capabilities fixture (no testdata file; U9 collect gates stages off these)."""
    return {
        "features": {
            "pull": True, "push": False, "timeline": True, "graph": True,
            "hunt": True, "event_search": True, "process_lookup": True,
            "event_timeline": True, "file_ingress": True,
            "host_inventory": True, "raw": False, "feedback": True,
            "response_actions": False,
        },
        "limits": {
            "max_page_size": 500, "max_query_range_hours": 168,
            "max_timeline_range_minutes": 60, "max_graph_repository_queries": 64,
            "cursor_ttl_minutes": 15, "event_search_broad_max_minutes": 60,
            "max_process_lookup_range_minutes": 10080,
        },
    }


def _client() -> EdrClient:
    return EdrClient(base_url=EDR_BASE, api_token="test-token")


def _state(external_id: str) -> dict[str, Any]:
    """Build the runner state dict for the case graph with a single alert."""
    return {
        "case_id": "case-1",
        "run_id": "run-1",
        "tenant_ref": "default",
        "alert_count": 1,
        "case_summary": "VSS snapshot false positive",
        "raw_case": {"source": "edr"},
        # Inject the real (respx-backed) EDR client so the HTTP path is exercised.
        "edr_client": _client(),
        # The alert references the testdata detection detail; a fixed event_time
        # feeds the U8 time-window grouping.
        "alerts": [
            {
                "external_id": external_id,
                "severity": "high",
                "id": "alert-1",
                "event_time": "2026-07-07T00:49:45Z",
                "raw_event": {"edr": {}},
            }
        ],
    }


def _edr_routes(respx_mock, external_id: str) -> None:
    """Serve the EDR testdata through respx (spec §9 testdata basis).

    This respx version matches ``path`` by exact equality (no regex), so routes
    are registered per concrete event id parsed from ``external_id``.
    """
    kind, event_id = external_id.split(":", 1)
    respx_mock.route(method="GET", path="/api/v2/ai-soc/capabilities").mock(
        return_value=httpx.Response(200, json=_caps())
    )
    respx_mock.route(method="GET", path=f"/api/v2/ai-soc/detections/{kind}/{event_id}").mock(
        return_value=httpx.Response(200, json=_load("detection-detail.json"))
    )
    respx_mock.route(method="GET", path=f"/api/v2/ai-soc/investigations/{kind}/{event_id}/timeline").mock(
        return_value=httpx.Response(200, json=_load("timeline-6700.json"))
    )
    respx_mock.route(method="GET", path=f"/api/v2/ai-soc/investigations/{kind}/{event_id}/graph").mock(
        return_value=httpx.Response(200, json={"nodes": [{"id": "n1"}], "edges": []})
    )
    # Host inventory: agent id comes from the detection-detail testdata.
    respx_mock.route(method="GET", path="/api/v2/ai-soc/hosts/0f75dd1c-65d9-4e40-8472-8eca6f48e92d").mock(
        return_value=httpx.Response(200, json=_load("host-inventory.json"))
    )
    respx_mock.route(method="POST", path="/api/v2/ai-soc/hunt").mock(
        return_value=httpx.Response(200, json=_load("detection-list.json"))
    )
    respx_mock.route(method="POST", path="/api/v2/ai-soc/events/search").mock(
        return_value=httpx.Response(200, json=_load("event-search.json"))
    )
    respx_mock.route(method="POST", path="/api/v2/ai-soc/investigations/file-ingress").mock(
        return_value=httpx.Response(200, json=_load("file-ingress.json"))
    )
    # Process detail: process id comes from the detection-detail testdata.
    respx_mock.route(method="GET", path="/api/v2/ai-soc/processes/34fb0ce9-bf5f-4261-9af3-5a35d02f804f").mock(
        return_value=httpx.Response(200, json=_load("process-detail.json"))
    )


def _no_db(monkeypatch: pytest.MonkeyPatch) -> None:
    """No database in the unit suite: ledger writes no-op (Q3 tier-unit recording)."""
    monkeypatch.setattr(case_ledger, "get_pool", mock.AsyncMock(return_value=None))


def _llm_unconfigured(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the LLM to be unconfigured so the synthesis node fails closed."""
    monkeypatch.setattr(case_synthesis, "resolve_api_key", mock.Mock(return_value=None))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_case_investigation_llm_unconfigured_is_insufficient(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """Acceptance 2 + §9.3: LLM unconfigured → verdict insufficient + llm_unavailable,
    while the EDR collection path still completes end-to-end (acceptance 7)."""
    _llm_unconfigured(monkeypatch)
    _no_db(monkeypatch)

    external_id = "dynamic:af093445-28a3-40c0-9481-e6397c0c1a56"
    state = _state(external_id)
    with respx.mock(base_url=EDR_BASE, assert_all_called=False) as respx_mock:
        _edr_routes(respx_mock, external_id)
        merged = await runner.run_case_investigation(state, persist=True)

    # §9.3: no LLM → insufficient + llm_unavailable, synthesis not performed.
    assert merged.get("verdict") == "insufficient"
    assert merged.get("synthesis_performed") is False
    assert "llm_unavailable" in (merged.get("limitations") or [])
    # §9.1: collection produced EDR evidence end-to-end.
    assert merged.get("edr_evidence")
    assert merged.get("bundle")


@pytest.mark.asyncio
async def test_case_run_budget_not_exhausted(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """Acceptance 7: the collection budget (U8 ``collection_budget``) is separate
    from the LLM budget; a single-alert run completes without hitting the cap."""
    _llm_unconfigured(monkeypatch)
    _no_db(monkeypatch)

    external_id = "dynamic:af093445-28a3-40c0-9481-e6397c0c1a56"
    state = _state(external_id)
    with respx.mock(base_url=EDR_BASE, assert_all_called=False) as respx_mock:
        _edr_routes(respx_mock, external_id)
        merged = await runner.run_case_investigation(state, persist=True)

    # A single alert must NOT exhaust the collection budget.
    assert "collection_budget_exceeded" not in (merged.get("limitations") or [])


@pytest.mark.asyncio
async def test_static_source_unavailable_pre_decision(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """§9.1: 'unavailable' is admitted only via the source_kind pre-decision
    (static timeline/graph): the client skips the HTTP call and records
    ``timeline_unavailable`` / ``graph_unavailable`` as "unavailable" (not
    "incomplete"), per the strict 'unavailable' rule (spec §5)."""
    _llm_unconfigured(monkeypatch)
    _no_db(monkeypatch)

    external_id = "static:15ae9697-9b04-48e5-a883-06db71e76d33"
    state = _state(external_id)
    with respx.mock(base_url=EDR_BASE, assert_all_called=False) as respx_mock:
        _edr_routes(respx_mock, external_id)
        merged = await runner.run_case_investigation(state, persist=True)

    ev = merged.get("edr_evidence") or {}
    assert any(
        isinstance(v, dict) and v.get("status") == "unavailable"
        for v in ev.values()
    )
    assert "timeline_unavailable(static)" in (merged.get("limitations") or [])
    assert "graph_unavailable(static)" in (merged.get("limitations") or [])
    assert merged.get("verdict") == "insufficient"
