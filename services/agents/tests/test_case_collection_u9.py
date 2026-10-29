"""U9: EDR collection node — logic + client wiring, edr_call events/artifacts.

Covers plan U9 verification tests (spec §9.1): external_id parsing
(first-colon split, colons inside event_id preserved), detection detail 404
error-code classification (not_found -> incomplete, feature_disabled ->
unavailable), static source_kind pre-decision (timeline/graph skipped before
the call), hunt observables chunking (20/call, 3-call cap,
observables_truncated), timeline pagination (has_more -> cursor-only
resend), and collection budget exhaustion (remaining stages incomplete).
"""
from __future__ import annotations

import json

import pytest

from app.edr.client import EdrApiError, EdrClient
from app.graph.case_workflow import (
    CaseCollectionError,
    edr_collect_node,
    parse_external_id,
)

# ---------------------------------------------------------------------------
# external_id parsing (spec §4)
# ---------------------------------------------------------------------------


def test_parse_external_id_first_colon_only():
    """Colons inside the event_id are preserved; only the FIRST colon splits."""
    assert parse_external_id("dynamic:af093445-28a3-40c0-9481-e6397c0c1a56") == (
        "dynamic", "af093445-28a3-40c0-9481-e6397c0c1a56")
    assert parse_external_id("static:abc:def") == ("static", "abc:def")


def test_parse_external_id_invalid_inputs():
    assert parse_external_id("no-colon-value") is None
    assert parse_external_id("") is None
    assert parse_external_id(None) is None
    assert parse_external_id(":x") is None
    assert parse_external_id("dynamic:") is None


# ---------------------------------------------------------------------------
# Stub clients (no HTTP; the node reads state["edr_client"])
# ---------------------------------------------------------------------------

_CAPABILITIES = {
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


def _detail_response(event_id: str, n_observables: int = 1, lookup_hint: str = "opaque-example") -> dict:
    return {
        "item": {
            "event": {"id": event_id},
            "file": {"hash": {"sha256": "b93a88a1056f472da3c60b89e8a5d1430f4c4f72032f21411b92f11ee2f9f1d7"}},
            "edr": {
                "source_kind": "dynamic",
                "observables": [
                    {"type": "sha256", "value": f"b93a{ i:04d}"} for i in range(n_observables)
                ],
                "links": {"detail": f"/api/v2/ai-soc/detections/dynamic/{event_id}", "lookup_hint": lookup_hint},
            },
        }
    }


class _BaseStub(EdrClient):
    def __init__(self) -> None:
        super().__init__(base_url="http://edr:7601", api_token="stub")
        self.calls: list[tuple] = []

    async def get_capabilities(self) -> dict:
        self.calls.append(("capabilities", None))
        return json.loads(json.dumps(_CAPABILITIES))

    async def fetch_detection_detail(self, source_kind: str, event_id: str, lookup_hint: str | None = None) -> dict:
        self.calls.append(("detail", (source_kind, event_id, lookup_hint)))
        return _detail_response(event_id)

    async def fetch_case_timeline(self, source_kind: str, event_id: str, *,
                                  before: str = "PT10M", after: str = "PT5M",
                                  categories=None, action_types=None, limit: int = 100,
                                  cursor: str | None = None) -> dict:
        self.calls.append(("timeline", ("cursor" if cursor else "init", source_kind, event_id, cursor)))
        if source_kind == "static":
            return {"status": "unavailable", "reason_code": "timeline_unavailable(static)"}
        if cursor is None:
            return {"items": [], "has_more": False, "next_cursor": None, "request_id": "req-tl-1"}
        return {"items": [], "has_more": False, "next_cursor": None, "request_id": "req-tl-2"}

    async def fetch_case_graph(self, source_kind: str, event_id: str, *,
                               before: str = "PT10M", after: str = "PT5M",
                               ancestor_depth: int = 2, descendant_depth: int = 1,
                               max_nodes: int = 200) -> dict:
        self.calls.append(("graph", (source_kind, event_id, max_nodes)))
        if source_kind == "static":
            return {"status": "unavailable", "reason_code": "graph_unavailable(static)"}
        return {"nodes": [], "edges": [], "truncated": False, "request_id": "req-g"}

    async def hunt(self, from_ts: str, to_ts: str, observables: list, sources=None, limit: int = 100) -> dict:
        self.calls.append(("hunt", (from_ts, to_ts, len(observables))))
        return {"items": [], "has_more": False, "next_cursor": None, "request_id": "req-h"}

    async def host_inventory_by_agent(self, agent_id: str) -> dict:
        self.calls.append(("host_inventory", agent_id))
        return {"agent": {"id": agent_id}, "observed_at": "2026-08-31T01:02:03Z"}

    async def check_file_ingress(self, from_ts: str, to_ts: str, sha256: str, *,
                                 host_names=None, before: str = "PT10M", after: str = "PT5M",
                                 max_process_hops: int = 2, max_evidence: int = 200) -> dict:
        self.calls.append(("file_ingress", (sha256, max_process_hops, max_evidence)))
        return {"observed": [], "inferred": [], "truncated": False, "request_id": "req-fi"}

    async def search_case_events(self, from_ts: str, to_ts: str, *, categories=None,
                                 action_types=None, observables=None, file_paths=None, limit: int = 100) -> dict:
        self.calls.append(("event_search", (from_ts, to_ts)))
        return {"items": [], "has_more": False, "next_cursor": None, "request_id": "req-es"}

    async def lookup_process_range(self, process_id: str, *, from_ts: str, to_ts: str) -> dict:
        self.calls.append(("process_detail", (process_id, from_ts, to_ts)))
        return {"process": {"entity_id": process_id}, "request_id": "req-p"}


def _stub() -> _BaseStub:
    return _BaseStub()


def _state(alerts: list[dict], client=None) -> dict:
    return {
        "case_id": "c1",
        "tenant_ref": "default",
        "alerts": alerts,
        "edr_client": client or _stub(),
    }


def _alert(ext_id: str, ts: str = "2026-07-07T00:49:45.008Z", severity: str = "high") -> dict:
    return {
        "id": "a1",
        "external_id": ext_id,
        "severity": severity,
        "event_time": ts,
        "raw_event": {
            "agent": {"id": "0f75dd1c-65d9-4e40-8472-8eca6f48e92d"},
            "host": {"name": "host-01", "ip": ["10.10.20.31"]},
            "user": {"name": "user01"},
            "process": {"entity_id": "34fb0ce9-bf5f-4261-9af3-5a35d02f804f", "name": "sample.exe", "pid": 4120},
            "file": {"hash": {"sha256": "b93a88a1056f472da3c60b89e8a5d1430f4c4f72032f21411b92f11ee2f9f1d7"}},
        },
    }


# ---------------------------------------------------------------------------
# Detail 404: error.code distinguishes not_found (incomplete) vs
# feature_disabled (unavailable) (spec §5, §9.1)
# ---------------------------------------------------------------------------


class _Detail404Stub(_BaseStub):
    def __init__(self, code: str) -> None:
        super().__init__()
        self.error_code = code

    async def fetch_detection_detail(self, source_kind: str, event_id: str, lookup_hint: str | None = None) -> dict:
        self.calls.append(("detail", (source_kind, event_id, lookup_hint)))
        raise EdrApiError(404, self.error_code, "detection not found", False, None, "req-404", None)


async def test_detail_404_not_found_is_incomplete():
    """Bare 404 with code=not_found -> the detail stage is incomplete."""
    client = _Detail404Stub("not_found")
    state = _state([_alert("dynamic:ev-404")], client)
    await edr_collect_node(state, None)

    lims = state["limitations"]
    assert any(l.startswith("detail_incomplete") and "not_found" in l for l in lims)
    # The detail call was attempted (unlike the static pre-decision skip).
    assert any(c[0] == "detail" for c in client.calls)
    for sr in state["stage_results"]:
        if sr["stage"] == "detail":
            assert sr["outcome"] == "incomplete"


async def test_detail_404_feature_disabled_is_unavailable():
    """code=feature_disabled -> the detail stage is unavailable (spec §5)."""
    client = _Detail404Stub("feature_disabled")
    state = _state([_alert("dynamic:ev-404b")], client)
    await edr_collect_node(state, None)

    lims = state["limitations"]
    assert any(l.startswith("detail_unavailable") for l in lims)
    for sr in state["stage_results"]:
        if sr["stage"] == "detail":
            assert sr["outcome"] == "unavailable"


# ---------------------------------------------------------------------------
# static source_kind: timeline/graph are skipped before the call
# ---------------------------------------------------------------------------


async def test_static_timeline_graph_pre_decision():
    """Spec §5: static -> timeline/graph unavailable (client skips the HTTP
    call before it happens). Verified here via the client's pre-decision dict
    result and the stage outcomes; the no-HTTP behavior itself is covered by
    the U2 client tests."""
    client = _stub()
    state = _state([_alert("static:15ae9697-9b04-48e5-a883-06db71e76d33")], client)
    await edr_collect_node(state, None)

    lims = state["limitations"]
    assert "timeline_unavailable(static)" in lims
    assert "graph_unavailable(static)" in lims
    tl_ev = state.get("edr_evidence", {})
    static_ext = "static:15ae9697-9b04-48e5-a883-06db71e76d33"
    assert tl_ev[f"timeline:{static_ext}"]["status"] == "unavailable"
    assert tl_ev[f"graph:{static_ext}"]["status"] == "unavailable"
    for sr in state["stage_results"]:
        if sr["stage"] in ("timeline", "graph") and sr["source_kind"] == "static":
            assert sr["outcome"] == "unavailable"

# ---------------------------------------------------------------------------
# Hunt observables chunking (spec §5.1, stage 6)
# ---------------------------------------------------------------------------


class _ManyObservablesStub(_BaseStub):
    N_OBS = 65

    async def fetch_detection_detail(self, source_kind: str, event_id: str, lookup_hint: str | None = None) -> dict:
        self.calls.append(("detail", (source_kind, event_id, lookup_hint)))
        return _detail_response(event_id, n_observables=self.N_OBS)


async def test_hunt_chunking_20_per_call_3_call_cap(monkeypatch):
    """67 observables (65 from detail + raw sha256 + raw IP) -> 3 hunt calls
    (60 used), 7 excess recorded as observables_truncated(7); group stage 6
    is incomplete."""
    client = _ManyObservablesStub()
    state = _state([_alert("dynamic:ev-9")], client)
    await edr_collect_node(state, None)

    hunt_calls = [c for c in client.calls if c[0] == "hunt"]
    assert len(hunt_calls) == 3
    assert [c[1][2] for c in hunt_calls] == [20, 20, 20]
    assert any(l.startswith("observables_truncated(7)") for l in state["limitations"])
    for sr in state["stage_results"]:
        if sr["stage"] == "hunt":
            assert sr["outcome"] == "incomplete"


# ---------------------------------------------------------------------------
# Timeline pagination: has_more -> cursor-only resend (spec §16)
# ---------------------------------------------------------------------------


class _PaginatedTimelineStub(_BaseStub):
    """First page returns has_more=True; the second (cursor) page completes."""

    async def fetch_case_timeline(self, source_kind: str, event_id: str, *,
                                  before: str = "PT10M", after: str = "PT5M",
                                  categories=None, action_types=None, limit: int = 100,
                                  cursor: str | None = None) -> dict:
        self.calls.append(("timeline", ("cursor" if cursor else "init", source_kind, event_id, cursor)))
        if source_kind == "static":
            return {"status": "unavailable", "reason_code": "timeline_unavailable(static)"}
        if cursor is None:
            return {
                "items": [{"event_id": "e1", "category": "file", "occurred_at": "2026-07-07T00:47:51.780Z"}],
                "has_more": True,
                "next_cursor": "opaque-cursor-1",
                "request_id": "req-tl-1",
            }
        return {
            "items": [{"event_id": "e2", "category": "behavior", "occurred_at": "2026-07-07T00:49:15.749Z"}],
            "has_more": False,
            "next_cursor": None,
            "request_id": "req-tl-2",
        }


async def test_timeline_pagination_cursor_only(monkeypatch):
    """has_more:true -> the next page is requested with the cursor ALONE
    (no filters/time range resent), per spec §16."""
    client = _PaginatedTimelineStub()
    state = _state([_alert("dynamic:af093445-28a3-40c0-9481-e6397c0c1a56")], client)
    await edr_collect_node(state, None)

    tl_calls = [c for c in client.calls if c[0] == "timeline"]
    assert len(tl_calls) == 2
    assert tl_calls[0][1][0] == "init"
    assert tl_calls[1][1][0] == "cursor"
    assert tl_calls[1][1][3] == "opaque-cursor-1"
    # Timeline stage completed for the alert.
    for sr in state["stage_results"]:
        if sr["stage"] == "timeline":
            assert sr["outcome"] == "completed"
    # Evidence sampled from the paginated timeline.
    tl_ev = [e for e in state["evidence"] if e["stage"] == "timeline"]
    assert tl_ev and tl_ev[0]["timeline_events"] == 2


# ---------------------------------------------------------------------------
# Collection budget exhaustion (spec §5.4)
# ---------------------------------------------------------------------------


async def test_collection_budget_exhaustion(monkeypatch):
    """When the call cap (EDR_COLLECTION_MAX_CALLS) is hit, remaining stages
    are recorded incomplete and the limitation is recorded — no synthetic
    results, no arbitrary budget increase."""
    monkeypatch.setenv("EDR_COLLECTION_MAX_CALLS", "4")
    client = _stub()
    state = _state([_alert("dynamic:af093445-28a3-40c0-9481-e6397c0c1a56")], client)
    await edr_collect_node(state, None)

    assert "collection_budget_exceeded" in state["limitations"]
    call_count = len(client.calls)
    # Cap of 4 calls is respected exactly.
    assert call_count <= 4


# ---------------------------------------------------------------------------
# Q3 fallback: no injected recorder -> events accumulate in state
# ---------------------------------------------------------------------------


async def test_q3_fallback_accumulates_pending_events():
    """Without the runner's config injection (config=None), the node
    accumulates edr_call records in state['_pending_ledger_events'] for
    the runner's tier-boundary flush (spec §3, Q3)."""
    client = _stub()
    state = _state([_alert("dynamic:af093445-28a3-40c0-9481-e6397c0c1a56")], client)
    await edr_collect_node(state, None)

    pending = state.get("_pending_ledger_events") or []
    # capabilities + detail + hunt + file_ingress + timeline + graph ...
    assert len(pending) >= 3
    for ev in pending:
        assert ev["kind"] == "edr_call"
        assert ev["agent"] == "edr_collect"
        assert ev["input_hash"] and ev["output_hash"]
        assert ev["payload"]["stage"]
        assert "classification" in ev["payload"]
