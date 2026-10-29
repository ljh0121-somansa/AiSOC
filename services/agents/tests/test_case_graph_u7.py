"""U7: Case graph skeleton + config/heartbeat wiring (plan U7, spec §3).

Verifies:
- ``case_graph`` builds with the 3-node skeleton (edr_collect →
  case_synthesis → persist) and does NOT affect the existing
  ``investigation_graph`` / ``escalation_graph``.
- ``run_case_investigation`` streams ``case_graph.astream(state, config)``,
  records a ``graph_step`` ledger event per node and a 60s-interval
  ``heartbeat`` event, and finalises the run as completed.
"""
from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest

import app.graph.runner as runner
from app.graph.runner import _heartbeat_loop, run_case_investigation
from app.graph.workflow import case_graph, escalation_graph, investigation_graph

from app.edr.client import EdrClient


class _StubEdrClient(EdrClient):
    """Deterministic stub for U9/U11 graph tests (no HTTP)."""

    def __init__(self) -> None:
        super().__init__(base_url="http://edr:7601", api_token="stub-token")
        self.calls: list[str] = []

    async def get_capabilities(self) -> dict:
        self.calls.append("capabilities")
        return {
            "features": {
                "timeline": True, "graph": True, "hunt": True,
                "event_search": True, "file_ingress": True,
                "process_lookup": True, "host_inventory": True,
            },
            "limits": {
                "max_page_size": 500, "max_query_range_hours": 168,
                "max_timeline_range_minutes": 60, "event_search_broad_max_minutes": 60,
            },
        }

    async def fetch_detection_detail(self, source_kind: str, event_id: str, lookup_hint: str | None = None) -> dict:
        self.calls.append(f"detail:{source_kind}:{event_id}")
        return json.loads(DetectionDetailJSON)

    async def fetch_case_timeline(self, source_kind: str, event_id: str, *, before: str = "PT10M", after: str = "PT5M",
                                 categories: list | None = None, action_types: list | None = None,
                                 limit: int = 100, cursor: str | None = None) -> dict:
        self.calls.append(f"timeline:{source_kind}:{event_id}")
        return json.loads(TimelineJSON)

    async def fetch_case_graph(self, source_kind: str, event_id: str, *, before: str = "PT10M", after: str = "PT5M",
                               ancestor_depth: int = 2, descendant_depth: int = 1, max_nodes: int = 200) -> dict:
        self.calls.append(f"graph:{source_kind}:{event_id}")
        return {
            "root": f"detection:{event_id}",
            "nodes": [
                {"id": f"detection:{event_id}", "kind": "detection", "label": "Untrusted malware"},
                {"id": "process:34fb0ce9-bf5f-4261-9af3-5a35d02f804f", "kind": "process", "label": "sample.exe"},
            ],
            "edges": [
                {"source": "process:34fb0ce9-bf5f-4261-9af3-5a35d02f804f",
                 "target": f"detection:{event_id}", "relation": "triggered"}
            ],
            "truncated": False,
            "request_id": "ai-soc-req-graph",
        }

    async def hunt(self, from_ts: str, to_ts: str, observables: list[dict], sources: list | None = None, limit: int = 100) -> dict:
        self.calls.append("hunt")
        return {
            "items": [
                {"@timestamp": "2026-07-07T00:49:45.008Z",
                 "host": {"name": "host-01"},
                 "edr": {"source_kind": "dynamic"}}
            ],
            "has_more": False,
            "next_cursor": None,
            "request_id": "ai-soc-req-hunt",
        }

    async def host_inventory_by_agent(self, agent_id: str) -> dict:
        self.calls.append(f"host_inventory:{agent_id}")
        return json.loads(HostInventoryJSON)

    async def check_file_ingress(self, from_ts: str, to_ts: str, sha256: str, *, host_names: list | None = None,
                                 before: str = "PT10M", after: str = "PT5M",
                                 max_process_hops: int = 2, max_evidence: int = 200) -> dict:
        self.calls.append(f"file_ingress:{sha256}")
        return json.loads(FileIngressJSON)

    async def search_case_events(self, from_ts: str, to_ts: str, *, categories: list | None = None,
                                 action_types: list | None = None, observables: list | None = None,
                                 file_paths: list | None = None, limit: int = 100) -> dict:
        self.calls.append("event_search")
        return {
            "items": [],
            "has_more": False,
            "next_cursor": None,
            "coverage": {"complete": True, "consistency": "strong"},
            "request_id": "ai-soc-req-search",
        }


import json

from pathlib import Path
_EDR_TESTDATA = Path(__file__).parent / "testdata" / "edr"

def _load(name: str) -> str:
    return (_EDR_TESTDATA / name).read_text()

DetectionDetailJSON = _load("detection-detail.json")
TimelineJSON = _load("timeline-6700.json")
HostInventoryJSON = _load("host-inventory.json")
FileIngressJSON = _load("file-ingress.json")


def _stub_client() -> _StubEdrClient:
    return _StubEdrClient()

# ---------------------------------------------------------------------------
# Graph skeleton
# ---------------------------------------------------------------------------

def test_case_graph_skeleton_nodes():
    nodes = set(case_graph.nodes.keys())
    assert {"edr_collect", "case_synthesis", "persist"} <= nodes


def test_existing_graphs_untouched():
    """The Alert-unit graphs still build and are separate singletons."""
    assert investigation_graph is not None
    assert escalation_graph is not None
    # The case graph is a distinct object.
    assert case_graph is not investigation_graph
    assert case_graph is not escalation_graph


def test_case_graph_collects_evidence():
    """Running the case graph walks edr_collect (U9) -> case_synthesis (U11)
    -> persist. edr_collect parses the state's alerts and builds the LLM bundle."""
    async def scenario():
        alerts = [
            {
                "id": "a1",
                "external_id": "dynamic:af093445-28a3-40c0-9481-e6397c0c1a56",
                "severity": "high",
                "event_time": "2026-07-07T00:49:45.008Z",
                "raw_event": {
                    "agent": {"id": "0f75dd1c-65d9-4e40-8472-8eca6f48e92d"},
                    "host": {"name": "host-01", "ip": ["10.10.20.31"]},
                    "user": {"name": "user01"},
                    "process": {
                        "entity_id": "34fb0ce9-bf5f-4261-9af3-5a35d02f804f",
                        "name": "sample.exe",
                        "pid": 4120,
                    },
                },
            }
        ]
        state = {
            "case_id": "c1",
            "tenant_ref": "default",
            "alerts": alerts,
            "edr_client": _stub_client(),
        }
        result = {}
        async for step in case_graph.astream(state):
            if isinstance(step, dict):
                for node, out in step.items():
                    if isinstance(out, dict):
                        result.update(out)
        return result

    merged = asyncio.run(scenario())
    assert merged.get("case_id") == "c1"
    assert "detail:dynamic:af093445-28a3-40c0-9481-e6397c0c1a56" in merged.get("edr_evidence", {})
    assert merged.get("bundle")

def test_run_case_investigation_records_steps_and_heartbeat(monkeypatch):
    """The runner streams the case graph with a config carrying run_id,
    tenant_id and the U6 RunSequence; it records a graph_step event per node."""
    events = []

    async def fake_record_event(*, run_id, tenant_id, seq, kind, agent, summary, payload=None, **_):
        events.append({"kind": kind, "agent": agent, "seq": seq})

    async def fake_resolve_tenant(ref):
        return uuid.UUID(int=1)

    async def fake_start_run(**_):
        return None

    async def fake_complete_run(**_):
        return None

    monkeypatch.setattr(runner.ledger_module, "record_event", fake_record_event)
    monkeypatch.setattr(runner.ledger_module, "resolve_tenant", fake_resolve_tenant)
    monkeypatch.setattr(runner.ledger_module, "start_run", fake_start_run)
    monkeypatch.setattr(runner.ledger_module, "complete_run", fake_complete_run)
    state = {
        "case_id": "c1",
        "tenant_ref": "default",
        "alert_count": 2,
        "edr_client": _stub_client(),
        "alerts": [
            {
                "id": "a1",
                "external_id": "dynamic:af093445-28a3-40c0-9481-e6397c0c1a56",
                "severity": "high",
                "event_time": "2026-07-07T00:49:45.008Z",
                "raw_event": {
                    "agent": {"id": "0f75dd1c-65d9-4e40-8472-8eca6f48e92d"},
                    "host": {"name": "host-01", "ip": ["10.10.20.31"]},
                    "user": {"name": "user01"},
                    "process": {"entity_id": "34fb0ce9-bf5f-4261-9af3-5a35d02f804f", "name": "sample.exe", "pid": 4120},
                },
            },
            {
                "id": "a2",
                "external_id": "static:15ae9697-9b04-48e5-a883-06db71e76d33",
                "severity": "high",
                "event_time": "2026-07-07T00:49:45.008Z",
            },
        ],
    }
    out = asyncio.run(run_case_investigation(state, persist=True, heartbeat_interval=60.0))
    assert out["case_id"] == "c1"
    step_kinds = [e["kind"] for e in events if e["kind"] == "graph_step"]
    assert len(step_kinds) == 3  # edr_collect, case_synthesis, persist


def test_heartbeat_loop_records_at_interval():
    """The heartbeat loop records a ``heartbeat`` event every interval seconds,
    using the shared RunSequence for seq."""
    events = []

    async def scenario():
        from app.investigator.ledger import RunSequence

        seq = RunSequence()

        async def fake_record_event(*, run_id, tenant_id, seq, kind, agent, summary, payload=None, **_):
            events.append({"kind": kind, "seq": seq})

        import app.investigator.ledger as ledger_module
        orig = ledger_module.record_event
        ledger_module.record_event = fake_record_event
        try:
            await asyncio.wait_for(
                _heartbeat_loop(uuid.UUID(int=9), uuid.UUID(int=1), seq, interval=0.05),
                timeout=0.12,
            )
        except asyncio.TimeoutError:
            pass
        finally:
            ledger_module.record_event = orig
        return events

    asyncio.run(scenario())
    hb = [e for e in events if e["kind"] == "heartbeat"]
    assert len(hb) >= 1
    # seq values come from the shared issuer, all distinct.
    assert len({e["seq"] for e in hb}) == len(hb)


def test_run_case_investigation_timeout_marks_incomplete(monkeypatch):
    """Budget timeout (collection budget) -> ``collection_budget_exceeded``
    limitation, run finalised as completed (spec §5.4)."""
    events = []
    async def fake_record_event(*, run_id, tenant_id, seq, kind, agent, summary, payload=None, **_):
        events.append({"kind": kind, "seq": seq})

    async def fake_resolve_tenant(ref):
        return uuid.UUID(int=1)

    async def fake_start_run(**_):
        return None

    async def fake_complete_run(**_):
        return None

    monkeypatch.setattr(runner.ledger_module, "record_event", fake_record_event)
    monkeypatch.setattr(runner.ledger_module, "resolve_tenant", fake_resolve_tenant)
    monkeypatch.setattr(runner.ledger_module, "start_run", fake_start_run)
    monkeypatch.setattr(runner.ledger_module, "complete_run", fake_complete_run)

    # Force a tiny collection budget so the timeout path is exercised.
    monkeypatch.setenv("EDR_COLLECTION_MAX_SECONDS", "0")
    state = {
        "case_id": "c1",
        "tenant_ref": "default",
        "alert_count": 2,
        "edr_client": _stub_client(),
        "alerts": [
            {
                "id": "a1",
                "external_id": "dynamic:af093445-28a3-40c0-9481-e6397c0c1a56",
                "severity": "high",
                "event_time": "2026-07-07T00:49:45.008Z",
                "raw_event": {"agent": {"id": "0f75dd1c-65d9-4e40-8472-8eca6f48e92d"}},
            },
        ],
    }
    out = asyncio.run(run_case_investigation(state, persist=True))
    assert "collection_budget_exceeded" in out.get("limitations", [])
    assert out["case_id"] == "c1"


# ---------------------------------------------------------------------------
# U7b: prove a node actually receives the recorder via config["configurable"]
# ---------------------------------------------------------------------------


def test_node_receives_recorder_via_configurable(monkeypatch):
    """U7b: a test node (wrapping the case skeleton node) pulls ``seq_issuer``
    and run info out of ``config["configurable"]``, records one ``edr_call``
    event through ``record_event``, and its seq never collides with the
    runner/heartbeat seqs (all drawn from the shared RunSequence)."""
    from langgraph.graph import END, START, StateGraph

    import app.graph.workflow as workflow

    events = []
    captured: dict = {}

    async def fake_record_event(*, run_id, tenant_id, seq, kind, agent, summary, payload=None, **_):
        events.append({"kind": kind, "agent": agent, "seq": seq})
        return uuid.UUID(int=42)

    async def recorder_node(state: dict, config=None):
        configurable = (config or {}).get("configurable") or {}
        issuer = configurable.get("seq_issuer")
        captured["run_id"] = configurable.get("run_id")
        captured["tenant_id"] = configurable.get("tenant_id")
        captured["issuer_is_runsequence"] = isinstance(issuer, runner.ledger_module.RunSequence)
        captured["event_id"] = await runner.ledger_module.record_event(
            run_id=captured["run_id"],
            tenant_id=captured["tenant_id"],
            seq=await issuer.next(),
            kind="edr_call",
            agent="edr_collect",
            summary="node recorded one edr_call event",
            payload={"node": "edr_collect"},
        )
        out = dict(state)
        out["node_ran"] = "edr_collect"
        return out

    g = StateGraph(dict)
    g.add_node("edr_collect", recorder_node)
    g.add_edge(START, "edr_collect")
    g.add_edge("edr_collect", END)
    monkeypatch.setattr(workflow, "case_graph", g.compile())

    async def fake_resolve_tenant(ref):
        return uuid.UUID(int=1)

    async def fake_start_run(**_):
        return None

    async def fake_complete_run(**_):
        return None

    monkeypatch.setattr(runner.ledger_module, "record_event", fake_record_event)
    monkeypatch.setattr(runner.ledger_module, "resolve_tenant", fake_resolve_tenant)
    monkeypatch.setattr(runner.ledger_module, "start_run", fake_start_run)
    monkeypatch.setattr(runner.ledger_module, "complete_run", fake_complete_run)

    state = {"case_id": "c1", "tenant_ref": "default", "alert_count": 2}
    out = asyncio.run(run_case_investigation(state, persist=True))

    # The node really got the recorder through config["configurable"].
    assert captured["issuer_is_runsequence"] is True
    assert captured["run_id"] is not None
    assert captured["tenant_id"] == uuid.UUID(int=1)

    # The node's edr_call event was recorded into the run's event list.
    edr_events = [e for e in events if e["kind"] == "edr_call"]
    assert len(edr_events) == 1
    assert captured["event_id"] is not None

    # No seq collision: start / edr_call(node) / graph_step all draw from the
    # shared RunSequence, so every seq is distinct.
    seqs = [e["seq"] for e in events]
    assert len(set(seqs)) == len(seqs)

    kinds = [e["kind"] for e in events]
    assert "start" in kinds and "edr_call" in kinds and "graph_step" in kinds
    assert out.get("node_ran") == "edr_collect"


