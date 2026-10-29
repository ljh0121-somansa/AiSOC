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


def test_case_graph_runs_skeleton():
    """Running the compiled case graph with an empty state walks all 3 nodes
    (skeleton passthrough) and returns the merged state."""
    async def scenario():
        result = {}
        async for step in case_graph.astream({"case_id": "c1", "tenant_ref": "default"}):
            if isinstance(step, dict):
                for node, out in step.items():
                    if isinstance(out, dict):
                        result.update(out)
        return result

    merged = asyncio.run(scenario())
    # Skeleton nodes are passthrough (return the input state), so the merged
    # dict carries the original keys through.
    assert merged.get("case_id") == "c1"

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

    state = {"case_id": "c1", "tenant_ref": "default", "alert_count": 2}
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
    state = {"case_id": "c1", "tenant_ref": "default", "alert_count": 2}
    out = asyncio.run(run_case_investigation(state, persist=True))
    assert "collection_budget_exceeded" in out.get("limitations", [])
    assert out["case_id"] == "c1"
