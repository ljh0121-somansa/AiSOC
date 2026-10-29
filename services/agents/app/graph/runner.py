"""Shared, durable investigation-graph runner (issue #569).

Both the Kafka auto-triage worker and the manual investigations API run the
*same* orchestration through here, so escalated alerts flow through one
implementation instead of two divergent ones:

* the manual API runs the FULL graph (auto-triage → triage → enrichment →
  investigation → attack-path) via :func:`run_full_investigation`;
* the auto-triage worker, having already produced a governed verdict, runs the
  post-triage escalation subgraph via :func:`run_escalation`.

Every node transition is recorded to the Investigation Ledger (append-only,
``ON CONFLICT (run_id, seq) DO NOTHING``), so a restart mid-investigation
re-runs idempotently — it never loses or duplicates the run. A wall-clock
budget bounds the run; a token budget is enforced upstream by the
``CostGovernor`` and a tool-call budget by the ReAct loop's ``max_iters``.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from dataclasses import dataclass

import structlog
from langchain_core.runnables.config import RunnableConfig

from app.agents.dispositions import NEEDS_REVIEW
from app.investigator import ledger as ledger_module
from app.investigation_rules import collection_budget
from app.models.state import AgentStatus, InvestigationState

logger = structlog.get_logger()


@dataclass(frozen=True)
class InvestigationBudget:
    """Resource envelope for one investigation (issue #569)."""

    max_seconds: float = 120.0
    max_tokens: int = 20_000
    max_tool_calls: int = 8


def default_budget() -> InvestigationBudget:
    return InvestigationBudget(
        max_seconds=float(os.getenv("AISOC_INVESTIGATION_MAX_SECONDS", "120")),
        max_tokens=int(os.getenv("AISOC_MAX_TOKENS_PER_ALERT", "20000")),
        max_tool_calls=int(os.getenv("AISOC_INVESTIGATION_MAX_TOOL_CALLS", "8")),
    )


async def _run(
    graph,  # noqa: ANN001 — a compiled LangGraph
    state: InvestigationState,
    *,
    budget: InvestigationBudget | None,
    persist: bool,
    seq_start: int,
) -> InvestigationState:
    budget = budget or default_budget()
    tenant_ref = str(state.tenant_id)
    state_dict = state.to_dict()
    merged: dict = dict(state_dict)

    tenant_uuid = await ledger_module.resolve_tenant(tenant_ref) if persist else None
    if persist:
        # Idempotent — start_run ON CONFLICT DO NOTHING (the worker may have
        # already opened this run when it persisted the triage verdict).
        await ledger_module.start_run(
            run_id=state.run_id,
            case_id=str(state.incident_id),
            tenant_ref=tenant_ref,
            alert_summary=state.alert_summary or "",
            raw_alert=state.raw_alert or {},
            model_used="graph:investigation",
        )

    seq = seq_start
    timed_out = False
    try:
        async with asyncio.timeout(budget.max_seconds):
            async for step in graph.astream(state_dict):
                if not isinstance(step, dict):
                    continue
                for node, out in step.items():
                    seq += 1
                    if isinstance(out, dict):
                        merged.update(out)
                    if tenant_uuid is not None:
                        await ledger_module.record_event(
                            run_id=state.run_id,
                            tenant_id=tenant_uuid,
                            seq=seq,
                            kind="graph_step",
                            agent=str(node),
                            summary=f"graph node '{node}' completed",
                            payload={"node": str(node)},
                        )
    except TimeoutError:
        timed_out = True
        logger.warning("investigation.budget_timeout", run_id=str(state.run_id), max_seconds=budget.max_seconds)

    try:
        result = InvestigationState.model_validate(merged)
    except Exception as exc:  # noqa: BLE001 — never let a mapping error lose the run
        logger.warning("investigation.state_rebuild_failed", run_id=str(state.run_id), error=str(exc))
        result = state

    if timed_out:
        result.add_finding(f"Investigation budget ({budget.max_seconds}s) exceeded — partial results, escalating.")
        if not result.verdict:
            result.verdict = NEEDS_REVIEW
        if result.status is AgentStatus.COMPLETED:
            result.status = AgentStatus.RUNNING

    if persist:
        await ledger_module.complete_run(
            run_id=result.run_id,
            tenant_id=tenant_uuid or result.tenant_id,
            status="completed",
            error=result.error,
            iterations=result.iteration_count,
        )
    return result


async def run_full_investigation(
    state: InvestigationState,
    *,
    budget: InvestigationBudget | None = None,
    persist: bool = True,
) -> InvestigationState:
    """Run the FULL graph (auto-triage → … → attack-path). Manual API entry."""
    from app.graph.workflow import investigation_graph  # noqa: PLC0415 — avoid import cycle

    return await _run(investigation_graph, state, budget=budget, persist=persist, seq_start=0)


async def run_escalation(
    state: InvestigationState,
    *,
    budget: InvestigationBudget | None = None,
    persist: bool = True,
    seq_start: int = 1,
) -> InvestigationState:
    """Run the post-triage escalation subgraph (triage → … → attack-path).

    Used by the auto-triage worker after it has produced (and persisted) a
    governed verdict. ``seq_start`` defaults to 1 so the recorded graph steps
    follow the worker's ``triage_verdict`` event (seq 1) without colliding.
    """
    from app.graph.workflow import escalation_graph  # noqa: PLC0415 — avoid import cycle

    return await _run(escalation_graph, state, budget=budget, persist=persist, seq_start=seq_start)


async def _heartbeat_loop(
    run_id: uuid.UUID,
    tenant_id: uuid.UUID,
    seq_issuer,
    interval: float = 60.0,
) -> None:
    """Record a ``heartbeat`` ledger event every ``interval`` seconds (plan U7, spec §3).

    Runs concurrently with the graph execution and is cancelled on normal
    completion, timeout, or exception. Uses the shared per-run sequence issuer
    (U6 ``RunSequence``) so heartbeat seq never collides with the graph-step
    recorder.
    """
    while True:
        await asyncio.sleep(interval)
        await ledger_module.record_event(
            run_id=run_id,
            tenant_id=tenant_id,
            seq=await seq_issuer.next(),
            kind="heartbeat",
            agent="runner",
            summary=f"heartbeat ({interval:.0f}s)",
            payload={"interval_s": int(interval)},
        )


async def run_case_investigation(
    state: dict,
    *,
    persist: bool = True,
    heartbeat_interval: float = 60.0,
    config: dict | None = None,
) -> dict:
    """Run the Case-dedicated graph (plan U7, spec §3).

    Separate entry point from the Alert-unit ``run_full_investigation`` /
    ``run_escalation`` (both untouched). Accepts a plain Case-state dict
    (``case_id``, ``run_id``, ``tenant_ref``, …) and:

    * opens the run in the Ledger (idempotent, ``ON CONFLICT DO NOTHING``),
    * starts a 60s-interval heartbeat task that records ``heartbeat`` events,
    * streams ``case_graph.astream(state, config)`` inside an
      ``asyncio.timeout`` bounded by the collection budget,
    * finalises the run as ``completed`` (or ``failed`` on a hard error).

    The heartbeat task is always cancelled on every exit path (normal,
    timeout, exception). The collection budget comes from U8's
    :func:`collection_budget` (separate from the LLM budget).
    """
    from app.graph.workflow import case_graph

    case_id = str(state.get("case_id", ""))
    run_id = state.get("run_id") or uuid.uuid4()
    tenant_ref = str(state.get("tenant_ref", "default"))
    state["run_id"] = run_id

    budget = collection_budget(int(state.get("alert_count", 1)))
    tenant_uuid = await ledger_module.resolve_tenant(tenant_ref) if persist else None
    seq_issuer = ledger_module.RunSequence()

    if persist:
        await ledger_module.start_run(
            run_id=run_id,
            case_id=case_id,
            tenant_ref=tenant_ref,
            alert_summary=str(state.get("case_summary", ""))[:8000],
            raw_alert=state.get("raw_case") or {},
            model_used="graph:case_investigation",
        )
        # Start event (spec §3): the case run is marked case-scoped so the
        # Ledger can distinguish it from the Alert-unit runs (incident id in
        # case_id). Recorded right after the run is opened, under the shared
        # RunSequence so its seq never collides with heartbeat/graph-step events.
        await ledger_module.record_event(
            run_id=run_id,
            tenant_id=tenant_uuid,
            seq=await seq_issuer.next(),
            kind="start",
            agent="runner",
            summary="case investigation started",
            payload={"scope": "case"},
        )

    merged: dict = dict(state)
    hb_task: asyncio.Task | None = None
    timed_out = False
    had_error: Exception | None = None
    # LangGraph forwards only ``config["configurable"]`` to nodes (U7b): the
    # per-run recorder handle (seq_issuer) plus run/tenant ids must live under
    # ``configurable`` so nodes can actually pick them up.
    cfg: RunnableConfig = config or {}
    cfg["configurable"] = {
        # Caller-supplied configurable keys are merged first; the runtime
        # run/tenant/seq_issuer are placed last so they always win over any
        # caller-supplied values (U7b invariant: nodes must see the real
        # per-run recorder, never a caller-injected one).
        **(cfg.get("configurable") or {}),
        "run_id": run_id,
        "tenant_id": tenant_uuid,
        "seq_issuer": seq_issuer,
    }

    try:
        if persist and tenant_uuid is not None:
            hb_task = asyncio.create_task(
                _heartbeat_loop(run_id, tenant_uuid, seq_issuer, heartbeat_interval)
            )
        async with asyncio.timeout(budget.max_seconds):
            async for step in case_graph.astream(state, cfg):
                if not isinstance(step, dict):
                    continue
                for node, out in step.items():
                    if isinstance(out, dict):
                        merged.update(out)
                    # Q3 fallback (spec §3): when nodes had no injected
                    # recorder, the node accumulates edr_call records in
                    # ``_pending_ledger_events``; the runner flushes them at
                    # the tier boundary (node transition) preserving the
                    # original call timestamps.
                    pending = out.get("_pending_ledger_events") if isinstance(out, dict) else None
                    if pending and tenant_uuid is not None:
                        for ev in pending:
                            await ledger_module.record_event(
                                run_id=run_id,
                                tenant_id=tenant_uuid,
                                seq=await seq_issuer.next(),
                                kind=ev.get("kind", "edr_call"),
                                agent=ev.get("agent", "edr_collect"),
                                summary=str(ev.get("summary", ""))[:8000],
                                payload=ev.get("payload"),
                                input_hash=ev.get("input_hash"),
                                output_hash=ev.get("output_hash"),
                                duration_ms=int(ev.get("duration_ms", 0)),
                            )
                    if tenant_uuid is not None:
                        await ledger_module.record_event(
                            run_id=run_id,
                            tenant_id=tenant_uuid,
                            seq=await seq_issuer.next(),
                            kind="graph_step",
                            agent=str(node),
                            summary=f"case graph node '{node}' completed",
                            payload={"node": str(node)},
                        )
    except TimeoutError:
        timed_out = True
        logger.warning("case_investigation.budget_timeout", case_id=case_id, max_seconds=budget.max_seconds)
    except Exception as exc:  # noqa: BLE001
        had_error = exc
        logger.warning("case_investigation.graph_error", case_id=case_id, error=str(exc))
    finally:
        if hb_task is not None:
            hb_task.cancel()
            try:
                await hb_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    if had_error is not None or timed_out:
        merged.setdefault("limitations", []).append("collection_budget_exceeded" if timed_out else "graph_error")

    if persist and tenant_uuid is not None:
        status = "failed" if had_error is not None else "completed"
        await ledger_module.complete_run(
            run_id=run_id,
            tenant_id=tenant_uuid,
            status=status,
            error=str(had_error) if had_error else None,
        )
    return merged
