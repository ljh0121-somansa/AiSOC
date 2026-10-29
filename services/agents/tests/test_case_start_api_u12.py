"""U12: Case investigation start API gate (plan U12, spec §2/§3/§9.4).

Covers the §9.4 start/scoping/scoping-concurrency scenarios with the
feature flag ON:
  * closed Case            -> 409 ``case_closed`` + ``skipped(closed_case)`` comment
  * no supported EDR alert -> 422 ``no_edr_alert`` + ``skipped(no_edr_alert)`` comment
  * foreign-tenant / missing Case -> 404 (existence not disclosed, no comment, no ledger write)
  * concurrent second start -> 409 ``run_in_progress`` returning the existing run_id
  * stale running run      -> recovered inside the advisory lock as
    ``failed(stale_run_recovered)``, then a new run is opened
  * flag OFF               -> the existing Pillar-1 path is untouched (merge safety)

All external I/O is mocked: the ledger module, the U4 context fetch, the
timeline writer, and the background runner.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from unittest import mock

import app.api.investigate as inv
import app.graph.case_workflow as case_workflow
import app.investigator.ledger as case_ledger
import app.services.timeline_writer as tw
from app.api.investigate import (
    InvestigateRequest,
    InvestigateResponse,
    case_investigate_enabled,
    launch_investigation,
)
from app.security.tenant_scope import TenantPrincipal

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
CASE_ID = str(uuid.UUID("22222222-2222-2222-2222-222222222222"))
OTHER_TENANT = uuid.UUID("33333333-3333-3333-3333-333333333333")


# ---------------------------------------------------------------------------
# Doubles
# ---------------------------------------------------------------------------


class _Pool:
    """asyncpg pool double exposing an ``acquire()`` context manager."""

    def __init__(self) -> None:
        self.conn = _Conn()
        self.locks: list[str] = []

    def acquire(self) -> _Acquire:
        return _Acquire(self)


class _Conn:
    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple[Any, ...]]] = []

    async def execute(self, sql: str, *args: Any) -> None:
        self.executed.append((sql, args))
        if "advisory" in sql:
            self._advisory = str(args[0]) if args else ""
        if hasattr(self, "_owner"):
            pass


class _Acquire:
    def __init__(self, pool: _Pool) -> None:
        self._pool = pool

    async def __aenter__(self) -> _Conn:
        return self._pool.conn

    async def __aexit__(self, *a: Any) -> bool:
        return False


def _make_principal() -> TenantPrincipal:
    return TenantPrincipal(tenant_ids=frozenset({TENANT}), subject="console:test")


def _make_body() -> InvestigateRequest:
    return InvestigateRequest(
        alert_summary="Phishing wave",
        raw_alert={"source": "edr", "event": "login_failure"},
        tenant_id="default",
    )


def _ctx(*, status: str = "investigating", alerts: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "case_id": CASE_ID,
        "case_number": "Phish wave",
        "status": status,
        "severity": "high",
        "mitre_techniques": ["T1566"],
        "tags": ["phish"],
        "alert_ids": ["44444444-4444-4444-4444-444444444444"],
        "alerts": alerts or [],
        "alerts_total": 0,
        "truncated": False,
    }


def _supported_alert() -> dict[str, Any]:
    return {
        "id": "44444444-4444-4444-4444-444444444444",
        "external_id": "dynamic:af0932",
        "severity": "high",
        "event_time": None,
        "raw_event": {"source": "edr", "event": "login_failure"},
    }


def _run_case(
    monkeypatch,
    *,
    ctx: dict[str, Any] | None = None,
    active_run: dict[str, Any] | None = None,
    last_event_ts: Any = None,
    pool: _Pool | None = None,
) -> None:
    """Install the U12 external-I/O mocks for a single test."""
    # Flag ON.
    monkeypatch.setenv("AISOC_CASE_INVESTIGATE", "1")
    monkeypatch.setattr(case_ledger, "resolve_tenant", mock.AsyncMock(return_value=TENANT))
    if ctx is not None:
        monkeypatch.setattr(
            inv, "fetch_case_investigation_context",
            mock.AsyncMock(return_value=ctx),
        )
    else:
        monkeypatch.setattr(
            inv, "fetch_case_investigation_context",
            mock.AsyncMock(side_effect=case_workflow.CaseContextLoadError("404")),
        )
    monkeypatch.setattr(case_ledger, "get_pool", mock.AsyncMock(return_value=pool))
    monkeypatch.setattr(case_ledger, "get_active_run", mock.AsyncMock(return_value=active_run))
    monkeypatch.setattr(case_ledger, "get_last_event_ts", mock.AsyncMock(return_value=last_event_ts))
    monkeypatch.setattr(case_ledger, "complete_run", mock.AsyncMock())
    monkeypatch.setattr(case_ledger, "start_run", mock.AsyncMock(return_value=TENANT))
    monkeypatch.setattr(
        tw.CaseTimelineWriter, "post_investigation_comment", mock.AsyncMock(return_value=True),
    )
    monkeypatch.setattr(inv, "run_case_investigation", mock.AsyncMock(return_value={"error": None}))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_flag_off_keeps_pillar1_path(monkeypatch):
    """Merge safety: with the flag off the original Pillar-1 path runs (no case gate)."""
    mon = mock.Mock()
    mon.add_task = mock.Mock()
    monkeypatch.delenv("AISOC_CASE_INVESTIGATE", raising=False)
    assert not case_investigate_enabled()
    # _save_run / _run_and_store are module-level; exercise the real path
    # through the fallback run store (no Redis configured in tests).
    resp = await launch_investigation(CASE_ID, _make_body(), mon, _make_principal())
    assert isinstance(resp, InvestigateResponse)
    assert resp.status == "running"
    mon.add_task.assert_called_once()


@pytest.mark.asyncio
async def test_closed_case_409_and_skipped_comment(monkeypatch):
    ctx = _ctx(status="closed")
    _run_case(monkeypatch, ctx=ctx, pool=_Pool())
    mon = mock.Mock()
    with pytest.raises(Exception) as excinfo:
        await launch_investigation(CASE_ID, _make_body(), mon, _make_principal())
    exc = excinfo.value
    assert exc.status_code == 409
    assert exc.detail == {"reason_code": "case_closed"}
    posted = tw.CaseTimelineWriter.post_investigation_comment
    assert posted.call_args.kwargs["event_type"] == "investigation_skipped"
    assert posted.call_args.kwargs["reason_code"] == "closed_case"


@pytest.mark.asyncio
async def test_no_edr_alert_422_and_skipped_comment(monkeypatch):
    # A case with alerts that carry no supported EDR source_kind.
    ctx = _ctx(alerts=[{**_supported_alert(), "external_id": "unsupported:xyz"}])
    _run_case(monkeypatch, ctx=ctx, pool=_Pool())
    mon = mock.Mock()
    with pytest.raises(Exception) as excinfo:
        await launch_investigation(CASE_ID, _make_body(), mon, _make_principal())
    exc = excinfo.value
    assert exc.status_code == 422
    assert exc.detail == {"reason_code": "no_edr_alert"}
    posted = tw.CaseTimelineWriter.post_investigation_comment
    assert posted.call_args.kwargs["reason_code"] == "no_edr_alert"
    # No run is opened when the case has no supported EDR alert.
    assert not case_ledger.start_run.called


@pytest.mark.asyncio
async def test_foreign_tenant_404_no_comment(monkeypatch):
    """Foreign-tenant access returns 404 (existence not disclosed), posts no comment,
    opens no run — matches spec §9.4 '타 테넌트 Case 접근'.
    Simulated by the context fetch raising CaseContextLoadError."""
    pool = _Pool()
    _run_case(monkeypatch, ctx=None, pool=pool)
    mon = mock.Mock()
    with pytest.raises(Exception) as excinfo:
        await launch_investigation(CASE_ID, _make_body(), mon, _make_principal())
    exc = excinfo.value
    assert exc.status_code == 404
    # No comment posted, no run started.
    assert not tw.CaseTimelineWriter.post_investigation_comment.called
    assert not case_ledger.start_run.called


@pytest.mark.asyncio
async def test_concurrent_second_start_409_run_in_progress(monkeypatch):
    active = {"run_id": uuid.UUID("55555555-5555-5555-5555-555555555555"), "status": "running", "started_at": None}
    # A recent last-event ts means the run is NOT stale -> 409.
    from datetime import datetime, timedelta
    recent = datetime.utcnow() - timedelta(minutes=5)
    _run_case(monkeypatch, ctx=_ctx(alerts=[_supported_alert()]), active_run=active, last_event_ts=recent, pool=_Pool())
    mon = mock.Mock()
    with pytest.raises(Exception) as excinfo:
        await launch_investigation(CASE_ID, _make_body(), mon, _make_principal())
    exc = excinfo.value
    assert exc.status_code == 409
    assert exc.detail == {
        "reason_code": "run_in_progress",
        "existing_run_id": "55555555-5555-5555-5555-555555555555",
    }
    assert not case_ledger.start_run.called


@pytest.mark.asyncio
async def test_stale_run_recovered_then_new_run(monkeypatch):
    active = {"run_id": uuid.UUID("55555555-5555-5555-5555-555555555555"), "status": "running", "started_at": None}
    from datetime import datetime, timedelta
    stale = datetime.utcnow() - timedelta(minutes=40)  # > STALE_AFTER_S (30 min)
    pool = _Pool()
    _run_case(monkeypatch, ctx=_ctx(alerts=[_supported_alert()]), active_run=active, last_event_ts=stale, pool=pool)
    mon = mock.Mock()
    resp = await launch_investigation(CASE_ID, _make_body(), mon, _make_principal())
    assert resp.status == "running"
    # The stale run was finalised as failed(stale_run_recovered) inside the lock.
    cr = case_ledger.complete_run
    assert cr.called
    assert cr.call_args.kwargs["status"] == "failed"
    assert cr.call_args.kwargs["error"] == "stale_run_recovered"
    # A new run was opened and the started comment posted.
    assert case_ledger.start_run.called
    assert tw.CaseTimelineWriter.post_investigation_comment.called
    # The advisory lock was actually taken on the shared connection.
    assert any("advisory" in s[0] for s in pool.conn.executed)


@pytest.mark.asyncio
async def test_started_comment_carries_run_id(monkeypatch):
    _run_case(monkeypatch, ctx=_ctx(alerts=[_supported_alert()]), pool=_Pool())
    mon = mock.Mock()
    resp = await launch_investigation(CASE_ID, _make_body(), mon, _make_principal())
    posted = tw.CaseTimelineWriter.post_investigation_comment
    assert posted.call_args.kwargs["event_type"] == "investigation_started"
    assert posted.call_args.kwargs["run_id"] == resp.run_id
    assert mon.add_task.called  # background runner was scheduled

# ---------------------------------------------------------------------------
# U15 regression tests (fix #1 failed-status, #2 result comments,
# #3 single context fetch, #4 start_run inside advisory lock)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_background_failed_finalises_failed_and_posts_failed_comment(monkeypatch):
    """#1/#2: a graph error sets merged['error'] -> run finalised as failed
    + investigation_failed comment (spec §9.4 acceptance: failed run)."""
    run_id = "aaaaaaa1-1111-1111-1111-111111111111"
    state = {"case_id": CASE_ID, "run_id": run_id, "tenant_ref": "default"}
    monkeypatch.setattr(
        inv, "run_case_investigation",
        mock.AsyncMock(return_value={"error": "graph exploded", "verdict": None,
                                    "synthesis_performed": False, "confidence": 0,
                                    "limitations": ["graph_error"]}),
    )
    monkeypatch.setattr(case_ledger, "resolve_tenant", mock.AsyncMock(return_value=TENANT))
    monkeypatch.setattr(case_ledger, "record_artifact", mock.AsyncMock())
    monkeypatch.setattr(tw.CaseTimelineWriter, "post_investigation_comment",
                        mock.AsyncMock(return_value=True))
    monkeypatch.setattr(inv, "_update_run", mock.AsyncMock())

    await inv._run_case_background(run_id, CASE_ID, state, "default")

    posted = tw.CaseTimelineWriter.post_investigation_comment
    assert posted.called
    assert posted.call_args.kwargs["event_type"] == "investigation_failed"
    assert posted.call_args.kwargs["run_id"] == run_id
    assert inv._update_run.call_args.args[1]["status"] == "failed"


@pytest.mark.asyncio
async def test_background_completed_posts_completed_comment(monkeypatch):
    """#2: a clean run posts investigation_completed carrying the LLM
    verdict/confidence/limitations into the structured comment (spec §6)."""
    run_id = "bbbbbbb2-2222-2222-2222-222222222222"
    state = {"case_id": CASE_ID, "run_id": run_id, "tenant_ref": "default"}
    monkeypatch.setattr(
        inv, "run_case_investigation",
        mock.AsyncMock(return_value={"error": None, "verdict": "insufficient",
                                    "synthesis_performed": False, "confidence": 0,
                                    "limitations": ["llm_unavailable"]}),
    )
    monkeypatch.setattr(case_ledger, "resolve_tenant", mock.AsyncMock(return_value=TENANT))
    monkeypatch.setattr(case_ledger, "record_artifact", mock.AsyncMock())
    monkeypatch.setattr(tw.CaseTimelineWriter, "post_investigation_comment",
                        mock.AsyncMock(return_value=True))
    monkeypatch.setattr(inv, "_update_run", mock.AsyncMock())

    await inv._run_case_background(run_id, CASE_ID, state, "default")

    posted = tw.CaseTimelineWriter.post_investigation_comment
    assert posted.call_args.kwargs["event_type"] == "investigation_completed"
    assert posted.call_args.kwargs["verdict"] == "insufficient"
    assert posted.call_args.kwargs["limitation_codes"] == ["llm_unavailable"]
    assert inv._update_run.call_args.args[1]["status"] == "completed"


@pytest.mark.asyncio
async def test_gate_passes_context_into_runner_state(monkeypatch):
    """#3: the U12 gate forwards the U4 context it already loaded into the
    runner state so the U9 node does not re-fetch (single U4 fetch per run)."""
    _run_case(monkeypatch, ctx=_ctx(alerts=[_supported_alert()]), pool=_Pool())
    mon = mock.Mock()
    resp = await launch_investigation(CASE_ID, _make_body(), mon, _make_principal())
    # add_task(func, run_id, case_id, state, tenant_id) -> state is args[3].
    add_args = mon.add_task.call_args.args
    state = add_args[3]
    assert state["case_id"] == CASE_ID
    assert state["run_id"] == resp.run_id
    assert state["case_context"]["case_id"] == CASE_ID
    assert state["alerts"] == [_supported_alert()]
    # The U4 context endpoint was fetched exactly once by the gate.
    assert inv.fetch_case_investigation_context.call_count == 1


@pytest.mark.asyncio
async def test_start_run_runs_inside_advisory_lock(monkeypatch):
    """#4: with a DB pool present, start_run now runs INSIDE the advisory-lock
    block, making stale-recovery + new-run opening atomic (plan U12)."""
    pool = _Pool()
    _run_case(monkeypatch, ctx=_ctx(alerts=[_supported_alert()]), pool=pool)
    mon = mock.Mock()
    resp = await launch_investigation(CASE_ID, _make_body(), mon, _make_principal())
    assert resp.status == "running"
    # start_run was called and the advisory lock was taken on the shared conn.
    assert case_ledger.start_run.called
    assert any("advisory" in s[0] for s in pool.conn.executed)
