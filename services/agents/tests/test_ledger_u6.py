"""U6: Investigation Ledger active-run / last-event queries + RunSequence
(plan U6, spec §2, §3).

Covers: active-run lookup (stale recovery prerequisite), last-event timestamp
lookups, and the single per-run seq issuer that prevents the
``ON CONFLICT DO NOTHING`` silent-drop collision described in spec §10-9.
"""
from __future__ import annotations

import asyncio
import uuid

import pytest

from app.investigator import ledger
from app.investigator.ledger import RunSequence, get_active_run, get_last_event_ts


def test_run_sequence_monotonic():
    async def scenario():
        seq = RunSequence()
        issued = [await seq.next() for _ in range(5)]
        assert issued == [0, 1, 2, 3, 4]
        assert seq.peek() == 5

    asyncio.run(scenario())


def test_run_sequence_concurrent_no_collision():
    """Concurrent next() calls never collide (spec §3 single sequence rule):
    N concurrent issuers get N distinct seqs."""
    async def scenario():
        seq = RunSequence()
        results = await asyncio.gather(*(seq.next() for _ in range(50)))
        assert len(set(results)) == 50
        assert sorted(results) == list(range(50))

    asyncio.run(scenario())


def test_run_sequence_start_offset():
    async def scenario():
        seq = RunSequence(start=10)
        assert await seq.next() == 10
        assert await seq.next() == 11

    asyncio.run(scenario())


def test_get_active_run_requires_db(monkeypatch):
    """No DATABASE_URL -> None (best-effort), matching the rest of the ledger."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    async def _no_pool():
        return None
    monkeypatch.setattr(ledger, "get_pool", _no_pool)
    result = asyncio.run(get_active_run("case-1", uuid.UUID(int=1)))
    assert result is None

def test_get_last_event_ts_requires_db(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    async def _no_pool():
        return None
    monkeypatch.setattr(ledger, "get_pool", _no_pool)
    result = asyncio.run(get_last_event_ts(uuid.uuid4(), uuid.UUID(int=1)))
    assert result is None


def test_get_active_run_query_uses_case_index(monkeypatch, caplog):
    """The active-run query filters ``case_id`` + ``status='running'`` and uses
    ``idx_inv_runs_case`` (ORDER BY started_at DESC)."""
    captured = {}

    class FakeConn:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None


        async def fetchrow(self, sql, case_id):
            captured["sql"] = sql
            captured["case_id"] = case_id
            return {"id": uuid.UUID(int=1), "status": "running", "started_at": None}

    class FakePool:
        def acquire(self):
            return FakeConn()

        async def close(self):
            pass

    async def _pool():
        return FakePool()
    monkeypatch.setattr(ledger, "get_pool", _pool)
    async def _no_rls(conn, tid):
        return None
    monkeypatch.setattr(ledger, "_set_rls_context", _no_rls)

    async def scenario():
        return await get_active_run("case-1", uuid.UUID(int=1))

    res = asyncio.run(scenario())
    assert res is not None
    assert "case_id = $1" in captured["sql"]
    assert "status = 'running'" in captured["sql"]
    assert res["status"] == "running"


def test_get_last_event_ts_orders_by_seq(monkeypatch):
    captured = {}

    class FakeConn:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def fetchrow(self, sql, run_id):
            captured["sql"] = sql
            from datetime import datetime
            return {"ts": datetime(2026, 1, 1)}

    class FakePool:
        def acquire(self):
            return FakeConn()

    async def _pool():
        return FakePool()
    monkeypatch.setattr(ledger, "get_pool", _pool)
    async def _no_rls(conn, tid):
        return None
    monkeypatch.setattr(ledger, "_set_rls_context", _no_rls)

    run_id = uuid.UUID(int=7)
    res = asyncio.run(get_last_event_ts(run_id, uuid.UUID(int=1)))
    assert "ORDER BY seq DESC" in captured["sql"]
    assert res.year == 2026
