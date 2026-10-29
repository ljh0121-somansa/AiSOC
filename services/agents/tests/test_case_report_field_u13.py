"""U13: GET /investigations/{run_id} report field (plan U13, spec §5 stage 11, §7.1).

The poll response is additive: Case runs expose a structured ``report``
summary (verdict / synthesis_performed / confidence / limitations /
entities / mitre_techniques) loaded from the ``case_report_json`` artifact.
``report_md``/``report_html`` stay stripped (slim policy kept).
"""

from __future__ import annotations

import json
import uuid
from typing import Any
from unittest import mock

import pytest

import app.api.investigate as inv
import app.investigator.ledger as case_ledger
from app.api.investigate import get_investigation
from app.security.tenant_scope import TenantPrincipal

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
RUN = str(uuid.uuid4())


def _principal() -> TenantPrincipal:
    return TenantPrincipal(tenant_ids=frozenset({TENANT}), subject="console:test")


def _seed_run(extra: dict[str, Any] | None = None) -> None:
    """Seed the in-memory fallback run store (no Redis in unit tests)."""
    inv._FALLBACK_RUNS[RUN] = {
        "run_id": RUN,
        "case_id": "c-1",
        "status": "completed",
        "started_at": "2026-10-29T00:00:00",
        "report_md": "# md body",
        "report_html": "<html></html>",
    }
    if extra:
        inv._FALLBACK_RUNS[RUN].update(extra)


def _mock_pool(conn_fetchrow_value) -> Any:
    """Build a pool double whose ``acquire()`` returns a conn with the given fetchrow."""
    conn = mock.MagicMock()
    conn.fetchrow = mock.AsyncMock(return_value=conn_fetchrow_value)

    class _Acquire:
        async def __aenter__(self) -> mock.MagicMock:
            return conn

        async def __aexit__(self, *a: Any) -> bool:
            return False

    pool = mock.MagicMock()
    pool.acquire.return_value = _Acquire()
    return pool


@pytest.mark.asyncio
async def test_report_field_from_case_report_json(monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_run()
    report = {
        "verdict": "true_positive",
        "synthesis_performed": True,
        "confidence": 0.8,
        "confidence_source": {"llm_reported": 0.92},
        "evidence": [],
        "limitations": ["timeline_truncated"],
        "entities": {"pc_name": "host-01"},
        "mitre_techniques": ["T1036.005"],
    }
    pool = _mock_pool({"content": json.dumps(report)})
    monkeypatch.setattr(case_ledger, "get_pool", mock.AsyncMock(return_value=pool))

    resp = await get_investigation(RUN, _principal())
    assert resp["report"]["verdict"] == "true_positive"
    assert resp["report"]["confidence"] == 0.8
    assert resp["report"]["limitations"] == ["timeline_truncated"]
    assert resp["report"]["mitre_techniques"] == ["T1036.005"]
    # Slim policy: large report bodies are still stripped.
    assert "report_md" not in resp
    assert "report_html" not in resp


@pytest.mark.asyncio
async def test_report_absent_when_no_artifact(monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_run()
    pool = _mock_pool(None)
    monkeypatch.setattr(case_ledger, "get_pool", mock.AsyncMock(return_value=pool))

    resp = await get_investigation(RUN, _principal())
    assert "report" not in resp
    assert resp["status"] == "completed"


@pytest.mark.asyncio
async def test_case_background_records_case_report_json(monkeypatch: pytest.MonkeyPatch) -> None:
    """U13 write side: the background task persists the synthesis report as
    a ``case_report_json`` artifact before finalising the run."""
    state = {
        "case_id": "c-1",
        "run_id": RUN,
        "tenant_ref": str(TENANT),
        "alert_count": 1,
        "case_summary": "Phish wave",
        "raw_case": {},
    }
    report = {
        "verdict": "insufficient",
        "synthesis_performed": False,
        "confidence": 0.0,
        "limitations": ["llm_unavailable"],
    }
    monkeypatch.setattr(inv, "run_case_investigation", mock.AsyncMock(return_value={"error": None, "report": report}))
    monkeypatch.setattr(case_ledger, "resolve_tenant", mock.AsyncMock(return_value=TENANT))
    monkeypatch.setattr(case_ledger, "record_artifact", mock.AsyncMock())
    monkeypatch.setattr(inv, "_update_run", mock.AsyncMock())

    await inv._run_case_background(RUN, "c-1", state, str(TENANT))

    ra = case_ledger.record_artifact
    assert ra.called
    assert ra.call_args.kwargs["kind"] == "case_report_json"
    assert json.loads(ra.call_args.kwargs["content"])["verdict"] == "insufficient"
    # LLM unconfigured -> run is completed (not failed), report carries llm_unavailable.
    upd = inv._update_run
    assert upd.call_args.args[1]["status"] == "completed"
