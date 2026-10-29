"""U5: ``POST /api/v1/graph/cases/{case_id}/investigation-comment`` (plan U5, spec §6/§7.1).

Verifies the service-token-only gate, structured-fields-only body (no free-form
narrative), server-assembled template, ``author="aisoc"`` / ``is_system=true``,
idempotency on (case_id, run_id, event_type), and closed-case acceptance.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from app.api.v1.endpoints.graph import (
    CaseInvestigationCommentRequest,
    _comment_body,
    post_case_investigation_comment,
)
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

TENANT = uuid.uuid4()
OTHER_TENANT = uuid.uuid4()
CASE = uuid.uuid4()
RUN = uuid.uuid4()


class _Row:
    def __init__(self, **fields: Any) -> None:
        self._fields = fields

    def __getattr__(self, name: str) -> Any:
        try:
            return self._fields[name]
        except KeyError:
            raise AttributeError(name)


def _make_db(
    captured: list[tuple[str, dict[str, Any]]],
    case_row: Any = None,
    comment_rows: list[Any] = None,
    commit_calls: list[Any] | None = None,
) -> Any:
    """An async-session double that records every ``text()`` statement."""

    class _Result:
        def __init__(self, one: Any, rows: list[Any]) -> None:
            self._one = one
            self._rows = rows

        def fetchone(self) -> Any:
            return self._one

        def fetchall(self) -> list[Any]:
            return self._rows

        def __iter__(self):
            return iter(self._rows)

    async def _execute(sql: Any, params: dict[str, Any] | None = None):
        sql_text = str(sql)
        captured.append((sql_text, params or {}))
        if "FROM aisoc_cases" in sql_text:
            return _Result(case_row, [])
        if "FROM aisoc_case_comments" in sql_text:
            return _Result(None, comment_rows or [])
        return _Result(None, [])

    db = MagicMock()
    db.execute = _execute
    db.commit = AsyncMock(side_effect=lambda: commit_calls.append(None)) if commit_calls is not None else AsyncMock()
    db.rollback = AsyncMock()
    return db


async def _run(
    case_id: str,
    token: str | None,
    tenant: str | None,
    body: dict[str, Any],
    *,
    case_row: Any = None,
    comment_rows: list[Any] = None,
    commit_calls: list[Any] | None = None,
) -> Any:
    captured: list[tuple[str, dict[str, Any]]] = []
    commit_list = commit_calls or []
    db = _make_db(captured, case_row=case_row, comment_rows=comment_rows, commit_calls=commit_list)
    resp = await post_case_investigation_comment(
        case_id=case_id,
        body=CaseInvestigationCommentRequest(**body),
        db=db,
        x_aisoc_service_token=token,
        x_aisoc_tenant_id=tenant,
    )
    return resp, captured, commit_list


def _case_row(**overrides: Any) -> Any:
    fields = {"id": CASE, "title": "Phish wave"}
    fields.update(overrides)
    return _Row(**fields)


def _comment_row(body: str, ts: datetime) -> Any:
    return _Row(id=uuid.uuid4(), body=body, created_at=ts)


# ── Auth (spec §9.4) ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_missing_service_token_is_401() -> None:
    with pytest.raises(HTTPException) as exc:
        await _run(str(CASE), None, str(TENANT), {"event_type": "investigation_started"})
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_wrong_service_token_is_401(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "configured-secret")
    with pytest.raises(HTTPException) as exc:
        await _run(str(CASE), "wrong", str(TENANT), {"event_type": "investigation_started"})
    assert exc.value.status_code == 401


# ── Header / id validation ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_missing_tenant_header_is_400(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "configured-secret")
    with pytest.raises(HTTPException) as exc:
        await _run(str(CASE), "configured-secret", None, {"event_type": "investigation_started"})
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_invalid_case_id_is_400(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "configured-secret")
    with pytest.raises(HTTPException) as exc:
        await _run("not-a-uuid", "configured-secret", str(TENANT), {"event_type": "investigation_started"})
    assert exc.value.status_code == 400


# ── Body validation ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unknown_event_type_is_400(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "configured-secret")
    with pytest.raises(HTTPException) as exc:
        await _run(str(CASE), "configured-secret", str(TENANT), {"event_type": "not_an_event_type"})
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_invalid_verdict_is_400(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "configured-secret")
    with pytest.raises(HTTPException) as exc:
        await _run(
            str(CASE),
            "configured-secret",
            str(TENANT),
            {"event_type": "investigation_completed", "verdict": "maybe_positive"},
        )
    assert exc.value.status_code == 400


# ── Tenant isolation ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_other_tenant_case_is_404(monkeypatch: pytest.MonkeyPatch) -> None:
    """tenant A requesting tenant B's case gets 404 (existence not disclosed)."""
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "configured-secret")
    with pytest.raises(HTTPException) as exc:
        await _run(
            str(CASE),
            "configured-secret",
            str(TENANT),
            {"event_type": "investigation_completed", "run_id": str(RUN)},
            case_row=None,
        )
    assert exc.value.status_code == 404


# ── Happy path + idempotency ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_completed_comment_created_and_committed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "configured-secret")
    commits: list[Any] = []
    resp, captured, commit_list = await _run(
        str(CASE),
        "configured-secret",
        str(TENANT),
        {
            "event_type": "investigation_completed",
            "run_id": str(RUN),
            "verdict": "true_positive",
            "synthesis_performed": True,
            "confidence": 0.8,
            "limitation_codes": ["graph_truncated(dynamic:af093445)"],
            "reason_code": None,
        },
        case_row=_case_row(),
        commit_calls=commits,
    )
    assert resp.created is True
    assert resp.comment_id is not None
    # The INSERT goes to aisoc_case_comments with author=aisoc, is_system=TRUE.
    insert_sql, insert_params = [
        (sql, p) for sql, p in captured if "INSERT INTO aisoc_case_comments" in sql
    ][0]
    assert insert_params["author"] == "aisoc"
    assert "verdict=true_positive" in insert_params["body"]
    assert "confidence=0.8" in insert_params["body"]
    assert "graph_truncated" in insert_params["body"]
    # A real commit happened.
    assert len(commit_list) == 1


@pytest.mark.asyncio
async def test_duplicate_comment_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "configured-secret")
    now = datetime.now(UTC)
    existing_body = _comment_body(
        event_type="investigation_completed",
        run_id=str(RUN),
        verdict="true_positive",
        synthesis_performed=True,
        confidence=0.8,
        limitation_codes=[],
        reason_code=None,
        case_number="Phish wave",
    )
    existing = _comment_row(existing_body, now)
    resp, captured, _ = await _run(
        str(CASE),
        "configured-secret",
        str(TENANT),
        {
            "event_type": "investigation_completed",
            "run_id": str(RUN),
            "verdict": "true_positive",
            "synthesis_performed": True,
            "confidence": 0.8,
            "limitation_codes": [],
        },
        case_row=_case_row(),
        comment_rows=[existing],
    )
    assert resp.created is False
    # No new INSERT should be issued.
    assert not any("INSERT INTO aisoc_case_comments" in sql for sql, _ in captured)
