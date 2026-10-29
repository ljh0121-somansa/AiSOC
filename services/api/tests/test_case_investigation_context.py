"""U4: ``GET /api/v1/graph/case-investigation-context/{case_id}`` (plan3 U4, spec §4/§9.4).

The agents service loads the Case + linked EDR alerts through this service-token-only route.
Three contracts matter:

- Auth: a missing/invalid service token must be refused (401) — the route
  has NO console-JWT fallback (spec §9.4 acceptance 10).
- Tenant isolation: every statement binds the caller's ``tenant_id``; another
  tenant's case returns 404, not the row.
- external_id: returned verbatim from ``alerts.external_id`` (spec §9.1) —
  the agents parse the source_kind/event id split themselves.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints.graph import case_investigation_context
from fastapi import HTTPException

TENANT = uuid.uuid4()
CASE = uuid.uuid4()
OTHER_TENANT = uuid.uuid4()
ALERT = uuid.uuid4()
ALERT2 = uuid.uuid4()


def _make_db(
    captured: list[tuple[str, dict[str, Any]]],
    case_row: Any = None,
    alert_rows: list[Any] = None,
) -> Any:
    """An AsyncSession double that records every ``text()`` statement."""

    class _Result:
        def __init__(self, one: Any, rows: list[Any]) -> None:
            self._one = one
            self._rows = rows

        def fetchone(self) -> Any:
            return self._one

        def __iter__(self):
            return iter(self._rows)

    async def _execute(sql: Any, params: dict[str, Any] | None = None):
        sql_text = str(sql)
        captured.append((sql_text, params or {}))
        if "FROM aisoc_cases" in sql_text:
            return _Result(case_row, [])
        elif "FROM alerts" in sql_text:
            return _Result(None, alert_rows or [])
        return _Result(None, [])

    db = MagicMock()
    db.execute = _execute
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    return db


async def _run(
    case_id: str,
    token: str | None,
    tenant: str | None,
    *,
    case_row: Any = None,
    alert_rows: list[Any] = None,
) -> Any:
    captured: list[tuple[str, dict[str, Any]]] = []
    db = _make_db(captured, case_row=case_row, alert_rows=alert_rows)
    resp = await case_investigation_context(
        case_id=case_id,
        db=db,
        x_aisoc_service_token=token,
        x_aisoc_tenant_id=tenant,
    )
    return resp, captured

class _Row:
    def __init__(self, **fields: Any) -> None:
        self._fields = fields

    def __getattr__(self, name: str) -> Any:
        try:
            return self._fields[name]
        except KeyError:
            raise AttributeError(name)

def _case_row(**overrides: Any) -> Any:
    fields = {
        "id": CASE,
        "title": "Phish wave",
        "status": "investigating",
        "severity": "high",
        "mitre_techniques": ["T1566"],
        "tags": ["phish"],
        "alert_ids": [ALERT, ALERT2],
    }
    fields.update(overrides)
    return _Row(**fields)


def _alert_row(**overrides: Any) -> Any:
    fields = {
        "id": ALERT,
        "external_id": "dynamic:af0932",
        "severity": "high",
        "event_time": datetime(2026, 10, 28, 12, 0, tzinfo=UTC),
        "raw_event": {"source": "edr", "event": "login_failure"},
    }
    fields.update(overrides)
    return _Row(**fields)




# ── Auth (spec §9.4 acceptance 10) ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_missing_service_token_is_401() -> None:
    with pytest.raises(HTTPException) as exc:
        await _run(str(CASE), None, str(TENANT))
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_wrong_service_token_is_401(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "configured-secret")
    with pytest.raises(HTTPException) as exc:
        await _run(str(CASE), "wrong-secret", str(TENANT))
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_service_token_configured_but_unsent_is_401(monkeypatch: pytest.MonkeyPatch) -> None:
    """The trap: configured token + absent header must not compare equal to empty."""
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "   ")
    with pytest.raises(HTTPException) as exc:
        await _run(str(CASE), None, str(TENANT))
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_valid_service_token_passes_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "configured-secret")
    resp, captured = await _run(
        str(CASE),
        "configured-secret",
        str(TENANT),
        case_row=_case_row(),
        alert_rows=[_alert_row(), _alert_row(id=ALERT2, external_id="elastic:SIG-77")],
    )
    assert isinstance(resp.case_id, str) and resp.case_id == str(CASE)
    # RLS context statement first, then the two SELECTs — all bind the tenant.
    assert "set_config" in captured[0][0]
    assert captured[0][1] == {"tid": str(TENANT)}


# ── Tenant isolation (spec §9.4) ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_other_tenant_case_is_404(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "configured-secret")
    with pytest.raises(HTTPException) as exc:
        await _run(str(CASE), "configured-secret", str(TENANT))
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_every_statement_binds_the_caller_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "configured-secret")
    _, captured = await _run(
        str(CASE),
        "configured-secret",
        str(TENANT),
        case_row=_case_row(),
        alert_rows=[_alert_row()],
    )
    for sql, params in captured:
        if "FROM cases" in sql or "FROM alerts" in sql:
            assert params.get("tenant_id") == str(TENANT)
            assert "tenant_id = :tenant_id" in sql


@pytest.mark.asyncio
async def test_missing_tenant_header_is_400(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "configured-secret")
    with pytest.raises(HTTPException) as exc:
        await _run(str(CASE), "configured-secret", None)
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_invalid_tenant_uuid_is_400(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "configured-secret")
    with pytest.raises(HTTPException) as exc:
        await _run(str(CASE), "configured-secret", "not-a-uuid")
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_invalid_case_id_is_400(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "configured-secret")
    with pytest.raises(HTTPException) as exc:
        await _run("not-a-uuid", "configured-secret", str(TENANT))
    assert exc.value.status_code == 400


# ── Content contract (spec §4 / §9.1) ─────────────────────────────────────


@pytest.mark.asyncio
async def test_response_shape_and_external_id_verbatim(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "configured-secret")
    resp, _ = await _run(
        str(CASE),
        "configured-secret",
        str(TENANT),
        case_row=_case_row(),
        alert_rows=[
            _alert_row(),
            _alert_row(id=ALERT2, external_id="elastic:SIG-77"),
        ],
    )
    assert resp.case_number == "Phish wave"
    assert resp.severity == "high"
    assert resp.mitre_techniques == ["T1566"]
    assert resp.alert_ids == [str(ALERT), str(ALERT2)]
    assert len(resp.alerts) == 2
    assert resp.alerts[0].external_id == "dynamic:af0932"
    assert resp.alerts[1].external_id == "elastic:SIG-77"
    assert resp.alerts[0].raw_event == {"source": "edr", "event": "login_failure"}
    assert resp.alerts[0].event_time.year == 2026


@pytest.mark.asyncio
async def test_malformed_stored_alert_id_is_skipped_not_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    """A single bad entry in ``case.alert_ids`` must not fail the read."""
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "configured-secret")
    resp, captured = await _run(
        str(CASE),
        "configured-secret",
        str(TENANT),
        case_row=_case_row(alert_ids=[ALERT, "not-a-uuid"]),
        alert_rows=[_alert_row()],
    )
    # Only the valid UUID reached the alerts query.
    alerts_sql, alerts_params = [
        (sql, p) for sql, p in captured if "FROM alerts" in sql
    ][0]
    assert [str(a) for a in alerts_params["alert_ids"]] == [str(ALERT)]
    assert len(resp.alerts) == 1
    # The response still echoes the raw alert_ids, including the bad entry.
    assert "not-a-uuid" in resp.alert_ids


@pytest.mark.asyncio
async def test_no_linked_alerts_returns_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "configured-secret")
    resp, captured = await _run(
        str(CASE),
        "configured-secret",
        str(TENANT),
        case_row=_case_row(alert_ids=[]),
    )
    assert resp.alerts == []
    # No alerts SELECT is issued when the case links no alerts.
    assert not any("FROM alerts" in sql for sql, _ in captured)

# ── Server-side cap & truncated (U4b) ─────────────────────────────────────


@pytest.mark.asyncio
async def test_alert_cap_truncates_and_sorts_by_severity(monkeypatch: pytest.MonkeyPatch) -> None:
    """The server clips the alert list to the cap (default 100, env-overridable),
    ordered by severity (critical>high>medium>low>info) then event_time, and
    reports ``alerts_total`` (pre-cap count) + ``truncated``.
    """
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "configured-secret")
    monkeypatch.setenv("AISOC_CASE_CTX_ALERT_LIMIT", "2")

    five_ids = [ALERT, ALERT2,
                 uuid.uuid4(), uuid.uuid4(), uuid.uuid4()]
    rows = [
        _alert_row(id=five_ids[2], severity="info",
                    event_time=datetime(2026, 10, 28, 12, 0, tzinfo=UTC)),
        _alert_row(id=five_ids[3], severity="low",
                    event_time=datetime(2026, 10, 28, 8, 0, tzinfo=UTC)),
        _alert_row(id=five_ids[4], severity="critical",
                    event_time=datetime(2026, 10, 28, 9, 0, tzinfo=UTC)),
        _alert_row(id=ALERT, severity="high",
                    event_time=datetime(2026, 10, 28, 12, 0, tzinfo=UTC)),
        _alert_row(id=ALERT2, severity="medium",
                    event_time=datetime(2026, 10, 28, 10, 0, tzinfo=UTC)),
    ]
    resp, _ = await _run(
        str(CASE),
        "configured-secret",
        str(TENANT),
        case_row=_case_row(alert_ids=five_ids),
        alert_rows=rows,
    )
    # Cap of 2 clips the list; the two highest-severity alerts survive.
    assert resp.truncated is True
    assert resp.alerts_total == 5
    assert len(resp.alerts) == 2
    # critical and high come before medium/low/info after sorting.
    assert [a.severity for a in resp.alerts] == ["critical", "high"]
    # The truncated list is the top of the severity-ordered sequence.
    assert [a.id for a in resp.alerts] == [str(five_ids[4]), str(ALERT)]


@pytest.mark.asyncio
async def test_alerts_total_and_truncated_flags_within_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    """Within the cap, ``truncated`` is False and ``alerts_total`` equals the
    number of tenant-owned alerts returned."""
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "configured-secret")
    monkeypatch.delenv("AISOC_CASE_CTX_ALERT_LIMIT", raising=False)
    resp, _ = await _run(
        str(CASE),
        "configured-secret",
        str(TENANT),
        case_row=_case_row(),
        alert_rows=[_alert_row(), _alert_row(id=ALERT2, external_id="elastic:SIG-77")],
    )
    assert resp.alerts_total == 2
    assert resp.truncated is False
    assert len(resp.alerts) == 2
