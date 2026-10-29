"""U4b: cross-tenant row-level isolation for the case-investigation-context API.

The U4 mock-based tests prove the SQL *binds* the tenant, but they cannot prove
that a row from another tenant is actually excluded from the returned alerts.
That needs a real Postgres with the migration chain applied, because:

- the endpoint uses the Postgres-only ``= ANY(:alert_ids)`` clause, and
- ``set_rls_context`` issues ``SELECT set_config('app.current_tenant_id', ...)``
  which only exists on Postgres.

Mirrors the ``test_mssp_portfolio_isolation.py`` harness: connect to
``DATABASE_URL``, seed two tenants with overlapping alert links, assert the
cross-tenant row is not returned, and that a foreign case 404s. Skips (or
fails, when ``CASE_CTX_ISOLATION_REQUIRED`` is set) when no database answers.
"""
from __future__ import annotations

import os
import uuid
import json

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.v1.endpoints.graph import case_investigation_context

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("CASE_CTX_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

# Fixed ids so a failure names something greppable.
TENANT_A = uuid.UUID("0b000000-0000-0000-0000-00000000000a")
TENANT_B = uuid.UUID("0b000000-0000-0000-0000-00000000000b")
CASE_A = uuid.UUID("1c000000-0000-0000-0000-000000000001")
CASE_B = uuid.UUID("1c000000-0000-0000-0000-000000000002")
ALERT_A = uuid.UUID("2d000000-0000-0000-0000-000000000001")
ALERT_B = uuid.UUID("2d000000-0000-0000-0000-000000000002")

pytestmark = [
    pytest.mark.skipif(
        "postgres" not in DSN and not REQUIRED,
        reason="needs a live Postgres with the migration chain applied (integration.yml)",
    ),
    pytest.mark.asyncio,
]


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine(DSN)
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1"))
    except Exception as exc:
        await engine.dispose()
        if REQUIRED:
            pytest.fail(
                "CASE_CTX_ISOLATION_REQUIRED is set but no database answered at DATABASE_URL — "
                f"the cross-tenant isolation proof did not run: {type(exc).__name__}: {exc}"
            )
        pytest.skip(f"no database at DATABASE_URL ({type(exc).__name__}) — runs in integration.yml")

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        await _teardown(session)
        await _seed(session)
        try:
            yield session
        finally:
            await _teardown(session)
    await engine.dispose()


async def _teardown(session) -> None:
    # tenants has no tenant_id column — delete by primary key.
    for table, col in (("alerts", "tenant_id"), ("cases", "tenant_id")):
        await session.execute(
            text(f"DELETE FROM {table} WHERE {col} = ANY(:ids)"),
            {"ids": [str(TENANT_A), str(TENANT_B)]},
        )
    await session.execute(
        text("DELETE FROM tenants WHERE id = ANY(:ids)"),
        {"ids": [str(TENANT_A), str(TENANT_B)]},
    )
    await session.commit()


async def _seed(session) -> None:
    await session.execute(
        text(
            "INSERT INTO tenants (id, name, slug, limits) VALUES "
            "(:a, 'Iso Case A', 'iso-case-a', '{}'), "
            "(:b, 'Iso Case B', 'iso-case-b', '{}')"
        ),
        {"a": str(TENANT_A), "b": str(TENANT_B)},
    )
    # Case A links BOTH its own alert and tenant B's alert in alert_ids.
    await session.execute(
        text(
            "INSERT INTO cases (id, tenant_id, case_number, title, alert_ids) VALUES "
            "(:ca, :a, 'ISO-100', 'case A', :ids_a), "
            "(:cb, :b, 'ISO-200', 'case B', '[]')"
        ),
        {
            "ca": str(CASE_A),
            "cb": str(CASE_B),
            "a": str(TENANT_A),
            "b": str(TENANT_B),
            "ids_a": json.dumps([str(ALERT_A), str(ALERT_B)]),
        },
    )
    await session.execute(
        text(
            "INSERT INTO alerts (id, tenant_id, title, severity, event_time, raw_event) VALUES "
            "(:aa, :a, 'A critical', 'critical', NOW(), '{}'), "
            "(:ab, :b, 'B critical', 'critical', NOW(), '{}')"
        ),
        {"aa": str(ALERT_A), "ab": str(ALERT_B), "a": str(TENANT_A), "b": str(TENANT_B)},
    )
    await session.commit()


@pytest.mark.usefixtures("db")
async def test_cross_tenant_alert_not_returned(db, monkeypatch) -> None:
    """Case A's alert_ids names tenant B's alert; only A's own alert is returned."""
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "configured-secret")
    resp = await case_investigation_context(
        case_id=str(CASE_A),
        db=db,
        x_aisoc_service_token="configured-secret",
        x_aisoc_tenant_id=str(TENANT_A),
    )
    returned = [a.id for a in resp.alerts]
    assert str(ALERT_A) in returned
    assert str(ALERT_B) not in returned
    # alerts_total counts only the alerts owned by the calling tenant.
    assert resp.alerts_total == 1
    assert resp.truncated is False
    assert resp.case_number == "ISO-100"


@pytest.mark.usefixtures("db")
async def test_other_tenant_case_is_404(db, monkeypatch) -> None:
    """Requesting tenant B's case under tenant A's header yields 404."""
    from fastapi import HTTPException

    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "configured-secret")
    with pytest.raises(HTTPException) as exc:
        await case_investigation_context(
            case_id=str(CASE_B),
            db=db,
            x_aisoc_service_token="configured-secret",
            x_aisoc_tenant_id=str(TENANT_A),
        )
    assert exc.value.status_code == 404
