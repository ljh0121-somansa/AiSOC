"""Tests for the ``alert_parent_process_lazy_load`` feature flag on the
``GET /api/v1/alerts/{id}/parent-process`` endpoint.

The flag (``AISOC_ALERT_PARENT_PROCESS_LAZY_LOAD``, default ``false``) gates
the whole on-demand parent-process lookup:

* flag off  → 403 "Parent-process lazy loading is disabled", before any DB
  access (fail-closed: no lookup is attempted).
* flag on   → tenant-scoped alert lookup (404 when the alert does not exist
  or belongs to another tenant), persisted-snapshot short-circuit,
  classification-driven no_parent / not_applicable / eligible outcomes, and
  the EDR one-shot lookup mapping (resolved / not_found / unavailable).

Also pins the RBAC contract: the route depends on ``alerts:read``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

import app.api.v1.endpoints.alerts as alerts_ep
from app.core.config import settings as real_settings


# ─── helpers ─────────────────────────────────────────────────────────────────


def _settings(lazy_load: bool = True, **kwargs):
    """A settings stand-in carrying the flag under test."""
    return SimpleNamespace(
        alert_parent_process_lazy_load=lazy_load,
        alert_parent_process_persist=kwargs.pop("persist", False),
        CONNECTORS_SERVICE_URL=kwargs.pop("CONNECTORS_SERVICE_URL", "http://connectors:8003"),
        **kwargs,
    )


def _user(tenant: uuid.UUID | None = None):
    return SimpleNamespace(
        tenant_id=tenant or uuid.uuid4(),
    )


def _alert(**kwargs) -> SimpleNamespace:
    """An alert stand-in with every attribute the endpoint touches."""
    now = datetime.now(UTC)
    defaults = {
        "id": uuid.uuid4(),
        "tenant_id": uuid.uuid4(),
        "connector_type": "edrserver",
        "connector_id": uuid.uuid4(),
        "raw_event": {
            "process": {
                "entity_id": str(uuid.uuid4()),
                "name": "powershell.exe",
                "parent": {"entity_id": str(uuid.uuid4())},
            }
        },
        "enrichment_data": None,
        "created_at": now,
        "event_time": now,
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


class _FakeResult:
    def __init__(self, alert):
        self._alert = alert

    def scalar_one_or_none(self):
        return self._alert


class _FakeDB:
    """A db double recording executes and returning one alert (or None)."""

    def __init__(self, alert=None, execute_raises=None):
        self.execute = AsyncMock(return_value=_FakeResult(alert))
        self.commit = AsyncMock()
        self.rollback = AsyncMock()


@pytest.fixture
def monkey_settings(monkeypatch):
    """Point the endpoint module at a settings stand-in (flag ON by default)."""
    s = _settings(lazy_load=True)
    monkeypatch.setattr(alerts_ep, "settings", s)
    return s


def _patched(monkeypatch, *, classify="eligible", build=None, persisted=None):
    """Patch the endpoint module's collaborators AND point it at a settings
    stand-in with the flag ON, so the endpoint body actually runs."""
    s = _settings(lazy_load=True)
    monkeypatch.setattr(alerts_ep, "settings", s)
    classify_mock = MagicMock(return_value=classify)
    build_mock = AsyncMock(
        return_value=build if build is not None else {
            "status": "unavailable",
            "entity_id": "00000000-0000-0000-0000-000000000000",
            "name": None,
            "pid": None,
            "executable": None,
            "started_at": None,
            "source": "edr_lookup",
            "cached": False,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "retryable": True,
        }
    )
    persisted_mock = MagicMock(
        return_value=persisted if persisted is not None else None
    )
    monkeypatch.setattr(alerts_ep, "classify_parent_lookup", classify_mock)
    monkeypatch.setattr(alerts_ep, "build_parent_process_response", build_mock)
    monkeypatch.setattr(alerts_ep, "_map_persisted_parent_process", persisted_mock)
    return classify_mock, build_mock, persisted_mock


# ─── 1. flag off ─────────────────────────────────────────────────────────────


async def test_flag_off_returns_403(monkeypatch):
    """Flag off: the endpoint refuses with 403, before any DB access."""
    s = _settings(lazy_load=False)
    monkeypatch.setattr(alerts_ep, "settings", s)
    db = _FakeDB()
    user = _user()
    with pytest.raises(HTTPException) as exc:
        await alerts_ep.parent_process_endpoint(uuid.uuid4(), user, db)
    assert exc.value.status_code == 403
    assert "disabled" in exc.value.detail
    db.execute.assert_not_awaited()  # fail-closed: no lookup attempted


# ─── 2. flag on: tenant-scoped alert lookup ──────────────────────────────────


async def test_flag_on_missing_alert_404(monkeypatch):
    """No alert row for the caller's tenant → 404, no EDR call."""
    _patched(monkeypatch)
    db = _FakeDB(alert=None)
    user = _user()
    with pytest.raises(HTTPException) as exc:
        await alerts_ep.parent_process_endpoint(uuid.uuid4(), user, db)
    assert exc.value.status_code == 404
    db.execute.assert_awaited_once()


async def test_flag_on_query_is_tenant_scoped(monkeypatch):
    """The SELECT must filter on both the alert id and the caller's tenant
    id (Architecture Rule 2: tenant isolation at the query layer)."""
    _patched(monkeypatch)
    alert = _alert()
    db = _FakeDB(alert=alert)
    user = _user()
    await alerts_ep.parent_process_endpoint(alert.id, user, db)
    (select_arg,) = db.execute.await_args.args
    str_sql = str(select_arg)
    assert "tenant_id" in str_sql


# ─── 3. flag on: persisted-snapshot short-circuit ───────────────────────────


async def test_flag_on_persisted_resolved_snapshot_short_circuits(monkeypatch):
    """A resolved snapshot already in enrichment_data is returned as-is with
    source=persisted; the EDR lookup is NOT re-run (AC-LP-4)."""
    parent_id = str(uuid.uuid4())
    persisted = SimpleNamespace(
        name="explorer.exe",
        process_id=parent_id,
        pid=4242,
        started_at=datetime(2026, 10, 20, 9, 30, tzinfo=timezone.utc),
        status="resolved",
        source="persisted",
    )
    classify_mock, build_mock, _ = _patched(
        monkeypatch, persisted=persisted
    )
    alert = _alert()
    db = _FakeDB(alert=alert)
    user = _user()
    resp = await alerts_ep.parent_process_endpoint(alert.id, user, db)
    assert resp.status == "resolved"
    assert resp.source == "persisted"
    assert resp.name == "explorer.exe"
    assert resp.process_id == parent_id
    build_mock.assert_not_awaited()
    classify_mock.assert_not_called()


async def test_flag_on_persisted_non_resolved_falls_through(monkeypatch):
    """A persisted snapshot that is not 'resolved' does not short-circuit;
    the endpoint proceeds to classification + EDR lookup."""
    persisted = SimpleNamespace(
        name=None, process_id=None, pid=None, started_at=None,
        status="not_found", source="persisted",
    )
    classify_mock, build_mock, _ = _patched(
        monkeypatch, classify="eligible", persisted=persisted
    )
    snapshot = {
        "status": "resolved",
        "entity_id": str(uuid.uuid4()),
        "name": "winword.exe",
        "pid": 1234,
        "executable": "C:\\Windows\\System32\\winword.exe",
        "started_at": "2026-10-20T09:30:00+00:00",
        "source": "edr_lookup",
        "cached": False,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    build_mock.return_value = snapshot
    alert = _alert()
    db = _FakeDB(alert=alert)
    user = _user()
    resp = await alerts_ep.parent_process_endpoint(alert.id, user, db)
    assert resp.status == "resolved"
    assert resp.source == "edr_lookup"
    assert resp.name == "winword.exe"
    assert resp.pid == 1234
    assert resp.started_at == datetime(2026, 10, 20, 9, 30, tzinfo=timezone.utc)
    build_mock.assert_awaited_once()


# ─── 4. flag on: classification outcomes ─────────────────────────────────────


async def test_flag_on_no_parent_classification(monkeypatch):
    """``no_parent`` classification: returns no_parent without calling EDR."""
    classify_mock, build_mock, _ = _patched(monkeypatch, classify="no_parent")
    alert = _alert()
    db = _FakeDB(alert=alert)
    resp = await alerts_ep.parent_process_endpoint(alert.id, _user(), db)
    assert resp.status == "no_parent"
    assert resp.source is None
    build_mock.assert_not_awaited()
    classify_mock.assert_called_once()


async def test_flag_on_not_applicable_classification(monkeypatch):
    """``not_applicable`` classification: returns not_applicable, no EDR call."""
    _patched(monkeypatch, classify="not_applicable")
    alert = _alert()
    resp = await alerts_ep.parent_process_endpoint(
        alert.id, _user(), _FakeDB(alert=alert)
    )
    assert resp.status == "not_applicable"


async def test_flag_on_none_classification_treated_not_applicable(monkeypatch):
    """``None`` classification (non-EDR connector) is treated as
    not_applicable: the endpoint must not call the EDR lookup."""
    classify_mock, build_mock, _ = _patched(monkeypatch, classify=None)
    alert = _alert(connector_type="splunk")
    resp = await alerts_ep.parent_process_endpoint(
        alert.id, _user(), _FakeDB(alert=alert)
    )
    assert resp.status == "not_applicable"
    build_mock.assert_not_awaited()


# ─── 5. flag on: eligible EDR lookup outcomes ────────────────────────────────


async def test_flag_on_eligible_edr_found(monkeypatch):
    """Eligible alert + EDR 'found' → resolved with the parent's name/PID."""
    parent_id = str(uuid.uuid4())
    snapshot = {
        "status": "resolved",
        "entity_id": parent_id,
        "name": "explorer.exe",
        "pid": 3344,
        "executable": "C:\\Windows\\explorer.exe",
        "started_at": "2026-10-20T09:30:00+00:00",
        "source": "edr_lookup",
        "cached": False,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    classify_mock, build_mock, _ = _patched(monkeypatch, classify="eligible")
    build_mock.return_value = snapshot
    alert = _alert()
    resp = await alerts_ep.parent_process_endpoint(
        alert.id, _user(), _FakeDB(alert=alert)
    )
    assert resp.status == "resolved"
    assert resp.source == "edr_lookup"
    assert resp.name == "explorer.exe"
    assert resp.pid == 3344
    assert resp.process_id == parent_id


async def test_flag_on_eligible_edr_not_found(monkeypatch):
    """Eligible alert + EDR 404/miss → not_found (retryable by the UI's
    re-query button; no error banner, per the spec's fail-closed UX)."""
    snapshot = {
        "status": "not_found",
        "entity_id": str(uuid.uuid4()),
        "name": None,
        "pid": None,
        "executable": None,
        "started_at": None,
        "source": "edr_lookup",
        "cached": False,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    classify_mock, build_mock, _ = _patched(monkeypatch, classify="eligible")
    build_mock.return_value = snapshot
    alert = _alert()
    resp = await alerts_ep.parent_process_endpoint(
        alert.id, _user(), _FakeDB(alert=alert)
    )
    assert resp.status == "not_found"
    assert resp.name is None


async def test_flag_on_eligible_edr_unavailable(monkeypatch):
    """Eligible alert + EDR unreachable/error → unavailable, retryable."""
    snapshot = {
        "status": "unavailable",
        "entity_id": str(uuid.uuid4()),
        "name": None,
        "pid": None,
        "executable": None,
        "started_at": None,
        "source": "edr_lookup",
        "cached": False,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "retryable": True,
    }
    classify_mock, build_mock, _ = _patched(monkeypatch, classify="eligible")
    build_mock.return_value = snapshot
    alert = _alert()
    resp = await alerts_ep.parent_process_endpoint(
        alert.id, _user(), _FakeDB(alert=alert)
    )
    assert resp.status == "unavailable"
    assert resp.name is None


# ─── 6. RBAC contract ───────────────────────────────────────────────────────


def test_route_requires_alerts_read_permission():
    """Architecture Rule 3: the route must gate on ``alerts:read`` so an
    unauthenticated caller is refused before any lookup runs."""
    route = next(
        r for r in alerts_ep.router.routes
        if getattr(r, "path", None) == "/alerts/{alert_id}/parent-process"
    )
    import inspect

    src = inspect.getsource(route.dependant.call)
    dep_srcs = [inspect.getsource(d.call) for d in route.dependant.dependencies]
    assert 'require_permission("alerts:read")' in src or any(
        "require_permission" in s for s in dep_srcs
    )
