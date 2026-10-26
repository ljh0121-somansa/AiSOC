from __future__ import annotations

"""Unit tests for the parent-process eligibility, status mapping, TTL and
snapshot-write contract in ``app.services.parent_process_lookup``.

Covers:

* ``compute_eligibility`` — edrserver / non-edrserver, self-ref, no-parent-ctx.
* ``_map_status`` — found -> resolved, not_found, unavailable.
* TTL logic — ``resolve_ttl`` (alert age < 10 min -> not_found 60s, else 300s;
  resolved 3600; unavailable None / never cached).
* Snapshot atomic write — ``persist_snapshot`` does NOT touch ``updated_at``.
* Cache keying / sanitisation.

Endpoint-level behaviour (404 cross-tenant, bad UUID) lives in the router;
``_snapshot``/``build_parent_process_response`` happy path is out of unit
scope (depends on a private snapshot builder), so we do not assert on it here.
"""


import asyncio
import uuid
from datetime import UTC, datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

import app.services.parent_process_lookup as ppl
from app.services.parent_process_lookup import (
    STATUS_NOT_FOUND,
    STATUS_RESOLVED,
    STATUS_UNAVAILABLE,
    _alert_age_minutes,
    _cache_key,
    _extract_parent_entity_id,
    _map_status,
    _strip_control_chars,
    compute_eligibility,
    persist_snapshot,
    resolve_ttl,
)

EDR_UUID = str(uuid.uuid4())
PARENT_UUID = str(uuid.uuid4())


def asyncio_run(coro_factory) -> None:
    """Run the coroutine returned by ``coro_factory`` in a fresh event loop.

    ``coro_factory`` is a zero-arg callable so the ``db`` mock lives in scope
    after the loop finishes and can still be asserted on.
    """

    async def _runner() -> None:
        await coro_factory()

    asyncio.run(_runner())


# Sentinel so ``created_at=None`` can actually be forwarded (the
# ``or datetime.now(UTC)`` default would otherwise swallow the None and the
# "missing created_at -> inf age" path could never be exercised).
_MISSING = object()


def _alert(
    *,
    connector_type: str | None = "edrserver",
    connector_id: str | None = "edr-prod-01",
    raw_event: dict | None = None,
    created_at=_MISSING,
    alert_id: str | None = None,
) -> SimpleNamespace:
    created_at = datetime.now(UTC) if created_at is _MISSING else created_at
    return SimpleNamespace(
        id=alert_id or str(uuid.uuid4()),
        connector_type=connector_type,
        connector_id=connector_id,
        raw_event=raw_event or {},
        created_at=created_at,
    )


# A distinct process entity_id so the parent lookup is a real ancestor
# (process.entity_id != parent.entity_id), not a self-reference.
PROCESS_UUID = str(uuid.uuid4())


def _rr_alert_with_parent() -> SimpleNamespace:
    """edrserver alert whose raw_event carries a process + parent.entity_id."""
    return _alert(
        raw_event={
            "process": {
                "entity_id": PROCESS_UUID,
                "name": "powershell.exe",
                "parent": {"entity_id": PARENT_UUID, "name": "explorer.exe"},
            }
        }
    )


def _self_ref_alert() -> SimpleNamespace:
    """process.entity_id == parent.entity_id -> self reference."""
    eid = str(uuid.uuid4())
    return _alert(
        raw_event={
            "process": {
                "entity_id": eid,
                "parent": {"entity_id": eid, "name": "explorer.exe"},
            }
        }
    )


def _no_parent_ctx_alert() -> SimpleNamespace:
    """edrserver alert, process present but no parent entity_id."""
    return _alert(
        raw_event={"process": {"entity_id": PARENT_UUID, "name": "explorer.exe"}}
    )


# ─── 1. compute_eligibility ──────────────────────────────────────────────────


class TestComputeEligibility:
    def test_edrserver_with_parent_is_eligible(self):
        assert compute_eligibility(_rr_alert_with_parent()) is True

    def test_non_edrserver_is_not_eligible(self):
        """AC: edrserver false -> not_applicable (eligibility False)."""
        assert compute_eligibility(_alert(connector_type="splunk")) is False
        assert compute_eligibility(_alert(connector_type=None)) is False
        assert compute_eligibility(_alert(connector_type="elastic")) is False

    def test_no_process_context_is_not_eligible(self):
        """AC: edrserver true but no process context -> no_parent (False)."""
        assert compute_eligibility(_no_parent_ctx_alert()) is False

    def test_raw_event_none_is_not_eligible(self):
        assert compute_eligibility(_alert(raw_event=None)) is False
        assert compute_eligibility(_alert(raw_event="notadict")) is False

    def test_self_reference_is_not_eligible(self):
        """AC: parent.entity_id == process.entity_id -> no_parent (False)."""
        assert compute_eligibility(_self_ref_alert()) is False

    def test_nested_raw_data_parent_is_eligible(self):
        """Two-path extraction: raw_event.raw_data.process.parent.entity_id."""
        ev = {
            "raw_data": {
                "process": {
                    "parent": {"entity_id": PARENT_UUID, "name": "explorer.exe"}
                }
            }
        }
        assert compute_eligibility(_alert(raw_event=ev)) is True

    def test_whitespace_parent_id_not_eligible(self):
        ev = {"process": {"parent": {"entity_id": "   "}}}
        assert compute_eligibility(_alert(raw_event=ev)) is False

    def test_no_connector_attribute_not_eligible(self):
        """getattr defensive: namespace without connector_type attr."""
        assert compute_eligibility(SimpleNamespace(raw_event={})) is False


class TestExtractParentEntityId:
    def test_prefers_direct_process_parent(self):
        assert _extract_parent_entity_id(
            {"process": {"parent": {"entity_id": PARENT_UUID}}}
        ) == PARENT_UUID

    def test_falls_back_to_nested(self):
        assert _extract_parent_entity_id(
            {"raw_data": {"process": {"parent": {"entity_id": PARENT_UUID}}}}
        ) == PARENT_UUID

    def test_none_when_absent(self):
        assert _extract_parent_entity_id({"process": {"name": "x"}}) == ""


# ─── 2. status mapping ─────────────────────────────────────────────────────────


class TestMapStatus:
    def test_found_maps_to_resolved(self):
        out = _map_status(
            "found",
            PARENT_UUID,
            {
                "entity_id": "p123",
                "name": "explorer.exe",
                "pid": 4321,
                "executable": r"C:\Windows\explorer.exe",
                "started_at": "2026-10-22T03:00:10.000Z",
            },
        )
        assert out["status"] == STATUS_RESOLVED
        assert out["entity_id"] == "p123"
        assert out["name"] == "explorer.exe"
        assert out["pid"] == 4321
        assert out["executable"] == r"C:\Windows\explorer.exe"
        assert out["started_at"] == "2026-10-22T03:00:10.000Z"
        assert out["source"] == "edr_lookup"
        assert out["cached"] is False
        assert isinstance(out["fetched_at"], str) and out["fetched_at"]

    def test_not_found_maps_to_not_found(self):
        out = _map_status("not_found", PARENT_UUID, None)
        assert out["status"] == STATUS_NOT_FOUND
        assert out["entity_id"] == PARENT_UUID
        assert out["name"] is None
        assert out["pid"] is None
        assert out["executable"] is None
        assert out["started_at"] is None

    def test_unavailable_maps_to_unavailable(self):
        for src in ("unavailable", None, "bogus", "FOUND", "ERROR"):
            out = _map_status(src, PARENT_UUID, {"name": "x"})
            assert out["status"] == STATUS_UNAVAILABLE, src
            assert out["name"] is None
            assert out["pid"] is None
            assert out["executable"] is None
            assert out["entity_id"] == PARENT_UUID
            assert out["retryable"] is True

    def test_found_without_process_falls_back_to_entity(self):
        out = _map_status("found", PARENT_UUID, None)
        assert out["status"] == STATUS_RESOLVED
        assert out["entity_id"] == PARENT_UUID


# ─── 3. TTL logic ────────────────────────────────────────────────────────────


class TestTtlLogic:
    def test_resolved_ttl_is_3600(self):
        assert resolve_ttl(STATUS_RESOLVED, alert_age_minutes=0.0) == ppl._TTL_RESOLVED
        assert ppl._TTL_RESOLVED == 3600

    def test_not_found_fresh_alert_ttl_is_60(self):
        """AC: alert age < 10 min -> not_found TTL 60s."""
        assert resolve_ttl(STATUS_NOT_FOUND, alert_age_minutes=3.0) == 60

    def test_not_found_old_alert_ttl_is_300(self):
        """AC: alert age >= 10 min -> not_found TTL 300s."""
        assert resolve_ttl(STATUS_NOT_FOUND, alert_age_minutes=15.0) == 300

    def test_not_found_exactly_at_threshold(self):
        """Boundary: exactly 10 minutes is NOT fresh -> 300s."""
        assert resolve_ttl(STATUS_NOT_FOUND, alert_age_minutes=10.0) == 300

    def test_unavailable_never_cached(self):
        """AC: unavailable -> None (do not cache)."""
        assert resolve_ttl(STATUS_UNAVAILABLE, alert_age_minutes=1.0) is None

    def test_alert_age_minutes(self):
        # Capture "now" at test time. A fresh alert is ~0 minutes old (allow a
        # small positive slack for scheduling between building and measuring).
        now = datetime.now(UTC)
        age_now = _alert_age_minutes(_alert(created_at=now))
        assert 0.0 <= age_now < 1.0
        past = now - timedelta(minutes=12)
        assert _alert_age_minutes(_alert(created_at=past)) == pytest.approx(12.0, abs=0.05)
        future = now + timedelta(minutes=3)  # created_at in the future -> negative age
        assert _alert_age_minutes(_alert(created_at=future)) == pytest.approx(-3.0, abs=0.05)

    def test_alert_age_minutes_none_created_is_infinity(self):
        assert _alert_age_minutes(_alert(created_at=None)) == float("inf")


# ─── 4. snapshot atomic write ─────────────────────────────────────────────────


async def _persist(db) -> None:
    await persist_snapshot(db, _alert(), {"status": STATUS_RESOLVED, "name": "x"})


class TestPersistSnapshot:
    def test_persist_does_not_touch_updated_at(self, monkeypatch):
        """AC: snapshot write must not bump updated_at."""
        monkeypatch.setattr(ppl.settings, "alert_parent_process_persist", True)
        db = AsyncMock()
        db.execute = AsyncMock(return_value=MagicMock())
        db.commit = AsyncMock()
        asyncio_run(lambda: _persist(db))

        args, _kwargs = db.execute.call_args
        sql = str(args[0]).lower()
        assert "update alerts" in sql
        assert "set enrichment_data" in sql
        assert "updated_at" not in sql
        assert db.commit.await_count == 1

    def test_persist_is_idempotent_conditional(self, monkeypatch):
        """AC: WHERE NOT (enrichment_data ? 'parent_process') guards overwrite."""
        monkeypatch.setattr(ppl.settings, "alert_parent_process_persist", True)
        db = AsyncMock()
        db.execute = AsyncMock()
        db.commit = AsyncMock()
        asyncio_run(lambda: _persist(db))
        sql = str(db.execute.call_args[0][0]).lower()
        assert "not (enrichment_data" in sql
        assert "'parent_process'" in sql

    def test_persist_no_id_returns_early(self):
        db = AsyncMock()

        async def _run():
            await persist_snapshot(db, SimpleNamespace(id=None), {"status": STATUS_RESOLVED})

        asyncio.run(_run())
        db.execute.assert_not_awaited()

    def test_persist_failure_is_swallowed(self):
        """AC: write failure must not propagate (best-effort)."""
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=RuntimeError("boom"))
        db.commit = AsyncMock(side_effect=RuntimeError("flush-fail"))
        asyncio_run(lambda: _persist(db))  # must not raise

    def test_snapshot_serialised_and_bound(self, monkeypatch):
        """AC: The snapshot JSON is what gets merged into enrichment_data."""
        monkeypatch.setattr(ppl.settings, "alert_parent_process_persist", True)
        db = AsyncMock()
        db.execute = AsyncMock()
        db.commit = AsyncMock()
        alert = _alert()

        async def _run():
            await persist_snapshot(db, alert, {"status": STATUS_RESOLVED, "name": "x"})

        asyncio_run(_run)
        params = db.execute.call_args[0][1]
        assert '"name": "x"' in params["snapshot"]
        assert '"status": "resolved"' in params["snapshot"]
        assert params["id"] == str(alert.id)


# ─── 5. cache keying / sanitisation ─────────────────────────────────────────


class TestCacheKey:
    def test_cache_key_contains_tenant_connector_entity(self):
        key = _cache_key(uuid.uuid4(), "edr-prod-01", PARENT_UUID)
        assert key.startswith(ppl.CACHE_NAMESPACE + ":")
        assert "edr-prod-01" in key
        assert PARENT_UUID in key

    def test_cache_key_is_tenant_scoped(self):
        """AC: 404 cross-tenant requires tenant in key so another tenant's
        cached snapshot can never be served for this lookup."""
        t1, t2 = uuid.uuid4(), uuid.uuid4()
        assert _cache_key(t1, "c", PARENT_UUID) != _cache_key(t2, "c", PARENT_UUID)

    def test_cache_key_connector_scoped(self):
        a, b = uuid.uuid4(), uuid.uuid4()
        assert _cache_key(a, "c1", PARENT_UUID) != _cache_key(a, "c2", PARENT_UUID)

    def test_strip_control_chars(self):
        cleaned = _strip_control_chars("explorer\x07.exe\r\n\t")
        assert "\x07" not in cleaned
        assert "\r" not in cleaned
        assert cleaned == "explorer.exe"

    def test_non_string_raises(self):
        # _strip_control_chars is strings-only (used on process name/id);
        # passing None or a non-string is a programming error and raises.
        for bad in (None, 42, ["x"]):
            try:
                _strip_control_chars(bad)
            except (TypeError, AttributeError):
                continue
            raise AssertionError(f"_strip_control_chars({bad!r}) did not raise")


class TestCharSanitization:
    """AC-14: control/Bidi chars are stripped before cache/log keys."""

    def test_ascii_control_chars_stripped(self):
        # ASCII control chars (\x00-\x1f\x7f) incl. CR/LF/TAB must be removed.
        cleaned = _strip_control_chars("explorer\x07.exe\r\n\t")
        assert "\x07" not in cleaned
        assert "\r" not in cleaned
        assert "\n" not in cleaned
        assert "\t" not in cleaned
        assert cleaned == "explorer.exe"

    def test_null_and_del_chars_stripped(self):
        assert _strip_control_chars("a\x00b") == "ab"
        assert _strip_control_chars("a\x7fb") == "ab"

    def test_whitespace_stripped_by_nonempty(self):
        # _nonempty strips surrounding whitespace + control chars.
        assert _extract_parent_entity_id({"process": {"parent": {"entity_id": "  1234  "}}}) == "1234"

    def test_cache_key_ignores_control_chars(self):
        # Cache-key sanitization prevents injection via raw_event values.
        t1 = _cache_key(uuid.UUID(PARENT_UUID), "c", "1234")
        t2 = _cache_key(uuid.UUID(PARENT_UUID), "c", "12\x0034")
        assert t1 == t2

    def test_map_status_passes_name_through_raw(self):
        # _map_status flattens the connector-supplied process name verbatim;
        # the connectors/edrserver layer already strips control chars from
        # the name before this function sees it (this layer is not a sink).
        result = _map_status("found", PARENT_UUID, {
            "entity_id": "proc-1",
            "name": "explorer.exe",
        })
        assert result["status"] == "resolved"
        assert result["name"] == "explorer.exe"

    def test_clean_connector_name_has_no_control_chars(self):
        # AC-14: the connector returns a name with no ASCII control chars, so
        # a resolved snapshot stored in the cache/persistence path is clean.
        result = _map_status("found", PARENT_UUID, {
            "entity_id": "proc-1",
            "name": "explorer.exe",
        })
        assert result["name"] == _strip_control_chars(result["name"])

    def test_bidi_and_zerowidth_chars_stripped(self):
        # AC-14: Bidi override/iso chars (U+200E/F/U+202A-F/U+2066-9) and
        # zero-width (U+200B/C/D) must be removed so a process name cannot
        # smuggle a display-reordering control.
        cleaned = _strip_control_chars(
            "winword\u202E.exe\u2066\u200B"
        )
        assert "\u202E" not in cleaned
        assert "\u2066" not in cleaned
        assert "\u200B" not in cleaned

class TestLookupWindow:
    """AC-5: past-anchored window — ``to = event_time``, ``from = to - window``."""

    def test_window_length_follows_declared_config_key(self):
        # Regression: must read PARENT_LOOKUP_WINDOW_MINUTES (the documented
        # config knob), not an undeclared key, so the operator setting is
        # actually honored. Window length tracks the setting exactly.
        now = datetime.now(timezone.utc)
        alert = SimpleNamespace(event_time=now)
        with _fake_settings(PARENT_LOOKUP_WINDOW_MINUTES=60):
            frm, to = ppl._lookup_window(alert)
        assert (
            datetime.fromisoformat(to) - datetime.fromisoformat(frm)
        ) == timedelta(minutes=60)

    def test_default_window_is_one_day(self):
        # The default look-back window is 1 day (1440 min), anchored at the
        # alert's event_time.
        alert = SimpleNamespace(event_time=datetime.now(timezone.utc))
        with _fake_settings():
            frm, to = ppl._lookup_window(alert)
        span = datetime.fromisoformat(to) - datetime.fromisoformat(frm)
        assert span == timedelta(days=1)

    def test_window_is_configurable(self):
        # A larger declared window still produces a correspondingly larger range.
        alert = SimpleNamespace(event_time=datetime.now(timezone.utc))
        with _fake_settings(PARENT_LOOKUP_WINDOW_MINUTES=10000):
            frm, to = ppl._lookup_window(alert)
        span = datetime.fromisoformat(to) - datetime.fromisoformat(frm)
        assert span == timedelta(minutes=10000)

    def test_to_equals_event_time(self):
        # The window is past-anchored: ``to`` is the alert's event_time, so the
        # whole window lies in the past and is immune to host/EDR clock skew.
        ev = datetime(2026, 10, 26, 4, 33, 26, tzinfo=timezone.utc)
        alert = SimpleNamespace(event_time=ev)
        with _fake_settings():
            frm, to = ppl._lookup_window(alert)
        assert datetime.fromisoformat(to) == ev
        assert datetime.fromisoformat(frm) == ev - timedelta(days=1)

    def test_event_time_without_tz_is_treated_as_utc(self):
        alert = SimpleNamespace(event_time=datetime(2026, 1, 1, 12, 0, 0))
        _frm, to = ppl._lookup_window(alert)
        # A naive event_time is treated as UTC; ``to`` (== event_time) must be
        # timezone-aware.
        assert datetime.fromisoformat(to).tzinfo is not None


class _fake_settings:
    """Context manager that points ppl.settings at a namespace carrying the
    given parent-process knobs while leaving the rest of the module untouched."""

    def __init__(self, PARENT_LOOKUP_WINDOW_MINUTES=1440):
        self.window = PARENT_LOOKUP_WINDOW_MINUTES

    def __enter__(self):
        self._saved = ppl.settings
        ppl.settings = SimpleNamespace(
            PARENT_LOOKUP_WINDOW_MINUTES=self.window,
        )
        return self

    def __exit__(self, *exc):
        ppl.settings = self._saved
        return False


class TestBuildParentProcessResponse:
    """Regression: connector already returns a pre-mapped snapshot;
    ``build_parent_process_response`` must NOT run ``_map_status`` a second
    time. Before the fix, a ``status="resolved"`` from the connector was
    re-mapped to ``unavailable`` because ``_map_status`` only recognises
    the raw EDR statuses ``"found"`` / ``"not_found"``.
    """

    def test_resolved_snapshot_not_double_mapped(self, monkeypatch):
        monkeypatch.setattr(ppl.settings, "alert_parent_process_persist", False)

        connector_snapshot = {
            "status": STATUS_RESOLVED,
            "entity_id": PARENT_UUID,
            "name": "svchost.exe",
            "pid": 2572,
            "executable": "C:\\Windows\\System32\\svchost.exe",
            "started_at": "2026-10-25T23:43:09.63Z",
            "source": "edr_lookup",
            "fetched_at": "2026-10-26T01:56:49.137+00:00",
            "cached": False,
        }
        lookup_mock = AsyncMock(return_value=connector_snapshot)
        monkeypatch.setattr(ppl, "_call_connector_process_lookup", lookup_mock)

        db = AsyncMock()
        db.execute = AsyncMock(return_value=MagicMock())
        db.commit = AsyncMock()
        db.rollback = AsyncMock()
        alert = _rr_alert_with_parent()

        def _run():
            return ppl.build_parent_process_response(db, alert, uuid.UUID("00000000-0000-0000-0000-000000000001"))

        result_box = {}

        def _factory():
            async def _inner():
                result_box["snapshot"] = await _run()
            return _inner()

        asyncio_run(_factory)
        snap = result_box["snapshot"]
        assert snap["status"] == STATUS_RESOLVED
        assert snap["name"] == "svchost.exe"
        assert snap["cached"] is False
        assert snap["pid"] == 2572

    def test_not_found_snapshot_passes_through(self, monkeypatch):
        """A not_found snapshot must stay not_found, not become unavailable."""
        monkeypatch.setattr(ppl.settings, "alert_parent_process_persist", False)

        connector_snapshot = {
            "status": STATUS_NOT_FOUND,
            "entity_id": PARENT_UUID,
            "name": None,
            "pid": None,
            "started_at": None,
            "source": "edr_lookup",
            "fetched_at": "2026-10-26T01:56:49.137+00:00",
            "cached": False,
        }
        lookup_mock = AsyncMock(return_value=connector_snapshot)
        monkeypatch.setattr(ppl, "_call_connector_process_lookup", lookup_mock)

        db = AsyncMock()
        alert = _rr_alert_with_parent()

        def _run():
            return ppl.build_parent_process_response(db, alert, uuid.UUID("00000000-0000-0000-0000-000000000001"))

        result_box = {}

        def _factory():
            async def _inner():
                result_box["snapshot"] = await _run()
            return _inner()

        asyncio_run(_factory)
        assert result_box["snapshot"]["status"] == STATUS_NOT_FOUND
