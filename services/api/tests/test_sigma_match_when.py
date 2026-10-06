"""Section 5 — Live-Detection Hot-Reload guardrail tests.

The console edits Sigma/YAML rule bodies; fusion evaluates the live stream
against the compiled ``match_when``. These tests close that loop:

* Check A  — the transpiler emits ``match_when`` the **vendored matcher**
  consumes, and every emitted grammar produces the correct verdict. The
  vendored copy ships under ``app._vendor.detection_matcher`` (see the plan's
  "vendored + parity-gated" convention) because the api Docker build context
  is ``services/api`` and can't import fusion at test time. This is the
  contract that makes hot-reload meaningful: an uncompilable/incorrect emit is
  a silent no-op in production.
* Check B  — stateful (windowed) rules are reported ``unsupported_stateful``
  and their ``match_when`` is dropped, so they are *never* broadcast to fusion
  as single-event matches (guardrail A-5: the operator sees the rule isn't live).
* Check C  — the reload-action decision logic: only observable state changes
  (activate / deactivate / upsert) broadcast; a fresh ``testing``-status rule or
  an unchanged active rule broadcasts nothing.
* Check D  — end-to-end compile -> persist -> broadcast (API) and the
  API->fusion action translation (``ENABLE`` -> ``CREATE`` etc.), so the two
  services agree on the reload vocabulary without a real Redis/Postgres.

Redis is mocked (a real server is not available in CI here); Postgres is
uninvolved because the compiler records the compile result on the in-memory
rule row, which is what the endpoints diff.
"""

from __future__ import annotations

import asyncio
import json
import types
import unittest.mock
import uuid
from pathlib import Path

import pytest

from app.services.detections.compiler import (
    apply_compile_and_reload,
    broadcast_rule_reload,
    decide_reload_action,
)
from app.services.detections.sigma_match_when import compile_sigma_to_match_when

# The matcher's exact operator semantics are the contract the transpiler output
# is validated against. Vendored (byte-faithful copy of the fusion matcher).
from app._vendor.detection_matcher import matches

# Fusion-side API->engine action map, loaded by path (fusion is not on the api
# test path; this mirrors the fusion parity test's _load_canonical()).
_REL = Path(__file__).resolve().parents[2] / "fusion" / "app" / "services" / "detection_reload.py"


def _load_fusion_reload():
    import importlib.util

    spec = importlib.util.spec_from_file_location("aisoc_detection_reload", _REL)
    assert spec and spec.loader, f"cannot load {_REL}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --- rule bodies --------------------------------------------------------------

INLIST_BODY = """
detection:
    selection:
        image_basename:
            - regsvr32.exe
            - mshta.exe
    condition: selection
"""

WILDCARD_BODY = """
detection:
    sel:
        commandline: '*powershell*'
    condition: sel
"""

# Selection and filter use *distinct* fields so the negation is exercised
# meaningfully: image must be regsvr32.exe AND user must not be ADMIN/SYSTEM.
FILTER_BODY = """
detection:
    selection:
        image_basename:
            - regsvr32.exe
    filter:
        user:
            - ADMIN
            - SYSTEM
    condition: selection and not filter
"""

STATEFUL_BODY = """
detection:
    selection:
        user: SYSTEM
    timeframe: 5m
    condition: selection
"""

PARSE_ERROR_BODY = "this: [is: not: valid: yaml: :"
PLAIN_BODY = "just a plain string"
NO_DETECTION_BODY = "title: x\nlogsource:\n  category: process_creation\n"


@pytest.fixture
def rule():
    """A minimal DetectionRule-shaped object for the compiler functions."""

    def _make(**overrides):
        base = {
            "id": uuid.uuid4(),
            "rule_language": "sigma",
            "rule_body": INLIST_BODY,
            "name": "Test Rule",
            "severity": "medium",
            "status": "testing",
            "category": "cloud",
            "version": 1,
            "compiled_spec": None,
            "compile_status": "pending",
            "compile_error": None,
        }
        base.update(overrides)
        return types.SimpleNamespace(**base)

    return _make


class _FakeRedis:
    """Record published ``(channel, payload)`` pairs for assertions."""

    def __init__(self):
        self.published: list[tuple[str, str]] = []

    async def publish(self, channel: str, message: str) -> None:
        self.published.append((channel, message))


class _FakeDB:
    """Mirror the real async Session: ``add`` is sync, ``commit``/``refresh`` async."""

    def __init__(self):
        self.added = 0
        self.committed = 0

    def add(self, obj) -> None:
        self.added += 1

    async def commit(self) -> None:
        self.committed += 1

    async def refresh(self, obj) -> None:
        pass


async def _awaitable_fake(fake: _FakeRedis):
    return fake


def _patch_redis(monkeypatch, fake: _FakeRedis) -> None:
    """Patch ``_get_redis_client`` so it awaits to a ready fake (see compiler)."""
    monkeypatch.setattr(
        "app.services.detections.compiler._get_redis_client",
        lambda: _awaitable_fake(fake),
    )


# --- Check A: transpiler unit + matcher verdicts ------------------------------

def test_A_inlist_emits_flat_membership_and_verdicts_match():
    result = compile_sigma_to_match_when(INLIST_BODY)
    assert result.status == "compiled"
    # Flat grammar: field suffix + list operand (not a nested {in: [...]} dict).
    assert result.match_when == {"image_basename_in": ["regsvr32.exe", "mshta.exe"]}
    # The emitted grammar is consumed by the vendored matcher with correct verdicts.
    assert matches(result.match_when, {"image_basename": "regsvr32.exe"}) is True
    assert matches(result.match_when, {"image_basename": "explorer.exe"}) is False


def test_A_wildcard_selection_emits_contains_and_verdict_matches():
    result = compile_sigma_to_match_when(WILDCARD_BODY)
    assert result.status == "compiled"
    assert result.match_when == {"command_line_contains": "powershell"}
    assert matches(result.match_when, {"command_line": "powershell.exe"}) is True
    assert matches(result.match_when, {"command_line": "notepad.exe"}) is False


def test_A_filter_emits_all_of_negation_and_verdicts_match():
    result = compile_sigma_to_match_when(FILTER_BODY)
    assert result.status == "compiled"
    assert result.match_when == {
        "all_of": [
            {"image_basename_in": ["regsvr32.exe"]},
            {"user_not_in": ["ADMIN", "SYSTEM"]},
        ]
    }
    # Excluded principals are filtered out; a non-excluded principal with a valid
    # image passes; and an excluded principal is dropped even with a valid image.
    assert matches(result.match_when, {"image_basename": "regsvr32.exe", "user": "LOCAL"}) is True
    assert matches(result.match_when, {"image_basename": "regsvr32.exe", "user": "ADMIN"}) is False
    assert matches(result.match_when, {"image_basename": "regsvr32.exe", "user": "SYSTEM"}) is False
    # A different image fails the selection clause regardless of user.
    assert matches(result.match_when, {"image_basename": "notepad.exe", "user": "LOCAL"}) is False


def test_A_compile_error_statuses_are_reported():
    for body in (PARSE_ERROR_BODY, PLAIN_BODY, NO_DETECTION_BODY):
        result = compile_sigma_to_match_when(body)
        assert result.status == "error"
        assert result.match_when is None
        assert result.error  # a human-readable reason, never a silent None


# --- Check B: stateful isolation ---------------------------------------------

def test_B_stateful_rule_is_unsupported_and_not_compilable():
    result = compile_sigma_to_match_when(STATEFUL_BODY)
    assert result.status == "unsupported_stateful"
    assert result.match_when is None
    assert result.error


# --- Check C: reload-action decision logic -----------------------------------

def test_C_new_active_compilable_rule_broadcasts_enable(rule):
    result = compile_sigma_to_match_when(INLIST_BODY)
    r = rule(status="active")
    action = decide_reload_action(r, result, prev_status=None, prev_body_changed=False)
    assert action == "ENABLE"


def test_C_active_unchanged_rule_broadcasts_nothing(rule):
    result = compile_sigma_to_match_when(INLIST_BODY)
    r = rule(status="active")
    action = decide_reload_action(r, result, prev_status="active", prev_body_changed=False)
    assert action is None


def test_C_active_body_change_broadcasts_upsert(rule):
    result = compile_sigma_to_match_when(INLIST_BODY)
    r = rule(status="active")
    action = decide_reload_action(r, result, prev_status="active", prev_body_changed=True)
    assert action == "UPSERT"


def test_C_testing_rule_never_broadcasts(rule):
    result = compile_sigma_to_match_when(INLIST_BODY)
    r = rule(status="testing")
    action = decide_reload_action(r, result, prev_status=None, prev_body_changed=False)
    assert action is None


def test_C_inactive_rule_that_was_live_broadcasts_disable(rule):
    result = compile_sigma_to_match_when(INLIST_BODY)
    r = rule(status="inactive")
    action = decide_reload_action(r, result, prev_status="active", prev_body_changed=True)
    assert action == "DISABLE"


def test_C_uncompilable_rule_broadcasts_disable_only_if_was_live(rule):
    result = compile_sigma_to_match_when(STATEFUL_BODY)  # unsupported_stateful
    r = rule(status="active")
    # was_active -> it was live in fusion, so remove it
    assert decide_reload_action(r, result, prev_status="active", prev_body_changed=True) == "DISABLE"
    # not previously active -> nothing to remove
    assert decide_reload_action(r, result, prev_status=None, prev_body_changed=False) is None


# --- Check D: compile -> persist -> broadcast + action translation -----------

async def test_D_apply_compile_and_reload_broadcasts_enable_with_shaped_payload(rule, monkeypatch):
    fake_redis = _FakeRedis()
    _patch_redis(monkeypatch, fake_redis)

    r = rule(status="active")
    db = _FakeDB()
    await apply_compile_and_reload(r, db, prev_status=None, prev_body_changed=False)

    assert db.committed == 1  # result persisted on the rule row
    assert len(fake_redis.published) == 1
    channel, raw = fake_redis.published[0]
    assert channel == "rules:reload"
    payload = json.loads(raw)
    assert payload["event_type"] == "RULE_STATE_CHANGED"
    assert payload["action"] == "ENABLE"
    # rule_id is the outer envelope id AND the inner compiled_rule id (guardrail).
    assert payload["rule_id"] == str(r.id)
    assert payload["compiled_rule"]["id"] == str(r.id)
    assert payload["compiled_rule"]["match_when"] == r.compiled_spec
    assert payload["version"] == 1


async def test_D_testing_rule_persists_but_never_broadcasts(rule, monkeypatch):
    fake_redis = _FakeRedis()
    _patch_redis(monkeypatch, fake_redis)

    r = rule(status="testing")
    db = _FakeDB()
    await apply_compile_and_reload(r, db, prev_status=None, prev_body_changed=False)

    assert db.committed == 1
    assert fake_redis.published == []  # nothing observable to fusion


async def test_D_non_sigma_language_never_reaches_reload(rule, monkeypatch):
    fake_redis = _FakeRedis()
    _patch_redis(monkeypatch, fake_redis)

    r = rule(rule_language="kql", rule_body="not sigma")
    db = _FakeDB()
    await apply_compile_and_reload(r, db, prev_status=None, prev_body_changed=False)

    assert db.committed == 0  # non-sigma languages never compile here
    assert fake_redis.published == []


def test_D_broadcast_rule_reload_payload_shape(rule):
    fake_redis = _FakeRedis()
    with unittest.mock.patch(
        "app.services.detections.compiler._get_redis_client",
        new=lambda: _awaitable_fake(fake_redis),
    ):
        asyncio.run(broadcast_rule_reload(rule(id=42, status="active", version=7), "ENABLE"))

    channel, raw = fake_redis.published[0]
    assert channel == "rules:reload"
    payload = json.loads(raw)
    assert payload["action"] == "ENABLE"
    # id is passed through str()-ed; a plain int survives the same cast path.
    assert payload["rule_id"] == str(rule(id=42, status="active", version=7).id)
    assert payload["version"] == 7


def test_D_fusion_action_map_translates_api_actions():
    reload = _load_fusion_reload()
    assert reload._map_action("ENABLE") == "CREATE"
    assert reload._map_action("UPSERT") == "UPDATE"
    assert reload._map_action("DISABLE") == "DISABLE"
    with pytest.raises(ValueError):
        reload._map_action("NOPE")
