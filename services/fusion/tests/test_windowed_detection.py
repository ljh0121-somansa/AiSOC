"""Wave 2 — cardinality gates + firewall-abuse rule.

Verifies the three-way distinction the ruleset must make:
  * a single-port SSH drop flood must NOT be labelled a port scan,
  * a multi-port sweep from one src_ip still fires port scan,
  * a single-port SSH drop flood fires wd-firewall-ssh-abuse, and
  * replaying the real fail2ban traffic emits exactly one alert (ssh-abuse).
"""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from app.services.windowed_detection import WindowedDetectionEngine


class _FakeRedis:
    """Minimal in-memory Redis for the sorted-set window + fired marker."""

    def __init__(self) -> None:
        self.zsets: dict[str, dict[str, float]] = {}
        self.strings: dict[str, str] = {}

    async def zadd(self, key: str, mapping: dict[str, float]) -> None:
        self.zsets.setdefault(key, {}).update(mapping)

    async def zremrangebyscore(self, key: str, min_s: float, max_s: float) -> None:
        z = self.zsets.get(key, {})
        for m in [m for m, s in list(z.items()) if min_s <= s <= max_s]:
            del z[m]

    async def expire(self, key: str, ttl: int) -> None:
        return None

    async def zcard(self, key: str) -> int:
        return len(self.zsets.get(key, {}))

    async def set(self, key: str, value: str, nx: bool = False, ex: int | None = None):
        if nx and key in self.strings:
            return None
        self.strings[key] = value
        return True


def _auth_fail_event(tenant: str, user: str = "alice", src: str = "1.2.3.4") -> dict:
    return {
        "tenant_id": tenant,
        "ocsf_event": {
            "tenant_uid": tenant,
            "raw_data": json.dumps({"event_type": "authentication", "outcome": "failure", "user": user, "src_ip": src}),
        },
    }


def _firewall_drop_event(tenant: str, *, src_ip: str, dst_port: int,
                         action: str = "drop", event_type: str = "network") -> dict:
    return {
        "tenant_id": tenant,
        "ocsf_event": {
            "tenant_uid": tenant,
            "raw_data": json.dumps({
                "event_type": event_type,
                "event_action": action,
                "dst_port": dst_port,
                "src_ip": src_ip,
            }),
        },
    }


@pytest.mark.asyncio
async def test_single_ssh_flood_is_not_port_scan():
    """Repeated drops on a single dst_port never reach the scan cardinality gate."""
    eng = WindowedDetectionEngine(_FakeRedis())
    tenant = str(uuid4())
    for _ in range(60):
        hits = await eng.evaluate(_firewall_drop_event(tenant, src_ip="45.133.1.40", dst_port=22))
        assert not any(h.rule_id == "wd-port-scan" for h in hits), "single-port flood mislabelled as scan"

    # A fresh engine (no fired-markers): the exact fail2ban traffic must fire
    # ssh-abuse, not port-scan.
    eng2 = WindowedDetectionEngine(_FakeRedis())
    fired = None
    for _ in range(40):
        for h in await eng2.evaluate(_firewall_drop_event(tenant, src_ip="45.133.1.40", dst_port=22)):
            fired = h.rule_id
    assert fired == "wd-firewall-ssh-abuse"


@pytest.mark.asyncio
async def test_multi_port_sweep_still_fires_port_scan():
    """A sweep across many distinct dst_ports from one src_ip must fire port scan."""
    eng = WindowedDetectionEngine(_FakeRedis())
    tenant = str(uuid4())
    hits: list[None] = []
    # One event per distinct port: once we hit 50 events we also have 50 distinct
    # ports (>= 15), so the cardinality gate is satisfied.
    for port in range(1, 51):
        hits = await eng.evaluate(
            _firewall_drop_event(tenant, src_ip="10.0.0.1", dst_port=port),
        )
    assert any(h.rule_id == "wd-port-scan" for h in hits)
    assert not any(h.rule_id == "wd-firewall-ssh-abuse" for h in hits)


@pytest.mark.asyncio
async def test_firewall_ssh_abuse_fires():
    """A sustained single-port SSH drop flood fires wd-firewall-ssh-abuse."""
    eng = WindowedDetectionEngine(_FakeRedis())
    tenant = str(uuid4())
    # Below threshold: 29 drops, no fire.
    for _ in range(29):
        assert not any(
            h.rule_id == "wd-firewall-ssh-abuse"
            for h in await eng.evaluate(_firewall_drop_event(tenant, src_ip="45.133.1.40", dst_port=22))
        )
    # 30th crosses the threshold and fires.
    hits = await eng.evaluate(_firewall_drop_event(tenant, src_ip="45.133.1.40", dst_port=22))
    assert any(h.rule_id == "wd-firewall-ssh-abuse" for h in hits)
    alert = eng.build_alert(
        _firewall_drop_event(tenant, src_ip="45.133.1.40", dst_port=22), hits[0]
    )
    assert alert is not None
    assert "45.133.1.40" in alert.description
    assert "22" in alert.description
    assert "wd-firewall-ssh-abuse" in alert.title or "ssh" in alert.title.lower()


@pytest.mark.asyncio
async def test_firewall_ssh_abuse_single_fire_per_window():
    """A sustained single-port SSH drop flood fires once; more events re-saturate the window."""
    eng = WindowedDetectionEngine(_FakeRedis())
    tenant = str(uuid4())
    fired = False
    for _ in range(40):
        hits = await eng.evaluate(_firewall_drop_event(tenant, src_ip="45.133.1.40", dst_port=22))
        if any(h.rule_id == "wd-firewall-ssh-abuse" for h in hits):
            assert not fired, "fired more than once within the window"
            fired = True
    assert fired, "ssh-abuse rule never fired"


@pytest.mark.asyncio
async def test_bruteforce_fires_at_threshold_once():
    eng = WindowedDetectionEngine(_FakeRedis())
    tenant = str(uuid4())

    # First 4 failures: below the threshold of 5 -> no brute-force hit.
    for i in range(4):
        hits = await eng.evaluate(_auth_fail_event(tenant))
        assert not any(h.rule_id == "wd-bruteforce-auth" for h in hits), f"fired early on attempt {i + 1}"

    # 5th crosses the threshold.
    hits = await eng.evaluate(_auth_fail_event(tenant))
    assert any(h.rule_id == "wd-bruteforce-auth" for h in hits)

    # 6th within the same window must NOT re-fire (fired-marker suppresses).
    hits6 = await eng.evaluate(_auth_fail_event(tenant))
    assert not any(h.rule_id == "wd-bruteforce-auth" for h in hits6)


@pytest.mark.asyncio
async def test_group_by_isolates_entities():
    eng = WindowedDetectionEngine(_FakeRedis())
    tenant = str(uuid4())
    # 4 failures for alice + 4 for bob: neither user reaches the per-user threshold.
    for _ in range(4):
        await eng.evaluate(_auth_fail_event(tenant, user="alice"))
    for _ in range(4):
        hits = await eng.evaluate(_auth_fail_event(tenant, user="bob"))
    assert not any(h.rule_id == "wd-bruteforce-auth" for h in hits)


@pytest.mark.asyncio
async def test_non_matching_event_never_fires():
    eng = WindowedDetectionEngine(_FakeRedis())
    tenant = str(uuid4())
    benign = {"tenant_id": tenant, "ocsf_event": {"raw_data": json.dumps({"event_type": "process", "user": "alice"})}}
    for _ in range(20):
        hits = await eng.evaluate(benign)
    assert hits == []


@pytest.mark.asyncio
async def test_build_alert_from_hit():
    eng = WindowedDetectionEngine(_FakeRedis())
    tenant = str(uuid4())
    hit = None
    for _ in range(5):
        for h in await eng.evaluate(_auth_fail_event(tenant)):
            hit = h
    assert hit is not None
    alert = eng.build_alert(_auth_fail_event(tenant), hit)
    assert alert is not None
    assert alert.source == "detection:wd-bruteforce-auth"
    assert alert.username == "alice"
