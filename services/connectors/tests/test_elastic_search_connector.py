"""
Unit tests for ``ElasticSearchConnector.normalize()``.

The Elastic SIEM connector ingests telemetry that is frequently *nested*
(``source.ip``, ``destination.port``, ``event.action`` ...), but the AiSOC
detection matcher only sees flat top-level keys. ``normalize()`` must therefore
re-key nested ECS sub-objects into flat alert fields while still falling back
to a flat dotted key when a deployment already emits a flat shape.

This test exercises ``normalize()`` directly -- it does not import ``respx`` or
talk to a live cluster -- so it runs even in environments where the broader
connector suite is not collectable.
"""

from __future__ import annotations

from app.connectors.elastic_search import ElasticSearchConnector


def _connector(index: str = "firewall-logs") -> ElasticSearchConnector:
    return ElasticSearchConnector(
        base_url="https://elastic.test.local",
        api_key="elastic-api-key",
        index=index,
    )


def test_requires_authentication():
    assert ElasticSearchConnector(base_url="https://elastic.test.local", api_key="k").connector_id == "elastic_search"
    try:
        ElasticSearchConnector(base_url="https://elastic.test.local")
    except ValueError:
        pass
    else:
        assert False, "expected ValueError without api_key or username+password"


# ---------------------------------------------------------------------------
# Nested ECS payload -> flat top-level alert fields
# ---------------------------------------------------------------------------


def test_normalize_flattens_nested_ecs_subobjects():
    raw = {
        "@timestamp": "2026-09-11T01:00:00Z",
        "message": "brute force detected",
        "event": {
            "id": "evt-01",
            "action": "authentication",
            "dataset": "sidewinder",
            "severity_label": "high",
            "risk_score": 7.5,
        },
        "source": {"ip": "10.1.1.5", "country_iso_code": "US"},
        "destination": {"ip": "10.1.1.9", "port": 22},
        "network": {"transport": "TCP"},
        "rule": {"id": "rule-42", "name": "Brute force"},
        "host": {"name": "dc01"},
    }
    out = _connector().normalize(raw)

    # Top-level identifiers flattened from nested sub-objects.
    assert out["external_id"] == "evt-01"
    assert out["src_ip"] == "10.1.1.5"
    assert out["dst_ip"] == "10.1.1.9"
    assert out["dst_port"] == 22
    assert out["hostname"] == "dc01"
    assert out["rule_id"] == "rule-42"
    assert out["event_action"] == "authentication"
    assert out["event_dataset"] == "sidewinder"
    assert out["src_geo"] == "US"
    assert out["severity"] == "high"
    assert out["risk_score"] == 7.5


# ---------------------------------------------------------------------------
# Flat-dotted fallback -> a deployment that already emits flat keys
# ---------------------------------------------------------------------------


def test_normalize_falls_back_to_flat_dotted_keys():
    raw = {
        "level": "warn",
        "message": "port scan",
        "log.original": "nmap scan from 10.9.9.9",
        "source.ip": "10.9.9.9",
        "event.action": "scan",
    }
    out = _connector().normalize(raw)

    # source.ip was NOT re-keyed (no nested `source` object), so it must be read
    # from the flat dotted key as documented.
    assert out["src_ip"] == "10.9.9.9"
    assert out["event_action"] == "scan"
    assert out["severity"] == "medium"


# ---------------------------------------------------------------------------
# severity mapping
# ---------------------------------------------------------------------------


def test_normalize_maps_high_severity():
    out = _connector().normalize(
        {
            "event": {"severity_label": "crit"},
            "source": {"ip": "10.0.0.1"},
        }
    )
    assert out["severity"] == "critical"


def test_normalize_defaults_unknown_severity_to_medium():
    out = _connector().normalize(
        {
            "event": {"severity_label": "mystery"},
            "source": {"ip": "10.0.0.1"},
        }
    )
    assert out["severity"] == "medium"


def test_publishes_event_type_outcome_user_for_windowed_rules():
    # Windowed detection rules (brute-force, spray, port-scan) key on these
    # top-level keys, so the connector must emit them even when the raw payload
    # lacks an explicit event_type.
    out = _connector().normalize(
        {
            "event": {
                "category": "firewall",
                "action": "drop",
                "outcome": "success",
            },
            "source": {"ip": "10.1.1.5"},
            "destination": {"ip": "10.1.1.9", "port": 22},
        }
    )
    assert out["event_type"] == "network"
    assert out["outcome"] == "success"
    assert out["user"] is None
