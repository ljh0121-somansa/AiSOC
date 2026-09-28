"""Tests for AlertDetailResponse including raw_event preservation."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints.alerts import AlertDetailResponse, AlertResponse


def _make_alert_mock(**kwargs):
    now = datetime.now(UTC)
    defaults = {
        "id": uuid.uuid4(),
        "tenant_id": uuid.uuid4(),
        "title": "Malware URL 접속 탐지",
        "description": "Suspicious URL access detected",
        "severity": "high",
        "status": "new",
        "priority": 50,
        "category": "malware",
        "mitre_tactics": ["Command and Control"],
        "mitre_techniques": ["T1071"],
        "connector_type": "splunk",
        "ai_score": 0.85,
        "ai_summary": "High confidence threat",
        "ai_recommendations": [],
        "confidence": 85,
        "confidence_label": "high",
        "confidence_rationale": [],
        "disposition": None,
        "affected_ips": ["10.220.129.29"],
        "affected_hosts": ["DESKTOP-TEST"],
        "affected_users": ["user1"],
        "case_id": None,
        "tags": ["splunk", "malware"],
        "event_time": now,
        "first_seen": now,
        "last_seen": now,
        "snoozed_until": None,
        "snoozed_by_id": None,
        "created_at": now,
        "updated_at": now,
        "raw_event": {"event_id": "123", "src": "10.220.129.29", "_raw": "threat detected"},
        "narrative": "Correlation narrative text",
        "related_entities": [],
        "mini_timeline": [],
        "recommended_actions": [],
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_alert_detail_response_includes_raw_event():
    alert = _make_alert_mock(raw_event={"key": "value", "count": 42})
    detail = AlertDetailResponse.model_validate(alert)
    assert detail.raw_event == {"key": "value", "count": 42}
    dumped = detail.model_dump()
    assert "raw_event" in dumped
    assert dumped["raw_event"] == {"key": "value", "count": 42}


def test_alert_detail_response_allows_none_raw_event():
    alert = _make_alert_mock(raw_event=None)
    detail = AlertDetailResponse.model_validate(alert)
    assert detail.raw_event is None
    dumped = detail.model_dump()
    assert dumped.get("raw_event") is None


def test_alert_list_response_excludes_raw_event_for_light_payload():
    alert = _make_alert_mock(raw_event={"large": "payload" * 100})
    list_resp = AlertResponse.model_validate(alert)
    dumped = list_resp.model_dump()
    assert "raw_event" not in dumped
