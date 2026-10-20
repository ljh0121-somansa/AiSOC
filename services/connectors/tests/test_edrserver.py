"""
Tests for the EdrServerConnector implementation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import respx

from app.connectors.edrserver import EdrServerConnector

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "edrserver"


def load_fixture(name: str) -> dict[str, Any]:
    p = FIXTURE_DIR / name
    return json.loads(p.read_text(encoding="utf-8"))


def test_edrserver_schema_and_test_connection_sync():
    schema = EdrServerConnector.schema()
    assert schema.connector_id == "edrserver"
    assert schema.category == "edr"
    field_names = [f.name for f in schema.fields]
    assert "base_url" in field_names
    assert "token" in field_names
    assert "verify_tls" in field_names


@pytest.mark.asyncio
async def test_edrserver_test_connection_success():
    connector = EdrServerConnector(base_url="https://edrserver.internal:7601", token="aisoc.id.secret")
    with respx.mock(base_url="https://edrserver.internal:7601") as respx_mock:
        respx_mock.get("/api/v2/ai-soc/capabilities").respond(
            200, json={"api_version": "2.0.0", "scopes": ["ai-soc.detection.read"]}
        )
        res = await connector.test_connection()
        assert res["success"] is True
        assert res["authenticated"] is True
        assert res["api_version"] == "2.0.0"


@pytest.mark.asyncio
async def test_edrserver_test_connection_auth_error():
    connector = EdrServerConnector(base_url="https://edrserver.internal:7601", token="bad-token")
    with respx.mock(base_url="https://edrserver.internal:7601") as respx_mock:
        respx_mock.get("/api/v2/ai-soc/capabilities").respond(401, json={"error": {"code": "invalid_token"}})
        res = await connector.test_connection()
        assert res["success"] is False
        assert res["error"] == "AUTH_INVALID_TOKEN"


@pytest.mark.asyncio
async def test_edrserver_checkpoint_and_window():
    connector = EdrServerConnector(base_url="https://edrserver.internal:7601", token="aisoc.id.secret")
    # Test checkpoint set & get
    assert connector.get_checkpoint() is None
    connector.set_checkpoint({"time": "2026-10-20T00:00:00Z"})
    assert connector._checkpoint is not None

    # Test window calculation
    start, end = connector._calculate_window(since_seconds=300)
    assert start < end


@pytest.mark.asyncio
async def test_edrserver_fetch_alerts_happy_path():
    connector = EdrServerConnector(base_url="https://edrserver.internal:7601", token="aisoc.id.secret")
    list_data = load_fixture("detection-list.json")
    detail_data = load_fixture("detection-detail.json")

    with respx.mock(base_url="https://edrserver.internal:7601") as respx_mock:
        respx_mock.get("/api/v2/ai-soc/detections").respond(200, json=list_data)
        respx_mock.get("/api/v2/ai-soc/detections/dynamic/det-001").respond(200, json=detail_data)

        alerts = await connector.fetch_alerts(since_seconds=300)
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert["source"] == "edrserver"
        assert alert["external_id"] == "dynamic:det-001"
        assert alert["enrichment_status"] == "complete"
        assert alert["host_ip"] == "10.0.0.1"
        assert alert["src_ip"] == "10.0.0.1"
        assert alert["hostname"] == "host-01"
        assert alert["actor"] == "user01"
        assert isinstance(alert["mitre_techniques"], list)
        assert "T1059" in alert["mitre_techniques"]
        assert alert["mitre_available"] is True
        assert connector.get_checkpoint() is not None
