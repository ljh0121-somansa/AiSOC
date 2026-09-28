"""Tests for scheduler and connector repo resilience against corrupted connector_config."""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from app.db.connector_repo import ConnectorInstance, normalize_config
from app.scheduler import _coerce_poll_interval


def test_normalize_config_dict():
    cfg = {"base_url": "https://test:8089", "poll_interval_seconds": 300}
    assert normalize_config(cfg) == cfg


def test_normalize_config_list_of_dicts():
    cfg_list = [
        {"base_url": "https://test:8089"},
        {"poll_interval_seconds": 60, "checkpoint": {"time": "2026-09-28T00:00:00Z"}},
    ]
    res = normalize_config(cfg_list)
    assert res["base_url"] == "https://test:8089"
    assert res["poll_interval_seconds"] == 60
    assert res["checkpoint"] == {"time": "2026-09-28T00:00:00Z"}


def test_normalize_config_list_with_json_strings():
    # Simulates corrupted PostgreSQL concatenation: [dict, json_string]
    cfg_list = [
        {"base_url": "https://test:8089", "page_size": 500},
        json.dumps({"checkpoint": {"time": "2026-09-28T09:00:00Z", "id": "123"}}),
    ]
    res = normalize_config(cfg_list)
    assert res["base_url"] == "https://test:8089"
    assert res["page_size"] == 500
    assert res["checkpoint"] == {"time": "2026-09-28T09:00:00Z", "id": "123"}


def test_normalize_config_empty_or_primitive():
    assert normalize_config([]) == {}
    assert normalize_config(None) == {}
    assert normalize_config("string") == {}
    assert normalize_config(123) == {}
    assert normalize_config(True) == {}


def test_coerce_poll_interval_with_various_types():
    assert _coerce_poll_interval({"poll_interval_seconds": 60}) == 60
    assert _coerce_poll_interval({"poll_interval_seconds": "120"}) == 120
    assert _coerce_poll_interval({"poll_interval_seconds": "invalid"}) == 300
    # List instead of dict: should rescue or default to 300
    assert _coerce_poll_interval([{"poll_interval_seconds": 45}]) == 45
    assert _coerce_poll_interval([]) == 300
    assert _coerce_poll_interval(None) == 300
    assert _coerce_poll_interval("not_a_dict") == 300
