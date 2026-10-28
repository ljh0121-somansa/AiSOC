"""U1: EdrApiError and EdrServer error-body parsing (connector-side copy, spec §7)."""
from __future__ import annotations

import json

from app.connectors.edrserver import (
    EdrApiError,
    parse_edr_error_body,
)


def test_parse_error_body_preserves_fields():
    body = json.dumps(
        {
            "error": {
                "code": "feature_disabled",
                "message": "Feature 'graph' is disabled for static source",
                "retryable": False,
                "details": {"feature": "graph", "source": "static"},
            },
            "request_id": "req-9f3c",
        }
    )
    err = parse_edr_error_body(body, 404, "3")
    assert isinstance(err, EdrApiError)
    assert err.status == 404
    assert err.code == "feature_disabled"
    assert err.message == "Feature 'graph' is disabled for static source"
    assert err.retryable is False
    assert err.details == {"feature": "graph", "source": "static"}
    assert err.request_id == "req-9f3c"
    assert err.retry_after == "3"


def test_parse_retryable_body():
    body = json.dumps(
        {
            "error": {"code": "rate_limit_exceeded", "message": "Too many requests", "retryable": True},
            "request_id": "req-42",
        }
    )
    err = parse_edr_error_body(body, 429, "5")
    assert err.code == "rate_limit_exceeded"
    assert err.retryable is True
    assert err.retry_after == "5"


def test_parse_unparseable_body_falls_back_to_incomplete():
    body = "<html><body>504 Gateway Time-out</body></html>"
    err = parse_edr_error_body(body, 504)
    assert err.code is None
    assert err.retryable is False
    assert err.request_id is None
    assert err.message == body[:200]


def test_parse_string_error_body_code_none():
    body = json.dumps({"error": "unauthorized"})
    err = parse_edr_error_body(body, 401)
    assert err.code is None
    assert err.message == body[:200]
    assert isinstance(err, Exception)


def test_404_codes_are_distinguishable():
    not_found = parse_edr_error_body(json.dumps({"error": {"code": "not_found"}, "request_id": "r-1"}), 404)
    feature_disabled = parse_edr_error_body(json.dumps({"error": {"code": "feature_disabled"}}), 404)
    assert not_found.code == "not_found"
    assert feature_disabled.code == "feature_disabled"


def test_400_unsupported_source_vs_bad_request():
    unsupported = parse_edr_error_body(
        json.dumps({"error": {"code": "unsupported_source", "message": "static source does not support this endpoint"}}), 400)
    bad = parse_edr_error_body(json.dumps({"error": {"code": "invalid_param", "message": "bad param"}}), 400)
    assert unsupported.code == "unsupported_source"
    assert bad.code == "invalid_param"
