"""U1: EdrApiError and EdrServer error-body parsing (spec §7, §5 "unavailable" rule)."""
from __future__ import annotations

import json

from app.edr.client import (
    EdrApiError,
    EdrClientError,
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
    # Spec §5: unparseable body -> code=None + raw-body prefix as message ("incomplete" handling)
    body = "<html><body>504 Gateway Time-out</body></html>"
    err = parse_edr_error_body(body, 504)
    assert err.code is None
    assert err.retryable is False
    assert err.request_id is None
    assert err.message == body[:200]


def test_parse_string_error_body_code_none():
    # Legacy shape {"error": "unauthorized"}: error is a string, not a dict
    body = json.dumps({"error": "unauthorized"})
    err = parse_edr_error_body(body, 401)
    assert err.code is None
    assert err.message == body[:200]
    assert isinstance(err, EdrClientError)


def test_404_codes_are_distinguishable():
    # Spec §5: bare 404 is NOT "unavailable" — error.code must distinguish not_found vs feature_disabled
    not_found = parse_edr_error_body(json.dumps({"error": {"code": "not_found"}, "request_id": "r-1"}), 404)
    feature_disabled = parse_edr_error_body(json.dumps({"error": {"code": "feature_disabled"}}), 404)
    assert not_found.code == "not_found"
    assert feature_disabled.code == "feature_disabled"


def test_400_unsupported_source_vs_bad_request():
    # Spec §5: only 400 + unsupported_source is "unavailable"; other 400s are incomplete(bad_request)
    unsupported = parse_edr_error_body(
        json.dumps({"error": {"code": "unsupported_source", "message": "static source does not support this endpoint"}}), 400)
    bad = parse_edr_error_body(json.dumps({"error": {"code": "invalid_param", "message": "bad param"}}), 400)
    assert unsupported.code == "unsupported_source"
    assert bad.code == "invalid_param"


def test_edr_api_error_is_client_error_subclass():
    # Existing EdrClientError-based catch blocks keep working
    err = parse_edr_error_body(json.dumps({"error": {"code": "not_found"}}), 404)
    assert isinstance(err, EdrClientError)
    assert "404" in str(err)
