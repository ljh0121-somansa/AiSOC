"""
EdrClient: Async HTTP client for EdrServer REST API v2.
Handles bearer auth, custom headers, schema-negotiated endpoints,
fail-closed error handling (401/403) and 429/503 exponential backoff.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()


class EdrClientError(Exception):
    """Base exception for EDR client errors."""


class EdrPermissionDeniedError(EdrClientError):
    """Raised when EdrServer returns 401 or 403."""


class EdrServerUnavailableError(EdrClientError):
    """Raised when EdrServer returns 429 or 503 repeatedly."""

class EdrApiError(EdrClientError):
    """Structured error from an EdrServer error body (spec §7).

    Carries the parsed ``error.code``, ``retryable``, ``details``,
    ``request_id`` and ``Retry-After`` header. A ``code=None`` means the
    body was not in the documented shape; callers must treat the call as
    "incomplete", never "unavailable" (spec §5).
    """

    def __init__(
        self,
        status: int,
        code: str | None,
        message: str,
        retryable: bool,
        details: dict[str, Any] | None,
        request_id: str | None,
        retry_after: str | None,
    ) -> None:
        self.status = status
        self.code = code
        self.message = message
        self.retryable = retryable
        self.details = details
        self.request_id = request_id
        self.retry_after = retry_after
        super().__init__(f"EDR API error ({status}) code={code} {message[:120]}")


def parse_edr_error_body(body: str, status: int, retry_after: str | None = None) -> EdrApiError:
    """Parse an EdrServer error body (``{"error": {code,message,retryable,details}, "request_id"}``).

    Unparseable or non-dict bodies yield ``code=None`` with the raw body
    prefix as the message — callers must treat that as incomplete.
    """
    code: str | None = None
    message = ""
    retryable = False
    details: dict[str, Any] | None = None
    request_id: str | None = None

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        data = None

    if isinstance(data, dict):
        error = data.get("error")
        if isinstance(error, dict):
            raw_code = error.get("code")
            code = str(raw_code) if raw_code is not None else None
            raw_msg = error.get("message")
            message = str(raw_msg) if raw_msg is not None else ""
            raw_retryable = error.get("retryable")
            retryable = raw_retryable is True
            raw_details = error.get("details")

            if isinstance(raw_details, dict):
                details = raw_details
        elif error is not None:
            message = body[:200]
        raw_request_id = data.get("request_id")
        if raw_request_id is not None:
            request_id = str(raw_request_id)

    if not message:
        message = body[:200]

    return EdrApiError(status, code, message, retryable, details, request_id, retry_after)


class EdrClient:
    """Async client interacting with EdrServer v2 API."""

    def __init__(
        self,
        base_url: str | None = None,
        api_token: str | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        self.base_url = (base_url or os.getenv("EDR_SERVER_BASE_URL", "http://127.0.0.1:7601")).rstrip("/")
        self.api_token = api_token or os.getenv("EDR_SERVER_API_TOKEN", "")
        self.timeout = timeout
        self.max_retries = max_retries

    def _default_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
        }

        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"

        return headers

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        url = f"{self.base_url}/api/v2/ai-soc{path}" if not path.startswith("/api/v2/ai-soc") else f"{self.base_url}{path}"
        req_headers = self._default_headers()
        if headers:
            req_headers.update(headers)

        attempt = 0
        backoff_delay = 0.1

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            while True:
                attempt += 1
                try:
                    resp = await client.request(
                        method=method,
                        url=url,
                        params=params,
                        json=json_data,
                        headers=req_headers,
                    )
                except httpx.RequestError as exc:
                    if attempt >= self.max_retries:
                        raise EdrServerUnavailableError(f"EDR server unreachable: {exc}") from exc

                    await asyncio.sleep(backoff_delay)
                    backoff_delay *= 2
                    continue

                if resp.status_code in (401, 403):
                    raise EdrPermissionDeniedError(f"EDR permission denied ({resp.status_code}): {resp.text}")

                if resp.status_code in (429, 503):
                    if attempt >= self.max_retries:
                        raise EdrServerUnavailableError(f"EDR server unavailable ({resp.status_code}) after {attempt} attempts")

                    retry_after = resp.headers.get("Retry-After")
                    delay = float(retry_after) if retry_after and retry_after.replace(".", "", 1).isdigit() else backoff_delay
                    await asyncio.sleep(delay)
                    backoff_delay *= 2
                    continue

                if resp.is_error:
                    raise EdrClientError(f"EDR request failed ({resp.status_code}): {resp.text}")

                return resp.json()

    async def get_capabilities(self) -> dict[str, Any]:
        return await self._request("GET", "/capabilities")

    async def get_schema(self, profile: str = "ecs-json-v1") -> dict[str, Any]:
        headers = {"Accept": "application/schema+json"}
        return await self._request("GET", "/schema", params={"profile": profile}, headers=headers)

    async def get_detection(self, source_kind: str, event_id: str) -> dict[str, Any]:
        return await self._request("GET", f"/detections/{source_kind}/{event_id}")

    async def fetch_timeline(
        self,
        computer_name: str,
        from_ts: str | None = None,
        to_ts: str | None = None,
        cursor: str | None = None,
        max_events: int = 1000,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"computer_name": computer_name, "max_events": max_events}
        if from_ts:
            params["from"] = from_ts
        if to_ts:
            params["to"] = to_ts
        if cursor:
            params["cursor"] = cursor

        return await self._request("GET", "/timeline", params=params)

    async def search_events(
        self,
        query: str,
        from_ts: str | None = None,
        to_ts: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"query": query, "limit": limit}
        if from_ts:
            params["from"] = from_ts
        if to_ts:
            params["to"] = to_ts

        return await self._request("GET", "/events/search", params=params)

    async def lookup_process(self, entity_id: str) -> dict[str, Any]:
        return await self._request("GET", f"/processes/{entity_id}")

    async def check_ingress(self, computer_name: str, sha256: str) -> dict[str, Any]:
        params = {"computer_name": computer_name, "sha256": sha256}
        return await self._request("GET", "/files/ingress", params=params)

    async def host_inventory(self, computer_name: str) -> dict[str, Any]:
        params = {"computer_name": computer_name}
        return await self._request("GET", "/hosts/inventory", params=params)

    async def put_disposition(
        self,
        source_kind: str,
        event_id: str,
        disposition: str,
        confidence: float = 1.0,
        comment: str = "",
        reason: str = "",
        analyst: str = "aisoc-agent",
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        key = idempotency_key or str(uuid.uuid4())
        headers = {"Idempotency-Key": key}
        body = {
            "disposition": disposition,
            "confidence": confidence,
            "comment": comment,
            "reason": reason,
            "analyst": analyst,
        }

        return await self._request(
            "PUT",
            f"/detections/{source_kind}/{event_id}/disposition",
            json_data=body,
            headers=headers,
        )
