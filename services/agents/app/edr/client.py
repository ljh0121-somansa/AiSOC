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
                    raise parse_edr_error_body(resp.text, resp.status_code, resp.headers.get("Retry-After"))

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

    # --- Case-investigation methods (plan U2, spec §5 stages 0-5, §7) ---
    # Distinct names; existing fetch_timeline / search_events / host_inventory
    # and their callers are untouched. get_capabilities is reused as-is.

    async def fetch_detection_detail(
        self, source_kind: str, event_id: str, lookup_hint: str | None = None
    ) -> dict[str, Any]:
        """GET /detections/{source_kind}/{event_id} (spec §5 stage 2).

        Error bodies are parsed into EdrApiError so callers can distinguish
        error.code = not_found (incomplete) vs feature_disabled (unavailable).
        """
        params: dict[str, Any] = {}
        if lookup_hint is not None:
            params["lookup_hint"] = lookup_hint

        return await self._request("GET", f"/detections/{source_kind}/{event_id}", params=params or None)

    async def fetch_case_timeline(
        self,
        source_kind: str,
        event_id: str,
        *,
        before: str = "PT10M",
        after: str = "PT5M",
        categories: list[str] | None = None,
        action_types: list[int] | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """GET /investigations/{source_kind}/{event_id}/timeline (spec §5 stage 3).

        static source_kind is not supported: skip the call and report
        unavailable (spec §5 "unavailable" strict rule — pre-decision, no HTTP
        call is made, so no error code is needed).
        """
        if source_kind == "static":
            return {"status": "unavailable", "reason_code": "timeline_unavailable(static)"}

        params: dict[str, Any] = {"before": before, "after": after, "limit": limit}
        if categories:
            params["categories"] = ",".join(categories)
        if action_types:
            params["action_types"] = ",".join(str(a) for a in action_types)

        return await self._request(
            "GET", f"/investigations/{source_kind}/{event_id}/timeline", params=params
        )

    async def fetch_case_graph(
        self,
        source_kind: str,
        event_id: str,
        *,
        before: str = "PT10M",
        after: str = "PT5M",
        ancestor_depth: int = 2,
        descendant_depth: int = 1,
        max_nodes: int = 200,
    ) -> dict[str, Any]:
        """GET /investigations/{source_kind}/{event_id}/graph (spec §5 stage 4).

        static: skip and report unavailable. When the response is truncated,
        retry once with max_nodes raised to 500 (spec "graph truncated retry");
        if still truncated the caller records incomplete(graph_truncated).
        """
        if source_kind == "static":
            return {"status": "unavailable", "reason_code": "graph_unavailable(static)"}

        params: dict[str, Any] = {
            "before": before,
            "after": after,
            "ancestor_depth": ancestor_depth,
            "descendant_depth": descendant_depth,
            "max_nodes": max_nodes,
        }
        path = f"/investigations/{source_kind}/{event_id}/graph"
        data = await self._request("GET", path, params=params)
        if data.get("truncated"):
            params["max_nodes"] = 500
            data = await self._request("GET", path, params=params)

        return data

    async def host_inventory_by_agent(self, agent_id: str) -> dict[str, Any]:
        """GET /hosts/{agent_id} (spec §5 stage 5)."""
        return await self._request("GET", f"/hosts/{agent_id}")

    async def hunt(
        self,
        from_ts: str,
        to_ts: str,
        observables: list[dict[str, str]],
        sources: list[str] | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """POST /hunt (spec §5 stage 6): do the same hash/IP/URL
        re-appear on other hosts/users? Exact-match observables only;
        chunking (20 per call, max 3 calls/case) is the caller's job (U8)."""
        body: dict[str, Any] = {"from": from_ts, "to": to_ts, "observables": observables, "limit": limit}
        if sources:
            body["sources"] = sources
        return await self._request("POST", "/hunt", json_data=body)

    async def search_case_events(
        self,
        from_ts: str,
        to_ts: str,
        *,
        categories: list[str] | None = None,
        action_types: list[int] | None = None,
        observables: list[dict[str, str]] | None = None,
        file_paths: list[str] | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """POST /events/search (spec §5 stage 9, case-investigation variant).
        Distinct from the legacy GET ``search_events`` (single ``query`` param),
        which is left untouched. Filtered values <= 100, page <= 500 are
        enforced by the caller (U8); unfiltered broad searches stay <= 60 min."""
        body: dict[str, Any] = {"from": from_ts, "to": to_ts, "limit": limit}
        if categories:
            body["categories"] = categories
        if action_types:
            body["action_types"] = action_types
        if observables:
            body["observables"] = observables
        if file_paths:
            body["file_paths"] = file_paths
        return await self._request("POST", "/events/search", json_data=body)

    async def check_file_ingress(
        self,
        from_ts: str,
        to_ts: str,
        sha256: str,
        *,
        host_names: list[str] | None = None,
        before: str = "PT10M",
        after: str = "PT5M",
        max_process_hops: int = 2,
        max_evidence: int = 200,
    ) -> dict[str, Any]:
        """POST /investigations/file-ingress (spec §5 stage 7). ``observed`` is
        confirmed, ``inferred`` stays a candidate (never a definitive answer);
        hops <= 2, evidence <= 200, query count <= 32 (U8 enforces)."""
        body: dict[str, Any] = {
            "from": from_ts,
            "to": to_ts,
            "sha256": sha256,
            "before": before,
            "after": after,
            "max_process_hops": max_process_hops,
            "max_evidence": max_evidence,
        }
        if host_names:
            body["host_names"] = host_names
        return await self._request("POST", "/investigations/file-ingress", json_data=body)

    async def lookup_process_range(
        self,
        process_id: str,
        *,
        from_ts: str,
        to_ts: str,
    ) -> dict[str, Any]:
        """GET /processes/{process_id}?from&to (spec §5 stage 8).
        Distinct from the legacy ``lookup_process`` (no time range), which is
        left untouched. The range selects the index partition (<= 10080 min)."""
        return await self._request(
            "GET",
            f"/processes/{process_id}",
            params={"from": from_ts, "to": to_ts},
        )
