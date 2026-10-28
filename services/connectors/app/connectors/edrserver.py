"""
EdrServer EDR Connector (v1.6 specification - Phase 1 Implementation).
Polls detections from EdrServer REST API v2 with persistent watermarks, chunk splitting, and concurrent detail enrichment.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote, urlparse

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()


class EdrAuthError(RuntimeError):
    """Raised when EdrServer returns 401 Unauthorized or 403 Forbidden."""


class PageCapReached(RuntimeError):
    """Raised when a chunk hits the 50-page collection limit."""

class EdrApiError(RuntimeError):
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

_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_BIDI_RE = re.compile(f"[‪-‮⁦-⁩‎‏​­]")
def _safe_log_val(value: str) -> str:
    """Strip ASCII control characters before logging, preventing log injection."""
    return _CTRL_RE.sub("", str(value))


def _strip_control_chars(value: Any) -> Any:
    """Strip ASCII control chars and bidi/format chars from a string.

    Names/paths come from a vendor the analyst cannot control. A CR/LF or
    an embedding control char is an attack surface, not a filename.
    Returns the input unchanged when it is not a string.
    """
    if not isinstance(value, str):
        return value
    return _BIDI_RE.sub("", _CTRL_RE.sub("", value))


class EdrServerConnector(BaseConnector):
    connector_id = "edrserver"
    connector_name = "SOMANSA EDR"
    connector_category = "edr"

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS,)

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="EdrServer EDR periodic detection polling connector with persistent watermarks.",
            docs_url="/docs/connectors/edrserver",
            fields=[
                Field("base_url", "string", "Base URL", default="https://edrserver.internal:7601"),
                Field("token", "secret", "API Bearer Token"),
                Field("verify_tls", "boolean", "Verify TLS", required=False, default=True),
            ],
        )

    def __init__(
        self,
        base_url: str = "https://edrserver.internal:7501",
        token: str = "",
        verify_tls: bool = True,
        **kwargs: Any,
    ) -> None:
        self._base_url = str(base_url).strip().rstrip("/")
        self._token = str(token).strip()
        self._verify_tls = bool(verify_tls)
        self._extra_kwargs = kwargs

        self._checkpoint: datetime | None = None
        self._next_checkpoint: datetime | None = None

    def set_checkpoint(self, cp: dict[str, Any] | None) -> None:
        if isinstance(cp, dict) and cp.get("time"):
            try:
                dt = datetime.fromisoformat(str(cp["time"]).replace("Z", "+00:00"))
                self._checkpoint = dt.astimezone(UTC).replace(tzinfo=None)
            except ValueError:
                self._checkpoint = None
        else:
            self._checkpoint = None

    def get_checkpoint(self) -> dict[str, str] | None:
        if self._next_checkpoint:
            return {"time": self._next_checkpoint.replace(tzinfo=UTC).isoformat()}
        return None

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _ssl_verify(self) -> bool | str:
        if not self._verify_tls:
            return False
        return True

    async def test_connection(self) -> dict[str, Any]:
        url = f"{self._base_url}/api/v2/ai-soc/capabilities"
        async with httpx.AsyncClient(timeout=10.0, verify=self._ssl_verify()) as client:
            try:
                resp = await client.get(url, headers=self._headers())
                resp.raise_for_status()
                data = resp.json()
                return {
                    "success": True,
                    "connector": self.connector_id,
                    "authenticated": True,
                    "api_version": data.get("api_version", "unknown"),
                    "scopes_ok": True,
                }
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                if status == 401:
                    return {"success": False, "connector": self.connector_id, "error": "AUTH_INVALID_TOKEN"}
                elif status == 403:
                    return {"success": False, "connector": self.connector_id, "error": "AUTH_SCOPE_MISSING"}
                return {"success": False, "connector": self.connector_id, "error": f"HTTP_{status}"}
            except (httpx.ConnectError, httpx.TimeoutException):
                return {"success": False, "connector": self.connector_id, "error": "NET_UNREACHABLE"}
            except Exception as exc:
                return {"success": False, "connector": self.connector_id, "error": str(exc)}

    def _calculate_window(self, since_seconds: int) -> tuple[datetime, datetime]:
        # EdrServer rejects queries with `to` in the future or exceeding server time.
        # Subtract a safety margin of 90s to account for clock skew and eventual consistency.
        safety_margin_seconds = 90
        now = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=safety_margin_seconds)
        start = now - timedelta(seconds=since_seconds)
        if self._checkpoint:
            start = min(self._checkpoint - timedelta(seconds=30), start)
        max_lookback = now - timedelta(hours=24)
        if start < max_lookback:
            logger.warning("edrserver.gap_clamped", original_start=start.isoformat(), clamped_start=max_lookback.isoformat())
            start = max_lookback
        return start, now

    def _split_chunks(self, start: datetime, end: datetime, chunk_seconds: int = 600) -> list[tuple[datetime, datetime]]:
        chunks = []
        cur = start
        while cur < end:
            nxt = min(cur + timedelta(seconds=chunk_seconds), end)
            chunks.append((cur, nxt))
            cur = nxt
        return chunks

    async def _list_chunk(self, client: httpx.AsyncClient, chunk_start: datetime, chunk_end: datetime, sources: str) -> list[dict[str, Any]]:
        url = f"{self._base_url}/api/v2/ai-soc/detections"
        items: list[dict[str, Any]] = []
        cursor: str | None = None
        pages = 0
        restarts = 0

        while True:
            params: dict[str, Any] = {}
            if cursor:
                params["cursor"] = cursor
            else:
                params["from"] = chunk_start.strftime("%Y-%m-%dT%H:%M:%SZ")
                params["to"] = chunk_end.strftime("%Y-%m-%dT%H:%M:%SZ")
                params["sources"] = sources
                params["limit"] = 100

            # ── 단일 페이지 요청 단위 재시도 루프 (최대 3회) ──
            resp = None
            for attempt in range(3):
                try:
                    resp = await client.get(url, params=params, headers=self._headers())
                    
                    # 410 Gone (Cursor 만료)은 기존대로 상위 페이징 재시작 로직으로 위임
                    if resp.status_code == 410:
                        break

                    # 일시적 장애(429, 503, 502, 504)에 대한 백오프 재시도
                    if resp.status_code in (429, 502, 503, 504):
                        logger.warning(
                            "edrserver.list_chunk.transient_error",
                            status=resp.status_code,
                            attempt=attempt + 1,
                        )
                        if attempt == 2:  # 마지막 시도 실패 시 즉시 에러 발생
                            resp.raise_for_status()
                        
                        retry_after = int(resp.headers.get("Retry-After", 2 ** attempt))
                        await asyncio.sleep(min(max(1, retry_after), 10))
                        continue

                    resp.raise_for_status()
                    break  # 성공 시 재시도 루프 탈출

                except (httpx.ConnectError, httpx.TimeoutException) as exc:
                    logger.warning("edrserver.list_chunk.net_error", attempt=attempt + 1, exc=str(exc))
                    if attempt == 2:
                        raise
                    await asyncio.sleep(2 ** attempt)

            if resp is None:
                raise RuntimeError("Failed to obtain response from EDR server")

            if resp.status_code == 410:
                restarts += 1
                if restarts > 2:
                    raise RuntimeError("cursor_expired restart limit (2) exceeded")
                cursor = None
                items.clear()
                pages = 0
                continue

            data = resp.json()
            page_items = data.get("items", [])
            items.extend(page_items)
            pages += 1

            has_more = data.get("has_more", False)
            if not has_more:
                break
            if pages >= 50:
                raise PageCapReached(f"Chunk hit 50-page limit between {chunk_start} and {chunk_end}")
            next_cursor = data.get("next_cursor")
            if not next_cursor:
                break
            cursor = quote(str(next_cursor))

        return items

    def _build_detail_url(self, item: dict[str, Any]) -> str | None:
        edr_block = item.get("edr", {})
        links = edr_block.get("links", {})
        detail_link = links.get("detail")
        lookup_hint = links.get("lookup_hint")

        base_parsed = urlparse(self._base_url)

        if detail_link:
            if detail_link.startswith("http://") or detail_link.startswith("https://"):
                link_parsed = urlparse(detail_link)
                if (link_parsed.scheme, link_parsed.hostname, link_parsed.port) != (base_parsed.scheme, base_parsed.hostname, base_parsed.port):
                    logger.warning("edrserver.detail_link_origin_mismatch", detail_link=detail_link)
                    return None
                url = detail_link
            else:
                url = f"{self._base_url}{detail_link}"
        else:
            source_kind = edr_block.get("source_kind", "dynamic")
            event_id = item.get("event", {}).get("id", "")
            if not event_id:
                return None
            url = f"{self._base_url}/api/v2/ai-soc/detections/{quote(str(source_kind))}/{quote(str(event_id))}"

        if lookup_hint:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}lookup_hint={quote(str(lookup_hint))}"
        return url

    async def _enrich(self, client: httpx.AsyncClient, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        # Default 4 (not 10): 10-way parallel detail calls exceed the EDR
        # rate limit (token rate or query concurrency), so 200 and 429 come
        # back mixed; lower it via EDR_DETAIL_MAX_CONCURRENCY if needed.
        sem = asyncio.Semaphore(self._detail_concurrency())

        async def one(item: dict[str, Any]) -> dict[str, Any]:
            async with sem:
                url = self._build_detail_url(item)
                if url is None:
                    return self._fallback(item)

                for attempt in range(3):
                    try:
                        resp = await client.get(url, headers=self._headers())
                        if resp.status_code == 200:
                            data = resp.json()
                            detail_item = data.get("item", item)
                            return self._complete(detail_item)
                        elif resp.status_code == 404:
                            return self._fallback(item)
                        elif resp.status_code in (429, 503):
                            retry_after = int(resp.headers.get("Retry-After", 5))
                            await asyncio.sleep(min(retry_after, 60))
                            continue
                        elif resp.status_code in (401, 403):
                            raise EdrAuthError(f"Detail auth failed: {resp.status_code}")
                        else:
                            return self._fallback(item)
                    except (httpx.ConnectError, httpx.TimeoutException):
                        if attempt == 2:
                            return self._fallback(item)
                        await asyncio.sleep(2 ** attempt)
                    except EdrAuthError:
                        raise
                    except Exception:
                        return self._fallback(item)
                return self._fallback(item)

        results = await asyncio.gather(*(one(item) for item in items))
        return list(results)

    def _fallback(self, item: dict[str, Any]) -> dict[str, Any]:
        copied = dict(item)
        copied["enrichment_status"] = "fallback_list_only"
        return self.to_canonical(copied, enrichment_status="fallback_list_only")

    def _complete(self, item: dict[str, Any]) -> dict[str, Any]:
        copied = dict(item)
        copied["enrichment_status"] = "complete"
        return self.to_canonical(copied, enrichment_status="complete")

    def to_canonical(self, item: dict[str, Any], enrichment_status: str = "complete") -> dict[str, Any]:
        event_block = item.get("event", {})
        edr_block = item.get("edr", {})
        rule_block = item.get("rule", {})
        host_block = item.get("host", {})
        user_block = item.get("user", {})

        source_kind = edr_block.get("source_kind", "dynamic")
        event_id = event_block.get("id", "")
        external_id = f"{source_kind}:{event_id}" if event_id else ""

        title = rule_block.get("name") or event_block.get("action") or "EDR detection"
        hostname = host_block.get("name")
        description = rule_block.get("description") or (f"EDR detection on {hostname}" if hostname else "EDR detection")

        severity = self._map_severity(edr_block.get("severity_level"), event_block.get("severity"))

        host_ip = self._extract_host_ip(host_block.get("ip"))
        src_ip = self._extract_src_ip(item, host_ip)

        actor = user_block.get("name") if enrichment_status == "complete" else None

        mitre_techniques, mitre_tactics, mitre_available = self._extract_mitre(item.get("behavior", {}).get("tags"))

        ts_raw = item.get("@timestamp") or event_block.get("created")
        timestamp = self._parse_timestamp(ts_raw)

        return {
            "source": "edrserver",
            "external_id": external_id,
            "title": title,
            "description": description,
            "severity": severity,
            "host_ip": host_ip,
            "src_ip": src_ip,
            "hostname": hostname or None,
            "actor": actor,
            "mitre_techniques": mitre_techniques,
            "mitre_tactics": mitre_tactics,
            "mitre_available": mitre_available,
            "enrichment_status": enrichment_status,
            "timestamp": timestamp,
            "created_at": timestamp,
            "raw_event": item,
        }

    def _map_severity(self, level_str: Any, severity_int: Any) -> str:
        if isinstance(level_str, str):
            cleaned = level_str.strip().lower()
            mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info", "informational": "info"}
            if cleaned in mapping:
                return mapping[cleaned]

        try:
            sev = int(severity_int)
            if 0 <= sev <= 3:
                return "low"
            elif 4 <= sev <= 6:
                return "medium"
            elif 7 <= sev <= 8:
                return "high"
            elif 9 <= sev <= 10:
                return "critical"
        except (TypeError, ValueError):
            pass

        return "medium"

    def _extract_host_ip(self, ip_raw: Any) -> str | None:
        ips: list[str] = []
        if isinstance(ip_raw, str):
            ips = [ip_raw]
        elif isinstance(ip_raw, list):
            ips = [str(x) for x in ip_raw if isinstance(x, str)]

        valid_ips = []
        for ip in ips:
            ip_clean = ip.strip()
            if not ip_clean:
                continue
            # Exclude loopback and link-local
            if ip_clean.startswith("127.") or ip_clean == "::1" or ip_clean.startswith("169.254.") or ip_clean.startswith("fe80:"):
                continue
            valid_ips.append(ip_clean)

        if not valid_ips:
            return None

        # IPv4 priority, then IPv6
        ipv4s = [i for i in valid_ips if ":" not in i]
        ipv6s = [i for i in valid_ips if ":" in i]
        return (ipv4s + ipv6s)[0] if (ipv4s + ipv6s) else None

    def _extract_src_ip(self, item: dict[str, Any], host_ip: str | None) -> str | None:
        source_ip = item.get("source", {}).get("ip")
        if isinstance(source_ip, str) and source_ip.strip():
            return source_ip.strip()
        return host_ip

    def _extract_mitre(self, tags_raw: Any) -> tuple[list[str], list[str], bool]:
        if not isinstance(tags_raw, list):
            return [], [], False

        techniques = []
        tactics = []
        tech_pattern = re.compile(r"^T\d{4}(?:\.\d{3})?$")
        tactic_pattern = re.compile(r"^TA\d{4}$")

        for tag in tags_raw:
            if not isinstance(tag, str):
                continue
            t_clean = tag.strip()
            if tech_pattern.match(t_clean) and t_clean not in techniques:
                techniques.append(t_clean)
            elif tactic_pattern.match(t_clean) and t_clean not in tactics:
                tactics.append(t_clean)

        return sorted(techniques), sorted(tactics), True

    def _parse_timestamp(self, raw: Any) -> str | None:
        if not isinstance(raw, str) or not raw.strip():
            return None
        try:
            dt = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
            return dt.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        except ValueError:
            logger.error("edrserver.timestamp_parse_failed", raw=raw)
            return None

    @staticmethod
    def _lookup_config() -> tuple[int, bool]:
        """Lookup-path knobs, independent of the polling poller.

        ``PARENT_LOOKUP_MAX_CONCURRENCY`` bounds how many EDR process
        lookups run at once — the polling ``_enrich`` path keeps its own
        semaphore(10) and 3x retry; this path must not touch them (AC-9).
        """
        max_concurrency = int(os.getenv("PARENT_LOOKUP_MAX_CONCURRENCY", "2") or "2")
        include_cmd_line = os.getenv(
            "PARENT_LOOKUP_INCLUDE_COMMAND_LINE", "false"
        ).strip().lower() in ("1", "true", "yes", "on")
        return max(1, max_concurrency), include_cmd_line

    @staticmethod
    def _detail_concurrency() -> int:
        """Detail-enrichment concurrency for the polling path.

        Default 4 (not 10): 10-way parallel detail calls exceed the EDR
        rate limit (token rate or query concurrency), so 200 and 429 come
        back mixed. Raise via ``EDR_DETAIL_MAX_CONCURRENCY`` if the volume
        needs it.
        """
        val = os.getenv("EDR_DETAIL_MAX_CONCURRENCY", "4")
        try:
            c = int(val)
        except (TypeError, ValueError):
            c = 4
        return max(1, c)

    async def process_lookup(
        self,
        *,
        entity_id: str,
        from_ts: str,
        to_ts: str,
    ) -> dict[str, Any]:
        """One-shot parent-process lookup: a single EDR call, no retries.

        The polling path and this lookup are deliberately separate. A
        failed lookup must never block an analyst from reading an alert,
        so every failure maps to ``unavailable`` (or ``not_found`` for a
        clean 404), never raises. Only the parent's entity_id, name,
        pid, executable and start are returned — command line is
        opt-in (see ``_lookup_config``) so AC-13 holds by default.
        """
        max_concurrency, include_cmd_line = self._lookup_config()
        url = f"{self._base_url}/api/v2/ai-soc/processes/{quote(str(entity_id))}"
        params = {"from": str(from_ts), "to": str(to_ts)}
        sem = asyncio.Semaphore(max_concurrency)

        async with sem:
            async with httpx.AsyncClient(
                timeout=2.5, verify=self._ssl_verify()
            ) as client:
                try:
                    resp = await client.get(
                        url, params=params, headers=self._headers()
                    )
                except (httpx.ConnectError, httpx.TimeoutException):
                    logger.warning(
                        "edrserver.process_lookup.net_error",
                        entity_id=_safe_log_val(entity_id),
                    )
                    return {"status": "unavailable", "entity_id": str(entity_id), "process": None}

        status = resp.status_code
        if status == 200:
            try:
                data = resp.json()
            except ValueError:
                logger.warning("edrserver.process_lookup.invalid_json", entity_id=str(entity_id))
                return {"status": "unavailable", "entity_id": str(entity_id), "process": None}
            proc = data.get("process", {}) if isinstance(data, dict) else {}
            if not isinstance(proc, dict):
                proc = {}
            name = proc.get("name")
            proc_id = proc.get("entity_id") or entity_id
            if isinstance(name, str) and name.strip():
                process = {
                    "entity_id": str(proc_id),
                    "name": _strip_control_chars(name),
                    "pid": proc.get("pid"),
                    "executable": (_strip_control_chars(proc.get("executable"))
                                   if isinstance(proc.get("executable"), str) else None),
                    "started_at": proc.get("start"),
                }
                if include_cmd_line and isinstance(proc.get("command_line"), str):
                    process["command_line"] = proc["command_line"][:1024]
                return {"status": "found", "entity_id": str(proc_id), "process": process}
            return {"status": "not_found", "entity_id": str(proc_id), "process": None}
        if status == 404:
            return {"status": "not_found", "entity_id": str(entity_id), "process": None}
        logger.warning(
            "edrserver.process_lookup.http_error",
            entity_id=_safe_log_val(entity_id),
            status=status,
        )
        return {"status": "unavailable", "entity_id": str(entity_id), "process": None}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        start, end = self._calculate_window(since_seconds)
        chunks = self._split_chunks(start, end, chunk_seconds=600)

        all_alerts: list[dict[str, Any]] = []
        max_events = 5000

        limits_timeout = 240.0
        try:
            async with asyncio.timeout(limits_timeout):
                async with httpx.AsyncClient(timeout=30.0, verify=self._ssl_verify()) as client:
                    for chunk_start, chunk_end in chunks:
                        try:
                            items = await self._list_chunk(client, chunk_start, chunk_end, sources="dynamic,static")
                            details = await self._enrich(client, items)
                            all_alerts.extend(details)
                            self._next_checkpoint = chunk_end
                            if len(all_alerts) >= max_events:
                                break
                        except PageCapReached:
                            if self._next_checkpoint is None:
                                raise
                            break
        except asyncio.TimeoutError:
            if self._next_checkpoint is None:
                raise RuntimeError("EdrServer polling deadline reached before completing any chunk")

        return all_alerts

    # --- Case-investigation methods (plan U2, spec §5 stages 2-5, §7) ---
    # Distinct names: the polling path (fetch_alerts / _enrich / _list_chunk)
    # and its callers are untouched.

    async def _edr_get(self, client: httpx.AsyncClient, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """One GET with error-body parsing: 429/503 get a Retry-After backoff
        (up to 3 attempts); any other error status is raised as EdrApiError
        with the parsed error.code so callers can apply the §5 "unavailable"
        strict rule (404 alone is NOT unavailable)."""
        url = f"{self._base_url}/api/v2/ai-soc{path}"
        for attempt in range(3):
            resp = await client.get(url, params=params, headers=self._headers())
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code in (429, 503):
                if attempt == 2:
                    raise parse_edr_error_body(resp.text, resp.status_code, resp.headers.get("Retry-After"))
                retry_after = resp.headers.get("Retry-After")
                delay = min(float(retry_after) if retry_after and retry_after.replace(".", "", 1).isdigit() else 2 ** attempt, 10)
                await asyncio.sleep(delay)
                continue
            raise parse_edr_error_body(resp.text, resp.status_code, resp.headers.get("Retry-After"))
        raise RuntimeError("EDR GET retry budget exhausted")

    async def _edr_post(self, client: httpx.AsyncClient, path: str, json_data: dict[str, Any]) -> dict[str, Any]:
        """POST sibling of ``_edr_get``: 429/503 backoff, other errors raise
        ``EdrApiError`` with parsed error.code (spec §7)."""
        url = f"{self._base_url}/api/v2/ai-soc{path}"
        for attempt in range(3):
            resp = await client.post(url, json=json_data, headers=self._headers())
            if resp.status_code in (200, 201, 202):
                return resp.json()
            if resp.status_code in (429, 503):
                if attempt == 2:
                    raise parse_edr_error_body(resp.text, resp.status_code, resp.headers.get("Retry-After"))
                retry_after = resp.headers.get("Retry-After")
                delay = min(float(retry_after) if retry_after and retry_after.replace(".", "", 1).isdigit() else 2 ** attempt, 10)
                await asyncio.sleep(delay)
                continue
            raise parse_edr_error_body(resp.text, resp.status_code, resp.headers.get("Retry-After"))
        raise RuntimeError("EDR POST retry budget exhausted")

    async def fetch_detection_detail(
        self, source_kind: str, event_id: str, lookup_hint: str | None = None
    ) -> dict[str, Any]:
        """GET /detections/{source_kind}/{event_id} (spec §5 stage 2).

        A 404 body is parsed: error.code = not_found -> incomplete;
        feature_disabled -> unavailable. No call is skipped here (detail has
        no source_kind pre-decision), so the error code decides.
        """
        params: dict[str, Any] = {}
        if lookup_hint is not None:
            params["lookup_hint"] = lookup_hint
        async with httpx.AsyncClient(timeout=10.0, verify=self._ssl_verify()) as client:
            return await self._edr_get(client, f"/detections/{source_kind}/{event_id}", params or None)

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

        static source_kind does not support timelines: skip the call and
        report unavailable without touching the API (spec §5 "unavailable"
        pre-decision rule).
        """
        if source_kind == "static":
            return {"status": "unavailable", "reason_code": "timeline_unavailable(static)"}
        params: dict[str, Any] = {"before": before, "after": after, "limit": limit}
        if categories:
            params["categories"] = ",".join(categories)
        if action_types:
            params["action_types"] = ",".join(str(a) for a in action_types)
        async with httpx.AsyncClient(timeout=10.0, verify=self._ssl_verify()) as client:
            return await self._edr_get(client, f"/investigations/{source_kind}/{event_id}/timeline", params)

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

        static: skip and report unavailable. If the first response is
        truncated, retry once with max_nodes raised to 500 (spec "graph
        truncated retry"); still truncated -> caller records
        incomplete(graph_truncated).
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
        async with httpx.AsyncClient(timeout=10.0, verify=self._ssl_verify()) as client:
            data = await self._edr_get(client, f"/investigations/{source_kind}/{event_id}/graph", params)
            if data.get("truncated"):
                params["max_nodes"] = 500
                data = await self._edr_get(client, f"/investigations/{source_kind}/{event_id}/graph", params)
            return data

    async def host_inventory_by_agent(self, agent_id: str) -> dict[str, Any]:
        """GET /hosts/{agent_id} (spec §5 stage 5): latest inventory with
        observed_at so callers can distinguish incident-time facts from the
        current snapshot (AGENTS.md §9)."""
        async with httpx.AsyncClient(timeout=10.0, verify=self._ssl_verify()) as client:
            return await self._edr_get(client, f"/hosts/{agent_id}")

    async def hunt(
        self,
        from_ts: str,
        to_ts: str,
        observables: list[dict[str, str]],
        sources: list[str] | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """POST /hunt (spec §5 stage 6): does the same hash/IP/URL re-appear
        on other hosts/users? Exact-match observables only. Chunking (20 per
        call, max 3 calls/case) is the caller's job (U8)."""
        body: dict[str, Any] = {"from": from_ts, "to": to_ts, "observables": observables, "limit": limit}
        if sources:
            body["sources"] = sources
        async with httpx.AsyncClient(timeout=10.0, verify=self._ssl_verify()) as client:
            return await self._edr_post(client, "/hunt", body)

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
        Distinct from the legacy GET ``search_events`` (single ``query``
        param), which is left untouched. Filtered values <= 100, page <= 500
        and unfiltered broad searches <= 60 min are enforced by the caller (U8)."""
        body: dict[str, Any] = {"from": from_ts, "to": to_ts, "limit": limit}
        if categories:
            body["categories"] = categories
        if action_types:
            body["action_types"] = action_types
        if observables:
            body["observables"] = observables
        if file_paths:
            body["file_paths"] = file_paths
        async with httpx.AsyncClient(timeout=10.0, verify=self._ssl_verify()) as client:
            return await self._edr_post(client, "/events/search", body)

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
        confirmed, ``inferred`` stays a candidate (never a definitive answer).
        ``404 feature_disabled`` / ``features.file_ingress=false`` -> unavailable;
        hops <= 2, evidence <= 200, query count <= 32 enforced by caller (U8)."""
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
        async with httpx.AsyncClient(timeout=10.0, verify=self._ssl_verify()) as client:
            return await self._edr_post(client, "/investigations/file-ingress", body)

    async def lookup_process_range(
        self,
        process_id: str,
        *,
        from_ts: str,
        to_ts: str,
    ) -> dict[str, Any]:
        """GET /processes/{process_id}?from&to (spec §5 stage 8). Distinct
        from the legacy ``lookup_process`` (no time range), which is left
        untouched. The range selects the index partition (<= 10080 min);
        ``command_line`` may be ``<redacted>`` — never attempt to restore it."""
        params = {"from": from_ts, "to": to_ts}
        async with httpx.AsyncClient(timeout=10.0, verify=self._ssl_verify()) as client:
            return await self._edr_get(client, f"/processes/{process_id}", params)

