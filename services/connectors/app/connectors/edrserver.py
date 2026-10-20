"""
EdrServer EDR Connector (v1.6 specification - Phase 1 Implementation).
Polls detections from EdrServer REST API v2 with persistent watermarks, chunk splitting, and concurrent detail enrichment.
"""

from __future__ import annotations

import asyncio
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

            try:
                resp = await client.get(url, params=params, headers=self._headers())
                if resp.status_code == 410:
                    restarts += 1
                    if restarts > 2:
                        raise RuntimeError("cursor_expired restart limit (2) exceeded")
                    cursor = None
                    items.clear()
                    pages = 0
                    continue
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPStatusError as exc:
                logger.error("edrserver.list_chunk.http_error", status=exc.response.status_code, body=exc.response.text[:500])
                if exc.response.status_code in (401, 403):
                    raise EdrAuthError(f"Authentication failed: {exc.response.status_code}") from exc
                raise

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
        sem = asyncio.Semaphore(10)

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
