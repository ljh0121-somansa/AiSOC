"""Abuse.ch ThreatFox and URLhaus API Clients.

Fetches open-source, Creative Commons CC0 threat intelligence indicators natively
and securely without external non-commercial key restrictions.
"""

from __future__ import annotations

import httpx
import structlog
from typing import Any

logger = structlog.get_logger(__name__)


class ThreatFoxClient:
    """Client for Abuse.ch ThreatFox API (C2 Tracking)."""

    def __init__(self, timeout: float = 30.0) -> None:
        self._url = "https://threatfox-api.abuse.ch/api/v1/"
        self._timeout = timeout

    async def fetch_recent_iocs(self, limit: int = 100) -> list[dict[str, Any]]:
        """Fetch recent high-fidelity malware C2 indicators."""
        payload = {"query": "get_iocs", "days": 1}
        try:
            logger.info("Polling ThreatFox C2 feed", url=self._url)
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(self._url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            if data.get("query_status") == "ok":
                return list(data.get("data", []))[:limit]
            return []
        except Exception as exc:
            logger.error("Failed to fetch from ThreatFox", error=str(exc))
            return []


class UrlhausClient:
    """Client for Abuse.ch URLhaus API (Malware Distribution URL)."""

    def __init__(self, timeout: float = 30.0) -> None:
        self._url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
        self._timeout = timeout

    async def fetch_recent_urls(self, limit: int = 100) -> list[dict[str, Any]]:
        """Fetch recently active malware distribution URL indicators."""
        try:
            logger.info("Polling URLhaus malware URL feed", url=self._url)
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(self._url)
            resp.raise_for_status()
            data = resp.json()
            if data.get("query_status") == "ok":
                return list(data.get("urls", []))[:limit]
            return []
        except Exception as exc:
            logger.error("Failed to fetch from URLhaus", error=str(exc))
            return []
