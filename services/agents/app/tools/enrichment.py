"""
Tool: IOC enrichment via the enrichment microservice.
"""

import asyncio
import json
import os
import urllib.request
import structlog

logger = structlog.get_logger()

_DEFAULT_ENRICHMENT_URL = "http://enrichment:8082"


def _enrichment_url() -> str:
    return os.getenv("ENRICHMENT_SERVICE_URL", "").strip() or os.getenv("ENRICHMENT_URL", "").strip() or _DEFAULT_ENRICHMENT_URL


def _sync_enrich(ioc_value: str, ioc_type: str) -> dict:
    url = f"{_enrichment_url()}/enrich"
    data = json.dumps({"value": ioc_value, "ioc_type": ioc_type}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=15.0) as response:
        return json.loads(response.read().decode("utf-8"))


async def enrich_ioc(ioc_value: str, ioc_type: str) -> dict:
    """Call the enrichment service to get threat intel for an IOC."""
    try:
        # Run synchronous urllib in a thread pool to avoid blocking the event loop.
        # This completely resolves any httpx/anyio async DNS/IPv6 socket connection races.
        return await asyncio.to_thread(_sync_enrich, ioc_value, ioc_type)
    except Exception as exc:
        logger.warning("IOC enrichment failed", ioc=ioc_value, error=str(exc))
        return {"error": str(exc), "value": ioc_value, "ioc_type": ioc_type}


def _sync_bulk_enrich(items: list[dict]) -> list[dict]:
    url = f"{_enrichment_url()}/enrich/bulk"
    data = json.dumps({"items": items}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=30.0) as response:
        resp_data = json.loads(response.read().decode("utf-8"))
        return resp_data.get("results", [])


async def bulk_enrich_iocs(items: list[dict]) -> list[dict]:
    """Bulk enrich up to 100 IOCs."""
    try:
        # Run synchronous urllib in a thread pool to avoid blocking the event loop.
        return await asyncio.to_thread(_sync_bulk_enrich, items)
    except Exception as exc:
        logger.warning("Bulk IOC enrichment failed", error=str(exc))
        return []
