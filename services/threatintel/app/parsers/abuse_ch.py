"""Parser for Abuse.ch Threat Intel payloads.

Standardizes heterogeneous ThreatFox and URLhaus JSON responses into the
platform-standard IOC model.
"""

from __future__ import annotations

from typing import Any


def parse_threatfox_ioc(raw: dict[str, Any]) -> dict[str, Any]:
    """Parse a single ThreatFox payload into standard IOC envelope."""
    raw_type = str(raw.get("ioc_type", "")).strip().lower()
    
    # Map to platform standard types
    ioc_type = "ip"
    if "domain" in raw_type:
        ioc_type = "domain"
    elif "hash" in raw_type or "md5" in raw_type or "sha256" in raw_type:
        ioc_type = "hash"
    elif "url" in raw_type:
        ioc_type = "url"

    return {
        "type": ioc_type,
        "value": str(raw.get("ioc", "")).strip(),
        "source": "threatfox",
        "severity": "high",  # Active C2 is always high-risk
        "description": f"ThreatFox C2: {raw.get('malware_printable', 'unknown')}",
    }


def parse_urlhaus_ioc(raw: dict[str, Any]) -> dict[str, Any]:
    """Parse a single URLhaus payload into standard IOC envelope."""
    return {
        "type": "url",
        "value": str(raw.get("url", "")).strip(),
        "source": "urlhaus",
        "severity": "medium",
        "description": f"URLhaus Malware: {raw.get('threat', 'unknown')}",
    }
