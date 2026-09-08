"""Promotion of ingest-normalized OCSF events into fusion RawAlerts.

Phase 3.1 (world-class program) closed the first of the two spine gaps the
reality audit exposed: ``services/ingest`` publishes normalized OCSF events to
``aisoc.raw_events`` and — before this module — **nothing consumed them**. The
fusion worker now subscribes to that topic and runs every message through
:func:`promote_normalized_event`.

Promotion policy (deterministic, no LLM, documented honestly):

* **Vendor-asserted findings are promoted.** Any event in the OCSF *Findings*
  category (``class_uid`` 2000–2999 — Security Finding, Detection Finding,
  etc.) is already an alert in the source product's judgment; dropping it on
  the floor would be silent data loss.
* **High/critical telemetry is promoted.** Non-finding events with
  ``severity_id >= 4`` (High / Critical / Fatal on the OCSF ladder) are
  promoted so a critical Okta or K8s event is never invisible to the SOC.
* **Everything else is NOT promoted.** Turning raw Medium-and-below telemetry
  into alerts is the job of the detection engine, not this bridge — promoting
  it here would destroy the alert-reduction property the fusion stage exists
  to provide.

Events whose ``tenant_id`` is not a UUID are skipped (the alert store keys
tenants by UUID; a non-UUID tenant header is a mis-configured connector, and
we log it rather than crash the consumer).
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any

import structlog

from app.models.alert import AlertSeverity, RawAlert
from app.services.provenance import extract_provenance

logger = structlog.get_logger()

# OCSF category 2 = Findings (Security Finding 2001, Vulnerability Finding
# 2002, Compliance Finding 2003, Detection Finding 2004, ...).
_FINDINGS_CATEGORY = 2

# OCSF severity_id >= 4 means High(4) / Critical(5) / Fatal(6).
_PROMOTE_SEVERITY_FLOOR = 4

_SEVERITY_BY_ID: dict[int, AlertSeverity] = {
    6: AlertSeverity.CRITICAL,  # OCSF Fatal collapses onto our critical tier
    5: AlertSeverity.CRITICAL,
    4: AlertSeverity.HIGH,
    3: AlertSeverity.MEDIUM,
    2: AlertSeverity.LOW,
    1: AlertSeverity.INFO,
    0: AlertSeverity.MEDIUM,  # Unknown — median tier, never silently info
}


def _get_nested(obj: dict[str, Any], *path: str) -> Any:
    cur: Any = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _first_file_hash(ocsf: dict[str, Any]) -> str | None:
    fingerprints = _get_nested(ocsf, "file", "fingerprints")
    if isinstance(fingerprints, list) and fingerprints:
        first = fingerprints[0]
        if isinstance(first, dict):
            value = first.get("value")
            if isinstance(value, str) and value:
                return value
    return None


def _mitre(ocsf: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Extract (tactics, techniques) from the ingest ATT&CK enrichment block."""
    tactics: list[str] = []
    techniques: list[str] = []
    block = ocsf.get("mitre_attck")
    if isinstance(block, list):
        for entry in block:
            if not isinstance(entry, dict):
                continue
            tid = entry.get("technique_id")
            if isinstance(tid, str) and tid and tid not in techniques:
                techniques.append(tid)
            names = entry.get("tactic_names")
            if isinstance(names, list):
                for name in names:
                    if isinstance(name, str) and name and name not in tactics:
                        tactics.append(name)
    return tactics, techniques


def _title(ocsf: dict[str, Any]) -> str:
    for key in ("message", "activity_name"):
        val = ocsf.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()[:500]
    class_name = ocsf.get("class_name") or "Security event"
    product = _get_nested(ocsf, "metadata", "product", "name")
    if isinstance(product, str) and product:
        return f"{class_name} from {product}"[:500]
    return str(class_name)[:500]


def _source(ocsf: dict[str, Any]) -> str:
    vendor = _get_nested(ocsf, "metadata", "product", "vendor_name")
    product = _get_nested(ocsf, "metadata", "product", "name")
    parts = [p for p in (vendor, product) if isinstance(p, str) and p]
    return " ".join(parts) or "ingest"


def _event_time(ocsf: dict[str, Any]) -> datetime | None:
    raw = ocsf.get("time")
    if isinstance(raw, str) and raw:
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def should_promote(ocsf: dict[str, Any]) -> bool:
    """Deterministic promotion decision — see module docstring for policy."""
    class_uid = ocsf.get("class_uid")
    if isinstance(class_uid, int) and class_uid // 1000 == _FINDINGS_CATEGORY:
        return True
    severity_id = ocsf.get("severity_id")
    return isinstance(severity_id, int) and severity_id >= _PROMOTE_SEVERITY_FLOOR


def _extract_splunk_kv(raw_data: str, key: str) -> str | None:
    """Extract a key="value", key=value, or "key": value from a Splunk raw_data string/JSON."""
    if not isinstance(raw_data, str) or not raw_data:
        return None
    # 1. JSON string pattern: "key": "value"
    pattern1 = r'\"' + re.escape(key) + r'\"\s*:\s*\"([^\"]*)\"'
    m = re.search(pattern1, raw_data)
    if m:
        return m.group(1)

    # 2. JSON number pattern: "key": 123.4
    pattern2 = r'\"' + re.escape(key) + r'\"\s*:\s*([0-9\.]+)'
    m = re.search(pattern2, raw_data)
    if m:
        return m.group(1)

    # 3. KV pattern: key="value"
    pattern3 = re.escape(key) + r'\s*=\s*\"([^\"]*)\"'
    m = re.search(pattern3, raw_data)
    if m:
        return m.group(1).replace('\\"', '"')

    # 4. KV pattern: key=value
    pattern4 = re.escape(key) + r'\s*=\s*(.*?)(?=\s+[a-zA-Z0-9_\.]+\s*=|\s*,\s*[a-zA-Z0-9_\.]+\s*=|[\r\n]|$)'
    m = re.search(pattern4, raw_data)
    if m:
        val = m.group(1).strip()
        if val.endswith(","):
            val = val[:-1].strip()
        return val
    return None

def _extract_splunk_mitre(raw_data: str) -> list[str]:
    """Extract T1234 from dirty annotations like T1496 (Resource Hijacking)."""
    val = _extract_splunk_kv(raw_data, "annotations.mitre_attack") or _extract_splunk_kv(raw_data, "mitre_attack")
    if not val:
        return []
    # Match T followed by 4 digits, optionally .001
    matches = re.findall(r'T\d{4}(?:\.\d{3})?', val)
    return list(set(matches))


def _clean_str(val: Any) -> str:
    if not val:
        return ""
    s = str(val).strip()
    while (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")) or (s.startswith('\\"') and s.endswith('\\"')) or (s.startswith('\\') or s.endswith('\\')):
        s = s.strip(' \t\r\n"\'\\')
    return s


def promote_normalized_event(message: dict[str, Any]) -> RawAlert | None:
    """Convert one ``aisoc.raw_events`` message into a RawAlert, or ``None``.

    ``message`` is the JSON body ``services/ingest`` publishes — a
    ``NormalizedEvent`` with ``ocsf_event`` carrying the OCSF payload.
    Returns ``None`` when the event doesn't meet the promotion policy or the
    message is malformed (logged, never raised — one bad event must not wedge
    the consumer; the Phase 5 DLQ takes over from there).
    """
    ocsf = message.get("ocsf_event")
    if not isinstance(ocsf, dict):
        logger.warning("promoter.malformed_message", keys=sorted(message.keys()))
        return None

    if not should_promote(ocsf):
        return None

    tenant_raw = message.get("tenant_id") or ocsf.get("tenant_uid")
    try:
        tenant_id = uuid.UUID(str(tenant_raw))
    except (ValueError, TypeError):
        logger.warning("promoter.non_uuid_tenant", tenant_id=str(tenant_raw)[:64])
        return None

    severity_id = ocsf.get("severity_id")
    severity = _SEVERITY_BY_ID.get(severity_id if isinstance(severity_id, int) else 0, AlertSeverity.MEDIUM)

    tactics, techniques = _mitre(ocsf)
    connector_id, connector_type, class_uid = extract_provenance(message, ocsf)

    # ─── Splunk Airgap Fallback (Parse raw_data) ───
    # If the Go normalizer failed to parse fields because the server is airgapped
    # and the new Go binary couldn't be built, we rescue the fields here in Python.
    raw_data_str = str(ocsf.get("raw_data") or "")
    if "Splunk" in str(ocsf.get("metadata", {}).get("product", {}).get("name", "")) or "splunk" in str(message.get("connector_type", "")):
        if severity == AlertSeverity.MEDIUM:
            raw_sev = _extract_splunk_kv(raw_data_str, "severity") or _extract_splunk_kv(raw_data_str, "urgency")
            if raw_sev:
                raw_sev = raw_sev.lower()
                if raw_sev == "critical": severity = AlertSeverity.CRITICAL
                elif raw_sev == "high": severity = AlertSeverity.HIGH
                elif raw_sev == "low": severity = AlertSeverity.LOW
                elif raw_sev in ("info", "informational"): severity = AlertSeverity.INFO

        if not techniques:
            techniques = _extract_splunk_mitre(raw_data_str)

    src_ip = (
        _get_nested(ocsf, "src_endpoint", "ip")
        or _extract_splunk_kv(raw_data_str, "src_ip")
        or _extract_splunk_kv(raw_data_str, "srcip")
        or _extract_splunk_kv(raw_data_str, "src")
    )
    dst_ip = (
        _get_nested(ocsf, "dst_endpoint", "ip")
        or _extract_splunk_kv(raw_data_str, "dst_ip")
        or _extract_splunk_kv(raw_data_str, "dstip")
        or _extract_splunk_kv(raw_data_str, "dst")
    )

    # Extract host (host_key / orig_host / entity / risk_object / dest)
    host_key = _extract_splunk_kv(raw_data_str, "host_key")
    dest = _extract_splunk_kv(raw_data_str, "dest")
    entity = _extract_splunk_kv(raw_data_str, "entity")
    risk_obj = _extract_splunk_kv(raw_data_str, "risk_object")
    orig_host = _extract_splunk_kv(raw_data_str, "orig_host")

    hostname = None
    for cand in (host_key, orig_host, entity, risk_obj, dest):
        if cand and cand.lower() not in ("none", "null"):
            hostname = cand
            break

    username = _get_nested(ocsf, "actor", "user", "name") or _extract_splunk_kv(raw_data_str, "username") or _extract_splunk_kv(raw_data_str, "user") or _extract_splunk_kv(raw_data_str, "USER")
    file_hash = _first_file_hash(ocsf) or _extract_splunk_kv(raw_data_str, "file_hash") or _extract_splunk_kv(raw_data_str, "hash") or _extract_splunk_kv(raw_data_str, "sha256")
    domain = _extract_splunk_kv(raw_data_str, "domain")

    raw_risk = (
        _extract_splunk_kv(raw_data_str, "risk_score")
        or _extract_splunk_kv(raw_data_str, "crscore")
        or _extract_splunk_kv(raw_data_str, "score")
    )
    risk_score = 0.0
    if raw_risk:
        try:
            val = float(raw_risk)
            risk_score = min(val / 100.0 if val > 1.0 else val, 1.0)
        except (ValueError, TypeError):
            risk_score = 0.0

    desc = raw_data_str
    if _extract_splunk_kv(raw_data_str, "risk_message"):
        desc = _extract_splunk_kv(raw_data_str, "risk_message")
    elif _extract_splunk_kv(raw_data_str, "orig_rule_description"):
        desc = _extract_splunk_kv(raw_data_str, "orig_rule_description")

    # Title extraction: prefer orig_rule_title / orig_rule_name over generic OCSF message
    splunk_title = (
        _extract_splunk_kv(raw_data_str, "orig_rule_title")
        or _extract_splunk_kv(raw_data_str, "orig_rule_name")
        or _extract_splunk_kv(raw_data_str, "rule_name")
        or _extract_splunk_kv(raw_data_str, "search_name")
        or _extract_splunk_kv(raw_data_str, "title")
    )
    title = _clean_str(splunk_title if (splunk_title and splunk_title.lower() != "splunk") else _title(ocsf))
    hostname = _clean_str(hostname)
    username = _clean_str(username)
    desc = _clean_str(desc)

    return RawAlert(
        tenant_id=tenant_id,
        source=_source(ocsf),
        title=title[:500],
        description=desc[:2000],
        severity=severity,
        src_ip=src_ip,
        dst_ip=dst_ip,
        hostname=hostname,
        username=username,
        file_hash=file_hash,
        domain=domain,
        risk_score=risk_score,
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        raw_event=ocsf,
        event_time=_event_time(ocsf),
        connector_id=connector_id,
        connector_type=connector_type,
        ocsf_class_uid=class_uid,
    )
