"""
Splunk connector.
Runs saved searches and fetches notable events from Splunk SIEM.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import quote

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field
from app.federated.query import UnifiedQuery
from app.federated.translators import to_spl

logger = structlog.get_logger()

# Page size for the results endpoint. ``head 100`` / ``count=100`` used to cap a
# poll at 100 notables and silently drop the rest (#529); we now page through
# every result. _MAX_PAGES bounds a single poll so a misconfigured saved search
# can't spin forever.
_DEFAULT_PAGE_SIZE = 500
_MAX_PAGES = 200
_JOB_POLL_ATTEMPTS = 30
_JOB_POLL_INTERVAL_S = 2.0
_SEVERITY_BY_URGENCY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}


def _clean_field(val: Any) -> str | None:
    if val is None:
        return None
    s = str(val).strip()
    while (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")) or (s.startswith('\\"') and s.endswith('\\"')) or (s.startswith('\\') or s.endswith('\\')):
        s = s.strip(' \t\r\n"\'\\')
    return s if s else None


class SplunkConnector(BaseConnector):
    connector_id = "splunk"
    connector_name = "Splunk SIEM"
    connector_category = "siem"
    supports_federated_search = True

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="Splunk Enterprise / Cloud notable events via the REST API.",
            docs_url="/docs/connectors/splunk",
            fields=[
                Field(
                    "base_url",
                    "string",
                    "Splunk URL",
                    placeholder="https://splunk.example.com:8089",
                    help_text="Management port (default 8089), not the web UI port.",
                ),
                Field("token", "secret", "HEC / API Token"),
                Field(
                    "saved_search",
                    "string",
                    "Saved Search Name",
                    required=False,
                    default="AiSOC_Alerts",
                    help_text="Dispatched via the saved-search endpoint. Leave blank to search index=notable.",
                ),
                Field(
                    "page_size",
                    "number",
                    "Results page size",
                    required=False,
                    default=_DEFAULT_PAGE_SIZE,
                    help_text="Number of results fetched per page. Polling pages through all results — there is no 100-event cap.",
                ),
                Field(
                    "ssl_verify",
                    "boolean",
                    "Verify SSL certificate",
                    required=False,
                    default=True,
                    help_text="Disable only for self-signed certificates in private deployments.",
                ),
                Field(
                    "poll_interval_seconds",
                    "integer",
                    "Polling Interval (seconds)",
                    required=False,
                    default=300,
                    help_text="How often to query Splunk for alerts (e.g. 300 for 5 min, 86400 for 24 hours).",
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Splunk surfaces notable events (alerts) and supports federated SPL
        # search over indexes — the latter maps to QUERY_LOGS.
        # WS-E5: Live Splunk REST API response actions now wired
        # via services/actions/app/clients/splunk_client.py
        return (
            Capability.PULL_ALERTS,
            Capability.QUERY_LOGS,
            Capability.SEARCH_SIEM,
            Capability.CREATE_NOTABLE_EVENT,
        )

    def __init__(
        self,
        base_url: str,
        token: str,
        saved_search: str = "AiSOC_Alerts",
        ssl_verify: bool = True,
        page_size: int = _DEFAULT_PAGE_SIZE,
    ):
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._saved_search = saved_search
        self._ssl_verify = ssl_verify
        try:
            self._page_size = max(1, int(page_size))
        except (TypeError, ValueError):
            self._page_size = _DEFAULT_PAGE_SIZE
        # Checkpoint plumbing (#529). ``_checkpoint`` is the last-accepted
        # (event_time, tie-breaker id) fed in by the scheduler before a poll;
        # ``_next_checkpoint`` is the advanced value the scheduler persists
        # *after* ingest accepts the batch. Both are ``{"time","id"}`` dicts.
        self._checkpoint: dict[str, str] | None = None
        self._next_checkpoint: dict[str, str] | None = None

    def set_checkpoint(self, checkpoint: dict[str, Any] | None) -> None:
        """Seed the poll with the last-accepted checkpoint (scheduler-owned)."""
        if isinstance(checkpoint, dict) and (checkpoint.get("time") or checkpoint.get("id")):
            self._checkpoint = {"time": str(checkpoint.get("time") or ""), "id": str(checkpoint.get("id") or "")}
        else:
            self._checkpoint = None

    def get_checkpoint(self) -> dict[str, str] | None:
        """Return the advanced checkpoint after a fetch, or None if unchanged.

        The scheduler persists this only once ingest has accepted the batch, so
        a failed ingest never advances the checkpoint (#529).
        """
        return self._next_checkpoint

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

    async def test_connection(self) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15.0, verify=self._ssl_verify) as client:
            try:
                resp = await client.get(
                    f"{self._base_url}/services/server/info",
                    headers=self._headers(),
                    params={"output_mode": "json"},
                )
                resp.raise_for_status()
                version = resp.json().get("entry", [{}])[0].get("content", {}).get("version")
                return {"success": True, "connector": self.connector_id, "version": version}
            except httpx.HTTPStatusError as exc:
                logger.warning("splunk.test_connection.failed", error_type=type(exc).__name__, status_code=exc.response.status_code)
                err_msg = f"Connection failed: HTTP {exc.response.status_code} {exc.response.reason_phrase}"
                return {"success": False, "connector": self.connector_id, "error": err_msg}
            except httpx.TimeoutException as exc:
                logger.warning("splunk.test_connection.failed", error_type=type(exc).__name__)
                return {"success": False, "connector": self.connector_id, "error": "Connection failed: Request timed out"}
            except httpx.ConnectError as exc:
                logger.warning("splunk.test_connection.failed", error_type=type(exc).__name__, error=str(exc))
                err_str = str(exc).lower()
                if "cert" in err_str or "ssl" in err_str or "handshake" in err_str:
                    return {"success": False, "connector": self.connector_id, "error": "Connection failed: SSL Certificate Verification Failed. Try unchecking 'Verify SSL certificate'."}
                return {"success": False, "connector": self.connector_id, "error": "Connection failed: Server unreachable or connection refused"}
            except Exception as exc:
                logger.warning("splunk.test_connection.failed", error_type=type(exc).__name__, error=str(exc))
                return {"success": False, "connector": self.connector_id, "error": f"Connection failed: {str(exc) or type(exc).__name__}"}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        earliest = f"-{max(1, int(since_seconds))}s"
        async with httpx.AsyncClient(timeout=60.0, verify=self._ssl_verify) as client:
            sid = await self._dispatch(client, earliest)
            if not sid:
                return []
            await self._await_job(client, sid)
            rows = await self._collect_results(client, sid)

        ordered = self._order_and_checkpoint(rows)
        return [self.normalize(r) for r in ordered]

    async def _dispatch(self, client: httpx.AsyncClient, earliest: str) -> str | None:
        """Kick off the search job and return its SID.

        Honors the configured saved search (#525): when ``saved_search`` names
        a real saved search we dispatch it via the dedicated endpoint with a
        URL-encoded name (never injecting the untrusted name into SPL) and
        override its time window. When it is empty or an ``index=`` expression
        we fall back to the original ad-hoc notable-index search.
        """
        ss = (self._saved_search or "").strip()
        if ss and not ss.startswith("index="):
            resp = await client.post(
                f"{self._base_url}/services/saved/searches/{quote(ss, safe='')}/dispatch",
                headers=self._headers(),
                data={
                    "output_mode": "json",
                    "dispatch.earliest_time": earliest,
                    "dispatch.latest_time": "now",
                    "trigger_actions": "0",
                },
            )
            resp.raise_for_status()
            return self._extract_sid(resp)

        index = ss[len("index=") :] if ss.startswith("index=") else "notable"
        resp = await client.post(
            f"{self._base_url}/services/search/jobs",
            headers=self._headers(),
            data={"search": f"search index={index} earliest={earliest}", "output_mode": "json"},
        )
        resp.raise_for_status()
        return self._extract_sid(resp)

    @staticmethod
    def _extract_sid(resp: httpx.Response) -> str | None:
        try:
            data = resp.json()
            if isinstance(data, dict) and data.get("sid"):
                return str(data["sid"])
        except (ValueError, KeyError):
            pass
        # The dispatch endpoint may answer with XML (<sid>…</sid>) despite
        # output_mode=json depending on Splunk version.
        match = re.search(r"<sid>([^<]+)</sid>", resp.text)
        return match.group(1) if match else None

    async def _await_job(self, client: httpx.AsyncClient, sid: str) -> str:
        for _ in range(_JOB_POLL_ATTEMPTS):
            resp = await client.get(
                f"{self._base_url}/services/search/jobs/{sid}",
                headers=self._headers(),
                params={"output_mode": "json"},
            )
            state = resp.json().get("entry", [{}])[0].get("content", {}).get("dispatchState", "")
            if state in ("DONE", "FAILED", "PAUSED"):
                return state
            await asyncio.sleep(_JOB_POLL_INTERVAL_S)
        return "TIMED_OUT"

    async def _collect_results(self, client: httpx.AsyncClient, sid: str) -> list[dict[str, Any]]:
        """Page through every result (#529) — no more silent ``head 100`` cap."""
        rows: list[dict[str, Any]] = []
        offset = 0
        for _ in range(_MAX_PAGES):
            resp = await client.get(
                f"{self._base_url}/services/search/jobs/{sid}/results",
                headers=self._headers(),
                params={"output_mode": "json", "count": self._page_size, "offset": offset},
            )
            resp.raise_for_status()
            page = resp.json().get("results", [])
            if not page:
                break
            rows.extend(page)
            if len(page) < self._page_size:
                break
            offset += len(page)
        return rows

    @staticmethod
    def _event_time(row: dict[str, Any]) -> str:
        return str(row.get("_time") or row.get("event_time") or "")

    @staticmethod
    def _event_tiebreak(row: dict[str, Any]) -> str:
        return str(row.get("event_id") or row.get("_cd") or "")

    def _order_and_checkpoint(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Sort by a stable (event_time, tie-breaker) tuple, drop anything at or
        before the incoming checkpoint (suppresses overlapping-window
        duplicates), and stage the advanced checkpoint for the scheduler."""
        ordered = sorted(rows, key=lambda r: (self._event_time(r), self._event_tiebreak(r)))
        cp = self._checkpoint or {}
        cp_key = (str(cp.get("time") or ""), str(cp.get("id") or ""))
        fresh: list[dict[str, Any]] = []
        for row in ordered:
            if cp_key[0] and (self._event_time(row), self._event_tiebreak(row)) <= cp_key:
                continue
            fresh.append(row)
        if fresh:
            last = fresh[-1]
            self._next_checkpoint = {"time": self._event_time(last), "id": self._event_tiebreak(last)}
        else:
            self._next_checkpoint = None
        return fresh

    async def query(self, unified: UnifiedQuery) -> list[dict[str, Any]]:
        """Run a translated SPL search and return raw rows.

        We deliberately do *not* call ``normalize`` here because federated
        search returns rows for analyst pivoting, not alerts that should
        flow into the fusion engine. The API layer wraps each row with
        connector identity so downstream consumers can tell sources apart.
        """
        index = self._saved_search if self._saved_search.startswith("index=") else "notable"
        spl = to_spl(unified, index=index)
        async with httpx.AsyncClient(timeout=60.0, verify=self._ssl_verify) as client:
            resp = await client.post(
                f"{self._base_url}/services/search/jobs",
                headers=self._headers(),
                data={"search": spl, "output_mode": "json", "exec_mode": "oneshot"},
            )
            resp.raise_for_status()
            return list(resp.json().get("results", []))

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        # Idempotency guard (#528): ``fetch_alerts`` already returns canonical
        # events, and the scheduler historically re-ran ``normalize`` on every
        # event. Re-normalizing a canonical envelope treated it as a raw Splunk
        # row (external_id -> "", title -> "splunk", severity -> medium,
        # nested raw_event). Detect the envelope and pass it straight through.
        if isinstance(raw, dict) and "raw_event" in raw and raw.get("source") == self.connector_id:
            return raw

        # Enrichment: pull ``_raw`` key=value tokens into the parsed dict so
        # nested Splunk payloads surface fields the flat access below can't see.
        parsed = dict(raw)
        _raw_str = str(raw.get("_raw", ""))
        if not _raw_str and isinstance(raw.get("raw_event"), dict):
            _raw_str = str(raw["raw_event"].get("_raw", ""))
        if _raw_str:
            for k, v in re.findall(r'([a-zA-Z0-9_\.]+)\s*=\s*\\?"?([^",\\]+)\\?"?', _raw_str):
                if k not in parsed or not parsed[k]:
                    parsed[k] = v.strip()

        # Prefer a stable vendor identifier so replays map to the same canonical
        # event ID downstream (#529). Emit it under both keys the ingest
        # normalizer understands.
        external_id = str(raw.get("event_id") or raw.get("_cd") or "")

        # Rule title (orig_rule_title preferred, falling back to search/rule).
        title = _clean_field(
            parsed.get("orig_rule_title")
            or parsed.get("orig_rule_name")
            or parsed.get("search_name")
            or parsed.get("rule_name")
            or parsed.get("signature")
            or parsed.get("source", "Splunk Notable Event")
        ) or "Splunk Notable Event"

        # Hostname (host_key / orig_host / entity / risk_object / dest).
        host_key = _clean_field(parsed.get("host_key"))
        dest = _clean_field(parsed.get("dest"))
        entity = _clean_field(parsed.get("entity"))
        risk_obj = _clean_field(parsed.get("risk_object"))
        orig_host = _clean_field(parsed.get("orig_host"))
        hostname = None
        for cand in (host_key, orig_host, entity, risk_obj, dest):
            if cand:
                c_clean = cand.split('"')[0].split(',')[0].strip()
                if c_clean and c_clean.lower() not in ("none", "null"):
                    hostname = c_clean
                    break

        # User, file hash, and domain.
        username = _clean_field(parsed.get("user") or parsed.get("orig_user") or parsed.get("src_user"))
        file_hash = parsed.get("hash") or parsed.get("orig_hash") or parsed.get("file_hash") or parsed.get("sha256")
        domain = parsed.get("domain") or parsed.get("dest_nt_domain")

        # IP addresses.
        src_ip = parsed.get("src") or parsed.get("orig_src") or parsed.get("src_ip") or parsed.get("srcip")
        dst_ip = parsed.get("dest_ip") or parsed.get("orig_dest") or parsed.get("dst_ip") or parsed.get("dstip")

        # MITRE ATT&CK (annotations.mitre_attack).
        mitre_tech = parsed.get("annotations.mitre_attack") or parsed.get("mitre_attack")
        mitre_techniques: list[str] = []
        if mitre_tech:
            if isinstance(mitre_tech, str):
                mitre_techniques = [mitre_tech]
            elif isinstance(mitre_tech, list):
                mitre_techniques = [str(x) for x in mitre_tech]

        # Severity via the shared urgency ladder, then a risk score.
        raw_sev = str(
            parsed.get("severity")
            or parsed.get("urgency")
            or parsed.get("severity_num")
            or ""
        ).strip().lower()
        raw_risk = parsed.get("risk_score") or parsed.get("crscore") or parsed.get("score")
        try:
            risk_score = min(float(raw_risk) / 100.0, 1.0) if raw_risk is not None else 0.0
        except (ValueError, TypeError):
            risk_score = 0.0

        description = (
            parsed.get("risk_message")
            or parsed.get("orig_rule_description")
            or parsed.get("description")
            or title
        )

        return {
            "source": self.connector_id,
            "external_id": external_id,
            "event_id": external_id,
            "title": title,
            "description": description,
            "severity": _SEVERITY_BY_URGENCY.get(raw_sev, "medium"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "hostname": hostname,
            "username": username,
            "file_hash": file_hash,
            "domain": domain,
            "url": parsed.get("url"),
            "mitre_techniques": mitre_techniques,
            "risk_score": risk_score,
            "raw_event": raw,
            "created_at": parsed.get("_time"),
        }
