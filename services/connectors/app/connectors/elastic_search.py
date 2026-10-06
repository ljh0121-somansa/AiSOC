"""
Elastic SIEM connector.

Federated-search-first: the Elastic deployments most AiSOC customers run today
already have their own native dashboards and pipelines for alert ingestion, so
this connector exists primarily to give the federated layer a way to run ES|QL
against the customer's existing Elasticsearch cluster without exfiltrating logs
into AiSOC's own data plane.

``fetch_alerts`` is intentionally a thin wrapper over ES|QL on the
``.alerts-security.alerts-*`` index pattern so a tenant who *does* want
Elastic-side alerts to flow into the fusion engine can opt in by enabling the
connector's poll schedule.
"""

from __future__ import annotations

import base64
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field
from app.federated.query import UnifiedQuery
from app.federated.translators import to_esql

logger = structlog.get_logger()


_EVENT_TYPE_MAP = {
    "firewall": "network",
    "auth": "authentication",
    "authentication": "authentication",
    "dns": "network",
    "process": "process",
    "login": "authentication",
}


def _event_type(event: dict[str, Any], raw: dict[str, Any]) -> str | None:
    """Normalized event_type for windowed detection rules.

    Falls back to ``event.category`` / a flat ``event_type`` key so a payload
    that names its category still maps onto the field rules key on (e.g. a
    ``firewall`` category becomes ``network`` for the port-scan rule).
    """
    if isinstance(event.get("type"), str) and event.get("type"):
        return event["type"]
    cat = str(event.get("category") or raw.get("event.category") or "").lower()
    if cat in _EVENT_TYPE_MAP:
        return _EVENT_TYPE_MAP[cat]
    return cat or None


class ElasticSearchConnector(BaseConnector):
    connector_id = "elastic_search"
    connector_name = "Elastic Search"
    connector_category = "database"
    supports_federated_search = True

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="Elasticsearch REST Search API. Acts as a high-performance log datastore for federated search.",
            docs_url="/docs/connectors/elastic_search",
            fields=[
                Field(
                    "base_url",
                    "string",
                    "Elasticsearch URL",
                    placeholder="https://elastic.example.com:9200",
                    help_text="Cluster endpoint",
                ),
                Field("api_key", "secret", "API Key", required=False),
                Field("username", "string", "Username", required=False),
                Field("password", "secret", "Password", required=False),
                Field(
                    "index",
                    "string",
                    "Default Index Pattern",
                    required=False,
                    default="firewall-logs",
                ),
                Field(
                    "ssl_verify",
                    "boolean",
                    "Verify SSL certificate",
                    required=False,
                    default=True,
                    help_text="Disable only for self-signed certificates in private deployments.",
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Elastic SIEM exposes detection alerts plus an ES|QL search surface
        # we federate against — the latter maps cleanly to QUERY_LOGS.
        # WS-E6: Live Elastic Security / Elasticsearch response actions now wired
        # via services/actions/app/clients/elastic_client.py
        return (
            Capability.PULL_ALERTS,
            Capability.QUERY_LOGS,
            Capability.SEARCH_SIEM,
            Capability.SYNC_DETECTION_RULE,
            Capability.UPDATE_WATCHER,
        )

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        username: str | None = None,
        password: str | None = None,
        index: str = "firewall-logs",
        ssl_verify: bool = True,
    ):
        if not api_key and not (username and password):
            raise ValueError("Elastic Search connector requires either api_key or username+password")

        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._username = username
        self._password = password
        self._index = index
        self._ssl_verify = ssl_verify

    def _headers(self) -> dict[str, str]:
        if self._api_key:
            return {
                "Authorization": f"ApiKey {self._api_key}",
                "Content-Type": "application/json",
            }
        # Basic auth fallback for older self-hosted deployments.
        token = base64.b64encode(f"{self._username}:{self._password}".encode()).decode()
        return {
            "Authorization": f"Basic {token}",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15.0, verify=self._ssl_verify) as client:
            try:
                resp = await client.get(f"{self._base_url}/", headers=self._headers())
                resp.raise_for_status()
                info = resp.json()
                return {
                    "success": True,
                    "connector": self.connector_id,
                    "version": info.get("version", {}).get("number"),
                    "cluster_name": info.get("cluster_name"),
                }
            except Exception as exc:
                logger.warning("elastic_search.test_connection.failed", error_type=type(exc).__name__)
                return {"success": False, "connector": self.connector_id, "error": "Connection failed"}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        # Poll the configured index (default: firewall-logs) for recent events.
        esql = f"FROM {self._index} | WHERE @timestamp > NOW() - {since_seconds} seconds | LIMIT 200"
        async with httpx.AsyncClient(timeout=60.0, verify=self._ssl_verify) as client:
            resp = await client.post(
                f"{self._base_url}/_query",
                headers=self._headers(),
                json={"query": esql},
            )
            resp.raise_for_status()
            data = resp.json()

        rows = self._rows_from_esql(data)
        return [self.normalize(r) for r in rows]

    async def query(self, unified: UnifiedQuery) -> list[dict[str, Any]]:
        """Run a translated ES|QL query and return raw rows.

        Mirrors the Splunk and Sentinel implementations: rows go back to the
        API layer untouched so the federated merger can tag each one with the
        originating connector id.
        """
        esql = to_esql(unified, index=self._index)
        async with httpx.AsyncClient(timeout=60.0, verify=self._ssl_verify) as client:
            resp = await client.post(
                f"{self._base_url}/_query",
                headers=self._headers(),
                json={"query": esql},
            )
            resp.raise_for_status()
            data = resp.json()
        return self._rows_from_esql(data)

    @staticmethod
    def _rows_from_esql(data: dict[str, Any]) -> list[dict[str, Any]]:
        """Flatten the ES|QL ``columns``/``values`` shape into row dicts.

        ES|QL responses look like::

            {
              "columns": [{"name": "@timestamp", "type": "date"}, ...],
              "values": [["2026-05-01T00:00:00Z", ...], ...]
            }

        We zip them together so the API layer never has to know the shape.
        """
        columns = [c.get("name") for c in data.get("columns", [])]
        values = data.get("values", [])
        return [dict(zip(columns, row, strict=False)) for row in values]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:

        severity_map = {
            "trace": "info", "debug": "info", "info": "info", "informational": "info", "notice": "info",
            "warn": "medium", "warning": "medium", "low": "low", "medium": "medium",
            "err": "high", "error": "high", "high": "high",
            "crit": "critical", "critical": "critical", "alert": "critical", "emerg": "critical", "fatal": "critical",
        }
        # ECS telemetry arrives nested (source.ip, destination.port, event.action, ...),
        # but the AiSOC detection matcher only sees flat top-level keys, so re-key every
        # nested ECS field into a top-level alert field. Fall back to a flat dotted key
        # for deployments that already emit a flat shape.

        def _nested(*keys):
            cur = raw
            for k in keys:
                if not isinstance(cur, dict):
                    return None
                cur = cur.get(k)

        def _flat(*keys):
            # Same precedence as `_nested`, but reading a flat dotted key
            # (``source.ip``) for deployments that already emit a flat shape.
            for k in keys:
                if k in raw and raw.get(k) is not None:
                    return raw.get(k)
            return None

        event = raw.get("event") if isinstance(raw.get("event"), dict) else {}
        source = raw.get("source") if isinstance(raw.get("source"), dict) else {}
        destination = raw.get("destination") if isinstance(raw.get("destination"), dict) else {}
        network = raw.get("network") if isinstance(raw.get("network"), dict) else {}
        rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
        host = raw.get("host") if isinstance(raw.get("host"), dict) else {}
        log = raw.get("log") if isinstance(raw.get("log"), dict) else {}

        raw_severity = str(
            raw.get("log.level") or log.get("level") or event.get("severity_label") or _flat("event.severity_label") or raw.get("level") or event.get("severity") or _flat("event.severity") or "info"
        ).lower()

        mitre_techniques = event.get("threat_technique_ids") or event.get("threat.technique.id") or raw.get("threat.technique.id") or []

        return {
            "source": self.connector_id,
            "external_id": str(event.get("id") or raw.get("_id") or f"{rule.get('id') or ''}@{raw.get('@timestamp') or ''}"),
            "title": str(raw.get("message") or event.get("action") or "Elasticsearch Event")[:100],
            "description": str(log.get("original") or raw.get("message") or ""),
            # Native severity preserved (no forced low): genuine high/critical
            # firewall events auto-promote via the severity_id>=4 gate;
            # low/medium fall through to the AiSOC detection ruleset.
            "severity": severity_map.get(raw_severity, "medium"),
            "src_ip": source.get("ip") or _nested("client", "ip") or _flat("source.ip", "client.ip"),
            "dst_ip": destination.get("ip") or _nested("server", "ip") or _flat("destination.ip", "server.ip"),
            "dst_port": destination.get("port") or _flat("destination.port"),
            "src_geo": source.get("country_iso_code"),
            "hostname": host.get("name") or host.get("hostname") or _flat("host.name"),
            "network_transport": network.get("transport") or _flat("network.transport"),
            "network_protocol": network.get("protocol") or _flat("network.protocol"),
            "rule_id": rule.get("id") or _flat("rule.id"),
            "rule_name": rule.get("name") or _flat("rule.name"),
            "event_action": event.get("action") or _flat("event.action"),
            "event_dataset": event.get("dataset") or _flat("event.dataset"),
            # Windowed detection rules (brute-force, spray, port-scan) key on
            # these top-level keys, so publish a normalized event_type/outcome
            # even when the raw payload lacks them.
            "event_type": _event_type(event, raw),
            "outcome": event.get("outcome") or None,
            "user": event.get("actor", {}).get("name") or source.get("user"),
            "mitre_techniques": mitre_techniques if isinstance(mitre_techniques, list) else [mitre_techniques],
            "risk_score": event.get("risk_score") or 0,
            "raw_event": raw,
            "created_at": raw.get("@timestamp") or event.get("ingested"),
        }
