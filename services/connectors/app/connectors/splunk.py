"""
Splunk connector.
Runs saved searches and fetches notable events from Splunk SIEM.
"""

from __future__ import annotations

import re
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field
from app.federated.query import UnifiedQuery
from app.federated.translators import to_spl

logger = structlog.get_logger()


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
        **kwargs: Any,
    ):
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._saved_search = saved_search
        self._ssl_verify = ssl_verify

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
        search_query = f"search index=notable earliest=-{since_seconds}s | head 100"

        async with httpx.AsyncClient(timeout=60.0, verify=self._ssl_verify) as client:
            resp = await client.post(
                f"{self._base_url}/services/search/jobs",
                headers=self._headers(),
                data={"search": search_query, "output_mode": "json", "exec_mode": "oneshot"},
            )
            resp.raise_for_status()
            results = resp.json().get("results", [])

        return [self.normalize(r) for r in results]

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
        urgency_map = {                                                                                    
            "critical": "critical",                                                                        
            "high": "high",                                                                                
            "medium": "medium",                                                                            
            "low": "low",                                                                                  
            "informational": "info",                                                                       
            "info": "info",                                                                                
            "7": "critical",                                                                               
            "6": "high",                                                                                   
            "5": "high",                                                                                   
            "4": "medium",                                                                                 
            "3": "medium",                                                                                 
            "2": "low",                                                                                    
            "1": "info",                                                                                   
        }                                                                                                  
                                                                                                            
        # 1. raw 객체 및 _raw 텍스트 추출 (중첩 구조 대비)                                                 
        parsed = dict(raw)                                                                                 
        _raw_str = str(raw.get("_raw", ""))                                                                
        if not _raw_str and isinstance(raw.get("raw_event"), dict):                                        
            _raw_str = str(raw["raw_event"].get("_raw", ""))                                               
                                                                                                            
        # 2. _raw 텍스트 내부의 key="value" 또는 key=value 자동 정규식 파싱                                
        if _raw_str:                                                                                       
            for k, v in re.findall(r'([a-zA-Z0-9_\.]+)\s*=\s*\\?"?([^",\\]+)\\?"?', _raw_str):             
                if k not in parsed or not parsed[k]:                                                       
                    parsed[k] = v.strip()                                                                  
                                                                                                            
        # 3. 룰 제목 추출 (orig_rule_title 최우선 채택)
        title = _clean_field(
            parsed.get("orig_rule_title")
            or parsed.get("orig_rule_name")
            or parsed.get("search_name")
            or parsed.get("rule_name")
            or parsed.get("signature")
            or parsed.get("source", "Splunk Notable Event")
        ) or "Splunk Notable Event"

        # 4. Hostname (host_key / orig_host / entity / risk_object / dest)
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

        # 5. Username, Hash, Domain
        username = _clean_field(parsed.get("user") or parsed.get("orig_user") or parsed.get("src_user"))                 
        file_hash = parsed.get("hash") or parsed.get("orig_hash") or parsed.get("file_hash") or parsed.get("sha256")                                                                                         
        domain = parsed.get("domain") or parsed.get("dest_nt_domain")                                      
                                                                                                            
        # 6. IP 주소                                                                                       
        src_ip = parsed.get("src") or parsed.get("orig_src") or parsed.get("src_ip") or parsed.get("srcip")                      
        dst_ip = parsed.get("dest_ip") or parsed.get("orig_dest") or parsed.get("dst_ip") or parsed.get("dstip")                  
                                                                                                            
        # 7. MITRE ATT&CK (annotations.mitre_attack)                                                       
        mitre_tech = parsed.get("annotations.mitre_attack") or parsed.get("mitre_attack")                  
        mitre_techniques = []                                                                              
        if mitre_tech:                                                                                     
            if isinstance(mitre_tech, str):                                                                
                mitre_techniques = [mitre_tech]                                                            
            elif isinstance(mitre_tech, list):                                                             
                mitre_techniques = [str(x) for x in mitre_tech]                                            
                                                                                                            
        # 8. Severity & Risk Score                                                                         
        raw_sev = str(                                                                                     
            parsed.get("severity")                                                                         
            or parsed.get("urgency")                                                                       
            or parsed.get("severity_num")                                                                  
            or ""                                                                                          
        ).strip().lower()                                                                                  
                                                                                                            
        raw_risk = (
            parsed.get("risk_score")
            or parsed.get("crscore")
            or parsed.get("score")
        )
        try:
            risk_score = min(float(raw_risk) / 100.0, 1.0) if raw_risk is not None else 0.0
        except (ValueError, TypeError):
            risk_score = 0.0                                                                               
                                                                                                            
        # 9. 고유 ID                                                                                       
        ext_id = (                                                                                         
            parsed.get("source_event_id")                                                                  
            or parsed.get("event_id")                                                                      
            or parsed.get("_cd")                                                                           
            or f"{parsed.get('_time', '')}_{title}_{hostname}"                                             
        )                                                                                                  
                                                                                                            
        description = (                                                                                    
            parsed.get("risk_message")                                                                     
            or parsed.get("orig_rule_description")                                                         
            or parsed.get("description")                                                                   
            or title                                                                                       
        )                                                                                                  
                                                                                                            
        return {                                                                                           
            "source": self.connector_id,                                                                   
            "external_id": ext_id,                                                                         
            "title": title,                                                                                
            "description": description,                                                                    
            "severity": urgency_map.get(raw_sev, "high"),                                                  
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
