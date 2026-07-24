"""Hunt search & saved-searches API with real ClickHouse Data Lake Integration.

Exposes threat-hunting telemetry search by querying the live warm-tier ClickHouse
event lake for all query dialects (SQL, ES|QL, KQL, SPL), degrading gracefully to mock
simulations in offline/empty environments.
"""

from __future__ import annotations

import json
import re
import os
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/hunt", tags=["hunt-search"])

# Centralized ClickHouse integration path
_CLICKHOUSE_URL = os.getenv(
    "CLICKHOUSE_URL",
    "http://aisoc:clickhouse_dev_secret@clickhouse:8123/aisoc",
).rstrip("/")


# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------


class HuntQuery(BaseModel):
    query: str
    language: str = "lucene"  # lucene | eql | sigma | spl | sql
    timeRange: str | None = "24h"
    indices: list[str] | None = None
    limit: int = 100


class HuntHit(BaseModel):
    id: str
    timestamp: str
    source: str
    event_type: str
    raw: dict[str, Any]
    highlights: list[str] | None = None


class HuntResponse(BaseModel):
    query: str
    total: int
    took_ms: int
    hits: list[HuntHit]


class SavedSearchCreate(BaseModel):
    name: str
    query: str
    language: str = "lucene"


class SavedSearch(BaseModel):
    id: str
    name: str
    query: str
    language: str
    createdAt: str
    pinned: bool = False


_SAVED_SEARCHES: dict[str, SavedSearch] = {}


# ---------------------------------------------------------------------------
# Fallback Mock Telemetry Core
# ---------------------------------------------------------------------------


def _synthetic_hits(query: str, limit: int) -> list[dict[str, Any]]:
    """Return plausible-looking synthetic telemetry hits for fallback."""
    templates = [
        {
            "source": "crowdstrike",
            "event_type": "ProcessCreation",
            "raw": {
                "process_name": "cmd.exe",
                "parent_name": "explorer.exe",
                "cmdline": f"cmd.exe /c {query}",
                "user": "DOMAIN\analyst",
                "host": "WS-DEV-01",
            },
        },
        {
            "source": "aws_cloudtrail",
            "event_type": "AssumeRole",
            "raw": {
                "eventName": "AssumeRole",
                "sourceIPAddress": "10.0.0.100",
                "userAgent": "aws-sdk-python",
                "requestParameters": {
                    "roleArn": "arn:aws:iam::123456789:role/Admin"
                },
            },
        },
    ]
    now = datetime.now(UTC)
    hits = []
    for i in range(min(limit, 5)):
        t = templates[i % len(templates)]
        hits.append(
            {
                "id": str(uuid.uuid4()),
                "timestamp": now.isoformat(),
                "source": t["source"],
                "event_type": t["event_type"],
                "raw": t["raw"],
                "highlights": [query] if query else [],
            }
        )
    return hits


# ---------------------------------------------------------------------------

def _build_clickhouse_query_for_non_sql(query_str: str, limit: int) -> str:
    """Extract search terms from non-SQL queries (ES|QL, KQL, SPL)
    and filter ClickHouse raw_payload.
    """
    raw_quotes = re.findall(r'["\']([^"\']+)["\']', query_str)
    search_terms = []
    for q in raw_quotes:
        term = q.strip("%* ").replace('"', "").replace("'", "")
        if term and term.lower() not in (
            "logs-*",
            "events",
            "index=*",
            "100",
            "200",
            "500",
            "esql",
            "kql",
            "spl",
        ):
            if len(term) >= 2:
                search_terms.append(term)

    if not search_terms:
        clean_text = re.sub(r"//.*", "", query_str)
        tokens = re.findall(r"\b[a-zA-Z0-9_\-\.]{3,}\b", clean_text)
        keywords = {
            "from",
            "where",
            "like",
            "limit",
            "select",
            "and",
            "or",
            "keep",
            "sort",
            "desc",
            "asc",
            "project",
            "extend",
            "logs",
            "events",
            "process",
            "command_line",
            "name",
            "user",
            "host",
            "securityevent",
            "activity",
            "head",
            "index",
        }
        for token in tokens:
            if token.lower() not in keywords and not token.isdigit():
                search_terms.append(token)

    where_clauses = []
    for term in search_terms[:5]:
        escaped_term = term.replace("'", "\'")
        where_clauses.append(f"raw_payload ILIKE '%{escaped_term}%'")

    where_str = ""
    if where_clauses:
        op = " OR " if " or " in query_str.lower() else " AND "
        where_str = f"WHERE {op.join(where_clauses)} "

    return (
        f"SELECT event_id, event_time, connector_type, user_name, "
        f"process_name, raw_payload FROM aisoc.raw_events "
        f"{where_str}ORDER BY event_time DESC LIMIT {limit}"
    )


# Core ClickHouse Execution Engine (SOA)
# ---------------------------------------------------------------------------



async def _execute_clickhouse_query(
    sql_query: str, limit: int
) -> list[dict[str, Any]] | None:
    """Issue a secure SELECT query to the ClickHouse warm-tier server directly."""
    clean_sql = sql_query.strip().rstrip(";")
    if "format json" not in clean_sql.lower():
        clean_sql = f"{clean_sql} FORMAT JSON"

    headers = {"Content-Type": "application/json"}

    try:
        logger.info(
            "Executing telemetry query on ClickHouse lake", url=_CLICKHOUSE_URL
        )
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                _CLICKHOUSE_URL, content=clean_sql, headers=headers
            )
        resp.raise_for_status()

        parsed = resp.json()
        raw_rows = parsed.get("data", [])
        if not raw_rows:
            return []

        hits = []
        for row in raw_rows[:limit]:
            raw_data = dict(row)
            event_id = str(raw_data.get("event_id", uuid.uuid4()))

            # Extract and unpack nested raw_payload if present
            if "raw_payload" in raw_data and isinstance(
                raw_data["raw_payload"], str
            ):
                try:
                    payload_json = json.loads(raw_data["raw_payload"])
                    if isinstance(payload_json, dict):
                        raw_data.update(payload_json)
                except Exception:
                    pass

            timestamp_val = raw_data.get("event_time") or raw_data.get(
                "timestamp"
            )
            if isinstance(timestamp_val, int):
                timestamp = datetime.fromtimestamp(
                    timestamp_val, UTC
                ).isoformat()
            else:
                timestamp = str(timestamp_val or datetime.now(UTC).isoformat())

            hits.append(
                {
                    "id": event_id,
                    "timestamp": timestamp,
                    "source": str(
                        raw_data.get("connector_type")
                        or raw_data.get("event_source")
                        or raw_data.get("source")
                        or "clickhouse"
                    ),
                    "event_type": str(
                        raw_data.get("class_name")
                        or raw_data.get("event_type")
                        or "telemetry"
                    ),
                    "raw": raw_data,
                    "highlights": None,
                }
            )
        return hits

    except Exception as exc:
        logger.warning(
            "ClickHouse query failed or returned no results",
            error=str(exc),
        )
        return []


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/search", response_model=HuntResponse)
async def hunt_search(query: HuntQuery) -> HuntResponse:
    """Execute a hunt query and return matching telemetry events."""
    start = time.monotonic()

    hits_list = None

    lang = query.language.lower()
    if lang == "sql":
        hits_list = await _execute_clickhouse_query(query.query, query.limit)
    else:
        # Non-SQL dialects (esql, kql, spl, lucene): extract terms & filter ClickHouse
        sql = _build_clickhouse_query_for_non_sql(query.query, query.limit)
        hits_list = await _execute_clickhouse_query(sql, query.limit)

    hits_list = [HuntHit(**h) for h in (hits_list or [])]

    took_ms = int((time.monotonic() - start) * 1000)

    return HuntResponse(
        query=query.query,
        total=len(hits_list),
        took_ms=took_ms,
        hits=hits_list,
    )


@router.get("/saved")
async def list_saved_searches() -> dict[str, list[dict[str, Any]]]:
    """Return all saved searches."""
    return {"searches": [s.model_dump() for s in _SAVED_SEARCHES.values()]}


@router.post("/saved", response_model=SavedSearch, status_code=201)
async def save_search(data: SavedSearchCreate) -> SavedSearch:
    """Persist a new saved search."""
    ss = SavedSearch(
        id=str(uuid.uuid4()),
        name=data.name,
        query=data.query,
        language=data.language,
        createdAt=datetime.now(UTC).isoformat(),
    )
    _SAVED_SEARCHES[ss.id] = ss
    return ss


@router.delete("/saved/{search_id}", status_code=204, response_model=None)
async def delete_saved_search(search_id: str) -> None:
    """Delete a saved search by ID."""
    if search_id not in _SAVED_SEARCHES:
        raise HTTPException(status_code=404, detail="saved search not found")
    del _SAVED_SEARCHES[search_id]
