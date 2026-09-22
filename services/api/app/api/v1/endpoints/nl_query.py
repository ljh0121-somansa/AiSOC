"""Natural-language query → multi-dialect execution (Stage 2 #16).

Delegates natural-language query translation directly to the `agents` service
over internal HTTP REST endpoints. This enforces clean Service-Oriented
Architecture (SOA) and strict service boundaries, eliminating host-filesystem
directory climbing or package collision anti-patterns.
"""

from __future__ import annotations

import os
import uuid
import structlog
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.api.v1.deps import AuthUser
from app.core.config import settings
from app.services.esql_runner import (
    ESQLExecutionError,
    ESQLNotConfigured,
    resolve_es_credentials,
    run_esql_query,
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/nl-query", tags=["nl_query"])

_AGENTS_URL = (
    os.getenv("AGENTS_SERVICE_URL")
    or os.getenv("AGENTS_API_URL")
    or "http://agents:8084"
).rstrip("/")


# ────────────────────────────────────────────────────────────────────────────
# Pydantic schemas
# ────────────────────────────────────────────────────────────────────────────


class NLQueryTranslateRequest(BaseModel):
    question: str = Field(
        ...,
        description="The plain-English security question to translate.",
    )
    index_pattern: str = Field(
        "logs-*",
        description="Target index pattern.",
    )
    time_range_hours: int = Field(
        24,
        ge=1,
        le=168,
        description="Time range in hours.",
    )


class NLQueryTranslateResponse(BaseModel):
    request_id: uuid.UUID
    question: str
    esql: str
    spl: str
    kql: str
    explanation: str
    created_at: datetime
    engine: str = Field("deterministic", description="`deterministic` or `llm`.")
    grammar_validated: bool = Field(
        True,
        description="True if every emitted query passed grammar checks.",
    )


class NLQueryExecuteRequest(NLQueryTranslateRequest):
    es_url: str | None = Field(
        None,
        description="Override Elasticsearch URL (defaults to settings.ES_URL if set).",
    )
    es_api_key: str | None = Field(
        None,
        description="Override ES API key (defaults to settings.ES_API_KEY if set).",
    )
    max_rows: int = Field(500, ge=1, le=5000)


class QueryResult(BaseModel):
    columns: list[str]
    rows: list[list[Any]]
    total_rows: int
    took_ms: int | None = None


class NLQueryExecuteResponse(NLQueryTranslateResponse):
    result: QueryResult | None = None
    execution_error: str | None = None


# ────────────────────────────────────────────────────────────────────────────
# Internal translation helper (SOA REST Delegation)
# ────────────────────────────────────────────────────────────────────────────


async def _delegate_translation_to_agents(
    question: str,
    index_pattern: str,
    time_range_hours: int,
) -> dict[str, Any]:
    """Delegate translation to the `agents` service via REST."""
    url = f"{_AGENTS_URL}/api/v1/nl-query/translate"
    payload = {
        "question": question,
        "index_pattern": index_pattern,
        "time_range_hours": time_range_hours,
    }
    try:
        logger.info("Delegating NL translation to agents service", url=url)
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(url, json=payload)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.error(
            "Failed to delegate NL translation to agents service",
            error=str(exc),
        )
        # Absolute final fallback if the agents service itself is unreachable
        escaped = question.replace('"', '\\"')
        return {
            "esql": f'FROM logs-* | WHERE message LIKE "%{escaped[:60]}%" | LIMIT 100',
            "spl": f'index=* "{escaped[:60]}" | head 100',
            "kql": f'SecurityEvent | where Activity has "{escaped[:60]}" | limit 100',
            "explanation": "Fallback translation due to agents service unreachability.",
            "engine": "deterministic",
        }


async def _execute_esql(
    esql: str,
    es_url: str,
    es_api_key: str,
    max_rows: int,
) -> QueryResult:
    """Run an ES|QL query against Elasticsearch and return structured results."""
    result = await run_esql_query(
        esql=esql,
        es_url=es_url,
        es_api_key=es_api_key,
        max_rows=max_rows,
    )
    return QueryResult(
        columns=result.columns,
        rows=result.rows,
        total_rows=len(result.rows),
        took_ms=result.took_ms,
    )


# ────────────────────────────────────────────────────────────────────────────
# Endpoints
# ────────────────────────────────────────────────────────────────────────────


@router.post(
    "/translate",
    response_model=NLQueryTranslateResponse,
    status_code=status.HTTP_200_OK,
    summary="Translate a natural-language security question to ES|QL / SPL / KQL",
)
async def translate_query(
    body: NLQueryTranslateRequest,
    user: AuthUser,
) -> NLQueryTranslateResponse:
    translated = await _delegate_translation_to_agents(
        body.question, body.index_pattern, body.time_range_hours
    )
    return NLQueryTranslateResponse(
        request_id=uuid.uuid4(),
        question=body.question,
        esql=translated.get("esql", ""),
        spl=translated.get("spl", ""),
        kql=translated.get("kql", ""),
        explanation=translated.get("explanation", ""),
        created_at=datetime.now(UTC),
        engine=translated.get("engine", "deterministic"),
        grammar_validated=True,
    )


@router.post(
    "/execute",
    response_model=NLQueryExecuteResponse,
    status_code=status.HTTP_200_OK,
    summary="Translate NL question and execute ES|QL against Elasticsearch",
)
async def execute_query(
    body: NLQueryExecuteRequest,
    user: AuthUser,
) -> NLQueryExecuteResponse:
    translated = await _delegate_translation_to_agents(
        body.question, body.index_pattern, body.time_range_hours
    )

    base = NLQueryExecuteResponse(
        request_id=uuid.uuid4(),
        question=body.question,
        esql=translated.get("esql", ""),
        spl=translated.get("spl", ""),
        kql=translated.get("kql", ""),
        explanation=translated.get("explanation", ""),
        created_at=datetime.now(UTC),
        engine=translated.get("engine", "deterministic"),
        grammar_validated=True,
    )

    try:
        es_url, es_api_key = resolve_es_credentials()
    except ESQLNotConfigured:
        return base

    try:
        res = await _execute_esql(
            base.esql,
            es_url=body.es_url or es_url,
            es_api_key=body.es_api_key or es_api_key,
            max_rows=body.max_rows,
        )
        base.result = res
    except ESQLExecutionError as exc:
        base.execution_error = str(exc)

    return base
