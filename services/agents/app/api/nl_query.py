"""REST API inside the Agents service for natural-language query translation.

Exposes the native NL translation and LLM enhancement capabilities, leveraging the
native `app.llm` and `app.nl_query` packages that are fully bundled inside the
agents package.
"""

from __future__ import annotations

import json
import os
import textwrap
import structlog
from datetime import UTC, datetime
from typing import Literal
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.nl_query import NLQuery
from app.nl_query import translate as deterministic_translate
from app.llm.contract import safe_chat_completions_request

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/nl-query", tags=["nl_query"])


class NLQueryTranslateRequest(BaseModel):
    question: str = Field(
        ...,
        description="The plain-English security question to translate.",
    )
    index_pattern: str = Field("logs-*", description="Target index pattern.")
    time_range_hours: int = Field(24, ge=1, le=168, description="Time range in hours.")


class NLQueryTranslateResponse(BaseModel):
    esql: str
    spl: str
    kql: str
    explanation: str
    engine: Literal["deterministic", "llm"]


def _clean_json_content(content: str) -> str:
    """Strip markdown backticks (e.g. ```json ... ```) from LLM responses."""
    content = content.strip()
    if content.startswith("```"):
        first_newline = content.find("\n")
        if first_newline != -1:
            content = content[first_newline:].strip()
        if content.endswith("```"):
            content = content[:-3].strip()
    return content


@router.post(
    "/translate",
    response_model=NLQueryTranslateResponse,
    status_code=status.HTTP_200_OK,
    summary="Translate plain-English to KQL / SPL / ES|QL using native LLM or fallback",
)
async def translate_query(body: NLQueryTranslateRequest) -> NLQueryTranslateResponse:
    deterministic = deterministic_translate(
        body.question,
        index_pattern=body.index_pattern,
        time_range_hours=body.time_range_hours,
    )

    api_key = (
        os.getenv("OPENAI_API_KEY", "").strip()
        or os.getenv("LLM_API_KEY", "").strip()
    )

    # If no LLM key is configured, return the deterministic fallback immediately
    if not api_key:
        return NLQueryTranslateResponse(
            esql=deterministic.esql,
            spl=deterministic.spl,
            kql=deterministic.kql,
            explanation=deterministic.explanation,
            engine="deterministic",
        )

    # Resolve environment LLM parameters dynamically inside the agents container
    base_url = (
        os.getenv("OPENAI_BASE_URL", "").strip()
        or os.getenv("LLM_BASE_URL", "").strip()
        or "https://api.openai.com/v1"
    )
    url = f"{base_url.rstrip('/')}/chat/completions"

    model = (
        os.getenv("LLM_MODEL", "").strip()
        or os.getenv("OPENAI_MODEL", "").strip()
        or "gpt-4o-mini"
    )

    prompt = textwrap.dedent(
        f"""
        Translate the following security question into ES|QL, KQL, and SPL.
        Return JSON only with keys esql, kql, spl, explanation.

        Question: {body.question}
        Index: {body.index_pattern}
        Time range: last {body.time_range_hours} hours
        """
    ).strip()

    messages = [
        {"role": "system", "content": "You translate security questions into queries."},
        {"role": "user", "content": prompt},
    ]

    try:
        # Use native app.llm with the correct custom URL and model configurations
        # We omit response_format because the KT Cloud proxy server returns 404
        # if JSON mode is requested explicitly.
        logger.info(
            "Issuing LLM safe_chat_completions_request",
            url=url,
            model=model,
            api_key=api_key[:10] if api_key else None,
        )
        payload = await safe_chat_completions_request(
            api_key=api_key,
            model=model,
            messages=messages,
            url=url,
            timeout=15.0,
            temperature=0,
        )
        content = payload["choices"][0]["message"]["content"]
        
        cleaned = _clean_json_content(content)
        parsed = json.loads(cleaned)

        esql = str(parsed.get("esql", "")).strip()
        kql = str(parsed.get("kql", "")).strip()
        spl = str(parsed.get("spl", "")).strip()

        if esql or kql or spl:
            return NLQueryTranslateResponse(
                esql=esql or deterministic.esql,
                kql=kql or deterministic.kql,
                spl=spl or deterministic.spl,
                explanation=str(parsed.get("explanation", deterministic.explanation)),
                engine="llm",
            )

    except Exception as exc:
        # If the LLM call fails, we gracefully degrade to the deterministic fallback
        logger.warning(
            "NL translation LLM call failed",
            error=str(exc),
        )

    return NLQueryTranslateResponse(
        esql=deterministic.esql,
        spl=deterministic.spl,
        kql=deterministic.kql,
        explanation=deterministic.explanation,
        engine="deterministic",
    )
