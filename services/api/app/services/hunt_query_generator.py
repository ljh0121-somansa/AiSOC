"""Hunt Query Generation Service (Tiered AI & Deterministic Fallback).

Implements the Single Responsibility Principle (SRP) by separating the
natural-language-to-query translation logic from the HTTP endpoints.

Tiered Execution Model:
- Tier 1: Public Cloud LLM (OpenAI, Anthropic, etc. outbound)
- Tier 2: Private / Local LLM (KT Cloud Qwen, On-Premise Ollama,
          LiteLLM, vLLM via allowed private endpoints)
- Tier 3: Deterministic Fallback (regex/string-matching based KQL, SPL, ES|QL template)

Integrates with the platform's standard `resolve_llm_config` resolver to respect
multi-tenant BYOK credentials, environment baselines, and air-gap policies.
"""

from __future__ import annotations

import json
import uuid
import httpx
import structlog
from typing import Any, TypedDict
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.llm_resolver import resolve_llm_config

# Use structlog to ensure safety with arbitrary keyword arguments in logs
logger = structlog.get_logger(__name__)

_HUNT_SYSTEM = """You are a senior threat hunter. Given a threat hypothesis, generate
detection queries for the listed platforms.

Return ONLY valid JSON with this structure:
{
  "esql": "<ES|QL query string>",
  "spl": "<Splunk SPL string>",
  "kql": "<KQL string>"
}
No prose. Just JSON."""


class GeneratedQueriesResult(TypedDict):
    esql: str
    spl: str
    kql: str
    query_generation_mode: str  # "ai" | "fallback"
    warnings: str | None


def _fallback_queries(hypothesis: str) -> dict[str, str]:
    escaped = hypothesis.replace('"', '\\"')
    return {
        "esql": f'FROM logs-* | WHERE message LIKE "%{escaped[:60]}%" | LIMIT 100',
        "spl": f'index=* "{escaped[:60]}" | head 100',
        "kql": (
            "// KQL hunt — adapt field names\n"
            "SecurityEvent\n"
            f'| where Activity has "{escaped[:60]}"\n'
            "| limit 100"
        ),
    }


def _clean_json_content(content: str) -> str:
    """Strip markdown backticks (e.g. ```json ... ```) from LLM responses
    before parsing.
    """
    content = content.strip()
    if content.startswith("```"):
        # Strip leading ```json or ```
        first_newline = content.find("\n")
        if first_newline != -1:
            content = content[first_newline:].strip()
        # Strip trailing ```
        if content.endswith("```"):
            content = content[:-3].strip()
    return content


async def generate_queries_tiered(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    hypothesis: str,
    mitre: str | None = None,
) -> GeneratedQueriesResult:
    """Generate platform-specific queries using a 3-tier strategy.

    Uses resolve_llm_config to determine whether AI generation is allowed (taking
    into account multi-tenant BYOK, air-gap, and environment variables).
    """
    # Standard configuration resolution using existing platform logic
    llm_config = await resolve_llm_config(db, tenant_id)

    if llm_config.allowed and llm_config.api_key:
        completions_url = f"{llm_config.base_url.rstrip('/')}/chat/completions"
        user_msg = f"HYPOTHESIS: {hypothesis}"
        if mitre:
            user_msg += f"\nMITRE TECHNIQUE: {mitre}"
        user_msg += "\nGenerate ES|QL, SPL, and KQL hunt queries."

        try:
            logger.info(
                "Attempting LLM query generation",
                url=completions_url,
                model=llm_config.model,
                source=llm_config.source,
            )
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    completions_url,
                    headers={"Authorization": f"Bearer {llm_config.api_key}"},
                    json={
                        "model": llm_config.model,
                        "messages": [
                            {"role": "system", "content": _HUNT_SYSTEM},
                            {"role": "user", "content": user_msg},
                        ],
                        "temperature": 0.2,
                        "response_format": {"type": "json_object"},
                    },
                )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]

            # Defensive cleaning of potential markdown wrapping inside content
            cleaned_content = _clean_json_content(content)
            parsed = json.loads(cleaned_content)

            # Ensure all required fields exist in parsed JSON
            esql = parsed.get("esql", "")
            spl = parsed.get("spl", "")
            kql = parsed.get("kql", "")

            if esql or spl or kql:
                return {
                    "esql": esql,
                    "spl": spl,
                    "kql": kql,
                    "query_generation_mode": "ai",
                    "warnings": None,
                }
            else:
                logger.warning("LLM returned empty query fields. Triggering fallback.")

        except Exception as exc:
            # Captures network timeouts, service down, JSON decode errors, etc.
            logger.warning(
                "AI query generation failed/timed out. Falling back to templates.",
                error=str(exc),
            )

    # Fallback to Deterministic Queries
    fallback_map = _fallback_queries(hypothesis)

    # Precise warnings formulated using the standard LlmConfig reason
    warning_msg = (
        llm_config.reason
        or "Local/private LLM was unreachable or returned an invalid response."
    )

    return {
        "esql": fallback_map["esql"],
        "spl": fallback_map["spl"],
        "kql": fallback_map["kql"],
        "query_generation_mode": "fallback",
        "warnings": warning_msg,
    }
