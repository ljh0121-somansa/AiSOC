"""
Phishing Analysis Agent: deep-dives into email-based security alerts.

Examines sender reputation, URL structure, attachment hashes, and
language patterns to determine whether an alert represents a genuine
phishing attempt.  Uses structured LLM reasoning to assess phishing
indicators and sets a verdict with calibrated confidence.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from app.context import ContextBundle
from app.investigator.prompt_sanitizer import sanitize_text, wrap_untrusted
from app.investigator.utils import safe_parse_agent_json
from app.llm import safe_ainvoke
from app.llm.prompt_builder import build_model_aware_messages
from app.models.state import AgentStatus, InvestigationState
from app.prompt_serialization import format_extra_fields_for_llm, summarize_structure_for_llm

logger = structlog.get_logger()

_SYSTEM_PROMPT = """You are the Phishing Analysis Agent of an AI Security Operations Centre.
Perform phishing analysis on email/messaging alerts and classify into: true_positive, false_positive, or benign.

[Example 1]
Alert: Email with mismatched sender and display URL http://paypa1-update.com
Output:
{"verdict": "true_positive", "confidence": 0.95, "phishing_indicators": ["homograph_domain", "credential_harvesting"], "rationale": "공식 도메인을 모사한 피싱 사이트로 연결되는 악성 링크가 포함되어 있습니다."}

[Example 2]
Alert: Internal HR announcement email with company portal link
Output:
{"verdict": "benign", "confidence": 0.90, "phishing_indicators": [], "rationale": "정상적인 사내 인사 공지 메일이며 악성 지표가 없습니다."}

[Response Format]
Return ONLY a JSON object:
{
  "verdict": "true_positive" | "false_positive" | "benign",
  "confidence": <float 0.0-1.0>,
  "phishing_indicators": ["<indicator1>", "<indicator2>"],
  "rationale": "<한국어 분석 근거>"
}
"""


def _build_phishing_context(state: InvestigationState) -> str:
    """Serialise alert data into a phishing-focused analysis prompt."""
    raw = state.raw_alert
    parts = [
        f"Alert Summary: {sanitize_text(state.alert_summary)}",
        f"Severity: {sanitize_text(str(raw.get('severity', 'unknown')))}",
    ]

    email_fields = {
        "sender": "Sender",
        "sender_domain": "Sender Domain",
        "reply_to": "Reply-To",
        "subject": "Subject",
        "recipient": "Recipient",
        "return_path": "Return-Path",
    }
    for key, label in email_fields.items():
        if raw.get(key):
            parts.append(f"{label}: {sanitize_text(str(raw[key]))}")

    if raw.get("urls"):
        parts.append("URLs found:\n" + summarize_structure_for_llm(raw["urls"], label="urls", max_lines=24, max_depth=2))
    if raw.get("url"):
        parts.append(f"Primary URL: {sanitize_text(str(raw['url']))}")
    if raw.get("domain"):
        parts.append(f"Domain: {sanitize_text(str(raw['domain']))}")

    if raw.get("attachment_hashes"):
        parts.append(
            "Attachment hashes:\n"
            + summarize_structure_for_llm(raw["attachment_hashes"], label="attachment_hashes", max_lines=16, max_depth=1)
        )
    if raw.get("file_hash"):
        parts.append(f"File hash: {sanitize_text(str(raw['file_hash']))}")

    auth_results = {
        "spf_result": "SPF",
        "dkim_result": "DKIM",
        "dmarc_result": "DMARC",
    }
    auth_parts = []
    for key, label in auth_results.items():
        if raw.get(key):
            auth_parts.append(f"{label}={sanitize_text(str(raw[key]))}")
    if auth_parts:
        parts.append(f"Email auth: {', '.join(auth_parts)}")

    if raw.get("body_snippet"):
        parts.append(f"Body snippet: {sanitize_text(str(raw['body_snippet']), max_len=500)}")

    extra_keys = {
        k
        for k in raw
        if k
        not in {
            "severity",
            "risk_score",
            *email_fields,
            "urls",
            "url",
            "domain",
            "attachment_hashes",
            "file_hash",
            "spf_result",
            "dkim_result",
            "dmarc_result",
            "body_snippet",
        }
    }
    if extra_keys:
        extras = {k: raw[k] for k in sorted(extra_keys)[:8]}
        parts.append("Additional fields:\n" + format_extra_fields_for_llm(extras, max_keys=8))

    return wrap_untrusted("\n".join(parts), label="phishing_telemetry")


def _parse_response(text: str) -> dict[str, Any]:
    """Extract JSON verdict from LLM output."""
    if not text or not str(text).strip():
        raise ValueError("LLM returned empty response")

    data = safe_parse_agent_json(text)
    if not data or not isinstance(data, dict):
        raise ValueError(f"Failed to parse valid JSON from LLM response (raw: {str(text)[:200]!r})")

    verdict = data.get("verdict", "true_positive")
    if verdict not in ("true_positive", "false_positive", "benign"):
        verdict = "true_positive"

    try:
        confidence = float(data.get("confidence", 0.5))
    except (ValueError, TypeError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))

    indicators = data.get("phishing_indicators", [])
    if not isinstance(indicators, list):
        indicators = [str(indicators)] if indicators else []

    rationale = str(data.get("rationale") or "No rationale provided.")

    return {
        "verdict": verdict,
        "confidence": confidence,
        "phishing_indicators": indicators,
        "rationale": rationale,
    }


async def run_phishing(
    state: InvestigationState,
    bundle: ContextBundle | None = None,
) -> InvestigationState:
    """Analyse an email-related alert for phishing indicators.

    Accepts an optional :class:`ContextBundle` (T2.1) carrying pre-fetched
    entity neighbourhood, historical similar-case verdicts, UEBA deviation,
    and threat-intel matches. When supplied the bundle's summary fields are
    appended to the LLM prompt; the agent's own enrichment paths become
    *augmentations*, not primary discovery.

    Backward-compatible: when ``bundle`` is ``None`` the agent falls back
    to the prior bare-alert reasoning path so existing eval / test harnesses
    continue to pass.
    """
    logger.info("Phishing agent starting", incident_id=str(state.incident_id))

    state.status = AgentStatus.RUNNING
    state.iteration_count += 1

    base_context = _build_phishing_context(state)
    bundle_lines = bundle.prompt_context_lines() if bundle is not None else []
    prompt_context = base_context + (("\n" + "\n".join(bundle_lines)) if bundle_lines else "")

    model_name = os.getenv("OPENAI_MODEL") or os.getenv("LLM_MODEL") or os.getenv("AISOC_LLM_MODEL", "gpt-4o-mini")
    llm = ChatOpenAI(model=model_name, temperature=0.0, max_tokens=1024)

    t0 = time.monotonic()
    raw_text = ""
    try:
        messages = build_model_aware_messages(
            system_prompt=_SYSTEM_PROMPT,
            user_content=prompt_context,
            model_name=model_name,
        )
        response = await safe_ainvoke(llm, messages)
        raw_text = str(getattr(response, "content", ""))
        result = _parse_response(raw_text)
    except Exception as exc:
        logger.error(
            "Phishing agent LLM call failed",
            error=str(exc),
            raw_response=raw_text[:200] if raw_text else "N/A",
            incident_id=str(state.incident_id),
        )
        state.add_finding(f"Phishing analysis LLM error: {exc}")
        return state

    elapsed_ms = round((time.monotonic() - t0) * 1000)

    verdict = result["verdict"]
    confidence = result["confidence"]
    indicators = result["phishing_indicators"]
    rationale = result["rationale"]

    state.confidence = confidence
    state.verdict = verdict
    state.confidence_basis = [
        f"Phishing analysis verdict: {verdict}",
        f"Confidence: {confidence:.2f}",
        f"Indicators: {', '.join(indicators) if indicators else 'none'}",
        f"Rationale: {rationale}",
    ]

    state.add_finding(
        f"Phishing analysis: verdict={verdict}, confidence={confidence:.2f}, indicators={len(indicators)}, latency={elapsed_ms}ms"
    )
    if indicators:
        state.add_finding(f"Phishing indicators: {', '.join(indicators)}")
    state.add_finding(f"Phishing rationale: {rationale}")

    logger.info(
        "Phishing analysis complete",
        verdict=verdict,
        confidence=round(confidence, 2),
        indicator_count=len(indicators),
        elapsed_ms=elapsed_ms,
        incident_id=str(state.incident_id),
    )
    return state
