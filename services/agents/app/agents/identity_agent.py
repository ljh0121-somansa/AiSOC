"""
Identity & Authentication Analysis Agent: investigates auth-related alerts.

Analyses impossible travel, credential stuffing, brute force, privilege
escalation, and suspicious login patterns.  Uses structured LLM reasoning
to classify the alert and assign a confidence-weighted verdict.
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

_SYSTEM_PROMPT = """You are the Identity & Authentication Analysis Agent of an AI Security Operations Centre.
Investigate identity/authentication alerts and classify into: true_positive, false_positive, or benign.

[Example 1]
Alert: Simultaneous logins for user 'admin' from Seoul (IP: 211.x) and London (IP: 82.x) within 5 minutes
Output:
{"verdict": "true_positive", "confidence": 0.95, "identity_indicators": ["impossible_travel", "concurrent_sessions"], "attack_type": "impossible_travel", "rationale": "물리적으로 불가능한 시간 내 원거리 동시 로그인 발생으로 계정 탈취 의심."}

[Example 2]
Alert: 2 failed login attempts followed by successful login during normal business hours
Output:
{"verdict": "benign", "confidence": 0.85, "identity_indicators": [], "attack_type": "unknown", "rationale": "단순 비밀번호 오입력 후 정상 로그인으로 이상 징후 없음."}

[Response Format]
Return ONLY a JSON object:
{
  "verdict": "true_positive" | "false_positive" | "benign",
  "confidence": <float 0.0-1.0>,
  "identity_indicators": ["<indicator1>", "<indicator2>"],
  "attack_type": "impossible_travel" | "credential_stuffing" | "brute_force" | "privilege_escalation" | "session_anomaly" | "unknown",
  "rationale": "<한국어 분석 근거>"
}
"""


def _build_identity_context(state: InvestigationState) -> str:
    """Serialise alert data into an identity-focused analysis prompt."""
    raw = state.raw_alert
    parts = [
        f"Alert Summary: {sanitize_text(state.alert_summary)}",
        f"Severity: {sanitize_text(str(raw.get('severity', 'unknown')))}",
    ]

    identity_fields = {
        "user": "User",
        "username": "Username",
        "user_email": "User Email",
        "source_ip": "Source IP",
        "source_geo": "Source Geo",
        "dest_ip": "Destination IP",
        "dest_geo": "Destination Geo",
        "device": "Device",
        "user_agent": "User Agent",
        "auth_method": "Auth Method",
        "mfa_status": "MFA Status",
    }
    for key, label in identity_fields.items():
        if raw.get(key):
            parts.append(f"{label}: {sanitize_text(str(raw[key]))}")

    if raw.get("login_attempts"):
        parts.append(
            "Login attempts:\n" + summarize_structure_for_llm(raw["login_attempts"], label="login_attempts", max_lines=24, max_depth=2)
        )
    if raw.get("failed_count"):
        parts.append(f"Failed attempt count: {raw['failed_count']}")

    geo_fields = ["login_locations", "geo_locations"]
    for gf in geo_fields:
        if raw.get(gf):
            parts.append(f"Geo locations ({gf}):\n" + summarize_structure_for_llm(raw[gf], label=gf, max_lines=20, max_depth=2))

    priv_fields = ["role_change", "group_added", "permissions_changed", "privilege_level"]
    priv_parts = []
    for pf in priv_fields:
        if raw.get(pf):
            priv_parts.append(f"{pf}={raw[pf]}")
    if priv_parts:
        parts.append(f"Privilege changes: {', '.join(priv_parts)}")

    if raw.get("timestamp"):
        parts.append(f"Event time: {raw['timestamp']}")
    if raw.get("previous_login"):
        parts.append(
            "Previous login:\n" + summarize_structure_for_llm(raw["previous_login"], label="previous_login", max_lines=16, max_depth=2)
        )

    extra_keys = {
        k
        for k in raw
        if k
        not in {
            "severity",
            "risk_score",
            *identity_fields,
            "login_attempts",
            "failed_count",
            *geo_fields,
            *priv_fields,
            "timestamp",
            "previous_login",
        }
    }
    if extra_keys:
        extras = {k: raw[k] for k in sorted(extra_keys)[:8]}
        parts.append("Additional fields:\n" + format_extra_fields_for_llm(extras, max_keys=8))

    return wrap_untrusted("\n".join(parts), label="identity_telemetry")


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

    indicators = data.get("identity_indicators", [])
    if not isinstance(indicators, list):
        indicators = [str(indicators)] if indicators else []

    attack_type = str(data.get("attack_type", "unknown"))
    rationale = str(data.get("rationale") or "No rationale provided.")

    return {
        "verdict": verdict,
        "confidence": confidence,
        "identity_indicators": indicators,
        "attack_type": attack_type,
        "rationale": rationale,
    }


async def run_identity(
    state: InvestigationState,
    bundle: ContextBundle | None = None,
) -> InvestigationState:
    """Analyse an identity/authentication alert for compromise indicators.

    Accepts an optional ContextBundle carrying pre-fetched entity neighbourhood.
    """
    logger.info("Identity agent starting", incident_id=str(state.incident_id))

    state.status = AgentStatus.RUNNING
    state.iteration_count += 1

    base_context = _build_identity_context(state)
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
            "Identity agent LLM call failed",
            error=str(exc),
            raw_response=raw_text[:200] if raw_text else "N/A",
            incident_id=str(state.incident_id),
        )
        state.add_finding(f"Identity analysis LLM error: {exc}")
        return state

    elapsed_ms = round((time.monotonic() - t0) * 1000)

    verdict = result["verdict"]
    confidence = result["confidence"]
    indicators = result["identity_indicators"]
    attack_type = result["attack_type"]
    rationale = result["rationale"]

    state.confidence = confidence
    state.verdict = verdict
    state.confidence_basis = [
        f"Identity analysis verdict: {verdict}",
        f"Attack type: {attack_type}",
        f"Confidence: {confidence:.2f}",
        f"Indicators: {', '.join(indicators) if indicators else 'none'}",
        f"Rationale: {rationale}",
    ]

    state.add_finding(
        f"Identity analysis: verdict={verdict}, attack_type={attack_type}, "
        f"confidence={confidence:.2f}, indicators={len(indicators)}, "
        f"latency={elapsed_ms}ms"
    )
    if indicators:
        state.add_finding(f"Identity indicators: {', '.join(indicators)}")
    state.add_finding(f"Identity rationale: {rationale}")

    logger.info(
        "Identity analysis complete",
        verdict=verdict,
        attack_type=attack_type,
        confidence=round(confidence, 2),
        indicator_count=len(indicators),
        elapsed_ms=elapsed_ms,
        incident_id=str(state.incident_id),
    )
    return state
