"""
Auto-Triage Agent: LLM-based autonomous alert classification.

Uses structured LLM reasoning to classify alerts as true_positive,
false_positive, or benign — replacing simple keyword heuristics with
contextual analysis.  High-confidence FP/benign verdicts are auto-closed;
uncertain alerts escalate into the full triage → enrichment → investigation
pipeline.

Metrics (module-level counters) are exposed via the /triage/stats API.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from app.investigator.prompt_sanitizer import sanitize_text, wrap_untrusted
from app.investigator.utils import safe_parse_agent_json
from app.llm import safe_ainvoke
from app.llm.prompt_builder import build_model_aware_messages
from app.models.state import AgentStatus, InvestigationState
from app.prompt_serialization import format_extra_fields_for_llm

logger = structlog.get_logger()

AUTO_CLOSE_THRESHOLD: float = float(os.getenv("AISOC_AUTO_CLOSE_THRESHOLD", "0.85"))

_metrics: dict[str, Any] = {
    "auto_resolved_count": 0,
    "escalated_count": 0,
    "total_processed": 0,
    "confidence_sum": 0.0,
    "fp_count": 0,
    "benign_count": 0,
    "tp_count": 0,
}

_SYSTEM_PROMPT = """You are the Auto-Triage Agent of an AI Security Operations Centre.
Classify incoming security alerts into exactly one verdict: true_positive, false_positive, or benign.

[Example 1]
Alert: Suspicious login from unknown public IP 198.51.100.23
Output:
{"verdict": "true_positive", "confidence": 0.85, "rationale": "인가되지 않은 외부 공인 IP 대역에서의 로그인 시도로 계정 탈취 의심이 있어 심층 조사가 필요합니다."}

[Example 2]
Alert: Scheduled Nessus Vulnerability Scanner activity on port 443
Output:
{"verdict": "false_positive", "confidence": 0.95, "rationale": "보안팀의 승인된 정기 취약점 점검 도구에 의해 발생한 정상 스캔 이벤트입니다."}

[Example 3]
Alert: Low-priority informational DNS query log with no IOC match
Output:
{"verdict": "benign", "confidence": 0.90, "rationale": "알려진 악성 IOC나 이상 징후가 없는 단순 정보성 DNS 쿼리 로그입니다."}

[Response Format]
Return ONLY a valid JSON object matching the examples above.
- "verdict": "true_positive" | "false_positive" | "benign"
- "confidence": float between 0.0 and 1.0
- "rationale": Professional explanation in Korean
"""


def get_metrics() -> dict[str, Any]:
    """Return a copy of current auto-triage metrics."""
    m = _metrics.copy()
    total = m["total_processed"]
    m["auto_resolution_rate"] = m["auto_resolved_count"] / total if total > 0 else 0.0
    m["fp_rate"] = m["fp_count"] / total if total > 0 else 0.0
    m["avg_confidence"] = m["confidence_sum"] / total if total > 0 else 0.0
    return m


def get_threshold() -> float:
    """Return the current auto-close confidence threshold."""
    return AUTO_CLOSE_THRESHOLD


def set_threshold(value: float) -> float:
    """Update the auto-close confidence threshold. Returns the new value."""
    global AUTO_CLOSE_THRESHOLD  # noqa: PLW0603
    value = max(0.0, min(1.0, value))
    AUTO_CLOSE_THRESHOLD = value
    return AUTO_CLOSE_THRESHOLD


def _build_alert_context(state: InvestigationState) -> str:
    """Serialise the alert into a compact string the LLM can reason over."""
    raw = state.raw_alert
    parts = [
        f"Alert Summary: {sanitize_text(state.alert_summary)}",
        f"Severity (vendor): {sanitize_text(str(raw.get('severity', 'unknown')))}",
        f"Risk Score (vendor): {sanitize_text(str(raw.get('risk_score', 'N/A')))}",
    ]

    ioc_fields = {
        "src_ip": "Source IP",
        "dst_ip": "Destination IP",
        "domain": "Domain",
        "file_hash": "File Hash",
        "url": "URL",
        "hostname": "Hostname",
    }
    present_iocs = {label: sanitize_text(str(raw[key])) for key, label in ioc_fields.items() if raw.get(key)}
    if present_iocs:
        parts.append("IOCs present: " + ", ".join(f"{k}={v}" for k, v in present_iocs.items()))
    else:
        parts.append("IOCs present: none")

    techniques = raw.get("mitre_techniques", [])
    if techniques:
        parts.append(f"MITRE Techniques: {', '.join(sanitize_text(str(t)) for t in techniques)}")

    extra_keys = {k for k in raw if k not in {"severity", "risk_score", "mitre_techniques", *ioc_fields}}
    if extra_keys:
        extras = {k: raw[k] for k in sorted(extra_keys)[:10]}
        parts.append("Additional fields (summary, not raw JSON):\n" + format_extra_fields_for_llm(extras))

    return wrap_untrusted("\n".join(parts), label="alert_telemetry")


def _parse_llm_response(text: str) -> dict[str, Any]:
    """Extract the JSON verdict from the LLM response, tolerating markdown fences and thinking tags."""
    if not text or not str(text).strip():
        return {
            "verdict": "true_positive",
            "confidence": 0.5,
            "rationale": "Empty LLM response received; escalating for manual triage.",
        }

    data = safe_parse_agent_json(text)
    if not data or not isinstance(data, dict):
        return {
            "verdict": "true_positive",
            "confidence": 0.5,
            "rationale": "Unstructured LLM response received; escalating for manual triage.",
        }

    verdict = data.get("verdict", "true_positive")
    if verdict not in ("true_positive", "false_positive", "benign"):
        verdict = "true_positive"

    try:
        confidence = float(data.get("confidence", 0.5))
    except (ValueError, TypeError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))

    rationale = data.get("rationale") or "No rationale provided by LLM."

    return {
        "verdict": verdict,
        "confidence": confidence,
        "rationale": str(rationale),
    }


async def run_auto_triage(state: InvestigationState) -> InvestigationState:
    """
    LLM-based auto-triage: classify the alert and decide whether to
    auto-close (FP/benign with high confidence) or escalate.
    """
    logger.info("Auto-triage agent starting", incident_id=str(state.incident_id))

    state.status = AgentStatus.RUNNING
    state.iteration_count += 1

    alert_context = _build_alert_context(state)

    model_name = os.getenv("OPENAI_MODEL") or os.getenv("LLM_MODEL") or os.getenv("AISOC_LLM_MODEL", "gpt-4o-mini")
    llm = ChatOpenAI(model=model_name, temperature=0.0, max_tokens=1024)

    t0 = time.monotonic()
    raw_text = ""
    try:
        messages = build_model_aware_messages(
            system_prompt=_SYSTEM_PROMPT,
            user_content=f"ALERT TELEMETRY:\n{alert_context}",
            model_name=model_name,
        )
        response = await safe_ainvoke(llm, messages)
        raw_text = str(getattr(response, "content", ""))
        result = _parse_llm_response(raw_text)
    except Exception as exc:
        logger.error(
            "Auto-triage LLM call failed, escalating",
            error=str(exc),
            raw_response=raw_text[:200] if raw_text else "N/A",
            incident_id=str(state.incident_id),
        )
        state.add_finding(f"Auto-triage LLM error: {exc} — escalating to manual triage")
        _metrics["escalated_count"] += 1
        _metrics["total_processed"] += 1
        return state

    elapsed_ms = round((time.monotonic() - t0) * 1000)

    verdict = result["verdict"]
    confidence = result["confidence"]
    rationale = result["rationale"]

    _metrics["total_processed"] += 1
    _metrics["confidence_sum"] += confidence
    if verdict == "false_positive":
        _metrics["fp_count"] += 1
    elif verdict == "benign":
        _metrics["benign_count"] += 1
    else:
        _metrics["tp_count"] += 1

    state.confidence = confidence
    state.verdict = verdict
    state.confidence_basis = [
        f"LLM auto-triage verdict: {verdict}",
        f"LLM confidence: {confidence:.2f}",
        f"Rationale: {rationale}",
    ]

    state.add_finding(f"Auto-triage: verdict={verdict}, confidence={confidence:.2f}, latency={elapsed_ms}ms")
    state.add_finding(f"Auto-triage rationale: {rationale}")

    should_auto_close = verdict in ("false_positive", "benign") and confidence >= AUTO_CLOSE_THRESHOLD

    if should_auto_close:
        _metrics["auto_resolved_count"] += 1
        state.status = AgentStatus.COMPLETED
        state.add_finding(f"Auto-closed as {verdict} (confidence {confidence:.2f} >= threshold {AUTO_CLOSE_THRESHOLD:.2f})")
        logger.info(
            "Auto-triage: auto-closed",
            verdict=verdict,
            confidence=round(confidence, 2),
            threshold=AUTO_CLOSE_THRESHOLD,
            incident_id=str(state.incident_id),
            elapsed_ms=elapsed_ms,
        )
    else:
        _metrics["escalated_count"] += 1
        state.add_finding(
            f"Escalating to full pipeline — "
            f"{'TP verdict' if verdict == 'true_positive' else f'confidence {confidence:.2f} < threshold {AUTO_CLOSE_THRESHOLD:.2f}'}"
        )
        logger.info(
            "Auto-triage: escalating",
            verdict=verdict,
            confidence=round(confidence, 2),
            threshold=AUTO_CLOSE_THRESHOLD,
            incident_id=str(state.incident_id),
            elapsed_ms=elapsed_ms,
        )

    return state
