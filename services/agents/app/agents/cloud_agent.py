"""
Cloud Infrastructure Analysis Agent: investigates cloud-related alerts.

Analyses misconfigurations (public buckets, open security groups), IAM
anomalies (excessive permissions, unusual API calls), and infrastructure
drift.  Uses structured LLM reasoning to classify the alert and assign
a confidence-weighted verdict.
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

_SYSTEM_PROMPT = """You are the Cloud Infrastructure Analysis Agent of an AI Security Operations Centre.
Investigate cloud infrastructure alerts and classify into: true_positive, false_positive, or benign.

[Example 1]
Alert: S3 bucket 'finance-records' made publicly readable with 0.0.0.0/0 ACL
Output:
{"verdict": "true_positive", "confidence": 0.95, "cloud_indicators": ["public_s3_bucket", "insecure_acl"], "risk_category": "storage_exposure", "cloud_provider": "aws", "rationale": "민감 금융 데이터 버킷이 외부에 전체 공개되어 데이터 유출 위험이 높습니다."}

[Example 2]
Alert: CloudFront origin access identity update via Terraform deployment
Output:
{"verdict": "benign", "confidence": 0.90, "cloud_indicators": [], "risk_category": "infra_drift", "cloud_provider": "aws", "rationale": "정상 IaC 파이프라인을 통한 CDN 배포 설정 변경입니다."}

[Response Format]
Return ONLY a JSON object:
{
  "verdict": "true_positive" | "false_positive" | "benign",
  "confidence": <float 0.0-1.0>,
  "cloud_indicators": ["<indicator1>", "<indicator2>"],
  "risk_category": "storage_exposure" | "security_group_misconfig" | "iam_anomaly" | "unusual_api" | "infra_drift" | "unknown",
  "cloud_provider": "aws" | "azure" | "gcp" | "other",
  "rationale": "<한국어 분석 근거>"
}
"""


def _build_cloud_context(state: InvestigationState) -> str:
    """Serialise alert data into a cloud-focused analysis prompt."""
    raw = state.raw_alert
    parts = [
        f"Alert Summary: {sanitize_text(state.alert_summary)}",
        f"Severity: {sanitize_text(str(raw.get('severity', 'unknown')))}",
    ]

    cloud_fields = {
        "cloud_provider": "Cloud Provider",
        "region": "Region",
        "account_id": "Account ID",
        "project_id": "Project ID",
        "subscription_id": "Subscription ID",
        "resource_type": "Resource Type",
        "resource_id": "Resource ID",
        "resource_arn": "Resource ARN",
        "service": "Service",
        "action": "API Action",
        "principal": "Principal",
        "principal_arn": "Principal ARN",
        "source_ip": "Source IP",
    }
    for key, label in cloud_fields.items():
        if raw.get(key):
            parts.append(f"{label}: {sanitize_text(str(raw[key]))}")

    if raw.get("bucket_acl") or raw.get("bucket_policy"):
        parts.append(f"Bucket ACL: {sanitize_text(str(raw.get('bucket_acl', 'N/A')))}")
        if raw.get("bucket_policy"):
            parts.append(
                "Bucket Policy:\n" + summarize_structure_for_llm(raw["bucket_policy"], label="bucket_policy", max_lines=28, max_depth=3)
            )

    if raw.get("security_group_rules"):
        parts.append(
            "SG Rules:\n"
            + summarize_structure_for_llm(raw["security_group_rules"], label="security_group_rules", max_lines=28, max_depth=3)
        )

    if raw.get("iam_policy") or raw.get("permissions"):
        val = raw.get("iam_policy") or raw.get("permissions")
        parts.append("IAM/Permissions:\n" + summarize_structure_for_llm(val, label="iam_permissions", max_lines=28, max_depth=3))

    if raw.get("api_calls"):
        parts.append("API calls:\n" + summarize_structure_for_llm(raw["api_calls"], label="api_calls", max_lines=28, max_depth=2))

    if raw.get("is_public") is not None:
        parts.append(f"Public access: {raw['is_public']}")

    if raw.get("finding_type"):
        parts.append(f"Finding type: {sanitize_text(str(raw['finding_type']))}")

    extra_keys = {
        k
        for k in raw
        if k
        not in {
            "severity",
            "risk_score",
            *cloud_fields,
            "bucket_acl",
            "bucket_policy",
            "security_group_rules",
            "iam_policy",
            "permissions",
            "api_calls",
            "is_public",
            "finding_type",
        }
    }
    if extra_keys:
        extras = {k: raw[k] for k in sorted(extra_keys)[:8]}
        parts.append("Additional fields:\n" + format_extra_fields_for_llm(extras, max_keys=8))

    return wrap_untrusted("\n".join(parts), label="cloud_telemetry")


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

    indicators = data.get("cloud_indicators", [])
    if not isinstance(indicators, list):
        indicators = [str(indicators)] if indicators else []

    risk_category = str(data.get("risk_category", "unknown"))
    cloud_provider = str(data.get("cloud_provider", "other"))
    rationale = str(data.get("rationale") or "No rationale provided.")

    return {
        "verdict": verdict,
        "confidence": confidence,
        "cloud_indicators": indicators,
        "risk_category": risk_category,
        "cloud_provider": cloud_provider,
        "rationale": rationale,
    }


async def run_cloud(
    state: InvestigationState,
    bundle: ContextBundle | None = None,
) -> InvestigationState:
    """Analyse a cloud infrastructure alert for misconfiguration or compromise.

    Accepts an optional :class:`ContextBundle` (T2.1) carrying pre-fetched
    entity neighbourhood, historical similar-case verdicts, UEBA deviation,
    and threat-intel matches. When supplied the bundle's safe summary
    fields are appended to the LLM prompt; the agent's own enrichment
    paths become *augmentations*, not primary discovery.

    Backward-compatible: when ``bundle`` is ``None`` the agent falls back
    to the prior bare-alert reasoning path.
    """
    logger.info("Cloud agent starting", incident_id=str(state.incident_id))

    state.status = AgentStatus.RUNNING
    state.iteration_count += 1

    base_context = _build_cloud_context(state)
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
            "Cloud agent LLM call failed",
            error=str(exc),
            raw_response=raw_text[:200] if raw_text else "N/A",
            incident_id=str(state.incident_id),
        )
        state.add_finding(f"Cloud analysis LLM error: {exc}")
        return state

    elapsed_ms = round((time.monotonic() - t0) * 1000)

    verdict = result["verdict"]
    confidence = result["confidence"]
    indicators = result["cloud_indicators"]
    risk_category = result["risk_category"]
    cloud_provider = result["cloud_provider"]
    rationale = result["rationale"]

    state.confidence = confidence
    state.verdict = verdict
    state.confidence_basis = [
        f"Cloud analysis verdict: {verdict}",
        f"Risk category: {risk_category}",
        f"Cloud provider: {cloud_provider}",
        f"Confidence: {confidence:.2f}",
        f"Indicators: {', '.join(indicators) if indicators else 'none'}",
        f"Rationale: {rationale}",
    ]

    state.add_finding(
        f"Cloud analysis: verdict={verdict}, category={risk_category}, "
        f"provider={cloud_provider}, confidence={confidence:.2f}, "
        f"indicators={len(indicators)}, latency={elapsed_ms}ms"
    )
    if indicators:
        state.add_finding(f"Cloud indicators: {', '.join(indicators)}")
    state.add_finding(f"Cloud rationale: {rationale}")

    logger.info(
        "Cloud analysis complete",
        verdict=verdict,
        risk_category=risk_category,
        cloud_provider=cloud_provider,
        confidence=round(confidence, 2),
        indicator_count=len(indicators),
        elapsed_ms=elapsed_ms,
        incident_id=str(state.incident_id),
    )
    return state
