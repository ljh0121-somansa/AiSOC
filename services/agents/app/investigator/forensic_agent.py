"""
ForensicAgent — Phase 2 of the investigator pipeline.

Responsibilities:
  • Build a chronological event timeline from enrichment data + raw alert
  • Hypothesise root cause and blast radius
  • Identify forensic artefacts (file paths, registry keys, network artefacts)
  • Produce a confidence-scored forensic summary
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from app.core.cost_telemetry import record_llm_call
from app.llm import safe_ainvoke
from app.llm.prompt_builder import build_audit_prompt_payload, build_model_aware_messages
from app.prompt_serialization import summarize_structure_for_llm
from app.investigator.utils import normalize_string_list, safe_parse_agent_json

from .bundle_prompt import format_bundle_prompt_append
from .prompt_sanitizer import (
    sanitize_iterable_of_strings,
    sanitize_text,
)
from .state import ForensicFindings, InvestigatorState, StepKind
from .tools import sha256_of

logger = structlog.get_logger()

_SYSTEM_PROMPT = """You are the ForensicAgent in an AI Security Operations Centre (AiSOC).
Reconstruct the multi-stage attack timeline and campaign from the alert and Attack Chain progression.

CRITICAL CONSTRAINTS:
1. Return ONLY a valid JSON object matching the schema below.
2. Write "description", "root_cause_hypothesis", and "forensic_summary" in professional Korean.
3. Keep JSON keys, Technique IDs, and event_type in English.

JSON Schema:
{
  "attack_timeline": [
    {
      "step": 1,
      "host": "<affected_hostname_or_ip>",
      "event_type": "<C2_BEACONING|CREDENTIAL_DUMP|LATERAL_MOVEMENT|VSS_DELETION|RANSOMWARE_IMPACT>",
      "description": "<공격 행위 설명 in Korean>",
      "mitre_technique": "<MITRE Technique ID e.g. T1071.001>"
    }
  ],
  "confidence": <float: 0.0 to 1.0>,
  "lateral_movement_detected": {
    "has_lateral_movement": <boolean: true or false>,
    "movement_paths": [
      {
        "source_host": "<source_host>",
        "target_host": "<target_host>",
        "protocol": "SMB",
        "used_account": "<used_account_or_unknown>"
      }
    ]
  },
  "compromised_assets": {
    "hosts": ["<compromised_host_1>", "<compromised_host_2>"],
    "identities": ["<compromised_account_1>"],
    "exfiltrated_data_bytes": <integer: estimated bytes or 0>
  },
  "artefacts": [
    "<file_path_or_registry_key_or_process_name_or_event_id>"
  ],
  "blast_radius": "<피해 확산 범위 요약 in Korean>",
  "root_cause_hypothesis": "<사고 근본 원인 분석 in Korean>",
  "forensic_summary": "<공격 체인 연관 분석 종합 요약 in Korean>"
}
"""

async def _llm_forensic(state: InvestigatorState) -> dict[str, Any]:
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    max_tokens = int(os.getenv("AISOC_MAX_TOKENS", "16384"))
    llm = ChatOpenAI(model=model, temperature=0, max_tokens=max_tokens)

    # Defence-in-depth: alert_summary, recon.summary, and the enrichment cache
    # can all carry attacker-controlled strings (banners, dark-web excerpts,
    # WHOIS values, etc.). Sanitise them and wrap the enrichment blob in an
    # explicit <UNTRUSTED_DATA> envelope so the system prompt stays trusted.
    safe_summary = sanitize_text(state.alert_summary, max_len=2_000)
    safe_recon = sanitize_text(state.recon.summary, max_len=2_000)
    safe_mitre = sanitize_iterable_of_strings(state.recon.mitre_techniques, max_item_len=64, max_items=25)
    enrichment_blob = summarize_structure_for_llm(
        dict(list(state.enrichment_cache.items())[:10]),
        label="enrichment_cache",
        max_lines=40,
        max_depth=2,
    )

    bundle_append = format_bundle_prompt_append(state.context_bundle)
    user_content = (
        f"Alert: {safe_summary}\n\n"
        f"Recon findings:\n{safe_recon}\n"
        f"MITRE techniques: {safe_mitre}\n\n"
        f"Enrichment Data:\n{enrichment_blob}"
    )
    if bundle_append:
        user_content = f"{user_content}\n\n{bundle_append}"

    messages = build_model_aware_messages(
        system_prompt=_SYSTEM_PROMPT,
        user_content=user_content,
        model_name=model,
    )

    prompt_hash = state.log_llm_prompt(
        agent="ForensicAgent",
        prompt=build_audit_prompt_payload(
            system_prompt=_SYSTEM_PROMPT,
            user_content=user_content,
            model_name=model,
        ),
        model=model,
        purpose="forensic: timeline, artefacts, root cause, blast radius",
    )

    t0 = time.monotonic()
    try:
        response = await safe_ainvoke(llm, messages)
        content = response.content
        latency_ms = int((time.monotonic() - t0) * 1000)
        tokens = 0
        if hasattr(response, "response_metadata"):
            tokens = response.response_metadata.get("token_usage", {}).get("total_tokens", 0) or 0
        # Tier 1.6: record cost telemetry on the active CostTracker.
        call_record = record_llm_call(
            response,
            model=model,
            latency_ms=latency_ms,
            step="forensic",
            tool="llm.forensic",
        )
        cost_usd = call_record.cost_usd if call_record is not None else 0.0
        reasoning = (
            getattr(response, "additional_kwargs", {}).get("reasoning_content")
            or getattr(response, "response_metadata", {}).get("reasoning_content")
            or getattr(response, "reasoning_content", None)
        )
        state.log_llm_response(
            agent="ForensicAgent",
            response=content if isinstance(content, str) else str(content),
            reasoning_content=str(reasoning) if reasoning else None,
            prompt_hash=prompt_hash,
            model=model,
            tokens_used=tokens,
            latency_ms=latency_ms,
            cost_usd=cost_usd,
        )
        return safe_parse_agent_json(content)
        # json_match = re.search(r"\{[\s\S]*\}", content)
        # if json_match:
        #     return json.loads(json_match.group())
        # raise ValueError("LLM 응답에서 유효한 JSON 구조를 찾을 수 없습니다.")
    except Exception as exc:  # noqa: BLE001
        logger.warning("forensic llm failed", error=str(exc))
        state.log(
            StepKind.ERROR,
            "ForensicAgent",
            f"LLM call failed: {exc}",
        )
        raise RuntimeError(f"[Forensic Agent 오류] {exc}") from exc
    


async def run_forensic(state_dict: dict[str, Any]) -> dict[str, Any]:
    """LangGraph node."""
    state = InvestigatorState.from_dict(state_dict)
    t0 = time.monotonic()

    logger.info("forensic_agent.start", case_id=state.case_id)

    llm_result = await _llm_forensic(state)

    try:
        conf_val = float(llm_result.get("confidence", 0.0))
    except (ValueError, TypeError):
        conf_val = 0.0

    timeline_data = llm_result.get("timeline") or llm_result.get("attack_timeline") or []
    if not isinstance(timeline_data, list):
        timeline_data = [timeline_data] if timeline_data else []

    blast_val = llm_result.get("blast_radius") or llm_result.get("compromised_assets") or ""
    if isinstance(blast_val, dict):
        hosts_str = ", ".join(blast_val.get("hosts", [])) if isinstance(blast_val.get("hosts"), list) else str(blast_val.get("hosts", ""))
        users_str = ", ".join(blast_val.get("identities", [])) if isinstance(blast_val.get("identities"), list) else str(blast_val.get("identities", ""))
        blast_str = f"영향 시스템: {hosts_str or '없음'} | 영향 계정: {users_str or '없음'}"
    else:
        blast_str = str(blast_val)

    summary_str = str(llm_result.get("summary") or llm_result.get("forensic_summary") or "")
    root_cause_str = str(llm_result.get("root_cause_hypothesis") or llm_result.get("root_cause_analysis") or "")

    state.forensic = ForensicFindings(
        timeline=timeline_data,
        artefacts=normalize_string_list(llm_result.get("artefacts", [])),
        root_cause_hypothesis=root_cause_str,
        blast_radius=blast_str,
        confidence=conf_val,
        summary=summary_str,
        lateral_movement_detected=llm_result.get("lateral_movement_detected", {}) if isinstance(llm_result.get("lateral_movement_detected"), dict) else {},
        compromised_assets=llm_result.get("compromised_assets", {}) if isinstance(llm_result.get("compromised_assets"), dict) else {},
    )

    # Cite each forensic artefact as evidence for downstream replay
    for artefact in state.forensic.artefacts[:50]:
        state.log_evidence(
            agent="ForensicAgent",
            evidence_kind="artefact",
            ref=str(artefact),
            weight=state.forensic.confidence,
        )

    if state.forensic.root_cause_hypothesis:
        state.log_decision(
            agent="ForensicAgent",
            decision="root_cause_hypothesis",
            reason=state.forensic.root_cause_hypothesis,
            confidence=state.forensic.confidence,
        )

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    state.log(
        StepKind.FORENSIC,
        "ForensicAgent",
        f"Timeline: {len(state.forensic.timeline)} events, confidence {state.forensic.confidence:.0%}",
        duration_ms=elapsed_ms,
        input_hash=sha256_of(state.recon.model_dump()),
        output_hash=sha256_of(state.forensic.model_dump()),
    )
    state.iteration += 1
    logger.info("forensic_agent.done", case_id=state.case_id, ms=elapsed_ms)
    return state.to_dict()
