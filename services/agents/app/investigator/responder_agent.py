"""
ResponderAgent — Phase 3 of the investigator pipeline.

Responsibilities:
  • Generate a prioritised response plan (containment → eradication → recovery)
  • Estimate effort and risk
  • All actions are DRY-RUN only — no live execution occurs here
"""

from __future__ import annotations

import os
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
from .state import InvestigatorState, ResponderPlan, StepKind
from .tools import sha256_of

logger = structlog.get_logger()

_SYSTEM_PROMPT = """You are the ResponderAgent in an AI Security Operations Centre (AiSOC).
Establish a prioritized containment and remediation plan based on forensic findings.

CRITICAL CONSTRAINTS:
1. Return ONLY a valid JSON object matching the exact schema below.
2. Write "rationale", "action_description", and "impact_assessment" in professional Korean.
3. Keep commands, IP addresses, JSON keys, and protocol names in standard English.
4. DO NOT over-analyze the target OS or directory environments. If exact OS is unknown, provide standard generic commands (e.g., iptables for Linux or generic PowerShell).

[Example 1 - Linux Network Isolation]
Output:
{
  "incident_disposition": {
    "threat_level": "HIGH",
    "containment_strategy": "TARGETED_BLOCKING",
    "rationale": "내부 웹 서버에서 비정상 아웃바운드 트래픽이 감지되어 외부 공격 인프라와의 즉각적인 통신 차단이 필요합니다."
  },
  "containment_actions": [
    {
      "timeframe": "P1_UNDER_1_HOUR",
      "action_type": "FIREWALL_BLOCK",
      "target": "10.0.0.50",
      "action_description": "알려진 외부 C2 서버 IP 대역으로의 아웃바운드 트래픽 전면 차단",
      "command_or_rule": "iptables -A OUTPUT -d 198.51.100.0/24 -j DROP",
      "requires_hitl_approval": true
    }
  ],
  "business_impact_assessment": {
    "service_interruption_risk": "LOW",
    "impact_assessment": "악성 목적지 IP만 선별 차단하므로 정상적인 대고객 웹 서비스에는 지장이 없습니다."
  }
}

[Example 2 - Windows Credential Reset]
Output:
{
  "incident_disposition": {
    "threat_level": "CRITICAL",
    "containment_strategy": "AGGRESSIVE_ISOLATION",
    "rationale": "자격 증명 탈취 후 내부 AD 서버로의 횡적이동이 확인되어 즉각적인 계정 무효화가 시급합니다."
  },
  "containment_actions": [
    {
      "timeframe": "P1_UNDER_1_HOUR",
      "action_type": "CREDENTIAL_RESET",
      "target": "admin_user",
      "action_description": "침해 의심 계정의 강제 세션 만료 및 비밀번호 초기화",
      "command_or_rule": "Revoke-AzureADUserAllRefreshToken -ObjectId admin_user; Set-ADAccountPassword -Identity admin_user -Reset",
      "requires_hitl_approval": false
    }
  ],
  "business_impact_assessment": {
    "service_interruption_risk": "MEDIUM",
    "impact_assessment": "해당 관리자 계정을 사용하는 배치 스크립트나 서비스가 있을 경우 일시적 인증 실패가 발생할 수 있습니다."
  }
}

JSON Schema:
{
  "incident_disposition": {
    "threat_level": "<CRITICAL|HIGH|MEDIUM|LOW>",
    "containment_strategy": "<AGGRESSIVE_ISOLATION|TARGETED_BLOCKING|MONITORING>",
    "rationale": "<대응 전략 선정 근거 in Korean>"
  },
  "containment_actions": [
    {
      "timeframe": "<P1_UNDER_1_HOUR|P2_UNDER_4_HOURS|P3_UNDER_24_HOURS>",
      "action_type": "<NETWORK_ISOLATION|FIREWALL_BLOCK|ACCOUNT_SUSPENSION|CREDENTIAL_RESET|THREAT_HUNTING>",
      "target": "<target_host_ip_or_user>",
      "action_description": "<대응 조치 설명 in Korean>",
      "command_or_rule": "<actionable_command_or_firewall_rule>",
      "requires_hitl_approval": <boolean: true or false>
    }
  ],
  "business_impact_assessment": {
    "service_interruption_risk": "<HIGH|MEDIUM|LOW>",
    "impact_assessment": "<비즈니스 영향도 평가 in Korean>"
  },
  "estimated_effort_hours": <float: e.g. 2.5>
}
"""

async def _llm_responder(state: InvestigatorState) -> dict[str, Any]:
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    max_tokens = int(os.getenv("AISOC_MAX_TOKENS", "16384"))
    llm = ChatOpenAI(model=model, temperature=0, max_tokens=max_tokens)

    # Defence-in-depth: every field surfaced here originated in attacker-
    # influenced data (alert payloads, banners, dark-web excerpts, LLM
    # summaries of the same). Sanitise scalars, cap list lengths, and wrap
    # the timeline blob in <UNTRUSTED_DATA> so the system prompt stays
    # authoritative.
    safe_alert = sanitize_text(state.alert_summary, max_len=2_000)
    safe_root_cause = sanitize_text(state.forensic.root_cause_hypothesis, max_len=1_000)
    safe_blast = sanitize_text(state.forensic.blast_radius, max_len=1_000)
    safe_mitre = sanitize_iterable_of_strings(state.recon.mitre_techniques, max_item_len=64, max_items=25)
    safe_actors = sanitize_iterable_of_strings(state.recon.threat_actors, max_item_len=128, max_items=25)
    timeline_blob = summarize_structure_for_llm(
        list(state.forensic.timeline[-5:]),
        label="timeline_tail",
        max_lines=35,
        max_depth=2,
    )

    user_content = (
        f"Alert: {safe_alert}\n\n"
        f"Root cause: {safe_root_cause}\n"
        f"Blast radius: {safe_blast}\n"
        f"Confidence: {state.forensic.confidence:.0%}\n"
        f"Threat actors: {safe_actors}"
    )
    bundle_append = format_bundle_prompt_append(state.context_bundle)
    if bundle_append:
        user_content = f"{user_content}\n\n{bundle_append}"

    messages = build_model_aware_messages(
        system_prompt=_SYSTEM_PROMPT,
        user_content=user_content,
        model_name=model,
    )

    prompt_hash = state.log_llm_prompt(
        agent="ResponderAgent",
        prompt=build_audit_prompt_payload(
            system_prompt=_SYSTEM_PROMPT,
            user_content=user_content,
            model_name=model,
        ),
        model=model,
        purpose="responder: containment/eradication/recovery plan",
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
            step="responder",
            tool="llm.responder",
        )
        cost_usd = call_record.cost_usd if call_record is not None else 0.0
        reasoning = (
            getattr(response, "additional_kwargs", {}).get("reasoning_content")
            or getattr(response, "response_metadata", {}).get("reasoning_content")
            or getattr(response, "reasoning_content", None)
        )
        state.log_llm_response(
            agent="ResponderAgent",
            response=content if isinstance(content, str) else str(content),
            reasoning_content=str(reasoning) if reasoning else None,
            prompt_hash=prompt_hash,
            model=model,
            tokens_used=tokens,
            latency_ms=latency_ms,
            cost_usd=cost_usd,
        )
        # json_match = re.search(r"\{[\s\S]*\}", content)
        # if json_match:
        #     return json.loads(json_match.group())
        return safe_parse_agent_json(content)
        # raise ValueError("LLM 응답에서 유효한 JSON 구조를 찾을 수 없습니다.")
    except Exception as exc:  # noqa: BLE001
        logger.warning("responder llm failed", error=str(exc))
        state.log(
            StepKind.ERROR,
            "ResponderAgent",
            f"LLM call failed: {exc}",
        )
        raise RuntimeError(f"[Responder Agent 오류] {exc}") from exc


async def run_responder(state_dict: dict[str, Any]) -> dict[str, Any]:
    """LangGraph node."""
    state = InvestigatorState.from_dict(state_dict)
    t0 = time.monotonic()

    logger.info("responder_agent.start", case_id=state.case_id)

    llm_result = await _llm_responder(state)

    # Extract risk_level from incident_disposition or direct key
    disp = llm_result.get("incident_disposition", {}) if isinstance(llm_result.get("incident_disposition"), dict) else {}
    risk_lvl = str(disp.get("threat_level") or llm_result.get("risk_level") or "medium").lower()
    if risk_lvl not in ("critical", "high", "medium", "low"):
        risk_lvl = "medium"

    # Extract summary from disposition rationale or summary
    resp_summary = str(disp.get("rationale") or llm_result.get("summary") or "")

    # Extract containment actions
    actions_raw = llm_result.get("containment_actions") or llm_result.get("recommended_actions") or []
    containment: list[str] = []
    eradication: list[str] = []
    recovery: list[str] = []
    rec_actions: list[dict[str, Any]] = []

    if isinstance(actions_raw, list):
        for act in actions_raw:
            if isinstance(act, dict):
                desc = act.get("action_description") or act.get("description") or act.get("action") or str(act)
                tf = act.get("timeframe", "")
                atype = act.get("action_type", "")
                cmd = act.get("command_or_rule", "")
                
                step_str = f"[{atype}] {desc}" + (f" (실행: `{cmd}`)" if cmd else "")
                if "P1" in tf or "1_HOUR" in tf:
                    containment.append(step_str)
                elif "P2" in tf or "4_HOURS" in tf:
                    eradication.append(step_str)
                else:
                    recovery.append(step_str)
                rec_actions.append(act)
            elif isinstance(act, str):
                containment.append(act)

    state.responder = ResponderPlan(
        recommended_actions=rec_actions or llm_result.get("recommended_actions", []),
        containment_steps=containment or normalize_string_list(llm_result.get("containment_steps", [])),
        eradication_steps=eradication or normalize_string_list(llm_result.get("eradication_steps", [])),
        recovery_steps=recovery or normalize_string_list(llm_result.get("recovery_steps", [])),
        estimated_effort_hours=float(llm_result.get("estimated_effort_hours", 2.0)),
        risk_level=risk_lvl,
        dry_run=True,
        summary=resp_summary,
        incident_disposition=llm_result.get("incident_disposition", {}) if isinstance(llm_result.get("incident_disposition"), dict) else {},
        containment_actions=llm_result.get("containment_actions", []) if isinstance(llm_result.get("containment_actions"), list) else [],
        business_impact_assessment=llm_result.get("business_impact_assessment", {}) if isinstance(llm_result.get("business_impact_assessment"), dict) else {},
    )

    # Record the headline risk decision so auditors can see why we picked this level
    state.log_decision(
        agent="ResponderAgent",
        decision=f"risk_level={state.responder.risk_level}",
        reason=(
            f"Based on root cause '{state.forensic.root_cause_hypothesis}' with "
            f"forensic confidence {state.forensic.confidence:.0%} and blast radius "
            f"'{state.forensic.blast_radius}'."
        ),
        confidence=state.forensic.confidence,
    )

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    state.log(
        StepKind.RESPONDER,
        "ResponderAgent",
        f"Generated {len(state.responder.recommended_actions)} recommended actions (risk={state.responder.risk_level}, dry_run=True)",
        duration_ms=elapsed_ms,
        input_hash=sha256_of(state.forensic.model_dump()),
        output_hash=sha256_of(state.responder.model_dump()),
    )
    state.iteration += 1
    logger.info("responder_agent.done", case_id=state.case_id, ms=elapsed_ms)
    return state.to_dict()
