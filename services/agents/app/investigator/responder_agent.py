"""
ResponderAgent — Phase 3 of the investigator pipeline.

Responsibilities:
  • Generate a prioritised response plan (containment → eradication → recovery)
  • Estimate effort and risk
  • All actions are DRY-RUN only — no live execution occurs here
"""

from __future__ import annotations

import time
from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage

from app.core.cost_telemetry import record_llm_call
from app.llm import safe_ainvoke
from app.llm.factory import make_chat_model, resolve_model_alias
from app.prompt_serialization import summarize_structure_for_llm
from app.investigator.utils import safe_parse_agent_json

from .bundle_prompt import format_bundle_prompt_append
from .prompt_sanitizer import (
    sanitize_iterable_of_strings,
    sanitize_text,
)
from .state import InvestigatorState, ResponderPlan, StepKind
from .tools import sha256_of

logger = structlog.get_logger()

_SYSTEM_PROMPT = """You are the ResponderAgent of an AI Security Operations Centre.
Based on the forensic findings, generate a concrete incident response plan.
All actions are DRY-RUN only — do NOT perform any real actions.

CRITICAL FORMATTING RULES:
   - Output ONLY raw JSON text matching the schema below.
   - Absolute Prohibition: Do NOT output <think> tags, thinking process, reasoning steps, or markdown wrappers (NEVER use ```json or ```).
   - Your response MUST strictly start with '{' and end with '}'.
   - Value language: Write 'action', 'rationale', step lists, and 'summary' strictly in KOREAN.
   - Tech specs: You MUST separate the exact CLI command or script (e.g. PowerShell, Bash, netsh, iptables, AD cmdlets) into the 'command' field of recommended_actions. Do NOT embed CLI commands inside the 'action' field, keep them in 'command' field separately for better readability. For steps arrays, include the command in backticks (`...`) inside the Korean text description.
   - The JSON keys MUST remain in English.
   - The values for 'risk' and 'risk_level' MUST strictly be one of: "low", "medium", "high", "critical" (do NOT translate these system status keywords).
Respond ONLY with a JSON object:
{
  "recommended_actions": [
    {
      "priority": 1,
      "action": "Korean action description explaining what to do",
      "command": "Exact CLI command or script to execute (e.g., netsh interface ipv4 set subinterface ...)",
      "rationale": "Korean rationale",
      "risk": "low|medium|high"
    }
  ],
  "containment_steps": ["Step 1: ...", "Step 2: ..." all steps in Korean text with `CLI command`],
  "eradication_steps": ["Korean text with `CLI command`"],
  "recovery_steps": ["Korean text with `CLI command`"],
  "estimated_effort_hours": 4.0,
  "risk_level": "low|medium|high|critical",
  "summary": "Two-sentence response summary in Korean."
}
"""

async def _llm_responder(state: InvestigatorState) -> dict[str, Any]:
    model = resolve_model_alias("investigation")
    llm = make_chat_model(
        "investigation",
        temperature=0,
        response_format={"type": "json_object"},
    )

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

    prompt = (
        f"Alert: {safe_alert}\n\n"
        f"Root cause: {safe_root_cause}\n"
        f"Blast radius: {safe_blast}\n"
        f"Confidence: {state.forensic.confidence:.0%}\n"
        f"MITRE: {safe_mitre}\n"
        f"Threat actors: {safe_actors}\n\n"
        f"Timeline (last 5):\n{timeline_blob}"
    )
    bundle_append = format_bundle_prompt_append(state.context_bundle)
    if bundle_append:
        prompt = f"{prompt}\n\n{bundle_append}"

    messages = [
        SystemMessage(content=_SYSTEM_PROMPT),
        HumanMessage(content=prompt),
    ]

    prompt_hash = state.log_llm_prompt(
        agent="ResponderAgent",
        prompt=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
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
        state.log_llm_response(
            agent="ResponderAgent",
            response=content if isinstance(content, str) else str(content),
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

    state.responder = ResponderPlan(
        recommended_actions=llm_result.get("recommended_actions", []),
        containment_steps=llm_result.get("containment_steps", []),
        eradication_steps=llm_result.get("eradication_steps", []),
        recovery_steps=llm_result.get("recovery_steps", []),
        estimated_effort_hours=float(llm_result.get("estimated_effort_hours", 0)),
        risk_level=llm_result.get("risk_level", "medium"),
        dry_run=True,
        summary=llm_result.get("summary", ""),
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
