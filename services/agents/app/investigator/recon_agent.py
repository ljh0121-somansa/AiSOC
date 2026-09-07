"""
ReconAgent — Phase 1 of the investigator pipeline.

Responsibilities:
  • Extract IOCs from the alert
  • Enrich each IOC via the enrichment service (fan-out, cached)
  • Map findings to MITRE ATT&CK techniques
  • Identify potential threat-actor clusters
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
import os

import structlog
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from app.core.cost_telemetry import record_llm_call
from app.llm import safe_ainvoke
from app.llm.prompt_builder import build_audit_prompt_payload, build_model_aware_messages
from app.prompt_serialization import summarize_structure_for_llm
from app.investigator.utils import normalize_string_list, safe_parse_agent_json

from .bundle_prompt import format_bundle_prompt_append
from .prompt_sanitizer import sanitize_text
from .state import InvestigatorState, ReconFindings, StepKind
from .tools import enrich_ioc, extract_iocs, map_to_mitre, sha256_of

logger = structlog.get_logger()

_SYSTEM_PROMPT = """You are the ReconAgent in an AI Security Operations Centre (AiSOC).
Your mission is to perform triage, extract indicators (IOCs), map MITRE ATT&CK techniques, and assess attack surface.

CRITICAL CONSTRAINTS:
1. Return ONLY a valid JSON object matching the schema below.
2. Write "analysis_rationale", "data_at_risk", "investigation_hypotheses", and "summary" in professional Korean.
3. Keep JSON keys, MITRE Technique IDs, Threat Actor names, and IOC types in English.

JSON Schema:
{
  "triage": {
    "is_true_positive": <boolean: true or false based on evidence>,
    "confidence_score": <float: 0.0 to 1.0>,
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "analysis_rationale": "<초기 정탐 판단 근거 in Korean>"
  },
  "iocs": [
    {
      "type": "ip|domain|url|hash|account|process",
      "value": "<ioc_value>",
      "scope": "internal|external",
      "context": "<IOC 역할 및 컨텍스트 in Korean/English>"
    }
  ],
  "mitre_mapping": [
    {
      "tactic": "<MITRE Tactic Name>",
      "technique_id": "<MITRE Technique ID e.g. T1071.001>",
      "technique_name": "<MITRE Technique Name>"
    }
  ],
  "threat_actors": [
    {
      "name": "<Threat Group or Campaign Name>",
      "evidence": "<위협 그룹/캠페인 추정 근거 in Korean>"
    }
  ],
  "attack_surface": {
    "affected_hosts": ["<host1>", "<host2>"],
    "affected_identities": ["<account1>"],
    "data_at_risk": "<위험 노출 자산 요약 in Korean>"
  },
  "investigation_hypotheses": [
    "<ForensicAgent가 검증할 포렌식 가설 in Korean>"
  ],
  "summary": "<초기 정찰 종합 요약 in Korean>"
}
"""

async def _llm_recon(state: InvestigatorState) -> dict[str, Any]:
    """Call LLM to perform structured reconnaissance.

    Records the LLM prompt and response into the audit ledger so the
    reasoning trace is replayable.
    """

    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    max_tokens = int(os.getenv("AISOC_MAX_TOKENS", "16384"))
    llm = ChatOpenAI(model=model, temperature=0, max_tokens=max_tokens)

    # Defence-in-depth: every field surfaced here can be attacker-influenced
    # (alert_summary often echoes log lines; raw_alert is verbatim event data).
    # Sanitise both before they hit the model, and wrap them in an
    # <UNTRUSTED_DATA> envelope so the system prompt's instructions stay
    # authoritative even if an attacker plants a "ignore previous instructions"
    # payload inside a banner or log message.
    safe_summary = sanitize_text(state.alert_summary, max_len=2_000)
    if isinstance(state.raw_alert, str):
        raw_alert_blob = sanitize_text(state.raw_alert, max_len=2_500)
    else:
        raw_alert_blob = summarize_structure_for_llm(
            state.raw_alert,
            label="alert_structure",
            max_lines=45,
            max_depth=3,
        )
    user_content = f"Alert summary:\n{safe_summary}\n\nStructured alert summary:\n{raw_alert_blob}"
    bundle_append = format_bundle_prompt_append(state.context_bundle)
    if bundle_append:
        user_content = f"{user_content}\n\n{bundle_append}"

    messages = build_model_aware_messages(
        system_prompt=_SYSTEM_PROMPT,
        user_content=user_content,
        model_name=model,
    )

    prompt_hash = state.log_llm_prompt(
        agent="ReconAgent",
        prompt=build_audit_prompt_payload(
            system_prompt=_SYSTEM_PROMPT,
            user_content=user_content,
            model_name=model,
        ),
        model=model,
        purpose="recon: extract IOCs, MITRE techniques, and threat actors",
    )

    t0 = time.monotonic()
    try:
        response = await safe_ainvoke(llm, messages)
        content = response.content
        latency_ms = int((time.monotonic() - t0) * 1000)
        tokens = 0
        if hasattr(response, "response_metadata"):
            tokens = response.response_metadata.get("token_usage", {}).get("total_tokens", 0) or 0
        # Record into the active CostTracker (Tier 1.6) so per-run cost
        # telemetry includes this LLM call. No-op when no tracker is bound.
        call_record = record_llm_call(
            response,
            model=model,
            latency_ms=latency_ms,
            step="recon",
            tool="llm.recon",
        )
        cost_usd = call_record.cost_usd if call_record is not None else 0.0
        reasoning = (
            getattr(response, "additional_kwargs", {}).get("reasoning_content")
            or getattr(response, "response_metadata", {}).get("reasoning_content")
            or getattr(response, "reasoning_content", None)
        )
        state.log_llm_response(
            agent="ReconAgent",
            response=content if isinstance(content, str) else str(content),
            reasoning_content=str(reasoning) if reasoning else None,
            prompt_hash=prompt_hash,
            model=model,
            tokens_used=tokens,
            latency_ms=latency_ms,
            cost_usd=cost_usd,
        )
        # logger.info("------------------")
        # logger.info(content)
        # logger.info("------------------")
        return safe_parse_agent_json(content)
        # Extract JSON from the response
        # json_match = re.search(r"\{[\s\S]*\}", content)
        # if json_match:
        #     return json.loads(json_match.group())
        # raise ValueError("LLM 응답에서 유효한 JSON 구조를 찾을 수 없습니다.")
    except Exception as exc:  # noqa: BLE001
        logger.warning("recon llm failed", error=str(exc))
        state.log(
            StepKind.ERROR,
            "ReconAgent",
            f"LLM call failed, falling back to heuristics: {exc}",
        )
        raise RuntimeError(f"[Recon Agent 오류] {str(exc)}") from exc


async def run_recon(state_dict: dict[str, Any]) -> dict[str, Any]:
    """LangGraph node — receives and returns a plain dict."""
    state = InvestigatorState.from_dict(state_dict)
    t0 = time.monotonic()

    logger.info("recon_agent.start", case_id=state.case_id)
    state.status = "running"

    # 1. LLM-powered recon
    llm_result = await _llm_recon(state)

    iocs: list[dict[str, Any]] = llm_result.get("iocs", [])
    # Also extract heuristically and merge
    heuristic_iocs = extract_iocs(state.alert_summary)
    seen = {i["value"] for i in iocs}
    for h in heuristic_iocs:
        if h["value"] not in seen:
            iocs.append(h)
            seen.add(h["value"])

    # 2. Enrich IOCs (fan-out, cached) - each enrichment is a tool call, recorded
    async def _enrich(ioc: dict[str, str]) -> tuple[str, dict[str, Any]]:
        cached = state.enrichment_cache.get(ioc["value"])
        if cached:
            state.log_tool_call(
                agent="ReconAgent",
                tool_name="enrich_ioc",
                args={"value": ioc["value"], "type": ioc["type"], "cached": True},
                result=cached,
                latency_ms=0,
                success=True,
            )
            return ioc["value"], cached
        t_enrich = time.monotonic()
        result = await enrich_ioc(ioc["value"], ioc["type"])
        state.log_tool_call(
            agent="ReconAgent",
            tool_name="enrich_ioc",
            args={"value": ioc["value"], "type": ioc["type"]},
            result=result,
            latency_ms=int((time.monotonic() - t_enrich) * 1000),
            success=bool(result),
        )
        return ioc["value"], result

    enrichment_results = await asyncio.gather(*[_enrich(ioc) for ioc in iocs])
    for val, result in enrichment_results:
        state.enrichment_cache[val] = result
        # Cite each IOC as a piece of evidence
        state.log_evidence(
            agent="ReconAgent",
            evidence_kind="ioc",
            ref=val,
            weight=1.0,
            details={"enrichment": result},
        )

    # 3. Build ReconFindings
    
    # Safely extract and format Threat Actors to preserve 'evidence'
    raw_actors = llm_result.get("threat_actors", [])
    formatted_actors = []
    if isinstance(raw_actors, list):
        for actor in raw_actors:
            if isinstance(actor, dict):
                name = actor.get("name") or actor.get("actor") or ""
                evidence = actor.get("evidence", "")
                if name:
                    formatted_actors.append(f"{name} (근거: {evidence})" if evidence else name)
            elif isinstance(actor, str):
                formatted_actors.append(actor)
    
    # Safely extract MITRE mapping from the correct prompt key
    raw_mitre = llm_result.get("mitre_mapping") or llm_result.get("mitre_techniques") or []
    mitre_list = []
    if isinstance(raw_mitre, list):
        for m in raw_mitre:
            if isinstance(m, dict):
                tid = m.get("technique_id", "")
                mitre_list.append(tid)
            elif isinstance(m, str):
                mitre_list.append(m)

    mitre = list(set(normalize_string_list(mitre_list) + map_to_mitre(state.alert_summary)))
    for technique in mitre:
        state.log_evidence(
            agent="ReconAgent",
            evidence_kind="mitre_technique",
            ref=technique,
            weight=0.8,
        )
        
    state.recon = ReconFindings(
        iocs=iocs,
        threat_actors=formatted_actors,
        attack_surface=llm_result.get("attack_surface", {}) if isinstance(llm_result.get("attack_surface"), dict) else {},
        mitre_techniques=mitre,
        summary=str(llm_result.get("summary") or ""),
        triage=llm_result.get("triage", {}) if isinstance(llm_result.get("triage"), dict) else {},
        investigation_hypotheses=normalize_string_list(llm_result.get("investigation_hypotheses", [])),
    )

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    state.log(
        StepKind.RECON,
        "ReconAgent",
        f"Found {len(iocs)} IOCs, {len(mitre)} MITRE techniques in {elapsed_ms}ms",
        ioc_count=len(iocs),
        duration_ms=elapsed_ms,
        input_hash=sha256_of(state.alert_summary),
        output_hash=sha256_of(state.recon.model_dump()),
    )
    state.iteration += 1
    logger.info("recon_agent.done", case_id=state.case_id, iocs=len(iocs), ms=elapsed_ms)
    return state.to_dict()
