"""
ReportWriterAgent — Final phase of the investigator pipeline.

Responsibilities:
  • Synthesise all agent findings into a structured Markdown report
  • Produce HTML variant (for PDF generation via Playwright/weasyprint)
  • Sign the report hash into the audit log
"""

from __future__ import annotations

import os
import time
from datetime import datetime
from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from app.core.cost_telemetry import record_llm_call
from app.llm import safe_ainvoke
from app.llm.prompt_builder import build_audit_prompt_payload, build_model_aware_messages
from app.prompt_serialization import summarize_structure_for_llm

from .bundle_prompt import format_bundle_prompt_append
from .prompt_sanitizer import (
    sanitize_iterable_of_strings,
    sanitize_text,
)
from .state import InvestigatorState, StepKind
from .tools import sha256_of

logger = structlog.get_logger()

_SYSTEM_PROMPT = """You are the ReportWriterAgent of an AI Security Operations Centre.
Synthesize the provided incident briefing into a professional Markdown security incident report in Korean.

DO NOT re-analyze or deliberate on evidence. Format directly into the following exact Markdown structure:

# 침해사고 보고서 — {case_id}
## 요약 보고 (Executive Summary)
(사건 요약 개요, 핵심 결론 및 평가된 리스크 레벨 서술)

## 침해지표 분석 (IOC Analysis)
| 지표 (IOC) | 유형 | 관측 컨텍스트 |
|---|---|---|
(제공된 침해지표 행 나열)

## MITRE ATT&CK 맵핑 (MITRE ATT&CK Mapping)
| 기법 ID | 기법명 / 행위 설명 |
|---|---|
(제공된 MITRE 기법 행 나열)

## 시간대별 주요 행위 (Timeline of Events)
| 단계 | 대상 호스트 | 이벤트 유형 | 행위 설명 | MITRE ID |
|---|---|---|---|---|
(제공된 시계열 증거 행 나열)

## 포렌식 분석 결과 (Forensic Findings)
- **근본 원인**: (근본 원인 가설)
- **피해 범위**: (영향 범위)
- **포렌식 신뢰도**: (신뢰도 수치)

## 대응 조치 계획 (Response Plan)
(실행된 격리 조치 및 방화벽/계정 대응 계획)

## 권고사항 (Recommendations)
1. (구체적인 보안 강화 권고사항)
2. (자격 증명 및 네트워크 통제 권고사항)
3. (모니터링 및 복구 절차 권고사항)

## 부록: 보강 데이터 (Appendix: Enrichment Data)
| 보강 데이터 키 | 유형 / 비고 |
|---|---|
(참조된 보강 데이터 키 목록)

OUTPUT LANGUAGE REQUIREMENT:
- All content under each header must be written in professional, clear, and natural Korean.
- Ensure technical terms are translated accurately or used alongside their standard English terms where appropriate.
"""


def _build_context(state: InvestigatorState) -> str:
    """Build a structured, hierarchical briefing from all prior agent outputs.
    
    This pre-assembled layout drastically reduces the cognitive load on reasoning models,
    preventing endless <think> loops by presenting chronological and semantic relationships clearly.
    """
    safe_alert = sanitize_text(state.alert_summary, max_len=2_000)
    safe_recon_summary = sanitize_text(state.recon.summary, max_len=2_500)
    safe_forensic_summary = sanitize_text(state.forensic.summary, max_len=2_500)
    safe_responder_summary = sanitize_text(state.responder.summary, max_len=2_000)
    safe_root_cause = sanitize_text(state.forensic.root_cause_hypothesis, max_len=1_000)
    safe_blast = sanitize_text(state.forensic.blast_radius, max_len=1_000)
    safe_risk_level = sanitize_text(state.responder.risk_level, max_len=32)

    safe_mitre = sanitize_iterable_of_strings(state.recon.mitre_techniques, max_item_len=64, max_items=25)
    safe_actors = sanitize_iterable_of_strings(state.recon.threat_actors, max_item_len=128, max_items=25)
    safe_artefacts = sanitize_iterable_of_strings(state.forensic.artefacts[:10], max_item_len=256, max_items=10)
    
    # Strip long executable scripts from containment steps to keep context clean
    import re
    cleaned_containment = []
    for c in state.responder.containment_steps[:5]:
        c_str = re.sub(r"\(실행:[^)]+\)", "", str(c)).strip()
        cleaned_containment.append(c_str)
    safe_containment = sanitize_iterable_of_strings(cleaned_containment, max_item_len=400, max_items=5)
    
    # Flatten IOCs into a clean string array instead of raw dictionary representations
    flat_iocs = []
    if isinstance(state.recon.iocs, dict):
        for k, v in list(state.recon.iocs.items())[:20]:
            flat_iocs.append(f"{k} ({v})")
    elif isinstance(state.recon.iocs, list):
        for item in state.recon.iocs[:20]:
            if isinstance(item, dict):
                val = item.get("value") or ""
                t = item.get("type") or "IOC"
                if val:
                    flat_iocs.append(f"{val} ({t})")
            else:
                flat_iocs.append(str(item))
    safe_iocs = sanitize_iterable_of_strings(flat_iocs, max_item_len=128, max_items=20)
    
    # Flatten Enrichment cache keys
    enrichment_keys = ", ".join(list(state.enrichment_cache.keys())[:15]) if state.enrichment_cache else "None"

    # Assemble timeline chronologically
    timeline_lines = []
    for t in state.forensic.timeline[:15]:
        step = t.get('step', '?')
        host = t.get('host', 'unknown')
        etype = t.get('event_type', 'event')
        desc = t.get('description', '')
        mitre = t.get('mitre_technique', '')
        timeline_lines.append(f"  * Step {step}: [{host}] {etype} - {desc} (MITRE: {mitre})")
    timeline_text = "\n".join(timeline_lines) if timeline_lines else "  * No timeline evidence recorded."

    sections = [
        f"[1. 사건 개요 및 대응 현황 (Executive Overview)]",
        f"- Case ID: {state.case_id}",
        f"- Alert Trigger: {safe_alert}",
        f"- 정찰 결론 (Recon): {safe_recon_summary}",
        f"- 포렌식 결론 (Forensic): {safe_forensic_summary}",
        f"- 대응 현황 (Response): {safe_responder_summary}",
        f"- 평가된 리스크 레벨: {safe_risk_level}",
        "",
        "[2. 공격 타임라인 및 핵심 증거 (Attack Flow & Evidence)]",
        f"- 근본 원인 가설 (Root Cause): {safe_root_cause}",
        f"- 영향 범위 (Blast Radius): {safe_blast}",
        f"- 포렌식 신뢰도 (Confidence): {state.forensic.confidence:.0%}",
        f"- 시계열 증거 (Timeline):",
        timeline_text,
        f"- 수집된 주요 유물 (Artefacts): {', '.join(safe_artefacts) if safe_artefacts else 'None'}",
        "",
        "[3. 기술적 침해지표 (Technical Indicators)]",
        f"- 식별된 위협 그룹 (Threat Actors): {', '.join(safe_actors) if safe_actors else 'None'}",
        f"- 연관 MITRE 기법 (Techniques): {', '.join(safe_mitre) if safe_mitre else 'None'}",
        f"- 주요 침해지표 (IOCs): {', '.join(safe_iocs) if safe_iocs else 'None'}",
        f"- 실행된 격리 조치 (Containment): {', '.join(safe_containment) if safe_containment else 'None'}",
        f"- 참조된 보강 데이터 키 (Enrichment Keys): {enrichment_keys}",
    ]
    return "\n".join(sections)


def _md_to_html(md: str, case_id: str) -> str:
    """Lightweight Markdown → HTML converter (no external deps required for basic output)."""
    try:
        import markdown

        body = markdown.markdown(md, extensions=["tables", "fenced_code"])
    except ImportError:
        # Fallback: wrap in <pre>
        body = f"<pre>{md}</pre>"

    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>AiSOC Incident Report — {case_id}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; max-width: 960px; margin: 40px auto; color: #1a1a1a; }}
  h1 {{ color: #c0392b; }} h2 {{ color: #2c3e50; border-bottom: 1px solid #eee; padding-bottom: 4px; }}
  table {{ border-collapse: collapse; width: 100%; }} th,td {{ border: 1px solid #ddd; padding: 8px; }}
  th {{ background: #2c3e50; color: white; }}
  code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }}
  pre {{ background: #f4f4f4; padding: 16px; overflow-x: auto; border-radius: 4px; }}
  .footer {{ color: #999; font-size: 0.8em; margin-top: 40px; }}
</style>
</head>
<body>
{body}
<div class="footer">Generated by AiSOC on {ts}</div>
</body>
</html>"""


async def run_report_writer(state_dict: dict[str, Any]) -> dict[str, Any]:
    """LangGraph node."""
    state = InvestigatorState.from_dict(state_dict)
    t0 = time.monotonic()

    logger.info("report_writer.start", case_id=state.case_id)

    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    max_tokens = int(os.getenv("AISOC_MAX_TOKENS", "16384"))                                                    
    llm = ChatOpenAI(model=model, temperature=0, max_tokens=max_tokens)

    context = _build_context(state)
    
    # Do NOT inject bundle_append here. 
    # Raw telemetry re-triggers endless <think> loops in reasoning models.
    # The ReportWriter relies EXCLUSIVELY on the structured briefing.

    system_prompt = _SYSTEM_PROMPT.format(case_id=state.case_id)
    
    messages = build_model_aware_messages(
        system_prompt=system_prompt,
        user_content=context,
        model_name=model,
    )

    prompt_hash = state.log_llm_prompt(
        agent="ReportWriterAgent",
        prompt=build_audit_prompt_payload(
            system_prompt=system_prompt,
            user_content=context,
            model_name=model,
        ),
        model=model,
        purpose="report: synthesise final markdown incident report",
    )

    t_llm = time.monotonic()
    try:
        response = await safe_ainvoke(llm, messages)
        raw_content = response.content or ""
        reasoning = (
            getattr(response, "additional_kwargs", {}).get("reasoning_content")
            or getattr(response, "response_metadata", {}).get("reasoning_content")
            or getattr(response, "reasoning_content", None)
        )
        full_text = raw_content if raw_content.strip() else str(reasoning or "")
        
        if "</think>" in full_text:
            cleaned_content = full_text.split("</think>")[-1].strip()
        else:
            cleaned_content = full_text.strip()

        # Proactive Fix: Strip markdown code block markers if the LLM wraps the response
        if cleaned_content.startswith("```markdown"):
            cleaned_content = cleaned_content.removeprefix("```markdown").strip()
            if cleaned_content.endswith("```"):
                cleaned_content = cleaned_content.removesuffix("```").strip()
        elif cleaned_content.startswith("```"):
            cleaned_content = cleaned_content.removeprefix("```").strip()
            if cleaned_content.endswith("```"):
                cleaned_content = cleaned_content.removesuffix("```").strip()

        # Deterministic Markdown synthesis from completed agent state if LLM content was empty
        if not cleaned_content and state.recon.summary:
            safe_mitre = ", ".join(state.recon.mitre_techniques) if state.recon.mitre_techniques else "식별된 MITRE 기법 없음"
            
            # extract IOCs safely
            iocs_list = []
            if isinstance(state.recon.iocs, dict):
                iocs_list = list(state.recon.iocs.keys())
            elif isinstance(state.recon.iocs, list):
                iocs_list = state.recon.iocs
            safe_iocs = ", ".join(str(x) for x in iocs_list[:10]) if iocs_list else "식별된 침해지표 없음"
            
            enrichment_keys = ", ".join(list(state.enrichment_cache.keys())[:10]) if state.enrichment_cache else "보강 데이터 없음"

            md_parts = [
                f"# 침해사고 보고서 — {state.case_id}",
                f"**Case ID**: `{state.case_id}` | **Severity**: `HIGH` | **Status**: `COMPLETED`",
                "> ⚠️ **시스템 알림**: LLM 추론 시간 초과 또는 응답 생성 실패로 인해 시스템이 에이전트 데이터를 기반으로 자동 합성한 리포트입니다.\n",
                "## 요약 보고 (Executive Summary)",
                f"{state.recon.summary}\n",
                "## 시간대별 주요 행위 (Timeline of Events)",
                "| 단계 | 대상 호스트 | 이벤트 유형 | 공격 행위 설명 | MITRE ID |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
            for t in state.forensic.timeline:
                md_parts.append(f"| Step {t.get('step', '-')} | `{t.get('host', '-')}` | {t.get('event_type', '-')} | {t.get('description', '-')} | `{t.get('mitre_technique', '-')}` |")
            
            md_parts.extend([
                "\n## 침해지표 분석 (IOC Analysis)",
                f"**식별된 주요 IOC**: {safe_iocs}\n",
                "## MITRE ATT&CK 맵핑 (MITRE ATT&CK Mapping)",
                f"**연관 기법**: {safe_mitre}\n",
                "## 포렌식 분석 결과 (Forensic Findings)",
                f"{state.forensic.summary or '포렌식 분석 완료'}\n",
                f"**근본 원인 가설**: {state.forensic.root_cause_hypothesis or '공격 체인 전파로 인한 침해'}\n",
                "## 대응 조치 계획 (Response Plan)",
                f"{state.responder.summary or '공격자 C2 차단 및 감염 호스트 격리 조치 수립'}\n",
                "## 권고사항 (Recommendations)",
            ])

            if state.responder.recommended_actions:
                for action in state.responder.recommended_actions:
                    if isinstance(action, dict):
                        priority = action.get("priority", "medium").upper()
                        act_text = action.get("action", "")
                        md_parts.append(f"- **[{priority}]** {act_text}")
                    else:
                        md_parts.append(f"- {action}")
            else:
                md_parts.append("- 추가 분석 및 모니터링 강화 권고")

            md_parts.extend([
                "\n## 부록: 보강 데이터 (Appendix: Enrichment Data)",
                f"**참조된 보강 컨텍스트 키**: {enrichment_keys}",
            ])
            cleaned_content = "\n".join(md_parts)

        state.report_md = cleaned_content
        latency_ms = int((time.monotonic() - t_llm) * 1000)
        tokens = 0
        if hasattr(response, "response_metadata"):
            tokens = response.response_metadata.get("token_usage", {}).get("total_tokens", 0) or 0
        # Tier 1.6: record cost telemetry on the active CostTracker.
        call_record = record_llm_call(
            response,
            model=model,
            latency_ms=latency_ms,
            step="report_writer",
            tool="llm.report_writer",
        )
        cost_usd = call_record.cost_usd if call_record is not None else 0.0
        reasoning = (
            getattr(response, "additional_kwargs", {}).get("reasoning_content")
            or getattr(response, "response_metadata", {}).get("reasoning_content")
            or getattr(response, "reasoning_content", None)
        )
        state.log_llm_response(
            agent="ReportWriterAgent",
            response=full_text,
            reasoning_content=str(reasoning) if reasoning else None,
            prompt_hash=prompt_hash,
            model=model,
            tokens_used=tokens,
            latency_ms=latency_ms,
            cost_usd=cost_usd,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("report_writer llm failed", error=str(exc))
        state.log(
            StepKind.ERROR,
            "ReportWriterAgent",
            f"LLM call failed, using fallback report: {exc}",
        )
        raise RuntimeError(f"[ReportWriter Agent 오류] 리포트 작성 실패: {exc}") from exc

    state.report_html = _md_to_html(state.report_md, state.case_id)

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    report_hash = sha256_of(state.report_md)
    state.log(
        StepKind.REPORT,
        "ReportWriterAgent",
        f"Report written ({len(state.report_md)} chars, hash={report_hash[:12]})",
        duration_ms=elapsed_ms,
        report_hash=report_hash,
    )
    state.status = "completed"
    state.completed_at = datetime.utcnow()
    state.iteration += 1
    logger.info("report_writer.done", case_id=state.case_id, ms=elapsed_ms)
    return state.to_dict()
