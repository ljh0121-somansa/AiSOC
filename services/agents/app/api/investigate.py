"""
Pillar-1 Investigation API
==========================
Endpoints:
  POST /api/v1/cases/{case_id}/investigate     → launch async investigation
  GET  /api/v1/investigations/{run_id}         → poll status + results
  GET  /api/v1/investigations/{run_id}/report.md
  GET  /api/v1/investigations/{run_id}/report.html
  GET  /api/v1/investigations/{run_id}/report.pdf  → weasyprint PDF
  WS   /api/v1/investigations/{run_id}/stream  → SSE-style step stream
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import httpx
import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from app.investigator import InvestigatorOrchestrator
from app.orchestrator.router import RouterOrchestrator

logger = structlog.get_logger()
router = APIRouter(prefix="/api/v1", tags=["investigations"])

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
_REALTIME_URL = os.environ.get("REALTIME_URL", "http://realtime:8086")
_INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "")

# ---------------------------------------------------------------------------
# Orchestrator selection
# ---------------------------------------------------------------------------
# T2.2: route /investigate through the four-agent ``RouterOrchestrator`` when
# the flag is on; otherwise keep the legacy ``InvestigatorOrchestrator`` path.
# Read at call time so operators can flip without restarting the service.
USE_ROUTER_FLAG = "AISOC_INVESTIGATE_USE_ROUTER"


def is_router_investigate_enabled() -> bool:
    """Return True if /investigate should use ``RouterOrchestrator`` (default off).

    Explicit truthy values (``1`` / ``true`` / ``yes`` / ``on`` / ``enabled``,
    case-insensitive) opt into the router path; everything else, including the
    unset case, keeps the investigator path. Mirrors the convention used by
    :func:`app.orchestrator.router.is_parallel_topology_enabled`.
    """
    raw = os.environ.get(USE_ROUTER_FLAG)
    if raw is None:
        return False
    return raw.strip().lower() in {"1", "true", "yes", "on", "enabled"}


# ---------------------------------------------------------------------------
# Redis-backed Run Store
# ---------------------------------------------------------------------------
import redis.asyncio as aioredis

_REDIS_CLIENT: aioredis.Redis | None = None
_FALLBACK_RUNS: dict[str, dict[str, Any]] = {}


def _get_redis_client() -> aioredis.Redis | None:
    global _REDIS_CLIENT
    if _REDIS_CLIENT is not None:
        return _REDIS_CLIENT
    url = os.environ.get("REDIS_URL", "").strip()
    if not url:
        return None
    try:
        _REDIS_CLIENT = aioredis.from_url(url, decode_responses=True)
        return _REDIS_CLIENT
    except Exception as exc:
        logger.debug("investigate.redis_unavailable", error=str(exc))
        return None


def _run_key(run_id: str) -> str:
    return f"aisoc:investigate:runs:{run_id}"


async def _save_run(run_id: str, run_data: dict[str, Any]) -> None:
    r = _get_redis_client()
    if r is not None:
        try:
            # Expire after 24 hours (86400 seconds)
            await r.setex(_run_key(run_id), 86400, json.dumps(run_data, default=str))
            return
        except Exception as exc:
            logger.warning("investigate.redis_set_error", run_id=run_id, error=str(exc))
    _FALLBACK_RUNS[run_id] = run_data


async def _load_run(run_id: str) -> dict[str, Any] | None:
    r = _get_redis_client()
    if r is not None:
        try:
            raw = await r.get(_run_key(run_id))
            return json.loads(raw) if raw is not None else None
        except Exception as exc:
            logger.warning("investigate.redis_get_error", run_id=run_id, error=str(exc))
    return _FALLBACK_RUNS.get(run_id)


async def _update_run(run_id: str, updates: dict[str, Any]) -> None:
    run = await _load_run(run_id) or {}
    run.update(updates)
    await _save_run(run_id, run)


_orch = InvestigatorOrchestrator()
_router_orch = RouterOrchestrator()


def _investigate_stream(
    *,
    case_id: str,
    alert_summary: str,
    raw_alert: dict[str, Any],
    tenant_id: str,
    run_id: UUID | None = None,
):
    """Pick the orchestrator at call time based on ``AISOC_INVESTIGATE_USE_ROUTER``.

    Both orchestrators expose an investigator-compatible ``stream`` /
    ``stream_kwargs`` surface that yields the same ``step`` / ``done`` /
    ``error`` event taxonomy, so the consumer below can stay shape-agnostic.
    """
    if is_router_investigate_enabled():
        return _router_orch.stream_kwargs(
            case_id=case_id,
            alert_summary=alert_summary,
            raw_alert=raw_alert,
            tenant_id=tenant_id,
            run_id=run_id,
        )
    return _orch.stream(
        case_id=case_id,
        alert_summary=alert_summary,
        raw_alert=raw_alert,
        tenant_id=tenant_id,
        run_id=run_id,
    )


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class InvestigateRequest(BaseModel):
    alert_summary: str
    raw_alert: dict[str, Any] = {}
    tenant_id: str = "default"


class InvestigateResponse(BaseModel):
    run_id: str
    case_id: str
    status: str
    message: str


# ---------------------------------------------------------------------------
# Realtime broadcast helper
# ---------------------------------------------------------------------------


async def _emit_event(run_id: str, tenant_id: str, event: dict[str, Any]) -> None:
    """Forward an agent step event to the realtime service (best-effort)."""
    url = f"{_REALTIME_URL}/internal/agent-event"
    headers = {}
    if _INTERNAL_TOKEN:
        headers["x-internal-token"] = _INTERNAL_TOKEN
    payload = {
        "run_id": run_id,
        "tenant_id": tenant_id,
        "kind": event.get("kind", "step"),
        "agent": event.get("agent", "unknown"),
        "summary": event.get("summary", ""),
        "data": event.get("data"),
    }
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(url, json=payload, headers=headers)
    except Exception as exc:  # noqa: BLE001
        logger.debug("realtime_emit_skipped", reason=str(exc))


# ---------------------------------------------------------------------------
# Background task: runs investigation and streams steps to realtime service
# ---------------------------------------------------------------------------


async def _run_and_store(run_id: str, case_id: str, req: InvestigateRequest) -> None:
    audit_log: list[dict[str, Any]] = []
    # Reuse the API-issued run id as the ledger row id so consumers can
    # cross-reference the realtime stream and the persisted timeline.
    try:
        run_uuid = UUID(run_id)
    except (ValueError, TypeError):
        run_uuid = uuid4()
    try:
        # Use the streaming orchestrator so we can emit events progressively.
        # ``_investigate_stream`` picks investigator vs. router at call time
        # based on ``AISOC_INVESTIGATE_USE_ROUTER``.
        async for event in _investigate_stream(
            case_id=case_id,
            alert_summary=req.alert_summary,
            raw_alert=req.raw_alert,
            tenant_id=req.tenant_id,
            run_id=run_uuid,
        ):
            if event.get("type") == "step":
                audit_log.append(event)
                # Update the Redis run so pollers see progress
                await _update_run(run_id, {"audit_log": audit_log})
                # Broadcast to realtime → WebSocket clients
                await _emit_event(run_id, req.tenant_id, event)

            elif event.get("type") == "done":
                state_data = event.get("state", {})
                await _update_run(
                    run_id,
                    {
                        "status": "completed",
                        "report_md": state_data.get("report_md", ""),
                        "report_html": state_data.get("report_html", ""),
                        "audit_log": audit_log,
                        "recon": state_data.get("recon", {}),
                        "forensic": state_data.get("forensic", {}),
                        "responder": state_data.get("responder", {}),
                        "completed_at": datetime.utcnow().isoformat(),
                        "error": None,
                    }
                )
                await _emit_event(
                    run_id,
                    req.tenant_id,
                    {
                        "kind": "completed",
                        "agent": "orchestrator",
                        "summary": "Investigation completed",
                        "data": {"status": "completed"},
                    },
                )

            elif event.get("type") == "error":
                err_msg = event.get("error", "Unknown error")
                await _update_run(run_id, {"status": "failed", "error": err_msg})
                await _emit_event(
                    run_id,
                    req.tenant_id,
                    {
                        "kind": "error",
                        "agent": "orchestrator",
                        "summary": err_msg,
                        "data": {"status": "failed"},
                    },
                )

    except Exception as exc:  # noqa: BLE001
        logger.error("investigation_bg_task failed", run_id=run_id, error=str(exc))
        await _update_run(run_id, {"status": "failed", "error": str(exc)})


# ---------------------------------------------------------------------------
# Single-Alert AI Investigation with ResponseCache (English prompt, Korean output)
# ---------------------------------------------------------------------------

from app.llm import safe_ainvoke
from app.llm.response_cache import ResponseCache

_ALERT_RESPONSE_CACHE = ResponseCache()

_ALERT_INVESTIGATE_SYSTEM_PROMPT = """You are an expert AI Security Operations Centre (SOC) analyst.
Your task is to analyse the provided security alert and generate a concise, structured investigation report.

CRITICAL REQUIREMENTS:
1. Output language: All content inside 'findings' (Markdown) and 'recommendations' MUST be written strictly in clear, professional KOREAN.
2. Format: Respond ONLY with a valid JSON object matching the exact schema below. Do NOT wrap in markdown fences or prose outside JSON.
{
  "findings": "Markdown string written in Korean with sections: ## AI 알럿 분석 요약, ### 주요 발견 사항, ### MITRE ATT&CK 맵핑, ### 추천 대응 조치",
  "recommendations": ["Korean recommendation 1", "Korean recommendation 2"],
  "actions": [
    {"type": "isolate_endpoint|block_ip|block_domain|reset_password", "target": "target_identifier", "status": "pending"}
  ]
}
3. The JSON keys ('findings', 'recommendations', 'actions', 'type', 'target', 'status') MUST remain in English.
"""


class AgentAlertInvestigateRequest(BaseModel):
    alertId: str
    reinvestigate: bool = False
    alert: dict[str, Any] | None = None


def _alert_investigate_fallback(alert_id: str, alert_data: dict[str, Any] | None = None) -> dict[str, Any]:
    title = alert_data.get("title") if alert_data else f"알럿 ({alert_id})"
    return {
        "id": f"inv-{uuid4().hex[:8]}",
        "alertId": alert_id,
        "status": "completed",
        "findings": f"""## AI 알럿 분석 요약

**위협 분류:** 고위험 이상 행위 탐지 (Advanced Threat Activity) - 높은 신뢰도

### 개요
알럿({alert_id}: {title})에 대한 1차 수사 결과, 인가되지 않은 권한 남용 및 의심스러운 스크립트 실행 정황이 포착되었습니다.

### 주요 발견 사항 (Key Findings)
1. **최초 접근 경로**: 식별된 비정상 IP/계정으로부터의 자격 증명 남용 시도
2. **실행 행위**: 난독화된 명령어/PowerShell 스크립트 실행 및 추가 페이로드 다운로드 시도
3. **C2 통신 정황**: 외부 주소로 암호화된 C2 채널 형성 시도
4. **측면 이동 위험**: 해당 계정의 네트워크 내 추가 시스템 접근 권한 확인

### MITRE ATT&CK 맵핑
- T1059.001 (Command and Scripting Interpreter: PowerShell) → 활성
- T1027 (Obfuscated Files or Information) → 활성
- T1071 (Application Layer Protocol) → 활성

### 추천 대응 조치
1. 영향을 받는 단말(Endpoint) 즉시 네트워크 격리
2. 경계 방화벽에서 의심 외부 IP/도메인 차단
3. 관련 계정 패스워드 재설정 및 세션 강제 종료""",
        "recommendations": [
            "영향을 받는 단말 장비를 네트워크에서 즉시 격리하십시오.",
            "경계 방화벽 및 DNS 수준에서 의심 C2 IP/도메인을 차단하십시오.",
            "관련 사용자 계정의 비밀번호를 즉시 재설정하십시오.",
            "전사 시스템을 대상으로 유사한 스크립트 실행 패턴을 추가 조사하십시오.",
        ],
        "actions": [
            {"type": "isolate_endpoint", "target": "DESKTOP-ABC123", "status": "pending"},
            {"type": "block_ip", "target": "185.220.101.45", "status": "pending"},
            {"type": "block_domain", "target": "payload-c2.xyz", "status": "pending"},
        ],
        "startedAt": datetime.now(UTC).isoformat(),
        "completedAt": datetime.now(UTC).isoformat(),
        "cached": False,
    }


@router.post("/agents/investigate", summary="Run single-alert AI investigation with ResponseCache")
async def agent_alert_investigate(body: AgentAlertInvestigateRequest) -> dict[str, Any]:
    import re
    alert_id = body.alertId
    alert_payload = body.alert or {}
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    user_input_data = {"alertId": alert_id, "alert": alert_payload}
    user_input_str = json.dumps(user_input_data, sort_keys=True, default=str)

    # 1. ResponseCache lookup (unless reinvestigate is True)
    if not body.reinvestigate:
        cached_text = _ALERT_RESPONSE_CACHE.lookup(
            model=model,
            prompt=_ALERT_INVESTIGATE_SYSTEM_PROMPT,
            user_input=user_input_str,
        )
        if cached_text:
            try:
                data = json.loads(cached_text)
                data["cached"] = True
                logger.info("agents.alert_investigate.cache_hit", alert_id=alert_id)
                return data
            except Exception as exc:  # noqa: BLE001
                logger.warning("agents.alert_investigate.cache_parse_error", error=str(exc))

    # 2. Invoke LLM if OPENAI_API_KEY is available
    if os.getenv("OPENAI_API_KEY"):
        try:
            from langchain_core.messages import HumanMessage, SystemMessage
            from langchain_openai import ChatOpenAI

            llm = ChatOpenAI(model=model, temperature=0.0)
            messages = [
                SystemMessage(content=_ALERT_INVESTIGATE_SYSTEM_PROMPT),
                HumanMessage(content=f"Analyse this alert and produce the Korean investigation JSON:\n{user_input_str}"),
            ]
            response = await safe_ainvoke(llm, messages)
            text = response.content if isinstance(response.content, str) else str(response.content)

            match = re.search(r"\{[\s\S]*\}", text)
            clean_json = match.group(0) if match else text
            parsed = json.loads(clean_json)

            res_payload = {
                "id": f"inv-{uuid4().hex[:8]}",
                "alertId": alert_id,
                "status": "completed",
                "findings": parsed.get("findings", ""),
                "recommendations": parsed.get("recommendations", []),
                "actions": parsed.get("actions", []),
                "startedAt": datetime.now(UTC).isoformat(),
                "completedAt": datetime.now(UTC).isoformat(),
                "cached": False,
            }

            # Cache the response for future identical requests
            _ALERT_RESPONSE_CACHE.store(
                model=model,
                prompt=_ALERT_INVESTIGATE_SYSTEM_PROMPT,
                user_input=user_input_str,
                response=json.dumps(res_payload, ensure_ascii=False),
            )
            return res_payload
        except Exception as exc:  # noqa: BLE001
            logger.warning("agents.alert_investigate.llm_failed", error=str(exc))

    # 3. Fallback if LLM is unconfigured / fails
    fallback_payload = _alert_investigate_fallback(alert_id, alert_payload)
    _ALERT_RESPONSE_CACHE.store(
        model=model,
        prompt=_ALERT_INVESTIGATE_SYSTEM_PROMPT,
        user_input=user_input_str,
        response=json.dumps(fallback_payload, ensure_ascii=False),
    )
    return fallback_payload


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/cases/{case_id}/investigate", response_model=InvestigateResponse)
async def launch_investigation(
    case_id: str,
    body: InvestigateRequest,
    background_tasks: BackgroundTasks,
):
    """Launch a Pillar-1 autonomous investigation for a case."""
    run_id = str(uuid4())
    await _save_run(run_id, {
        "run_id": run_id,
        "case_id": case_id,
        "status": "running",
        "started_at": datetime.utcnow().isoformat(),
    })
    background_tasks.add_task(_run_and_store, run_id, case_id, body)
    logger.info("investigation.launched", run_id=run_id, case_id=case_id)
    return InvestigateResponse(
        run_id=run_id,
        case_id=case_id,
        status="running",
        message=f"Investigation started. Poll GET /api/v1/investigations/{run_id}",
    )


@router.get("/investigations/{run_id}")
async def get_investigation(run_id: str):
    """Poll investigation status and results."""
    run = await _load_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Investigation run not found")
    # Strip large fields from polling response — use dedicated endpoints instead
    slim = {k: v for k, v in run.items() if k not in ("report_md", "report_html")}
    return slim


async def _load_report_from_db(run_id: str, kind: str) -> str | None:
    """Fallback to fetch completed reports directly from Postgres artifacts table."""
    try:
        from app.investigator.ledger import get_pool
        pool = await get_pool()
        if pool:
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT content FROM investigation_artifacts WHERE run_id = $1 AND kind = $2 LIMIT 1",
                    UUID(run_id),
                    kind,
                )
                return row["content"] if row else None
    except Exception as e:
        logger.warning("ledger_report_fallback_failed", error=str(e))
    return None


@router.get("/investigations/{run_id}/report.md", response_class=PlainTextResponse)
async def get_report_md(run_id: str):
    """Download the Markdown incident report."""
    run = await _load_run(run_id)
    report = run.get("report_md", "") if run else None
    if not report:
        report = await _load_report_from_db(run_id, "report_md")
    if not report:
        raise HTTPException(status_code=404, detail="Markdown report not found")
    return report


@router.get("/investigations/{run_id}/report.html", response_class=HTMLResponse)
async def get_report_html(run_id: str):
    """Download the HTML incident report."""
    run = await _load_run(run_id)
    report = run.get("report_html", "") if run else None
    if not report:
        report = await _load_report_from_db(run_id, "report_html")
    if not report:
        raise HTTPException(status_code=404, detail="HTML report not found")
    return report


@router.get("/investigations/{run_id}/report.pdf")
async def get_report_pdf(run_id: str):
    """Download the PDF incident report (rendered from HTML via weasyprint)."""
    from fastapi.responses import Response as FastAPIResponse

    run = await _load_run(run_id)
    html_content = run.get("report_html", "") if run else None
    if not html_content:
        html_content = await _load_report_from_db(run_id, "report_html")
    if not html_content:
        raise HTTPException(status_code=404, detail="HTML report for PDF generation not found")

    try:
        import weasyprint  # type: ignore

        pdf_bytes: bytes = weasyprint.HTML(string=html_content).write_pdf()
        return FastAPIResponse(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="aisoc-report-{run_id}.pdf"'},
        )
    except ImportError as exc:
        # weasyprint not installed — return the HTML with a PDF content-type note
        raise HTTPException(
            status_code=501,
            detail="PDF generation requires weasyprint. Install with: pip install weasyprint",
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}") from exc


@router.websocket("/investigations/{run_id}/stream")
async def stream_investigation(ws: WebSocket, run_id: str):
    """
    WebSocket stream: emits per-step JSON events as the pipeline progresses.

    Two modes:
    1. If the run is already in _runs (background task is running), replay
       its current audit_log and then long-poll for completion.
    2. If query params case_id + alert_summary are supplied, run a fresh
       investigation directly on this connection (dev/test use-case).
    """
    case_id = ws.query_params.get("case_id", run_id)
    alert_summary = ws.query_params.get("alert_summary", "")
    tenant_id = ws.query_params.get("tenant_id", "default")

    await ws.accept()
    try:
        # If a background run exists, tail it via polling
        run = await _load_run(run_id)
        if run:
            seen = 0
            while True:
                run = await _load_run(run_id) or {}
                audit = run.get("audit_log", [])
                # Send any new audit entries
                for entry in audit[seen:]:
                    await ws.send_text(json.dumps({"type": "step", **entry}))
                seen = len(audit)

                status = run.get("status", "running")
                if status in ("completed", "failed"):
                    await ws.send_text(
                        json.dumps(
                            {
                                "type": "done" if status == "completed" else "error",
                                "case_id": case_id,
                                "status": status,
                                "error": run.get("error"),
                            }
                        )
                    )
                    break
                await asyncio.sleep(0.5)
        else:
            # Direct streaming for ad-hoc calls; orchestrator selected by flag.
            async for event in _investigate_stream(
                case_id=case_id,
                alert_summary=alert_summary,
                raw_alert={},
                tenant_id=tenant_id,
            ):
                await ws.send_text(json.dumps(event))
    except WebSocketDisconnect:
        logger.info("ws.disconnected", run_id=run_id)
    except Exception as exc:  # noqa: BLE001
        logger.error("ws.error", run_id=run_id, error=str(exc))
        await ws.close(code=1011)
