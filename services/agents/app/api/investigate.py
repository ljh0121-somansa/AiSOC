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
import hmac
import json
import os
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

import httpx
import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel
from fastapi import status

from app.investigator import InvestigatorOrchestrator
from app.graph.runner import run_case_investigation
from app.investigator import ledger as case_ledger
from app.services.timeline_writer import CaseTimelineWriter
from app.graph.case_workflow import CaseContextLoadError, fetch_case_investigation_context
from app.orchestrator.router import RouterOrchestrator
from app.security.tenant_scope import (
    TENANT_HEADER,
    TenantPrincipal,
    require_console_or_service_auth,
    resolve_console_secret,
    resolve_service_token,
    scoped_tenant_or_403,
    verify_console_token,
)

logger = structlog.get_logger()
router = APIRouter(prefix="/api/v1", tags=["investigations"])

#: The console reaches this service directly through a Next rewrite, sending
#: the first-party access token as a bearer credential. The tenant comes from
#: that verified token; a `tenant_id` on the request is only ever a filter,
#: intersected with it, so naming a foreign tenant is a 403 rather than a
#: selector for somebody else's investigation.
ScopedPrincipal = Annotated[TenantPrincipal, Depends(require_console_or_service_auth)]


async def _ws_principal(ws: WebSocket) -> TenantPrincipal | None:
    """Resolve a WebSocket caller's tenant scope, or ``None`` to refuse.

    The HTTP routes take ``ScopedPrincipal`` and a router-level dependency
    would be the obvious way to cover this one too — but a dependency that
    raises ``HTTPException`` has no defined rendering on a WebSocket scope,
    and a browser cannot set an ``Authorization`` header on a WS handshake
    regardless. So the credential is read from the header when a machine
    client sends one, and from ``?token=`` when the browser connects, which
    is the same shape ``services/realtime`` already uses for its tickets.

    Verification is the shared vendored logic, not a second implementation:
    a parallel verifier is how one side ends up accepting ``alg: none`` after
    the other stopped.
    """
    header = ws.headers.get("authorization") or ""
    token = header[len("Bearer ") :].strip() if header.startswith("Bearer ") else (ws.query_params.get("token") or "").strip()
    if not token:
        return None

    secret = resolve_console_secret()
    if secret:
        claims = verify_console_token(token, secret)
        if claims is not None:
            try:
                return TenantPrincipal(
                    tenant_ids=frozenset({UUID(str(claims["tenant_id"]))}),
                    subject=f"console:{claims.get('sub', 'unknown')}",
                )
            except (KeyError, ValueError, TypeError):
                return None

    service_token = resolve_service_token()
    if service_token and hmac.compare_digest(token, service_token):
        declared = (ws.headers.get(TENANT_HEADER.lower()) or ws.query_params.get("tenant_id") or "").strip()
        if not declared:
            # A service token identifies a service, not a tenant. Absent is
            # an empty scope, never every scope.
            return None
        try:
            return TenantPrincipal(tenant_ids=frozenset({UUID(declared)}), subject="service", delegated=True)
        except ValueError:
            return None
    return None


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
# U12: Case-dedicated start gate (flag default OFF)
# ---------------------------------------------------------------------------
CASE_INVESTIGATE_FLAG = "AISOC_CASE_INVESTIGATE"

#: A running run whose last ledger event is older than this (spec §9.4:
# 30 min) is considered stale and is recovered inside the advisory lock.
STALE_AFTER_S = float(os.getenv("AISOC_CASE_STALE_AFTER_S", "1800"))


def case_investigate_enabled() -> bool:
    """True when the U12 start gate (plan U12, spec §2/§3) is enabled.

    Default off: when off, ``launch_investigation`` keeps the existing
    Pillar-1 path untouched (merge safety, plan U12 review point 1).
    """
    raw = os.environ.get(CASE_INVESTIGATE_FLAG)
    if raw is None:
        return False
    return raw.strip().lower() in {"1", "true", "yes", "on", "enabled"}


async def _launch_case_investigation(
    case_id: str,
    body: InvestigateRequest,
    background_tasks: BackgroundTasks,
    principal: ScopedPrincipal,
) -> InvestigateResponse:
    """U12 start gate: pre-flight 4-checks, advisory lock, stale recovery.

    1. Case exists & is owned by the caller's tenant (U4 context API;
       foreign-tenant or missing -> 404, nothing logged or posted).
    2. Case not closed -> 409 ``case_closed`` + ``skipped(closed_case)``
       comment via CaseTimelineWriter.
    3. At least one supported EDR alert (source_kind dynamic/static) ->
       otherwise 422 ``no_edr_alert`` + ``skipped(no_edr_alert)`` comment.
    4. No active non-stale running run -> 409 ``run_in_progress`` with the
       existing run_id; a stale run is finalised inside the advisory lock
       as failed(``stale_run_recovered``) before opening the new run.
    """
    body.tenant_id = str(scoped_tenant_or_403(principal, body.tenant_id))
    tenant_uuid = await case_ledger.resolve_tenant(body.tenant_id)

    tenant_header = str(tenant_uuid) if tenant_uuid is not None else str(body.tenant_id)
    try:
        ctx = await fetch_case_investigation_context(case_id, tenant_header)
    except CaseContextLoadError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="case not found",
        ) from None
    if ctx.get("status") == "closed":
        writer = CaseTimelineWriter()
        await writer.post_investigation_comment(
            case_id=case_id,
            tenant_id=str(tenant_uuid or body.tenant_id),
            event_type="investigation_skipped",
            reason_code="closed_case",
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"reason_code": "case_closed"},
        )

    alerts = ctx.get("alerts") or []
    supported = [
        a for a in alerts
        if str(a.get("external_id") or "").split(":", 1)[0] in ("dynamic", "static")
    ]
    if not supported:
        writer = CaseTimelineWriter()
        await writer.post_investigation_comment(
            case_id=case_id,
            tenant_id=str(tenant_uuid or body.tenant_id),
            event_type="investigation_skipped",
            reason_code="no_edr_alert",
        )
        raise HTTPException(
            status_code=422,
            detail={"reason_code": "no_edr_alert"},
        )

    pool = await case_ledger.get_pool()
    new_run_id = uuid4()
    run_id = str(new_run_id)
    if tenant_uuid is None:
        # No resolvable tenant: the run is not opened (matches the existing
        # no-op behavior for unresolvable tenants).
        pass
    elif pool is not None:
        lock_key = abs(hash(case_id)) & 0x7FFFFFFF
        async with pool.acquire() as conn:
            await conn.execute("SELECT pg_advisory_xact_lock($1)", lock_key)
            active = await case_ledger.get_active_run(case_id, tenant_uuid)
            if active is not None:
                last_ts = await case_ledger.get_last_event_ts(active["run_id"], tenant_uuid)
                stale = last_ts is None or (datetime.utcnow() - last_ts).total_seconds() > STALE_AFTER_S
                if stale:
                    await case_ledger.complete_run(
                        run_id=active["run_id"],
                        tenant_id=tenant_uuid,
                        status="failed",
                        error="stale_run_recovered",
                    )
                else:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail={
                            "reason_code": "run_in_progress",
                            "existing_run_id": str(active["run_id"]),
                        },
                    )
            # #4: open the new run INSIDE the advisory lock so a concurrent
            # stale-recovery race is serialised and start_run is atomic with
            # the stale finalisation (plan U12: "same lock, atomic").
            await case_ledger.start_run(
                run_id=new_run_id,
                case_id=case_id,
                tenant_ref=body.tenant_id,
                alert_summary=str(body.alert_summary or "")[:8000],
                raw_alert=body.raw_alert or {},
                model_used="graph:case_investigation",
            )
    else:
        # No DB pool: open the run without the lock (degraded path, existing
        # behavior preserved).
        await case_ledger.start_run(
            run_id=new_run_id,
            case_id=case_id,
            tenant_ref=body.tenant_id,
            alert_summary=str(body.alert_summary or "")[:8000],
            raw_alert=body.raw_alert or {},
            model_used="graph:case_investigation",
        )

    writer = CaseTimelineWriter()
    await writer.post_investigation_comment(
        case_id=case_id,
        tenant_id=str(tenant_uuid or body.tenant_id),
        event_type="investigation_started",
        run_id=run_id,
    )

    state = {
        "case_id": case_id,
        "run_id": run_id,
        "tenant_ref": body.tenant_id,
        "alert_count": len(supported),
        "case_summary": str(body.alert_summary or "")[:8000],
        "raw_case": body.raw_alert or {},
        # #3: forward the U4 context the gate already loaded so the U9 node
        # does not re-fetch it (single U4 fetch per run, spec §2/§4).
        "case_context": ctx,
        "alerts": ctx.get("alerts") or [],
    }
    background_tasks.add_task(_run_case_background, run_id, case_id, state, body.tenant_id)
    logger.info(
        "case_investigation.launched",
        run_id=run_id,
        case_id=case_id,
        tenant=str(body.tenant_id),
    )
    return InvestigateResponse(
        run_id=run_id,
        case_id=case_id,
        status="running",
        message=f"Case investigation started. Poll GET /api/v1/investigations/{run_id}",
    )


async def _run_case_background(
    run_id: str,
    case_id: str,
    state: dict,
    tenant_id: str,
) -> None:
    """Background task: run the U7/U9/U11 case graph, finalise the run (U13)."""
    import json
    merged = await run_case_investigation(state, persist=True)
    status_value = "completed"
    error = None
    if merged.get("error") is not None:
        status_value = "failed"
        error = str(merged.get("error"))
    tenant_uuid = await case_ledger.resolve_tenant(state.get("tenant_ref", "default"))
    # U13: persist the LLM synthesis report as a `case_report_json` artifact
    # (spec §5 stage 11 / §7.1); the GET endpoint reads it back.
    report = merged.get("report")
    if report and tenant_uuid is not None:
        try:
            await case_ledger.record_artifact(
                run_id=UUID(run_id),
                tenant_id=tenant_uuid,
                kind="case_report_json",
                content=json.dumps(report, ensure_ascii=False),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("case_report_artifact_failed", run_id=run_id, error=str(exc)[:200])
    # #2: post the result comment (spec §6): completed -> investigation_completed,
    # failed -> investigation_failed. A failed post does NOT invalidate the run
    # (spec §6 review point 3); we only log it.
    cmt_tenant = str(tenant_uuid or state.get("tenant_ref", "default"))
    writer = CaseTimelineWriter()
    if status_value == "failed":
        posted = await writer.post_investigation_comment(
            case_id=case_id,
            tenant_id=cmt_tenant,
            event_type="investigation_failed",
            run_id=run_id,
            reason_code=str(error or "graph_error")[:120],
        )
        if not posted:
            logger.warning("case_investigation.failed_comment_post_failed", run_id=run_id)
    else:
        posted = await writer.post_investigation_comment(
            case_id=case_id,
            tenant_id=cmt_tenant,
            event_type="investigation_completed",
            run_id=run_id,
            verdict=merged.get("verdict"),
            synthesis_performed=bool(merged.get("synthesis_performed", False)),
            confidence=merged.get("confidence"),
            limitation_codes=merged.get("limitations") or [],
        )
        if not posted:
            logger.warning("case_investigation.completed_comment_post_failed", run_id=run_id)
    await _update_run(run_id, {"status": status_value, "error": error})
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

            elif event.get("type") in ("done", "error"):
                state_data = event.get("state", {})
                has_error = any(item.get("kind") == "error" for item in audit_log)
    
                if has_error or state_data.get("status") == "failed" or event.get("type") == "error":
                    final_status = "failed"
                    # audit_log에서 실패 원인 요약 문구 추출
                    last_error_log = next((item.get("summary") for item in reversed(audit_log) if item.get("kind") == "error"), "Investigation failed")
                    final_error = state_data.get("error") or last_error_log
                else:
                    final_status = "completed"
                    final_error = None
                await _update_run(
                    run_id,
                    {
                        "status": final_status,
                        "report_md": state_data.get("report_md", ""),
                        "report_html": state_data.get("report_html", ""),
                        "audit_log": audit_log,
                        "recon": state_data.get("recon", {}),
                        "forensic": state_data.get("forensic", {}),
                        "responder": state_data.get("responder", {}),
                        "completed_at": datetime.utcnow().isoformat(),
                        "error": final_error,
                    }
                )
                await _emit_event(
                    run_id,
                    req.tenant_id,
                    {
                        "kind": "completed" if final_status == "completed" else "error",
                        "agent": "orchestrator",
                        "summary": final_error if final_status == "failed" else "Investigation completed",
                        "data": {"status": final_status, "error": final_error},
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
4. OUTPUT WRAPPER RULE: Your entire output MUST be a valid JSON object matching the schema above. Do NOT   
 include any thinking, reasoning, or preamble text outside the JSON object.
"""


class AgentAlertInvestigateRequest(BaseModel):
    alertId: str
    reinvestigate: bool = False
    alert: dict[str, Any] | None = None


def _alert_investigate_fallback(alert_id: str, alert_data: dict[str, Any] | None = None) -> dict[str, Any]:
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="LLM 서비스를 이용할 수 없습니다. (Fallback 요약 생성이 비활성화됨)"
    )


@router.post("/agents/investigate", summary="Run single-alert AI investigation with ResponseCache")
async def agent_alert_investigate(body: AgentAlertInvestigateRequest) -> dict[str, Any]:
    import re
    alert_id = body.alertId
    alert_payload = body.alert or {}
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    safe_keys = {
        "title", "name", "severity", "source", "connector_type",
        "category", "description", "host", "hostname", "user",
        "user_name", "src_ip", "source_ip", "dest_ip", "destination_ip",
        "src_port", "dest_port", "process_name", "process", "file_hash",
        "domain", "url", "tags", "mitre_techniques", "mitre_attack",
    }
    safe_alert = {k: v for k, v in alert_payload.items() if k in safe_keys and v not in (None, "", [], {})}
    user_input_data = {"alertId": alert_id, "alert": safe_alert}
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
            max_tokens = int(os.getenv("AISOC_MAX_TOKENS", "2048")) 
            llm = ChatOpenAI(model=model, temperature=0.0, max_tokens=max_tokens, response_format={"type":           
 "json_object"})
            messages = [
                SystemMessage(content=_ALERT_INVESTIGATE_SYSTEM_PROMPT),
                HumanMessage(content=f"Analyse this alert and produce the Korean investigation JSON:\n{user_input_str}"),
            ]
            response = await safe_ainvoke(llm, messages)
            text = response.content if isinstance(response.content, str) else str(response.content)

            cleaned_text = text.strip()
            if "</think>" in cleaned_text:
                cleaned_text = cleaned_text.split("</think>", 1)[1].strip()
            else:
                cleaned_text = re.sub(r"<think>[\s\S]*?</think>", "", cleaned_text).strip()

            # 마크다운 ```json ... ``` 펜스 제거
            cleaned_text = re.sub(r"^```(?:json)?\s*", "", cleaned_text, flags=re.IGNORECASE)
            cleaned_text = re.sub(r"\s*```$", "", cleaned_text).strip()

            # 완벽한 JSON 객체만 추출
            match = re.search(r"\{[\s\S]*\}", cleaned_text)
            json_target = match.group(0) if match else cleaned_text

            try:
                parsed = json.loads(json_target)
            except json.JSONDecodeError:
                # Extra data가 뒤에 남아있을 경우 첫 번째 유효한 JSON만 추출
                decoder = json.JSONDecoder()
                parsed, _ = decoder.raw_decode(json_target)

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
    principal: ScopedPrincipal,
):
    """Launch a Pillar-1 autonomous investigation for a case."""
    if case_investigate_enabled():
        return await _launch_case_investigation(case_id, body, background_tasks, principal)
    body.tenant_id = str(scoped_tenant_or_403(principal, body.tenant_id))
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
async def get_investigation(run_id: str, principal: ScopedPrincipal):
    """Poll investigation status and results (U13: Case runs also expose the
    structured ``report`` loaded from the ``case_report_json`` artifact)."""
    run = await _load_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Investigation run not found")
    # Strip large fields from polling response — use dedicated endpoints instead
    slim = {k: v for k, v in run.items() if k not in ("report_md", "report_html")}
    # U13 (spec §5 stage 11, §7.1): Case runs carry a structured report
    # persisted as a ``case_report_json`` artifact. Additive key — non-case
    # runs simply have no such artifact, so ``report`` stays None.
    import json as _json
    report_json = await _load_report_from_db(run_id, "case_report_json")
    if report_json:
        try:
            report_data = _json.loads(report_json)
        except ValueError:
            report_data = None
        if report_data:
            slim["report"] = {
                "verdict": report_data.get("verdict"),
                "synthesis_performed": report_data.get("synthesis_performed"),
                "confidence": report_data.get("confidence"),
                "limitations": report_data.get("limitations") or [],
                "entities": report_data.get("entities") or {},
                "mitre_techniques": report_data.get("mitre_techniques") or [],
            }
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
async def get_report_md(run_id: str, principal: ScopedPrincipal):
    """Download the Markdown incident report."""
    run = await _load_run(run_id)
    report = run.get("report_md", "") if run else None
    if not report:
        report = await _load_report_from_db(run_id, "report_md")
    if not report:
        raise HTTPException(status_code=404, detail="Markdown report not found")
    return report


@router.get("/investigations/{run_id}/report.html", response_class=HTMLResponse)
async def get_report_html(run_id: str, principal: ScopedPrincipal):
    """Download the HTML incident report."""
    run = await _load_run(run_id)
    report = run.get("report_html", "") if run else None
    if not report:
        report = await _load_report_from_db(run_id, "report_html")
    if not report:
        raise HTTPException(status_code=404, detail="HTML report not found")
    return report


@router.get("/investigations/{run_id}/report.pdf")
async def get_report_pdf(run_id: str, principal: ScopedPrincipal):
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
    principal = await _ws_principal(ws)
    if principal is None:
        # 1008 = policy violation. Refused before accept() so an anonymous
        # caller never reaches the branch below that starts a fresh
        # investigation — which spends the tenant's LLM budget.
        await ws.close(code=1008, reason="unauthenticated")
        return

    case_id = ws.query_params.get("case_id", run_id)
    alert_summary = ws.query_params.get("alert_summary", "")
    # The tenant comes from the verified credential. It used to come from a
    # query parameter defaulting to the literal "default", which names no
    # tenant anywhere in this schema.
    tenant_id = str(scoped_tenant_or_403(principal, ws.query_params.get("tenant_id")))

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
