"""CaseTimelineWriter (plan U12, spec §6/§7.1).

Wraps the api service's result-comment endpoint (U5) so the agents service
never writes to the ``aisoc_case_comments`` table directly (AGENTS.md: agents
must not compose SQL or write the timeline tables themselves). This is the
default implementation of the spec §6 writer abstraction.

Service-token only (spec §7.1): the comment route refuses a console JWT.
Without a service token the writer logs loudly and returns False — no
comment is posted, matching the rest of the service-token callers.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import structlog

from app.core.service_token import service_token

logger = structlog.get_logger()

_API_URL = os.getenv("API_SERVICE_URL", "http://api:8000")
_API_TIMEOUT_S = float(os.getenv("AGENTS_API_TIMEOUT", "10.0"))

#: Event types accepted by the U5 endpoint (graph.py ``_EVENT_TYPES``).
_EVENT_TYPES = (
    "investigation_started",
    "investigation_completed",
    "investigation_failed",
    "investigation_skipped",
)
#: Verdict enum (spec §6.1): true_positive / false_positive / insufficient.
_VERDICTS = ("true_positive", "false_positive", "insufficient")


def _service_token() -> str:
    """Shared secret for the internal route (delegated to app.core.service_token)."""
    return service_token()


class CaseTimelineWriter:
    """Posts structured investigation comments to a case timeline (spec §6)."""

    async def post_investigation_comment(
        self,
        case_id: str,
        tenant_id: str,
        event_type: str,
        run_id: str | None = None,
        verdict: str | None = None,
        synthesis_performed: bool = False,
        confidence: float | None = None,
        limitation_codes: list[str] | None = None,
        reason_code: str | None = None,
    ) -> bool:
        """POST /api/v1/graph/cases/{case_id}/investigation-comment (U5).

        Returns True on 2xx, False otherwise (missing token or API error).
        Only structured fields are accepted; free-form narrative is rejected
        by the server template (spec §5.3/§6).
        """
        if event_type not in _EVENT_TYPES:
            logger.warning(
                "case_timeline_writer.bad_event_type", event_type=event_type,
            )
            return False
        if verdict is not None and verdict not in _VERDICTS:
            logger.warning(
                "case_timeline_writer.bad_verdict", verdict=verdict,
            )
            return False
        token = _service_token()
        if not token:
            logger.warning(
                "case_timeline_writer.no_service_token",
                reason="AISOC_AGENTS_SERVICE_TOKEN is unset, so the API's service path is closed",
            )
            return False
        headers: dict[str, str] = {"X-AiSOC-Service-Token": token}
        if tenant_id:
            headers["X-AiSOC-Tenant-ID"] = str(tenant_id)
        payload: dict[str, Any] = {
            "event_type": event_type,
            "run_id": run_id,
            "verdict": verdict,
            "synthesis_performed": synthesis_performed,
            "confidence": confidence,
            "limitation_codes": limitation_codes or [],
            "reason_code": reason_code,
        }
        url = f"{_API_URL}/api/v1/graph/cases/{case_id}/investigation-comment"
        try:
            async with httpx.AsyncClient(timeout=_API_TIMEOUT_S) as client:
                resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code in (200, 201):
                    return True
                logger.warning(
                    "case_timeline_writer.post_failed",
                    status_code=resp.status_code,
                    case_id=case_id,
                    detail=str(resp.text[:200]),
                )
                return False
        except httpx.HTTPError as exc:
            logger.warning(
                "case_timeline_writer.unreachable",
                case_id=case_id, error=str(exc)[:300],
            )
            return False
