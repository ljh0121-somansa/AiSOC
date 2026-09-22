"""SOC Shift Management endpoints."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.v1.deps import AuthUser

router = APIRouter(prefix="/shifts", tags=["shifts"])


class ShiftAnalyst(BaseModel):
    id: str
    name: str
    role: str

    model_config = {"from_attributes": True}


class ShiftSummary(BaseModel):
    id: str
    name: str
    started_at: str
    ended_at: str | None = None
    status: str
    lead: ShiftAnalyst
    analyst_count: int
    alerts_handled: int
    escalations: int
    handoff_notes: str | None = None

    model_config = {"from_attributes": True}


class ShiftCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    analysts: list[str] = Field(default_factory=list, description="Analyst user IDs")
    lead_id: str | None = None


class HandoffNotes(BaseModel):
    notes: str = Field(..., min_length=1)
    pending_items: list[str] = Field(default_factory=list)


_DEFAULT_ANALYSTS = {}

_now = datetime.now(UTC)
_DEFAULT_SHIFTS: list[dict] = []


@router.get("", response_model=list[ShiftSummary])
async def list_shifts(
    current_user: AuthUser,
    status_filter: str | None = Query(None, alias="status", description="active | completed"),
    limit: int = Query(20, ge=1, le=100),
):
    """Return shift summaries, newest first."""
    shifts = _DEFAULT_SHIFTS
    if status_filter:
        shifts = [s for s in shifts if s["status"] == status_filter]
    return [ShiftSummary(**s) for s in shifts[:limit]]


@router.get("/current", response_model=ShiftSummary)
async def get_current_shift(current_user: AuthUser):
    """Return the currently active shift."""
    for s in _DEFAULT_SHIFTS:
        if s["status"] == "active":
            return ShiftSummary(**s)
    raise HTTPException(status_code=404, detail="No active shift")


@router.post("", response_model=ShiftSummary, status_code=201)
async def create_shift(
    body: ShiftCreate,
    current_user: AuthUser,
):
    """Start a new shift."""
    new_shift = {
        "id": f"shift-{uuid.uuid4().hex[:8]}",
        "name": body.name,
        "started_at": datetime.now(UTC).isoformat(),
        "ended_at": None,
        "status": "active",
        "lead": _DEFAULT_ANALYSTS.get(body.lead_id or "a1", _DEFAULT_ANALYSTS["a1"]),
        "analyst_count": max(len(body.analysts), 1),
        "alerts_handled": 0,
        "escalations": 0,
        "handoff_notes": None,
    }
    _DEFAULT_SHIFTS.insert(0, new_shift)
    return ShiftSummary(**new_shift)


@router.put("/{shift_id}/handoff", response_model=ShiftSummary)
async def add_handoff_notes(
    shift_id: str,
    body: HandoffNotes,
    current_user: AuthUser,
):
    """Attach handoff notes to a shift and mark it completed."""
    for s in _DEFAULT_SHIFTS:
        if s["id"] == shift_id:
            s["handoff_notes"] = body.notes
            s["status"] = "completed"
            s["ended_at"] = datetime.now(UTC).isoformat()
            return ShiftSummary(**s)
    raise HTTPException(status_code=404, detail="Shift not found")
