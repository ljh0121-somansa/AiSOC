"""Authentication endpoints: login, refresh, logout, user preferences."""

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, update

from app.api.v1.deps import AuthUser, DBSession, get_current_user
from app.services.audit import emit_audit

__all__ = ["router", "get_current_user"]
from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_password_hash,
    verify_password,
)
from app.models.tenant import User

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60


class RefreshRequest(BaseModel):
    refresh_token: str


class UserMeResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    username: str
    role: str
    is_active: bool
    preferences: dict[str, Any] = {}

    model_config = {"from_attributes": True}


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class ProfileUpdate(BaseModel):
    username: str | None = None
    title: str | None = None
    timezone: str | None = None


class PreferencesPatch(BaseModel):
    """Partial update payload for user preferences (merged server-side)."""

    preferences: dict[str, Any]


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, req: Request, db: DBSession) -> TokenResponse:
    """Authenticate with email/password, return JWT tokens."""
    requested_tenant = req.headers.get("x-tenant-id")

    stmt = select(User).where(User.email == request.email, User.is_active.is_(True))
    if requested_tenant:
        try:
            tid = uuid.UUID(requested_tenant)
            stmt = stmt.order_by((User.tenant_id == tid).desc(), User.created_at.desc())
        except ValueError:
            stmt = stmt.order_by(User.created_at.desc())
    else:
        stmt = stmt.order_by(User.created_at.desc())

    result = await db.execute(stmt)
    matching_users = result.scalars().all()

    user = None
    for u in matching_users:
        if verify_password(request.password, u.hashed_password):
            user = u
            break

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Update last login
    await db.execute(update(User).where(User.id == user.id).values(last_login=datetime.now(UTC)))

    # Emit audit event for login
    try:
        await emit_audit(
            db=db,
            tenant_id=user.tenant_id,
            actor_id=user.id,
            actor_email=user.email,
            action="auth:login",
            resource="user",
            resource_id=str(user.id),
            changes={"email": user.email, "username": user.username},
            request=req,
        )
    except Exception:  # noqa: BLE001
        pass

    await db.commit()

    token_data = {
        "sub": str(user.id),
        "tenant_id": str(user.tenant_id),
        "role": user.role,
        "email": user.email,
    }
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshRequest, db: DBSession) -> TokenResponse:
    """Refresh access token using a valid refresh token."""
    try:
        payload = decode_token(request.refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
        user_id = payload.get("sub")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token") from e

    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id), User.is_active.is_(True)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    token_data = {
        "sub": str(user.id),
        "tenant_id": str(user.tenant_id),
        "role": user.role,
        "email": user.email,
    }
    return TokenResponse(
        access_token=create_access_token(token_data),
        refresh_token=create_refresh_token(token_data),
    )


@router.get("/me", response_model=UserMeResponse)
async def get_me(current_user: AuthUser, db: DBSession) -> UserMeResponse:
    """Get current authenticated user info."""
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    res_dict = UserMeResponse.model_validate(user).model_dump()
    res_dict["tenant_id"] = str(current_user.tenant_id)
    return UserMeResponse.model_validate(res_dict)


@router.patch("/me", response_model=UserMeResponse)
async def update_me(
    body: ProfileUpdate,
    current_user: AuthUser,
    db: DBSession,
) -> UserMeResponse:
    """Update current authenticated user's profile info (e.g. username, title, timezone)."""
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if body.username and body.username.strip():
        user.username = body.username.strip()

    prefs = dict(user.preferences or {})
    if body.title is not None:
        prefs["title"] = body.title.strip()
    if body.timezone is not None:
        prefs["timezone"] = body.timezone.strip()
    user.preferences = prefs

    await db.commit()
    await db.refresh(user)

    return UserMeResponse.model_validate(user)


@router.patch("/me/preferences", response_model=UserMeResponse)
async def patch_me_preferences(
    body: PreferencesPatch,
    current_user: AuthUser,
    db: DBSession,
) -> UserMeResponse:
    """Merge user preferences (e.g. theme) into the stored JSONB column.

    Only the keys supplied in the request body are updated; all other
    existing keys are preserved.  This lets the frontend evolve independent
    preference namespaces without overwriting each other.
    """
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    merged = {**(user.preferences or {}), **body.preferences}
    await db.execute(update(User).where(User.id == current_user.user_id).values(preferences=merged))
    await db.commit()

    # Re-fetch to return fresh state
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    return UserMeResponse.model_validate(user)


@router.post("/me/change-password", status_code=status.HTTP_200_OK)
async def change_password(
    body: ChangePasswordRequest,
    current_user: AuthUser,
    db: DBSession,
    req: Request,
) -> dict[str, str]:
    """Change current user's password."""
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if not verify_password(body.current_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect / 현재 비밀번호가 일치하지 않습니다.",
        )

    new_pwd = body.new_password.strip()
    if len(new_pwd) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be at least 6 characters / 새 비밀번호는 6자 이상이어야 합니다.",
        )

    await db.execute(
        update(User)
        .where(User.id == user.id)
        .values(hashed_password=get_password_hash(new_pwd))
    )

    try:
        await emit_audit(
            db=db,
            tenant_id=user.tenant_id,
            actor_id=user.id,
            actor_email=user.email,
            action="auth:change_password",
            resource="user",
            resource_id=str(user.id),
            request=req,
        )
    except Exception:  # noqa: BLE001
        pass

    await db.commit()
    return {"message": "Password updated successfully / 비밀번호가 성공적으로 변경되었습니다."}
