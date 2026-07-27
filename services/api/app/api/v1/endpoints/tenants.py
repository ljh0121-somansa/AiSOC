"""Tenant and user management endpoints."""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import delete, or_, select, text, update

from app.api.v1.deps import AuthUser, CurrentUser, DBSession, require_permission
from app.core.security import get_password_hash
from app.models.tenant import Tenant, User
from app.services.audit import emit_audit

router = APIRouter(prefix="/tenants", tags=["tenants"])


class TenantHeaderResponse(BaseModel):
    """Minimal tenant identity payload — safe for *any* authenticated user.

    Used by the SOC console TopBar to render the tenant switcher and role
    badge (Workstream 5). Intentionally excludes `plan`, `settings`, and
    `limits` so it does not leak privileged config to viewer/analyst roles.
    """

    id: uuid.UUID
    name: str
    mssp_role: str | None
    parent_tenant_id: uuid.UUID | None

    model_config = {"from_attributes": True}


class TenantResponse(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    plan: str
    is_active: bool
    settings: dict
    limits: dict
    mssp_role: str | None = None
    parent_tenant_id: uuid.UUID | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class UserResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    username: str
    role: str
    is_active: bool
    last_login: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class CreateUserRequest(BaseModel):
    email: EmailStr
    username: str
    password: str
    role: str = "soc_analyst"


class UpdateUserRequest(BaseModel):
    username: str | None = None
    role: str | None = None
    is_active: bool | None = None
    password: str | None = None


class UpdateTenantSettingsRequest(BaseModel):
    name: str | None = None
    settings: dict | None = None


class CreateTenantRequest(BaseModel):
    name: str
    slug: str | None = None
    plan: str = "enterprise"


@router.get("/me/identity", response_model=TenantHeaderResponse)
async def get_my_tenant_identity(
    current_user: AuthUser,
    db: DBSession,
) -> TenantHeaderResponse:
    """Get minimal tenant identity for the current user.

    Returns only `id`, `name`, `mssp_role`, and `parent_tenant_id`. This is
    safe for **any** authenticated user (analyst, viewer, responder, etc.)
    because it does not expose plan, settings, or limits. Used by the SOC
    console TopBar to render the tenant switcher pill and role badge.
    """
    result = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return TenantHeaderResponse.model_validate(tenant)


@router.get("/me", response_model=TenantResponse)
async def get_my_tenant(
    current_user: Annotated[AuthUser, Depends(require_permission("settings:read"))],
    db: DBSession,
) -> TenantResponse:
    """Get the current user's tenant details (full config — requires settings:read)."""
    result = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return TenantResponse.model_validate(tenant)


@router.patch("/me/settings", response_model=TenantResponse)
async def update_tenant_settings(
    request: UpdateTenantSettingsRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
    db: DBSession,
) -> TenantResponse:
    """Update tenant settings and name."""
    updates: dict = {"updated_at": datetime.now(UTC)}
    if request.name is not None:
        updates["name"] = request.name
    if request.settings is not None:
        updates["settings"] = request.settings

    await db.execute(
        update(Tenant)
        .where(Tenant.id == current_user.tenant_id)
        .values(**updates)
    )
    await db.commit()

    result = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    return TenantResponse.model_validate(result.scalar_one())


@router.get("/me/users", response_model=list[UserResponse])
async def list_users(
    current_user: Annotated[AuthUser, Depends(require_permission("users:read"))],
    db: DBSession,
) -> list[UserResponse]:
    """List all users in the current tenant."""
    result = await db.execute(
        select(User)
        .where(User.tenant_id == current_user.tenant_id, User.is_active == True)  # noqa: E712
        .order_by(User.created_at)
    )
    users = result.scalars().all()
    return [UserResponse.model_validate(u) for u in users]


@router.post("/me/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    request: CreateUserRequest,
    req: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("users:write"))],
    db: DBSession,
) -> UserResponse:
    """Create a new user in the current tenant."""
    # Check email uniqueness
    existing = await db.execute(select(User).where(User.email == request.email))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this email already exists",
        )

    user = User(
        tenant_id=current_user.tenant_id,
        email=request.email,
        username=request.username,
        hashed_password=get_password_hash(request.password),
        role=request.role,
    )
    db.add(user)

    try:
        await emit_audit(
            db=db,
            tenant_id=current_user.tenant_id,
            actor_id=current_user.user_id,
            actor_email=current_user.email,
            action="users:create",
            resource="user",
            resource_id=str(user.id),
            changes={"email": user.email, "username": user.username, "role": user.role},
            request=req,
        )
    except Exception:  # noqa: BLE001
        pass

    await db.commit()
    await db.refresh(user)
    return UserResponse.model_validate(user)


@router.patch("/me/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: uuid.UUID,
    request: UpdateUserRequest,
    req: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("users:write"))],
    db: DBSession,
) -> UserResponse:
    """Update a user."""
    result = await db.execute(select(User).where(User.id == user_id, User.tenant_id == current_user.tenant_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if (user.role == "platform_admin") and current_user.role != "platform_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="최고 플랫폼 관리자 계정은 수정할 수 없습니다.",
        )

    updates: dict = {}
    for field in ["username", "role", "is_active"]:
        val = getattr(request, field, None)
        if val is not None:
            setattr(user, field, val)
            updates[field] = val

    if request.password is not None and request.password.strip():
        user.hashed_password = get_password_hash(request.password)
        updates["hashed_password"] = True

    if updates:
        user.updated_at = datetime.now(UTC)

        try:
            audit_changes = {k: v for k, v in updates.items() if k != "hashed_password"}
            if "hashed_password" in updates:
                audit_changes["password_changed"] = True
            await emit_audit(
                db=db,
                tenant_id=current_user.tenant_id,
                actor_id=current_user.user_id,
                actor_email=current_user.email,
                action="users:update",
                resource="user",
                resource_id=str(user.id),
                changes=audit_changes,
                request=req,
            )
        except Exception:  # noqa: BLE001
            pass

        await db.commit()
        await db.refresh(user)

    return UserResponse.model_validate(user)


@router.delete("/me/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: uuid.UUID,
    req: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("users:write"))],
    db: DBSession,
) -> None:
    """Delete a team member from the current tenant."""
    if user_id == current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own active account",
        )

    result = await db.execute(select(User).where(User.id == user_id, User.tenant_id == current_user.tenant_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if (user.role == "platform_admin") and current_user.role != "platform_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="최고 플랫폼 관리자 계정은 삭제할 수 없습니다.",
        )

    user_email = user.email
    user_username = user.username
    target_user_id = str(user.id)

    try:
        await db.execute(delete(User).where(User.id == user_id))
        await db.commit()
    except Exception:
        await db.rollback()
        # Fallback to soft delete (deactivation) if Foreign Key constraints prevent hard deletion
        await db.execute(update(User).where(User.id == user_id).values(is_active=False, updated_at=datetime.now(UTC)))
        await db.commit()

    try:
        await emit_audit(
            db=db,
            tenant_id=current_user.tenant_id,
            actor_id=current_user.user_id,
            actor_email=current_user.email,
            action="users:delete",
            resource="user",
            resource_id=target_user_id,
            changes={"email": user_email, "username": user_username},
            request=req,
        )
        await db.commit()
    except Exception:  # noqa: BLE001
        pass


@router.post("", response_model=TenantResponse, status_code=status.HTTP_201_CREATED)
async def create_tenant(
    request: CreateTenantRequest,
    req: Request,
    current_user: Annotated[CurrentUser, Depends(require_permission("settings:write"))],
    db: DBSession,
) -> TenantResponse:
    """Create a new tenant workspace and seed default RBAC roles."""
    clean_name = request.name.strip()
    if not clean_name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Tenant name cannot be empty")

    base_slug = request.slug or clean_name.lower().replace(" ", "-")
    # Clean slug characters
    base_slug = "".join(c for c in base_slug if c.isalnum() or c in ("-", "_")) or "tenant"
    slug = base_slug

    existing = await db.execute(select(Tenant).where(Tenant.slug == slug))
    if existing.scalar_one_or_none() is not None:
        slug = f"{base_slug}-{uuid.uuid4().hex[:4]}"

    user_res = await db.execute(select(User).where(User.id == current_user.user_id))
    creator_user = user_res.scalar_one_or_none()
    home_parent_id = creator_user.tenant_id if creator_user else current_user.tenant_id

    # Link new tenant as a child of the current parent workspace if applicable
    parent_tenant = await db.get(Tenant, home_parent_id)
    if parent_tenant and parent_tenant.mssp_role != "child":
        parent_tenant.mssp_role = "parent"
        parent_id = home_parent_id
        mssp_role = "child"
    else:
        parent_id = None
        mssp_role = "standalone"

    new_tenant = Tenant(
        id=uuid.uuid4(),
        name=clean_name,
        slug=slug,
        plan=request.plan,
        parent_tenant_id=parent_id,
        mssp_role=mssp_role,
    )
    db.add(new_tenant)

    await db.flush()

    # Seed default RBAC roles for the new tenant
    try:
        await db.execute(text("SELECT seed_system_roles(:tid)").bindparams(tid=new_tenant.id))
    except Exception:  # noqa: BLE001
        pass

    # Automatically register creator into users table for the new tenant
    if creator_user:
        new_user = User(
            id=uuid.uuid4(),
            tenant_id=new_tenant.id,
            email=creator_user.email,
            username=creator_user.username,
            hashed_password=creator_user.hashed_password,
            role=creator_user.role if creator_user.role in ("platform_admin", "admin", "tenant_admin") else "tenant_admin",
            is_active=True,
        )
        db.add(new_user)

    try:
        await emit_audit(
            db=db,
            tenant_id=current_user.tenant_id,
            actor_id=current_user.user_id,
            actor_email=current_user.email,
            action="tenant:create",
            resource="tenant",
            resource_id=str(new_tenant.id),
            changes={"name": new_tenant.name, "slug": new_tenant.slug},
            request=req,
        )
    except Exception:  # noqa: BLE001
        pass

    await db.commit()
    await db.refresh(new_tenant)
    return TenantResponse.model_validate(new_tenant)


@router.delete("/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tenant(
    tenant_id: uuid.UUID,
    req: Request,
    current_user: Annotated[CurrentUser, Depends(require_permission("settings:write"))],
    db: DBSession,
) -> None:
    """Delete a child tenant workspace."""
    tenant = await db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")

    user_res = await db.execute(select(User).where(User.id == current_user.user_id))
    db_user = user_res.scalar_one_or_none()
    home_parent_id = db_user.tenant_id if db_user else current_user.tenant_id

    if tenant.id == home_parent_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete the primary root workspace / 메인 루트 테넌트는 삭제할 수 없습니다.",
        )

    if tenant.parent_tenant_id != home_parent_id and tenant.id != current_user.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to delete this tenant / 이 테넌트를 삭제할 권한이 없습니다.",
        )

    await db.execute(delete(Tenant).where(Tenant.id == tenant_id))

    try:
        await emit_audit(
            db=db,
            tenant_id=current_user.tenant_id,
            actor_id=current_user.user_id,
            actor_email=current_user.email,
            action="tenant:delete",
            resource="tenant",
            resource_id=str(tenant_id),
            changes={"name": tenant.name, "slug": tenant.slug},
            request=req,
        )
    except Exception:  # noqa: BLE001
        pass

    await db.commit()


@router.get("/my-tenants", response_model=list[TenantHeaderResponse])
async def list_my_tenants(
    current_user: AuthUser,
    db: DBSession,
) -> list[TenantHeaderResponse]:
    """Recursively resolve the full accessible tenant hierarchy tree (platform_admin only) or member tenants."""
    if current_user.role == "platform_admin":
        sql = text("""
            WITH RECURSIVE
              user_home AS (
                SELECT tenant_id FROM users WHERE email = :email AND is_active = TRUE
              ),
              descendants AS (
                SELECT id, name, mssp_role, parent_tenant_id, created_at
                FROM tenants
                WHERE id IN (SELECT tenant_id FROM user_home)
                UNION ALL
                SELECT t.id, t.name, t.mssp_role, t.parent_tenant_id, t.created_at
                FROM tenants t
                JOIN descendants d ON t.parent_tenant_id = d.id
              ),
              ancestors AS (
                SELECT id, name, mssp_role, parent_tenant_id, created_at
                FROM tenants
                WHERE id = :active_tid
                UNION ALL
                SELECT t.id, t.name, t.mssp_role, t.parent_tenant_id, t.created_at
                FROM tenants t
                JOIN ancestors a ON t.id = a.parent_tenant_id
              )
            SELECT DISTINCT id, name, mssp_role, parent_tenant_id, created_at
            FROM (
              SELECT * FROM descendants
              UNION ALL
              SELECT * FROM ancestors
            ) tree
            ORDER BY created_at
        """)
    else:
        sql = text("""
            SELECT DISTINCT t.id, t.name, t.mssp_role, t.parent_tenant_id, t.created_at
            FROM tenants t
            JOIN users u ON u.tenant_id = t.id
            WHERE u.email = :email AND u.is_active = TRUE
            ORDER BY t.created_at
        """)

    result = await db.execute(
        sql,
        {"email": current_user.email, "active_tid": current_user.tenant_id},
    )
    rows = result.mappings().all()
    return [
        TenantHeaderResponse(
            id=row["id"],
            name=row["name"],
            mssp_role=row["mssp_role"],
            parent_tenant_id=row["parent_tenant_id"],
        )
        for row in rows
    ]
