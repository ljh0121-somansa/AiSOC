"""FastAPI dependency injection.

Authentication supports two credential types:
  1. JWT Bearer token   – issued by /auth/login
  2. API key Bearer     – prefixed with "aisoc_", validated against the api_keys table

API key auth carries explicit ``scopes``; JWT auth derives permissions from the
user's role via ``ROLE_PERMISSIONS``.

Multi-tenant Row-Level Security (RLS)
--------------------------------------
Use ``TenantDBSession`` (from ``app.db.rls``) instead of ``DBSession`` for
endpoints that must be tenant-isolated at the database level.  It sets the
Postgres session variable ``app.current_tenant_id`` before yielding, which
activates the RLS policies defined in ``migrations/002_rls.sql``.

    from app.db.rls import TenantDBSession

    @router.get("/cases")
    async def list_cases(db: TenantDBSession, user: AuthUser):
        ...
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dev_auth import (
    DEMO_TENANT_ID,
    DEMO_USER_EMAIL,
    DEMO_USER_ID,
    DEMO_USER_ROLE,
    is_dev_mode,
)
from app.core.security import decode_token, has_permission, hash_api_key
from app.db.database import get_db
from app.models.tenant import ApiKey, User

bearer_scheme = HTTPBearer(auto_error=False)

_API_KEY_PREFIX = "aisoc_"


class CurrentUser:
    """Resolved authenticated user context.

    ``scopes`` is only populated when authenticated via an API key; it
    holds the explicit permission strings granted to that key.  When ``None``
    the user's role-based permissions apply.

    Permission resolution order:
      1. API-key scopes (explicit list)
      2. RBAC ``user_roles`` → ``role_permissions`` (database-backed)
      3. Static ``ROLE_PERMISSIONS`` fallback (legacy / bootstrap)
    """

    def __init__(
        self,
        user_id: uuid.UUID,
        tenant_id: uuid.UUID,
        role: str,
        email: str,
        scopes: list[str] | None = None,
    ) -> None:
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.role = role
        self.email = email
        self.scopes = scopes  # None → role-based; list → API-key scoped

    def require_permission(self, permission: str) -> None:
        if self.scopes is not None:
            # API-key path: check explicit scopes list
            allowed = "*" in self.scopes or permission in self.scopes or f"{permission.split(':')[0]}:*" in self.scopes
            if not allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"API key missing scope: {permission}",
                )
        else:
            # JWT / role path — static ROLE_PERMISSIONS fallback
            if not has_permission(self.role, permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: {permission}",
                )

    async def has_permission_db(self, permission: str, db: AsyncSession) -> bool:
        """Check permission via RBAC tables (granular RBAC).

        Falls back to the static ROLE_PERMISSIONS map when the user has
        no rows in ``user_roles`` (e.g. fresh tenants not yet migrated).
        """
        if is_dev_mode() or self.role == "platform_admin":
            return True

        if self.scopes is not None:
            return "*" in self.scopes or permission in self.scopes or f"{permission.split(':')[0]}:*" in self.scopes

        # Query RBAC tables
        from app.models.rbac import Permission as PermModel  # noqa: PLC0415
        from app.models.rbac import Role, RolePermission, UserRole

        result = await db.execute(
            select(PermModel.name)
            .join(RolePermission, RolePermission.permission_id == PermModel.id)
            .join(Role, Role.id == RolePermission.role_id)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == self.user_id, Role.tenant_id == self.tenant_id)
        )
        db_perms: list[str] = [row[0] for row in result.all()]

        if db_perms:
            return "*" in db_perms or permission in db_perms or f"{permission.split(':')[0]}:*" in db_perms

        # Fallback to static map
        return has_permission(self.role, permission)

    async def require_permission_db(self, permission: str, db: AsyncSession) -> None:
        """Async permission check (RBAC tables then static fallback)."""
        if not await self.has_permission_db(permission, db):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission}",
            )


async def _resolve_api_key(raw_key: str, db: AsyncSession) -> CurrentUser:
    """Look up and validate an aisoc_ API key; return its CurrentUser."""
    hashed = hash_api_key(raw_key)
    result = await db.execute(
        select(ApiKey).where(
            ApiKey.hashed_key == hashed,
            ApiKey.is_active == True,  # noqa: E712
        )
    )
    api_key: ApiKey | None = result.scalar_one_or_none()
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check expiry
    if api_key.expires_at is not None and api_key.expires_at < datetime.now(UTC):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Update last_used_at in background (fire-and-forget style — don't await)
    await db.execute(update(ApiKey).where(ApiKey.id == api_key.id).values(last_used_at=datetime.now(UTC)))

    # Fetch the owning user for context (user_id may be NULL for service keys)
    role = "api_service"
    email = f"api-key:{api_key.key_prefix}"
    user_id = api_key.user_id or api_key.tenant_id  # fallback to tenant UUID

    if api_key.user_id is not None:
        user_res = await db.execute(
            select(User).where(User.id == api_key.user_id, User.is_active == True)  # noqa: E712
        )
        user = user_res.scalar_one_or_none()
        if user is not None:
            role = user.role
            email = user.email
            user_id = user.id

    return CurrentUser(
        user_id=user_id,
        tenant_id=api_key.tenant_id,
        role=role,
        email=email,
        scopes=api_key.scopes or [],
    )


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)],
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> CurrentUser:
    """Resolve Bearer token to CurrentUser.

    Accepts both JWT tokens and aisoc_ API keys.

    In development mode an unauthenticated request resolves to a deterministic
    demo user (see ``app.api.v1.dev_auth``). Production requires a bearer token.
    """
    if credentials is None:
        if is_dev_mode():
            tenant_header = request.headers.get("x-tenant-id")
            resolved_tenant = DEMO_TENANT_ID
            if tenant_header:
                try:
                    resolved_tenant = uuid.UUID(tenant_header)
                except ValueError:
                    pass
            return CurrentUser(
                user_id=DEMO_USER_ID,
                tenant_id=resolved_tenant,
                role=DEMO_USER_ROLE,
                email=DEMO_USER_EMAIL,
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    # --- API key path ---
    if token.startswith(_API_KEY_PREFIX):
        return await _resolve_api_key(token, db)

    # --- JWT path ---
    try:
        payload = decode_token(token)
        user_id: str = payload.get("sub")  # type: ignore[assignment]
        token_type: str = payload.get("type", "access")
        if user_id is None or token_type != "access":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        ) from e

    result = await db.execute(
        select(User).where(User.id == uuid.UUID(user_id), User.is_active == True)  # noqa: E712
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    active_tenant_id = user.tenant_id
    tenant_header = request.headers.get("x-tenant-id")
    if tenant_header:
        try:
            requested_tid = uuid.UUID(tenant_header)
            if requested_tid != user.tenant_id:
                # 1. Direct membership check: user is explicitly registered in requested_tid
                direct_res = await db.execute(
                    select(User.id).where(
                        User.email == user.email,
                        User.tenant_id == requested_tid,
                        User.is_active == True,  # noqa: E712
                    )
                )
                if direct_res.scalar_one_or_none() is not None:
                    active_tenant_id = requested_tid
                elif user.role == "platform_admin":
                    # 2. Platform admin accessing a child tenant in the hierarchy tree
                    check_sql = text("""
                        WITH RECURSIVE
                          user_home AS (
                            SELECT tenant_id FROM users WHERE email = :email AND is_active = TRUE
                          ),
                          tree AS (
                            SELECT id FROM tenants WHERE id IN (SELECT tenant_id FROM user_home)
                            UNION ALL
                            SELECT t.id FROM tenants t JOIN tree ON t.parent_tenant_id = tree.id
                          )
                        SELECT id FROM tree WHERE id = :requested_tid
                    """)
                    c_res = await db.execute(check_sql, {"email": user.email, "requested_tid": requested_tid})
                    if c_res.scalar_one_or_none() is not None:
                        active_tenant_id = requested_tid
        except Exception:  # noqa: BLE001
            pass

    return CurrentUser(
        user_id=user.id,
        tenant_id=active_tenant_id,
        role=user.role,
        email=user.email,
    )


async def get_current_active_user(
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> CurrentUser:
    return current_user


def require_permission(permission: str):
    """Factory for permission-checking dependencies."""

    async def _check(
        current_user: CurrentUser = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> CurrentUser:
        await current_user.require_permission_db(permission, db)
        return current_user

    return _check


# Type aliases
DBSession = Annotated[AsyncSession, Depends(get_db)]
AuthUser = Annotated[CurrentUser, Depends(get_current_user)]


# Re-export TenantDBSession for convenience so endpoints can import from one place
# Actual implementation lives in app.db.rls to avoid circular imports.
def _get_tenant_db_session() -> "Annotated[AsyncSession, ...]":  # pragma: no cover
    from app.db.rls import TenantDBSession as _T  # noqa: PLC0415

    return _T  # type: ignore[return-value]
