"""Tests for detection rule mutation authorization & RBAC.

Covers both:
- Frontend compat endpoints (/api/v1/detection/rules/{rule_id})
- Canonical endpoints (/api/v1/rules/{rule_id})

Ensures platform built-in rules (tenant_id IS NULL, is_builtin = True) can only be
mutated or deleted by users with role 'platform_admin'. Tenant users cannot mutate
platform rules or other tenants' rules.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints.detection_compat import (
    BulkToggleBody,
    UpdateBody,
    bulk_toggle_rules,
    delete_rule_compat,
    update_rule_compat,
)
from app.api.v1.endpoints.detection_rules import (
    UpdateRuleRequest,
    delete_rule,
    update_rule,
)
from app.models.detection_rule import DetectionRule


def _user(role: str = "soc_analyst", tenant_id: uuid.UUID | None = None) -> CurrentUser:
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        role=role,
        email=f"{role}@example.com",
    )


def _fake_rule(
    rule_id: uuid.UUID | None = None,
    tenant_id: uuid.UUID | None = None,
    is_builtin: bool = False,
    name: str = "Test Rule",
    status: str = "active",
) -> DetectionRule:
    rule = DetectionRule()
    rule.id = rule_id or uuid.uuid4()
    rule.tenant_id = tenant_id
    rule.name = name
    rule.description = "Test Description"
    rule.rule_language = "sigma"
    rule.rule_body = "title: test\nstatus: active"
    rule.category = "custom"
    rule.status = status
    rule.severity = "medium"
    rule.confidence = 50
    rule.mitre_tactics = ["execution"]
    rule.mitre_techniques = ["T1059"]
    rule.fp_rate = 0.0
    rule.total_hits = 5
    rule.last_triggered = datetime.now(UTC)
    rule.tags = ["test"]
    rule.is_builtin = is_builtin
    rule.version = 1
    rule.created_at = datetime.now(UTC)
    rule.updated_at = datetime.now(UTC)
    return rule


class TestDetectionCompatRBAC:
    """Test /api/v1/detection/rules endpoints."""

    @pytest.mark.asyncio
    async def test_platform_admin_can_update_builtin_rule(self):
        rule_id = uuid.uuid4()
        rule = _fake_rule(rule_id=rule_id, tenant_id=None, is_builtin=True)

        db = MagicMock()
        exec_mock = AsyncMock()
        scalar_mock = MagicMock()
        scalar_mock.scalar_one_or_none.return_value = rule
        exec_mock.return_value = scalar_mock
        db.execute = exec_mock
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        admin_user = _user(role="platform_admin")
        body = UpdateBody(name="Updated Builtin Name", severity="high")

        res = await update_rule_compat(rule_id, body, admin_user, db)
        assert res.name == "Updated Builtin Name"
        assert res.severity == "high"
        assert res.isBuiltin is True
        assert db.commit.called

    @pytest.mark.asyncio
    async def test_tenant_analyst_cannot_update_builtin_rule(self):
        rule_id = uuid.uuid4()
        rule = _fake_rule(rule_id=rule_id, tenant_id=None, is_builtin=True)

        db = MagicMock()
        exec_mock = AsyncMock()
        scalar_mock = MagicMock()
        scalar_mock.scalar_one_or_none.return_value = rule
        exec_mock.return_value = scalar_mock
        db.execute = exec_mock

        analyst = _user(role="soc_analyst")
        body = UpdateBody(name="Hacked Builtin")

        with pytest.raises(HTTPException) as exc_info:
            await update_rule_compat(rule_id, body, analyst, db)

        assert exc_info.value.status_code == 403
        assert "Built-in platform detection rules can only be modified by a platform administrator" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_update_nonexistent_rule_returns_404(self):
        rule_id = uuid.uuid4()
        db = MagicMock()
        exec_mock = AsyncMock()
        scalar_mock = MagicMock()
        scalar_mock.scalar_one_or_none.return_value = None
        exec_mock.return_value = scalar_mock
        db.execute = exec_mock

        admin_user = _user(role="platform_admin")
        body = UpdateBody(name="Nonexistent")

        with pytest.raises(HTTPException) as exc_info:
            await update_rule_compat(rule_id, body, admin_user, db)

        assert exc_info.value.status_code == 404
        assert exc_info.value.detail == "Rule not found"

    @pytest.mark.asyncio
    async def test_tenant_analyst_cannot_update_other_tenant_rule(self):
        rule_id = uuid.uuid4()
        other_tenant = uuid.uuid4()
        rule = _fake_rule(rule_id=rule_id, tenant_id=other_tenant, is_builtin=False)

        db = MagicMock()
        exec_mock = AsyncMock()
        scalar_mock = MagicMock()
        scalar_mock.scalar_one_or_none.return_value = rule
        exec_mock.return_value = scalar_mock
        db.execute = exec_mock

        my_tenant = uuid.uuid4()
        analyst = _user(role="soc_analyst", tenant_id=my_tenant)
        body = UpdateBody(name="Other Tenant Rule")

        with pytest.raises(HTTPException) as exc_info:
            await update_rule_compat(rule_id, body, analyst, db)

        assert exc_info.value.status_code == 404
        assert "Rule not found or cannot be modified" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_tenant_analyst_can_update_own_rule(self):
        rule_id = uuid.uuid4()
        my_tenant = uuid.uuid4()
        rule = _fake_rule(rule_id=rule_id, tenant_id=my_tenant, is_builtin=False)

        db = MagicMock()
        exec_mock = AsyncMock()
        scalar_mock = MagicMock()
        scalar_mock.scalar_one_or_none.return_value = rule
        exec_mock.return_value = scalar_mock
        db.execute = exec_mock
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        analyst = _user(role="soc_analyst", tenant_id=my_tenant)
        body = UpdateBody(name="My Updated Rule", enabled=False)

        res = await update_rule_compat(rule_id, body, analyst, db)
        assert res.name == "My Updated Rule"
        assert res.enabled is False
        assert res.isBuiltin is False
        assert db.commit.called

    @pytest.mark.asyncio
    async def test_delete_rule_compat_rbac(self):
        rule_id = uuid.uuid4()
        builtin_rule = _fake_rule(rule_id=rule_id, tenant_id=None, is_builtin=True)

        db = MagicMock()
        exec_mock = AsyncMock()
        scalar_mock = MagicMock()
        scalar_mock.scalar_one_or_none.return_value = builtin_rule
        exec_mock.return_value = scalar_mock
        db.execute = exec_mock
        db.delete = AsyncMock()
        db.commit = AsyncMock()

        analyst = _user(role="soc_analyst")
        with pytest.raises(HTTPException) as exc_info:
            await delete_rule_compat(rule_id, analyst, db)
        assert exc_info.value.status_code == 403

        admin = _user(role="platform_admin")
        await delete_rule_compat(rule_id, admin, db)
        assert db.delete.called
        assert db.commit.called

    @pytest.mark.asyncio
    async def test_bulk_toggle_platform_admin_vs_analyst(self):
        builtin_id = uuid.uuid4()
        own_id = uuid.uuid4()
        tenant_id = uuid.uuid4()

        db = MagicMock()

        # Analyst run
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = [own_id]
        exec_result = MagicMock()
        exec_result.scalars.return_value = scalars_mock
        db.execute = AsyncMock(return_value=exec_result)
        db.commit = AsyncMock()

        analyst = _user(role="soc_analyst", tenant_id=tenant_id)
        body = BulkToggleBody(ruleIds=[str(builtin_id), str(own_id)], enabled=True)

        res_analyst = await bulk_toggle_rules(body, analyst, db)
        assert res_analyst.updated == 1
        assert str(builtin_id) in res_analyst.skipped

        # Platform admin run
        scalars_mock_admin = MagicMock()
        scalars_mock_admin.all.return_value = [builtin_id, own_id]
        exec_result_admin = MagicMock()
        exec_result_admin.scalars.return_value = scalars_mock_admin
        db.execute = AsyncMock(return_value=exec_result_admin)

        admin = _user(role="platform_admin", tenant_id=tenant_id)
        res_admin = await bulk_toggle_rules(body, admin, db)
        assert res_admin.updated == 2
        assert len(res_admin.skipped) == 0


class TestCanonicalDetectionRulesRBAC:
    """Test /api/v1/rules endpoints."""

    @pytest.mark.asyncio
    async def test_platform_admin_can_update_builtin_canonical(self):
        rule_id = uuid.uuid4()
        rule = _fake_rule(rule_id=rule_id, tenant_id=None, is_builtin=True)

        db = MagicMock()
        exec_mock = AsyncMock()
        scalar_mock = MagicMock()
        scalar_mock.scalar_one_or_none.return_value = rule
        exec_mock.return_value = scalar_mock
        db.execute = exec_mock
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        admin = _user(role="platform_admin")
        req = UpdateRuleRequest(name="Canonical Admin Update")

        res = await update_rule(rule_id, req, admin, db)
        assert res.name == "Canonical Admin Update"
        assert res.is_builtin is True

    @pytest.mark.asyncio
    async def test_analyst_cannot_update_builtin_canonical(self):
        rule_id = uuid.uuid4()
        rule = _fake_rule(rule_id=rule_id, tenant_id=None, is_builtin=True)

        db = MagicMock()
        exec_mock = AsyncMock()
        scalar_mock = MagicMock()
        scalar_mock.scalar_one_or_none.return_value = rule
        exec_mock.return_value = scalar_mock
        db.execute = exec_mock

        analyst = _user(role="soc_analyst")
        req = UpdateRuleRequest(name="Forbidden Update")

        with pytest.raises(HTTPException) as exc_info:
            await update_rule(rule_id, req, analyst, db)

        assert exc_info.value.status_code == 403
        assert "Built-in platform detection rules can only be modified by a platform administrator" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_delete_rule_canonical_rbac(self):
        rule_id = uuid.uuid4()
        builtin_rule = _fake_rule(rule_id=rule_id, tenant_id=None, is_builtin=True)

        db = MagicMock()
        exec_mock = AsyncMock()
        scalar_mock = MagicMock()
        scalar_mock.scalar_one_or_none.return_value = builtin_rule
        exec_mock.return_value = scalar_mock
        db.execute = exec_mock
        db.delete = AsyncMock()
        db.commit = AsyncMock()

        analyst = _user(role="soc_analyst")
        with pytest.raises(HTTPException) as exc_info:
            await delete_rule(rule_id, analyst, db)
        assert exc_info.value.status_code == 403

        admin = _user(role="platform_admin")
        await delete_rule(rule_id, admin, db)
        assert db.delete.called
        assert db.commit.called
