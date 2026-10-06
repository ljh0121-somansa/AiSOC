from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import graph as graph_ep
from app.services import graph_service


def _user(tenant_id: uuid.UUID | None = None) -> CurrentUser:
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        role="analyst",
        email="analyst@example.com",
    )


@pytest.mark.asyncio
async def test_overview_prefers_live_over_relational():
    live = {
        "source": "neo4j",
        "nodes": [{"id": "x", "label": "n", "kind": "host"}],
        "edges": [],
        "generatedAt": "t",
    }
    with (
        patch.object(graph_service, "get_overview_graph", return_value=live),
        patch.object(graph_ep, "_graph_overview_from_relational") as rel,
    ):
        resp = await graph_ep.get_overview(
            db=AsyncMock(), depth=3, current_user=_user()
        )
    assert resp.source == "neo4j"
    rel.assert_not_called()


@pytest.mark.asyncio
async def test_overview_falls_back_to_relational_when_empty():
    with (
        patch.object(graph_service, "get_overview_graph", return_value=None),
        patch.object(
            graph_ep,
            "_graph_overview_from_relational",
            return_value={"nodes": [], "edges": [], "generatedAt": "t"},
        ),
    ):
        resp = await graph_ep.get_overview(
            db=AsyncMock(), depth=3, current_user=_user()
        )
    assert resp.source == "relational"
