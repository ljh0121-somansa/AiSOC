from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, patch

from app.services import graph_service


@asynccontextmanager
async def _data_session(rows):
    """Patch graph_service.get_session with a session whose .data() returns rows.

    The session must yield itself as a real async context manager, because the
    production code does ``async with get_session() as s:`` — patching with
    ``return_value=fake_session`` would make ``s`` an unconfigured ``MagicMock``.

    Returns the underlying session so callers can inspect call_args.
    """
    fake_session = AsyncMock()

    async def fake_run(cypher, **params):
        fake_session._last_cypher = cypher
        fake_session._last_params = params
        return AsyncMock(data=AsyncMock(return_value=rows))

    fake_session.run = fake_run

    @asynccontextmanager
    async def cm():
        yield fake_session

    with patch.object(graph_service, "get_session", return_value=cm()):
        yield fake_session


@asynccontextmanager
async def _single_session(row):
    """Patch graph_service.get_session whose .single() returns row (a real dict)."""
    fake_session = AsyncMock()
    single = {} if row is None else dict(row)

    async def fake_run(cypher, **params):
        fake_session._last_cypher = cypher
        fake_session._last_params = params
        return AsyncMock(single=AsyncMock(return_value=single))

    fake_session.run = fake_run

    @asynccontextmanager
    async def cm():
        yield fake_session

    with patch.object(graph_service, "get_session", return_value=cm()):
        yield fake_session


async def test_overview_derivs_id_from_natural_key_and_marks_source():
    rows = [{
        "n": {"natural_key": "endpoint:tid:win-host-1", "name": "win-host-1",
              "tenant_id": "tid", "severity": "critical"},
        "labels": ["Endpoint"],
        "r": {"id": "e1"},
        "m": {"natural_key": "detection:mitre:T1078", "mitre_technique_name": "Valid Accounts",
              "tenant_id": "tid"},
        "target_labels": ["Detection"],
        "rel_type": "TRIGGERED",
    }]

    async with _data_session(rows) as sess:
        result = await graph_service.get_overview_graph(tenant_id="tid", depth=3, limit=200)

    assert result is not None
    assert result["source"] == "neo4j"
    node_ids = [n["id"] for n in result["nodes"]]
    # Id derived from natural_key, NOT from a missing .id field.
    assert "endpoint:tid:win-host-1" in node_ids
    # The tenant_id is bound as a real parameter, never an empty literal.
    assert "tenant_id = $tenant_id" in sess._last_cypher


async def test_overview_returns_none_when_empty():
    async with _data_session([]):
        result = await graph_service.get_overview_graph(tenant_id="tid", depth=3, limit=200)
    assert result is None


async def test_mitre_coverage_reads_detection_triggering():
    rows = [{
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "alert_count": 2,
    }]

    async with _data_session(rows) as sess:
        records = await graph_service.get_mitre_coverage(tenant_id="tid")

    assert records == rows
    # The query must reference Detection nodes + TRIGGERED edges,
    # not MAPS_TO/Technique.
    query = sess._last_cypher
    assert "TRIGGERED" in query and ":Detection" in query
    assert "MAPS_TO" not in query and ":Technique" not in query


async def test_blast_radius_resolves_endpoint_by_natural_key():
    row = {
        "all_nodes": [
            {"id": "endpoint:tid:win-1", "label": "Endpoint", "properties": {}},
            {"id": "detection:mitre:T1078", "label": "Detection", "properties": {}},
        ]
    }

    async with _single_session(row) as sess:
        result = await graph_service.get_blast_radius("endpoint:tid:win-1", "host", "tid", 3)

    assert result["total_affected"] == 2
    assert result["type_breakdown"]["Endpoint"] == 1
    # Resolved on the ingest Endpoint label matched by natural_key.
    assert sess._last_cypher is not None and "Endpoint" in sess._last_cypher


async def test_blast_score_uses_endpoint_weight():
    score = graph_service._calc_blast_score({"Endpoint": 1, "Alert": 1})
    # Endpoint=10, Alert=6 in the new weights => (10 + 6) / 10 = 1.6
    assert score == 1.6


async def test_neighbor_resolves_endpoint_by_natural_key():
    row = {
        "source": {"id": "endpoint:tid:win-1", "label": "Endpoint"},
        "neighbors": [
            {"id": "detection:mitre:T1078", "label": "Detection", "rel_type": "TRIGGERED"},
        ],
    }

    async with _single_session(row) as sess:
        result = await graph_service.get_entity_neighbors("endpoint:tid:win-1", "host", "tid")

    assert result["neighbor_count"] == 1
    assert sess._last_cypher is not None and "Endpoint" in sess._last_cypher
