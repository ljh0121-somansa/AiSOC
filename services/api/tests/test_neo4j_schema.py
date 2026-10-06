from __future__ import annotations

from unittest.mock import AsyncMock, patch


INGEST_LABELS = [
    "User", "Endpoint", "NetworkPath", "Resource", "Alert", "Detection",
    "Repo", "Identity", "ServiceAccount", "SaaSApp", "Permission",
    "Role", "Policy", "Container", "Image", "Case",
]


async def _capture_schema_statements() -> list[str]:
    from app.db import neo4j
    statements: list[str] = []

    async def fake_run(cypher: str, **params) -> None:
        statements.append(cypher.strip())

    fake_session = AsyncMock()
    fake_session.run = fake_run

    cm = AsyncMock()
    cm.__aenter__.return_value = fake_session
    cm.__aexit__.return_value = None

    with patch.object(neo4j, "get_session", lambda: cm):
        await neo4j._create_schema()
    return statements


async def test_schema_targets_only_ingest_labels():
    statements = await _capture_schema_statements()
    joined = "\n".join(statements)
    # Ingest labels present.
    for label in INGEST_LABELS:
        assert f":{label}" in joined, f"missing constraint for {label}"
    # Old vocabulary deleted and never re-added.
    for forbidden in ("Host", "IOC", "Technique", "Process"):
        assert f":{forbidden}" not in joined, f"forbidden label {forbidden} still present"


async def test_schema_constraint_keyed_on_natural_key():
    statements = await _capture_schema_statements()
    joined = "\n".join(statements)
    # Per Invariant #1/#2: uniqueness is keyed on natural_key, not id/technique_id/value.
    assert "natural_key IS UNIQUE" in joined
    assert "id IS UNIQUE" not in joined
    assert "technique_id IS UNIQUE" not in joined


async def test_schema_has_per_label_tenant_index():
    statements = await _capture_schema_statements()
    joined = "\n".join(statements)
    for label in INGEST_LABELS:
        assert f"(n:{label}) REQUIRE (n.tenant_id)" in joined, f"missing tenant_id index for {label}"
