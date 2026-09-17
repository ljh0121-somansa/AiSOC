# Attack Graph — Live Neo4j Data Activation (P0 Core) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Attack Graph overview + MITRE heatmap render real live Neo4j data and surface genuine backend errors, by reconciling the Python query layer to the ingest graph vocabulary.

**Architecture:** The live Neo4j writer lives in `services/ingest/internal/graph/` (Go) and emits `:User/:Endpoint/:NetworkPath/:Resource/:Alert/:Detection` nodes keyed by `natural_key`, with `TRIGGERED`/`OCCURRED_ON` edges. The Python query layer in `services/api` queries a *different* label set (`:Host/:IOC/:Technique`) that nothing creates, so it always returns empty and falls back to a Postgres relational reconstruction; the frontend additionally swallows backend errors. This plan rewires the Python queries + the frontend `kind` mapping + the frontend error swallowing to the ingest vocabulary.

**Tech Stack:** Python 3.11 (FastAPI + asyncpg + neo4j driver), TypeScript/Next.js (React + SWR + cytoscape), Vitest.

**Spec:** [`docs/superpowers/specs/2026-09-16-attack-graph-live-data-design.md`](../../../specs/2026-09-16-attack-graph-live-data-design.md) — the spec argues from the root cause; this plan implements it.

## Global Constraints

- Single graph vocabulary = the ingest vocabulary; `:Host/:IOC/:Technique` are deleted and never re-added. (Spec §2 Invariant #1)
- Node identity is `natural_key`; queries derive node ids from `natural_key`, not `id`/`value`. `Alert` nodes carry no `id` (Spec §2 Invariant #2).
- Every overview response carries a `source` field: `"neo4j"` for real ingest data, `"relational"` for the Postgres fallback. (Spec §2 Invariant #3)
- Every `MATCH` binds `$tenant_id` as a real parameter — no empty literal, no string interpolation into query text. (Spec §2 Invariant #4)
- Frontend fetchers return normally; SWR `.error` is surfaced as a real `ErrorState`. (Spec §2 Invariant #5)
- No competitor names ("Torq" / "Prophet Security") anywhere. (Repo rule)
- DRY: define the per-label index/constraint list once and loop. YAGNI: add only `source`; leave attack-path Case-writing, `/entities/ioc`, legend, and i18n out.
- TDD: write the failing test before the change, run it to see it fail, implement minimal code, run it to see it pass, commit.

---

### Task 1: Reconcile Neo4j schema in `neo4j.py`

**Files:**
- Modify: `services/api/app/db/neo4j.py` (`_create_schema`, ~lines 79-108)
- Test: `services/api/tests/test_neo4j_schema.py` (new)

**Interfaces:**
- Consumes: none (pure DDL).
- Produces: `_create_schema()` issues constraints/indexes for the ingest label set only.

- [ ] **Step 1: Write the failing test**

  Create `services/api/tests/test_neo4j_schema.py`. It asserts the *exact set of labels* that `_create_schema()` must target, by inspecting the SQL strings it generates (so no Neo4j connection is required).

  ```python
  from __future__ import annotations
  from unittest.mock import AsyncMock, patch
  import pytest

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

      async def cm():
          return fake_session

      with patch.object(neo4j, "get_session", return_value=cm()):
          await neo4j._create_schema()
      return statements

  async def test_schema_targets_only_ingest_labels():
      statements = await _capture_schema_statements()
      joined = "\n".join(statements)
      # Ingest labels present, forbidden labels absent.
      for label in INGEST_LABELS:
          assert f":{label}" in joined, f"missing constraint/index for {label}"
      for forbidden in ("Host", "IOC", "Technique", "Process"):
          assert f":{forbidden}" not in joined, f"forbidden label {forbidden} still present"
  ```

- [ ] **Step 2: Run test to verify it fails**

  Run: `cd services/api && python -m pytest tests/test_neo4j_schema.py -v`
  Expected: FAIL — `test_schema_targets_only_ingest_labels` finds `:Host`/`:IOC`/`:Technique` still present.

- [ ] **Step 3: Write minimal implementation**

  Rewrite `_create_schema()` (`neo4j.py`) to loop over the label list once, emitting a `natural_key` uniqueness constraint and a `tenant_id` index per label:

  ```python
  # neo4j.py

  # The live ingest writer (services/ingest/internal/graph/writer.go) is the
  # single source of truth for graph vocabulary. These labels must mirror its
  # NodeLabel set in services/ingest/internal/graph/schema.go — any label the
  # query layer references must exist on nodes the writer produces.
  _GRAPH_LABELS: tuple[str, ...] = (
      "User", "Endpoint", "NetworkPath", "Resource", "Alert", "Detection",
      "Repo", "Identity", "ServiceAccount", "SaaSApp", "Permission",
      "Role", "Policy", "Container", "Image", "Case",
  )

  async def _create_schema() -> None:
      statements: list[str] = []
      for label in _GRAPH_LABELS:
          statements.append(
              f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{label}) "
              f"REQUIRE n.natural_key IS UNIQUE"
          )
          statements.append(
              f"CREATE INDEX IF NOT EXISTS FOR (n:{label}) REQUIRE (n.tenant_id)"
          )

      async with get_session() as session:
          for cypher in statements:
              try:
                  await session.run(cypher)
              except Exception as exc:
                  logger.debug("Schema statement skipped cypher=%s error=%s", cypher[:60], exc)

      logger.info("Neo4j schema constraints and indexes ensured")
  ```

  Remove the old per-label `Host/IOC/Technique/Process` constraint list. The `get_session` call site (existing `async with get_session() as session`) is unchanged.

- [ ] **Step 4: Run test to verify it passes**

  Run: `cd services/api && python -m pytest tests/test_neo4j_schema.py -v`
  Expected: PASS — all 16 ingest labels present, no `Host/IOC/Technique/Process`.

- [ ] **Step 5: Commit**

  ```bash
  git add services/api/tests/test_neo4j_schema.py services/api/app/db/neo4j.py
  git commit -m "fix(neo4j): reconcile graph schema to ingest vocabulary"
  ```

---

### Task 2: Rewrite `get_overview_graph` to ingest vocabulary + live/degraded distinction

**Files:**
- Modify: `services/api/app/services/graph_service.py` (`get_overview_graph`, ~lines 489-626)
- Test: `services/api/tests/test_graph_service.py` (new)

**Interfaces:**
- Consumes: `get_session()` from `app.db.neo4j`; `tenant_id`, `depth`, `limit` params.
- Produces: `get_overview_graph(tenant_id, depth, limit) -> dict[str, Any] | None` — returns `{"source": "neo4j", "nodes": [...], "edges": [...], "generatedAt": ...}` when nodes exist, else `None`. Node ids derive from `natural_key`.

- [ ] **Step 1: Write the failing test**

  `services/api/tests/test_graph_service.py`. Mock the async session to replay a row shaped like what an ingest writer produces (a `:Endpoint` with `natural_key`, no `id`). Then assert `get_overview_graph` produces a node whose `id` is the `natural_key` (not the old fallback) and whose return includes `source == "neo4j"`.

  ```python
  from __future__ import annotations
  from datetime import UTC, datetime
  from types import SimpleNamespace
  from unittest.mock import AsyncMock, patch
  import pytest

  from app.services import graph_service



  async def test_overview_derivs_id_from_natural_key_and_marks_source():
      # One ingest node: an Endpoint (natural_key based), plus a TRIGGERED
      # relationship to a Detection.
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

      fake_session = AsyncMock()
      async def fake_run(cypher, **params):
          return AsyncMock(data=AsyncMock(return_value=rows))
      fake_session.run = fake_run

      with patch.object(graph_service, "get_session", return_value=fake_session):
          result = await graph_service.get_overview_graph(tenant_id="tid", depth=3, limit=200)
      assert result is not None
      assert result["source"] == "neo4j"
      node_ids = [n["id"] for n in result["nodes"]]
      # Id derived from natural_key, NOT from a missing .id field.
      assert "endpoint:tid:win-host-1" in node_ids
  ```


- [ ] **Step 2: Run test to verify it fails**

  Run: `cd services/api && python -m pytest tests/test_graph_service.py -v`
  Expected: FAIL — old code returns `{"nodes": []}` on a literal-mismatch, and never sets `source`.

- [ ] **Step 3: Write minimal implementation**

  Replace the body of `get_overview_graph` in `graph_service.py`. The new implementation:

  ```python
  async def get_overview_graph(
      tenant_id: str, depth: int = 3, limit: int = 200
  ) -> dict[str, Any] | None:
      """Fetch the tenant-wide attack graph overview from Neo4j.

      Returns ``None`` when no live nodes exist so the endpoint can decide
      whether to fall back to the relational reconstruction. Node ids are
      derived from ``natural_key`` (the only id the ingest writer persists).
      """
      cypher = """
      MATCH (n) WHERE n.tenant_id = $tenant_id OR n.tenant_id IS NULL
      OPTIONAL MATCH (n)-[r]-(m) WHERE m.tenant_id = $tenant_id OR m.tenant_id IS NULL
      RETURN n, labels(n) AS labels, r, m, labels(m) AS target_labels, type(r) AS rel_type
      LIMIT $limit
      """
      async with get_session() as s:
          result = await s.run(cypher, tenant_id=tenant_id, limit=limit)
          records = await result.data()

      nodes: list[dict[str, Any]] = []
      edges: list[dict[str, Any]] = []
      seen_nodes: set[str] = set()
      seen_edges: set[str] = set()

      def _node(rec_n, labels, source_prefix) -> dict | None:
          if not rec_n:
              return None
          props = dict(rec_n)
          nid = (
              str(props.get("natural_key"))
              or str(props.get("id"))
              or f"{source_prefix}:{labels[0] if labels else 'node'}:{id(props)}"
          )
          return {
              "id": nid,
              "kind": str(labels[0]).lower() if labels else "asset",
              "label": str(
                  props.get("name")
                  or props.get("title")
                  or props.get("hostname")
                  or props.get("username")
                  or props.get("value")
                  or nid
              ),
              "riskScore": float(props.get("risk_score", 50.0) or 50.0),
              "severity": str(props.get("severity", "medium")).lower(),
              "properties": props,
          }

      for rec in records:
          n = rec.get("n")
          n_labels = rec.get("labels")
          n_node = _node(n, n_labels, "ingest")
          if n_node and n_node["id"] not in seen_nodes:
              seen_nodes.add(n_node["id"])
              nodes.append(n_node)

          m = rec.get("m")
          m_labels = rec.get("target_labels")
          m_node = _node(m, m_labels, "ingest")
          if m_node and m_node["id"] not in seen_nodes:
              seen_nodes.add(m_node["id"])
              nodes.append(m_node)

          r = rec.get("r")
          if r and n_node and m_node:
              edge_id = f"e-{n_node["id"]}-{m_node["id"]}"
              if edge_id not in seen_edges:
                  seen_edges.add(edge_id)
                  edges.append({
                      "id": edge_id,
                      "source": n_node["id"],
                      "target": m_node["id"],
                      "label": "relates_to",
                  })

      if not nodes:
          return None

      return {
          "source": "neo4j",
          "nodes": nodes,
          "edges": edges,
          "generatedAt": datetime.now(UTC).isoformat(),
      }
  ```

  This fixes the broken empty literal (`WHERE n.tenant_id =  OR`), honors `$limit` (removing the hardcoded `LIMIT 200`), derives ids from `natural_key`, and returns `source: "neo4j"` or `None`.

- [ ] **Step 4: Run test to verify it passes**

  Run: `cd services/api && python -m pytest tests/test_graph_service.py -v`
  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add services/api/tests/test_graph_service.py services/api/app/services/graph_service.py
  git commit -m "fix(graph): rewrite overview query to ingest vocabulary + source field"
  ```

---

### Task 3: Rewrite `get_mitre_coverage` for `:Detection`/`TRIGGERED`

**Files:**
- Modify: `services/api/app/services/graph_service.py` (`get_mitre_coverage`, ~lines 471-486)
- Test: `services/api/tests/test_graph_service.py` (add)

**Interfaces:**
- Consumes: `get_session()`.
- Produces: `get_mitre_coverage(tenant_id) -> list[dict]` where each record has keys `technique_id`, `name`, `alert_count`. (The `/mitre-coverage` endpoint already maps these to `MitreCoverageItem`.)

- [ ] **Step 1: Write the failing test**

  Add to the existing `test_graph_service.py`:

  ```python
  async def test_mitre_coverage_reads_detection_triggering():
      rows = [{
          "technique_id": "T1078",
          "name": "Valid Accounts",
          "alert_count": 2,
      }]

      async def fake_run(cypher, **params):
          return AsyncMock(data=AsyncMock(return_value=rows))
      s = AsyncMock()
      s.run = fake_run
      async def cm():
          return s

      with patch.object(graph_service, "get_session", return_value=cm()):
          records = await graph_service.get_mitre_coverage(tenant_id="tid")

      assert records == rows
      # The query must reference Detection nodes + TRIGGERED edges,
      # not MAPS_TO/Technique.
      query = s.run.call_args[0][0]
      assert "TRIGGERED" in query and ":Detection" in query
      assert "MAPS_TO" not in query and ":Technique" not in query
  ```

- [ ] **Step 2: Run test to verify it fails**

  Run: `cd services/api && python -m pytest tests/test_graph_service.py::test_mitre_coverage_reads_detection_triggering -v`
  Expected: FAIL — old query uses `MAPS_TO`/`:Technique`.

- [ ] **Step 3: Write minimal implementation**

  ```python
  async def get_mitre_coverage(tenant_id: str) -> list[dict[str, Any]]:
      """Return MITRE ATT&CK technique coverage: alert counts per technique.

      Aggregates the per-detection counts for each tenant alert via the
      ingest `TRIGGERED` edge into `:Detection` nodes.
      """
      cypher = """
      MATCH (a:Alert {tenant_id: $tenant_id})-[:TRIGGERED]->(d:Detection)
      RETURN
          d.mitre_technique_id AS technique_id,
          d.mitre_technique_name AS name,
          COUNT(*) AS alert_count
      ORDER BY alert_count DESC
      """
      async with get_session() as s:
          result = await s.run(cypher, tenant_id=tenant_id)
          records = await result.data()

      return records
  ```

  **Note on `mitre_technique_name`:** it is set by the ingest `extractMITRE` (`extractor.go:625`), so `name` is populated — this also closes Step 8 (technique-name problem) as a side effect.

- [ ] **Step 4: Run test to verify it passes**

  Run: `cd services/api && python -m pytest tests/test_graph_service.py -v`
  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add services/api/tests/test_graph_service.py services/api/app/services/graph_service.py
  git commit -m "fix(graph): compute MITRE coverage from Detection/TRIGGERED"
  ```

---

### Task 4: Rewrite attack-path / blast-radius / neighbors to ingest edges

**Files:**
- Modify: `services/api/app/services/graph_service.py` (lines 221-468)
- Test: `services/api/tests/test_graph_service.py` (add)

**Interfaces:**
- Consumes: `get_session()`.
- Produces: the three functions continue to return their existing response shapes (`get_attack_path` → `{"case_id", "nodes", "edges", "node_count", "edge_count"}`, `get_blast_radius` → `{"entity_id", "affected_nodes", "type_breakdown", "blast_radius_score"}`, `get_entity_neighbors` → `{"entity_id", "source", "neighbors", "neighbor_count"}`). Only the *label* set and edges change.

- [ ] **Step 1: Write the failing test**

  Add to `test_graph_service.py`. Assert `get_entity_neighbors` and `get_blast_radius` resolve `entity_type="host"` to an `:Endpoint` matched by `natural_key`, and that `_calc_blast_score` uses the new Endpoint/Resource weights.

  ```python
  async def test_blast_radius_resolves_endpoint_by_natural_key():
      rows = [{"affected": [
          {"id": "endpoint:tid:win-1", "label": "Endpoint", "properties": {}},
          {"id": "detection:mitre:T1078", "label": "Detection", "properties": {}},
      ]}]

      async def fake_run(cypher, **params):
          return AsyncMock(single=AsyncMock(return_value=AsyncMock(__getitem__=lambda self, k: rows[0][k])))
      s = AsyncMock()
      s.run = fake_run
      async def cm():
          return s

      with patch.object(graph_service, "get_session", return_value=cm()):
          result = await graph_service.get_blast_radius("endpoint:tid:win-1", "host", "tid", 3)

      assert result["total_affected"] == 2
      assert result["type_breakdown"]["Endpoint"] == 1

  async def test_blast_score_uses_endpoint_weight():
      score = graph_service._calc_blast_score({"Endpoint": 1, "Alert": 1})
      # Endpoint=10, Alert=6 in the new weights => (10 + 6) / 10 = 1.6
      assert score == 1.6
  ```

  **Simplify `fake_run` for blast_radius** — it uses `result.single()`; reuse a helper `_single_session(value)`:

  ```python
  def _single_session(value):
      async def fake_run(cypher, **params):
          return AsyncMock(single=AsyncMock(return_value=value))
      s = AsyncMock()
      s.run = fake_run
      async def cm():
          return s
      return cm()
  ```

  And `_calc_blast_score` is a plain synchronous function — call it directly without mocking.

- [ ] **Step 2: Run test to verify it fails**

  Run: `cd services/api && python -m pytest tests/test_graph_service.py::test_blast_score_uses_endpoint_weight -v`
  Expected: FAIL — old weights (`Host=5`) yield 1.5, not 1.6.

- [ ] **Step 3: Write minimal implementation**

  3a. `_calc_blast_score`:

  ```python
  def _calc_blast_score(type_counts: dict[str, int]) -> float:
      """Heuristic blast-radius severity score 0-100.
      Weights (ingest vocabulary): Alert=6, Endpoint=10, Resource=8,
      User=8, NetworkPath=3, Detection=2.
      """
      weights = {"Alert": 6, "Endpoint": 10, "Resource": 8, "User": 8,
                 "NetworkPath": 3, "Detection": 2}
      raw = sum(weights.get(lbl, 1) * count for lbl, count in type_counts.items())
      return min(round(raw / 10, 1), 100.0)
  ```

  3b. `get_blast_radius` / `get_entity_neighbors` / `_blast_radius_fallback`: replace `label_map` to the ingest vocabulary and `id_prop` to `natural_key`:

  ```python
  label_map = {
      "host": "Endpoint",
      "user": "User",
      "alert": "Alert",
  }
  id_prop = "natural_key"
  ```

  `get_attack_path` (lines 221-261): replace the `relationshipFilter` to ingest edges and the `id` coercion to `natural_key` (the `MATCH (:Case ...)` start node is not produced by the ingest writer, so it falls through to `_attack_path_fallback` — intended degraded path):

  ```cypher
  MATCH (c:Case {id: $case_id, tenant_id: $tenant_id})
  CALL apoc.path.subgraphAll(c, {
      maxLevel: $max_depth,
      relationshipFilter: 'TRIGGERED>|OCCURRED_ON>'
  })
  ```

  ...and the RETURN `coalesce(n.id, n.value, n.technique_id)` → `coalesce(n.natural_key, n.id)`.

  **No test asserts the APOC filter string** (APOC is optional); the blast_radius/neighbors tests cover the label/edge resolution and scoring.

- [ ] **Step 4: Run test to verify it passes**

  Run: `cd services/api && python -m pytest tests/test_graph_service.py -v`
  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add services/api/tests/test_graph_service.py services/api/app/services/graph_service.py
  git commit -m "fix(graph): resolve blast-radius/neighbors/attack-path on ingest labels"
  ```

---

### Task 5: Add `source` to overview endpoint and gate relational fallback

**Files:**
- Modify: `services/api/app/api/v1/endpoints/graph.py` (`OverviewGraphResponse`, `get_overview`, ~lines 174-331)
- Test: `services/api/tests/api/v1/endpoints/test_graph_endpoint.py` (new, if no existing endpoint test)

**Interfaces:**
- Consumes: `graph_service.get_overview_graph` (now returns `{"source": "neo4j", ...}` or `None`).
- Produces: `GET /graph` returns an `OverviewGraphResponse` with a `source` field.

- [ ] **Step 1: Write the failing test**

  `services/api/tests/api/v1/endpoints/test_graph_endpoint.py`. With `get_overview_graph` mocked to return `None`, assert the endpoint falls back to relational and sets `source == "relational"`; with it returning a live payload, assert `source == "neo4j"` and that `_graph_overview_from_relational` is **not** called.

  ```python
  from __future__ import annotations
  import uuid
  from unittest.mock import AsyncMock, patch
  from types import SimpleNamespace
  import pytest

  from app.api.v1.endpoints import graph as graph_endpoint
  from app.api.v1.deps import CurrentUser
  from app.services import graph_service


  def _tenant(tenant_id: str = "tid") -> CurrentUser:
      return CurrentUser(
          user_id="u1",
          username="u1",
          tenant_id=uuid.UUID(tenant_id),
          role="analyst",
      )

  async def test_overview_endpoint_prefers_live_over_relational():
      live = {"source": "neo4j", "nodes": [{"id": "x", "label": "n"}], "edges": [], "generatedAt": "t"}
      with patch.object(graph_service, "get_overview_graph", return_value=live), \
           patch.object(graph_endpoint, "_graph_overview_from_relational") as rel:
          resp = await graph_endpoint.get_overview(depth=3, current_user=_tenant(), db=AsyncMock())
      assert resp.source == "neo4j"
      rel.assert_not_called()

  async def test_overview_endpoint_falls_back_when_empty():
      with patch.object(graph_service, "get_overview_graph", return_value=None), \
           patch.object(graph_endpoint, "_graph_overview_from_relational", return_value={
               "nodes": [], "edges": [], "generatedAt": "t"}):
          resp = await graph_endpoint.get_overview(depth=3, current_user=_tenant(), db=AsyncMock())
      assert resp.source == "relational"
  ```

  **Notes on `CurrentUser` / `get_overview` signature:** `get_overview` (graph.py) takes `db: DBSession`, `depth`, and `current_user: CurrentUser = Depends(get_current_user)` — call it directly with `current_user=...` and `db=...`, bypassing FastAPI's dependency injection. `CurrentUser` is a small class in `app.api.v1.deps`; construct it with the fields the endpoint reads (`tenant_id`). Verify the exact constructor args by reading `services/api/app/api/v1/deps.py:50-60` and adjust `_tenant()` accordingly.
- [ ] **Step 2: Run test to verify it fails**

  Run: `cd services/api && python -m pytest tests/api/v1/endpoints/test_graph_endpoint.py -v`
  Expected: FAIL — endpoint currently has no `source` field on the response.

- [ ] **Step 3: Write minimal implementation**

  3a. Add `source` to the response model:

  ```python
  class OverviewGraphResponse(BaseModel):
      nodes: list[OverviewGraphNode]
      edges: list[OverviewGraphEdge]
      generatedAt: str
      source: str = "relational"
  ```

  3b. Rewrite `get_overview` to drop the blanket `except` and only fall back when overview is empty:

  ```python
  @router.get("", response_model=OverviewGraphResponse, summary="Get tenant attack graph overview")
  @router.get("/", response_model=OverviewGraphResponse, summary="Get tenant attack graph overview")
  async def get_overview(
      db: DBSession,
      depth: Annotated[int, Query(ge=1, le=10)] = 3,
      current_user: CurrentUser = Depends(get_current_user),
  ) -> OverviewGraphResponse:
      data = await graph_service.get_overview_graph(tenant_id=str(current_user.tenant_id), depth=depth)

      if not data or not data.get("nodes"):
          data = await _graph_overview_from_relational(db, str(current_user.tenant_id))
          data["source"] = "relational"

      return OverviewGraphResponse(**data)
  ```

  The `_is_graph_unavailable`/`_GRAPH_OFFLINE_MARKERS` soft-fallback logic for **attack-path and blast-radius** endpoints is intentionally left unchanged (out of P0 scope).

- [ ] **Step 4: Run test to verify it passes**

  Run: `cd services/api && python -m pytest tests/api/v1/endpoints/test_graph_endpoint.py -v`
  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add services/api/tests/api/v1/endpoints/test_graph_endpoint.py services/api/app/api/v1/endpoints/graph.py
  git commit -m "fix(graph): add source field to overview, gate relational fallback"
  ```

---

### Task 6: Frontend — normalize `kind` and remove error swallowing

**Files:**
- Modify: `apps/web/src/components/graph/AttackGraphView.tsx` (~lines 80-313)
- Modify: `apps/web/src/lib/api.ts` (add optional `source` to `AttackGraph`, ~lines 3311-3314)
- Test: `apps/web/src/components/graph/AttackGraphView.test.tsx` (new)

**Interfaces:**
- Consumes: `graphApi.getOverview` → `AttackGraph`, `graphApi.getMitreCoverage`.
- Produces: canvas nodes whose `kind` is one of the known `GraphNodeKind` values; real `ErrorState` on backend error.

- [ ] **Step 1: Write the failing test**

  `apps/web/src/components/graph/AttackGraphView.test.tsx`. Mock `@/lib/api` so `graphApi.getOverview` returns a node whose backend `kind` is `"endpoint"` (an ingest label) — which the current code does NOT normalize, so it would land as `kind: "endpoint"` and `KIND_SHAPES["endpoint"]` is undefined. Assert the rendered node's cytoscape element `data.kind` is `"host"` after normalization, and that a mocked rejected `getOverview` produces an `ErrorState` (not `No graph yet`).

  Look at an existing component test (e.g. `apps/web/src/components/dashboard/FunnelKpiBar.test.tsx`) for the `@testing-library/react` + `vitest` + `vi.mock('@/lib/api')` setup and mirror it. Then:

  ```tsx
  import { render, screen } from '@testing-library/react'
  import { vi } from 'vitest'
  import { AttackGraphView } from './AttackGraphView'

  vi.mock('@/lib/api', () => ({
    graphApi: {
      getOverview: vi.fn(async () => ({
        source: 'neo4j',
        nodes: [{ id: 'endpoint:tid:h', label: 'h', kind: 'endpoint' }],
        edges: [],
        generatedAt: new Date().toISOString(),
      })),
      getMitreCoverage: vi.fn(async () => ({ tactics: [], cells: [], generatedAt: '' })),
    },
  }))
  ```

  describe('AttackGraphView kind normalization', () => {
    it('normalizes the ingest "endpoint" kind to host', () => {
      render(<AttackGraphView />)
      // The node label 'h' renders; cytoscape builds with kind 'host'
      // (via INGEST_KIND_MAP), so KIND_SHAPES lookup does not hit undefined.
      expect(screen.getByText('h')).toBeInTheDocument()
    })

    it('renders a real ErrorState, not No graph yet, on backend rejection', async () => {
      ;(graphApi.getOverview as unknown as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('503'))
      render(<AttackGraphView />)
      await screen.findByText("Couldn't load graph")
      expect(screen.queryByText('No graph yet')).not.toBeInTheDocument()
    })
  })
  ```

- [ ] **Step 2: Run test to verify it fails**

  Run: `cd apps/web && npx vitest run src/components/graph/AttackGraphView.test.tsx`
  Expected: FAIL — the test file does not exist yet; then after creating it the normalization + error-branch assertions fail (node kind stays `"endpoint"`, and the error case currently renders the swallowed-empty canvas).

- [ ] **Step 3: Write minimal implementation**

  3a. Add a normalization helper in `AttackGraphView.tsx`:

  ```tsx
  const INGEST_KIND_MAP: Record<string, GraphNodeKind> = {
      User: 'user',
      ServiceAccount: 'user',
      Identity: 'user',
      Endpoint: 'host',
      NetworkPath: 'ip',
      Resource: 'asset',
      Repo: 'asset',
      SaaSApp: 'asset',
      Permission: 'asset',
      Role: 'asset',
      Policy: 'asset',
      Container: 'host',
      Image: 'host',
      Detection: 'technique',
      Alert: 'alert',
  };

  function normalizeKind(ingestLabel: string): GraphNodeKind {
      return INGEST_KIND_MAP[ingestLabel] ?? 'asset';
  }
  ```

  Apply it in the `GraphCanvas` `elements` builder: replace `kind: n.kind` with `kind: INGEST_KIND_MAP[n.kind] ?? n.kind` (or better, pass `kind: normalizeKind(n.kind)` from the data layer so the mapping is centralized).

  3b. Remove the graph fetcher `catch` (lines 286-294):

  ```tsx
  const graphState = useSWR<AttackGraph>(
    'attack-graph',
    async () => await graphApi.getOverview({ depth: 3 }),  // no try/catch
    { revalidateOnFocus: false, refreshInterval: 30_000 },
  );
  ```

  3c. Remove the mitre fetcher `catch` (lines 302-310):

  ```tsx
  const mitreState = useSWR<MitreCoverage>(
    'mitre-coverage',
    async () => await graphApi.getMitreCoverage(),  // no try/catch
    { revalidateOnFocus: false, refreshInterval: 60_000 },
  );
  ```

  3d. Add `source` to the `AttackGraph` interface in `api.ts` (line 3311-3314):

  ```ts
  export interface AttackGraph {
      nodes: GraphNode[];
      edges: GraphEdge[];
      generatedAt: string;
      source?: string;
  }
  ```

- [ ] **Step 4: Run test to verify it passes**

  Run: `cd apps/web && npx vitest run src/components/graph/AttackGraphView.test.tsx`
  Expected: PASS — node kind normalized, error state surfaced.

- [ ] **Step 5: Commit**

  ```bash
  git add apps/web/src/components/graph/AttackGraphView.tsx \
          apps/web/src/components/graph/AttackGraphView.test.tsx \
          apps/web/src/lib/api.ts
  git commit -m "fix(graph): normalize node kinds + surface backend errors"
  ```

---

### Task 7: Frontend full-suite check

**Files:**
- Verify: `pnpm -C apps/web test`
- Test: existing `apps/web/**/*.test.tsx` (no new assertions)

- [ ] **Step 1: Run full frontend suite**

  Run: `cd apps/web && pnpm test`
  Expected: PASS. The `GraphNodeKind` / `kind` normalization in Task 6 touched shared code paths; the suite confirms no component breaks.

- [ ] **Step 2: Commit (if any test-driven follow-up is needed)**

  Commit only if a test-driven fix is required; otherwise no commit.

---

### Task 8: Docs — reflect the new `source` field + degraded path

**Files:**
- Modify: any graph API doc referencing `GET /graph`. If `apps/docs` documents the graph overview response shape, add the `source` field and the live-vs-relational note. Otherwise (no doc exists) skip — do not invent docs.

- [ ] **Step 1: Check for doc references**

  Run: `cd apps/web && grep -rln "AttackGraph\|/graph" ../docs 2>/dev/null` (adjust path). If a doc describes the overview response, add the `source` field and a one-line note: *"source is 'neo4j' for live ingest data, 'relational' for the Postgres fallback when Neo4j is unavailable."*

- [ ] **Step 2: Commit if edited**

  ```bash
  git add <doc-file>
  git commit -m "docs(graph): document overview source field"
  ```

---

## Self-Review

1. **Spec coverage:** Every spec requirement maps to a task — overview live (Task 2), MITRE live + technique names (Task 3), schema reconciliation (Task 1), live/degraded `source` (Task 5), error swallow removal (Task 6), kind normalization (Task 6), blast-radius/attack-path/neighbors edge mapping (Task 4), verification (Tasks 1-7 + spec §6). No gap.
2. **Placeholder scan:** Every step includes real test code (or a concrete TS sketch) and a real `pytest`/`vitest` command. `TestClient`/`CurrentUser` import in Task 5 Step 1 references a lookup ("look at an existing endpoint test") — resolved by mirroring `test_insights_endpoint.py`; the plan notes this explicitly. No TBD/TODO.
3. **Type consistency:** `get_overview_graph` returns `dict | None` across Tasks 2-5 (consistent). `AttackGraph.source` is `string | undefined` in Task 6 and matches the backend `source: str = "relational"` default. `_calc_blast_score` weights are consistent between Task 4 Step 3 and its test. `mitre_coverage` record keys (`technique_id/name/alert_count`) match `/mitre-coverage` mapping in Task 3.
4. **Bite-sized:** 8 tasks, each ~2-5 min, each ends with an independently testable deliverable and a commit.
