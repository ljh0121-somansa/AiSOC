# Attack Graph — Live Neo4j Data Activation (P0 Core)

**Status:** APPROVED by user — implement per this spec
**Date:** 2026-09-16
**Related plan:** [`plans/attack-graph-rebuild.plan.md`](../../../plans/attack-graph-rebuild.plan.md)
**Scope:** P0 core only — overview + MITRE coverage become live; error swallowing removed.
**Out of scope (follow-up plan):** attack-path Case-neo4j wiring, `/entities/ioc` route, legend/i18n polish (Steps 4–9 of the plan).

---

## 1. Problem

The Attack Graph UI (`AttackGraphView`) appears empty (`No graph yet` / `커버리지 데이터 없음`) on a
real deployment because its backend data path is **structurally dead**:

- The **ingest writer** (`services/ingest/internal/graph/`, Go, live against Kafka, `AISOC_GRAPH_ENABLED`)
  produces nodes labelled `:User :Endpoint :NetworkPath :Resource :Alert :Detection` with edges
  `TRIGGERED` / `OCCURRED_ON`, keyed by `natural_key`. It **never** creates `:Host`, `:IOC`, or
  `:Technique`.
- The **API query layer** (`services/api/app/services/graph_service.py`, `neo4j.py`) queries a
  **different** label set (`:Host :IOC :Technique :Case :User`, edges `OBSERVED_ON / CONTAINS_ALERT /
  MAPS_TO / CONTAINS_IOC`) and always falls back to a Postgres relational reconstruction.
- The **frontend** swallows every backend error (`catch → return empty`), so a failed backend renders
  a silent canvas.

Result: overview + MITRE coverage never show live data, and errors are hidden.

---

## 2. Invariants

1. **Single graph vocabulary = the ingest vocabulary.** `:Host / :IOC / :Technique` are deleted from
   `neo4j.py` and never re-added. The query layer consumes the ingest schema.
2. **Node identity is `natural_key`.** Queries derive node ids from `natural_key` (not `id`/`value`),
   which is the only id the writer persists. `Alert` nodes carry no `id` — use
   `f"{Label}:{natural_key}"` as the id fallback (matches `extractor.go`).
3. **`source` distinguishes live from degraded.** Every overview response carries a `source` field:
   `"neo4j"` for real ingest data, `"relational"` for the Postgres fallback. This prevents relational
   data from masquerading as live Neo4j data.
4. **Tenant isolation.** Every `MATCH` binds `$tenant_id` as a real parameter — no empty literal,
   no string interpolation.
5. **Frontend never swallows backend errors.** `graphApi` fetchers return normally; `useSWR(...).error`
   is surfaced as a real `ErrorState`.
6. **Id collision safety.** live (`alert:tid:id`) and relational (`alert:{id}`) node ids use different
   prefixes, so they never collide in a shared canvas.
7. **No competitor names** ("Torq" / "Prophet Security") in any changed code or doc.
8. **The relational fallback remains** as an explicit, documented degradation path when Neo4j is
   empty/unreachable — but it is never auto-substituted for live data.

---

## 3. Target Files

### New / modified
| File | Change | Why |
|---|---|---|
| `services/api/app/db/neo4j.py` (`_create_schema`) | Replace label set → ingest vocabulary; per-`natural_key` constraint + per-label `tenant_id` index | Schema must match the live writer. |
| `services/api/app/services/graph_service.py` | Rewrite `get_overview_graph`, `get_mitre_coverage`, `get_attack_path`, `get_blast_radius`, `get_entity_neighbors`, `_calc_blast_score` to ingest vocab + `natural_key` | Queries must consume the ingest schema. |
| `services/api/app/api/v1/endpoints/graph.py` | Add `source` to `OverviewGraphResponse`; remove unconditional relational fallback for overview; keep fallback only when overview returns no nodes | live/degraded distinction; prevent fake live data. |
| `apps/web/src/components/graph/AttackGraphView.tsx` | Add ingest→`GraphNodeKind` normalization; remove both SWR `catch` swallows | live kinds render; real errors surface. |
| `apps/web/src/lib/api.ts` | (optional) `AttackGraph.source` field | TS type parity with backend. |

### Regression-surface (must remain green, no edits expected)
- `services/api/tests/test_graphql.py` (no `test_graph*` graph tests exist — add new ones; see §6).
- `pnpm -C apps/web test` — shared `GraphNodeKind` touched by Step 1C.

---

## 4. Design

### Step 1 — Schema reconciliation

#### 1A. `neo4j.py` — `_create_schema()`

Delete `Host`, `IOC`, `Technique`, `Process` constraints/indexes. Add per-label constraint keyed on
`natural_key` + per-label `tenant_id` index for:

```
User, Endpoint, NetworkPath, Resource, Alert, Detection,
Repo, Identity, ServiceAccount, SaaSApp, Permission,
Role, Policy, Container, Image, Case
```

Pattern (single helper loop avoids repetition):

```cypher
-- for each LABEL:
CREATE CONSTRAINT IF NOT EXISTS FOR (n:<LABEL>) REQUIRE n.natural_key IS UNIQUE
CREATE INDEX IF NOT EXISTS   FOR (n:<LABEL>)   REQUIRE (n.tenant_id)
```

**Rationale:** the writer (`writer.go:519-534`) does `MERGE (n:<LABEL> {natural_key}) SET n += props`.
`natural_key` is the only unique id; `id`/`value`/`technique_id` indexes reference properties the
writer never writes.

#### 1B. `graph_service.py` — query rewrite

**`get_overview_graph(tenant_id, depth, limit)`** — fix the broken empty literal (`graph_service.py:494-496`
`WHERE n.tenant_id =  OR ...`), derive ids from `natural_key`, respect `$depth`/`$limit`, and return
`{"source": "neo4j", ...}` when nodes are found, else `None` so the endpoint can decide on fallback.

```cypher
MATCH (n) WHERE n.tenant_id = $tenant_id OR n.tenant_id IS NULL
OPTIONAL MATCH (n)-[r]-(m) WHERE m.tenant_id = $tenant_id OR m.tenant_id IS NULL
RETURN n, labels(n) AS labels, r, m, labels(m) AS target_labels, type(r) AS rel_type
```

`node_id` derivation priority: `props.get("natural_key") or props.get("id") or f"{label0}:{fallback}"`.
(`Alert` has no `id` → falls to `Alert:alert:{natural_key}`.)

**`get_mitre_coverage(tenant_id)`** (`graph_service.py:471-481`) — replace `MAPS_TO/Technique`:

```cypher
MATCH (:Alert {tenant_id: $tenant_id})-[:TRIGGERED]->(d:Detection)
RETURN
    d.mitre_technique_id AS technique_id,
    d.mitre_technique_name AS name,
    COUNT(*) AS alert_count
ORDER BY alert_count DESC
```

`d.mitre_technique_name` exists (ingest `extractor.go:625`) → **Step 8 technique-name problem is
resolved here as a side-effect.**

**`get_attack_path` / `get_blast_radius` / `get_entity_neighbors`** — re-map `label_map` and edges to
the ingest vocabulary:

```
"host"     -> "Endpoint"
"ioc"      -> <removed: never produced>
"user"     -> "User"
"alert"    -> "Alert"
+          -> "Endpoint", "NetworkPath", "Resource", "Detection"
```

- `id_prop` becomes `"natural_key"` for all labels.
- Edges: `TRIGGERED` (User/Alert → Detection), `OCCURRED_ON` (Alert → Endpoint/NetworkPath/Resource).
- `get_attack_path` start node is `:Case`, which the **ingest writer never creates** — so its `MATCH
  (:Case ...)` yields empty and it falls through to the relational fallback. This is the intended
  degraded path; keep the fallback, do not add Neo4j Case-writing (out of scope).
- `_calc_blast_score` weights (graph_service.py:423-430) → `Endpoint=10, Resource=8, User=8,
  Alert=6, NetworkPath=3, Detection=2` (was `Host/IOC/Technique`-weighted).

#### 1C. Frontend `kind` normalization (`AttackGraphView.tsx`)

ingest label → `GraphNodeKind` map, applied right before the cytoscape `elements` build
(graph_service.py returns `kind = str(labels[0]).lower()`):

| ingest label(s) | GraphNodeKind |
|---|---|
| `User`, `ServiceAccount`, `Identity` | `user` |
| `Endpoint` | `host` |
| `NetworkPath` | `ip` |
| `Resource`, `Repo`, `SaaSApp`, `Permission`, `Role`, `Policy` | `asset` |
| `Container`, `Image` | `host` |
| `Detection` | `technique` |
| `Alert` | `alert` |

This fixes RC-2 (kinds like `endpoint`/`networkpath`/`resource`/`detection` falling to the
`#94a3b8` fallback) by mapping them to a known kind the legend + `KIND_SHAPES` understand.

### Step 2 — `get_overview_graph` Cypher fix (contained in Step 1B above)

- Remove `WHERE n.tenant_id = ` (empty literal).
- `LIMIT 200` hardcode → `$limit`.
- `$depth` controls the `OPTIONAL MATCH` depth.

### Step 3 — Remove frontend error swallowing

#### 3A. `AttackGraphView.tsx` — graph fetcher (lines 283-297)

```diff
const graphState = useSWR<AttackGraph>('attack-graph', async () => {
-  try { return await graphApi.getOverview({ depth: 3 }); }
-  catch (err) { return { nodes: [], edges: [], generatedAt: ... }; }
+  return await graphApi.getOverview({ depth: 3 });
}, { revalidateOnFocus: false, refreshInterval: 30_000 });
```

The existing `graphState.error ? ErrorState(...)` branch (lines 346-353) is currently **dead code**
(error was always swallowed). It becomes live.

#### 3B. `AttackGraphView.tsx` — mitre fetcher (lines 299-313)

Same removal. This makes `mitreState.error` real, so the Korean-hardcoded empty state
(lines 476-478, `title="커버리지 데이터 없음"`) is replaced by a real error state (or by real cells).

#### 3C. Keep the graceful degradation at the endpoint, not the frontend

The endpoint (`graph.py`) already returns an empty `source: "relational"` when Neo4j is offline — that
is the *intended* graceful path. The frontend no longer needs to fabricate an empty canvas on error.

---

## 5. Response model change

`OverviewGraphResponse` (`graph.py:174-177`) gains one optional field for the live/degraded distinction:

```python
class OverviewGraphResponse(BaseModel):
    nodes: list[OverviewGraphNode]
    edges: list[OverviewGraphEdge]
    generatedAt: str
    source: str = "relational"   # "neo4j" | "relational"
```

`get_overview` endpoint (`graph.py:311-331`) change:

```python
data = await graph_service.get_overview_graph(tenant_id=..., depth=depth)   # returns {"source":...} or None
if not data or not data.get("nodes"):
    data = await _graph_overview_from_relational(db, tenant_id)
    data["source"] = "relational"
return OverviewGraphResponse(**data)
```

Remove the blanket `except` (graph.py:323-324) that logged Neo4j failures silently — let it raise so
the caller (and Step 3C) can distinguish error vs empty. **Keep** the existing
`_is_graph_unavailable` soft-path for attack-path/blast-radius endpoints (out of P0 scope, unchanged).

---

## 6. Verification

Do **not** skip any of these.

1. **Backend unit test** (`services/api/tests/test_graph_service.py`, new file) — assert:
   - `get_overview_graph` derives ids from `natural_key`, not `id`/`value`.
   - `get_mitre_coverage` matches on `-[:TRIGGERED]->(:Detection)`.
   - `$tenant_id` is bound as a parameter (no empty literal).
   - Returns `{"source": "neo4j"}` when nodes present; `None` when empty.
   - `_calc_blast_score` uses the new Endpoint/Resource weights.
2. **Live replay (Neo4j available):** seed ingest data → `GET /api/v1/graph` returns `source == "neo4j"`
   with non-empty `nodes`; `kind` values are normalized (`host`/`user`/`ip`/`technique`/`alert`/`asset`),
   **not** `asset`-only and **not** raw `endpoint`/`networkpath`.
3. **Relational fallback path (Neo4j unavailable):** `source == "relational"`; relational ids
   (`alert:{id}`) do not collide with live ids.
4. **Frontend smoke (mocked SWR error):** a failing backend renders a real `ErrorState` (title
   `"Couldn't load graph"`), never a silent `No graph yet` canvas.
5. **Full frontend suite:** `pnpm -C apps/web test` — the `GraphNodeKind` change is shared.

---

## 7. Risks & Mitigation

- **Risk:** relational fallback's `source="relational"` may show a graph on a fresh tenant with no Neo4j
  data. **Mitigation:** the `source` field documents that it is fallback — the user sees it as degraded,
  not as fabricated live data.
- **Risk:** changing `graph_service.py` labels breaks any test asserting the old label set. **Mitigation:**
  §6.1; add new graph tests; no third label set re-introduced (Invariant #1).
- **Risk:** deleting the error swallow exposes transient 500 noise. **Mitigation:** SWR default retry
  (`onRetry`, backoff) — not an error page.
- **Risk:** `natural_key` id fallback differs from relational fallback id → cytoscape collision.
  **Mitigation:** Invariant #6 (different prefixes).

---

## 8. Expected Outcome

- **User:** overview canvas shows real Neo4j live data; live vs relational fallback is distinguishable;
  MITRE heatmap shows technique **names** + `alert_count`-intensity.
- **Developer:** single graph vocabulary (no re-breakage), KISS/DRY preserved, errors surface instead of
  a silent canvas.
- **QA:** unit + live-replay + relational-fallback paths each verifiable.
- **PM:** the "live Neo4j data" promise matches the implementation; degraded paths are transparent.
