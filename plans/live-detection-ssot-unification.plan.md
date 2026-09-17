# Live Detection Ruleset Single-Source-of-Truth Unification

## Context & Root Cause Analysis

Fusion's live detection engine currently loads two parallel native ruleset pipelines:
- **Pipeline A (Legacy Static Artifact)**: `scripts/detection_specs*.py` → `scripts/export_detection_ruleset.py` → `services/fusion/app/data/detection_ruleset.json` (loaded once by fusion on boot, decoupled from database state and console toggles).
- **Pipeline B (Dynamic Database SSOT)**: `detections/` YAML → `seed_native_ruleset` → `detection_rules` table → `reconcile_from_postgres` & `listen_detection_reload` → `DetectionEngine.apply_reload`.

Six defects keep Pipeline B from being the single source of truth:
1. **Sigma Compiler Mismatch**: Native YAML rules under `detections/` use a multiline **infix condition string** under `detection.condition` (e.g. `connection_count > 50 AND interval_consistency > 0.85`), not Sigma `selection`/`filter`. Both `_record_compile` (native_ruleset.py line 226) **and** the console-write path `compile_rule` (compiler.py line 59) currently call `compile_sigma_to_match_when` unconditionally. Seeded native rules fail (`status='error'`, `compiled_spec=None`), and a console `PATCH /api/v1/rules/{id}` on a native rule recompiles it with Sigma → `error` → broadcasts `DISABLE` → removes the rule permanently from Fusion's memory.
2. **Critical Redis Pub/Sub Payload Drift**: `broadcast_rule_reload` (compiler.py) publishes `match_when` **nested** under `payload["compiled_rule"]["match_when"]`, but `listen_detection_reload` reads `payload.get("match_when")` at the **root** (detection_reload.py line 82) — so `match_when` is always `None` and hot-reload raises `ValueError("CREATE requires match_when")` and fails silently.
3. **Loss of Metadata on Reload**: `DetectionEngine.apply_reload` hardcodes incoming rules to `{"name": rule_id, "severity": "medium", "category": "custom"}`, discarding real rule metadata.
4. **Missing Delete Hook**: `DELETE /api/v1/rules/{rule_id}` removes the row from Postgres but never broadcasts `DISABLE`, leaving deleted rules active in Fusion's memory.
5. **UUID vs String Type Mismatch**: `asyncpg` returns `id` as a `uuid.UUID`; Redis reload events send `str(uuid)`. Keys in `_rules_map` must be consistently stringified.
6. **Fusion Boot Race**: `_start_detection_reload` is a `asyncio.create_task` (main.py line 136) that runs *after* `worker.start()` (line 125), so events arriving during the few seconds Postgres-reconcile reads rules are evaluated with an empty or stale `_rules_map` and silently missed.

Additionally:
- **25 aggregate/stateful native rules** reference connector fields that no network connector emits (`distinct_ports_per_src`, `connection_count`, `interval_consistency`, `time_window_minutes`, `concurrency`), so they can never fire and must be quarantined. (Of the 836-rule executable set, exactly 25 carry aggregate keys.)
`block_untrusted_ssh` is **not** present in AiSOC's own detection ruleset (`detection_rules` table or `git grep`), but it **is** a real alert on a live deployment: an `elastic_search` connector pulling from the customer's own Elasticsearch SIEM cluster surfaces a native ES rule named `block_untrusted_ssh` (`rule.id=1001`). It was never a AiSOC rule, so no runtime-trace code applies. See `HISTORY`/session notes for the full root-cause writeup.

**DO NOT delete `scripts/detection_specs*.py`**: `scripts/validate_detections.py`, `services/agents/tests/test_detection_fp_rate.py`, and CI import them directly. Pipeline A decommissioning is strictly limited to `services/fusion/app/data/detection_ruleset.json`, `scripts/export_detection_ruleset.py`, and the CI drift step.

---

## Section 0 — Architecture Invariants & Prerequisites

1. **Redis Endpoint & Instance-Global Pub/Sub**: `services/api` (`settings.REDIS_URL`) and `services/fusion` (`settings.redis_url`) MUST connect to the **identical Redis host and port**. Pub/Sub (`rules:reload`) is instance-global, not database-scoped — a `PUBLISH` on any Logical DB index is received by subscribers on any other index. **Do NOT force services onto the same Logical DB**: the deployed stacks use different indices per service (e.g. API db 0, the ingest/realtime-style service db 3 in `docker-compose.yml`). Changing a service's Redis index is out of scope and would disturb its existing dedup/state store — the plan only relies on the channel routing being instance-global.
2. **UUID String Typing Invariant**: Every `rule_id` entering Fusion's `_rules_map` or Redis reload channels MUST be `str(rule_id)`.
3. **Reload Action Vocabulary**: API emits `ENABLE` | `DISABLE` | `UPSERT`; Fusion translates `ENABLE→CREATE`, `UPSERT→UPDATE`, `DISABLE→DISABLE`.
4. **Payload Structure Compatibility**:
   ```json
   {
     "event_type": "RULE_STATE_CHANGED",
     "rule_id": "<uuid_str>",
     "action": "ENABLE",
     "version": 1,
     "match_when": { ... },
     "compiled_rule": {
       "id": "<uuid_str>",
       "name": "Rule Name",
       "severity": "critical",
       "category": "cloud",
       "match_when": { ... }
     }
   }
   ```
   Fusion consumer MUST parse `match_when = payload.get("match_when") or payload.get("compiled_rule", {}).get("match_when")` (both, for forward/backward compatibility).
5. **Matcher Contract**: Emitted `match_when` dicts target flat connector raw data fields with suffixes in `detection_matcher.py`: equality, `_in`/`_not_in` (lists), `_contains`/`_contains_any`/`_startswith`/`_startswith_any`/`_endswith`/`_endswith_any`/`_match`/`_match_any`, `*_gt`/`*_gte`/`*_lt`/`*_lte`, nested `all_of`/`any_of`. No bare `not` key, no `all` key.
6. **Upsert is SQLAlchemy ORM, not raw SQL**: the seed upserts by mutating an existing `DetectionRule` row by attribute (native_ruleset.py, `existing` block), never a raw `ON CONFLICT ... DO UPDATE`. Preserve this style. Verified columns: `description text`, `version integer`, `updated_at timestamptz`, `rule_language varchar(30)`, `rule_body text`, `is_builtin boolean`, `rule_type varchar`, `compiled_spec jsonb`, `compile_status varchar(20)`, `compile_error text`. `rule_hash` column does **NOT** exist.

---

## Step 1 — Implement Native Infix DSL Compiler & Wire It Into BOTH Compile Paths

**Targets** (new): `services/api/app/services/detections/native_match_when.py`.
**Targets** (change): `services/api/app/services/detections/native_ruleset.py` (`_record_compile`, ~line 226) and `services/api/app/services/detections/compiler.py` (`compile_rule`, line 59).

Compiler contract (identical interface to `compile_sigma_to_match_when`):
```python
class CompileResult(NamedTuple):
    status: str                    # "compiled" | "unsupported_stateful" | "error"
    match_when: dict[str, Any] | None
    error: str | None
```

1. **Aggregate / Stateful Detection (first pass)**: if the condition/YAML text contains any aggregate field (`time_window_minutes`, `connection_count`, `interval_consistency`, `distinct_ports_per_src`, `distinct_dst_per_src`, `distinct_hosts_per_src`, `distinct_users_per_ip`, `event_count`, `failed_attempts`, `request_rate`, `bytes_transferred_total`), return:
   ```python
   CompileResult(status="unsupported_stateful", match_when=None, error="Requires stateful aggregate telemetry fields")
   ```
2. **Infix Grammar Parser**: parse expression lines separated by `AND`/`OR`/`NOT`:
   - `field == "val"` → `{field: "val"}`; `field == true/false` → `{field: True/False}`; `field IS NULL` → `{field: None}`.
   - `field IN [...]` → `{f"{field}_in": [...]}`; `field NOT IN [...]` → `{f"{field}_not_in": [...]}`.
   - `field CONTAINS "a"` → `{f"{field}_contains": "a"}`; `CONTAINS_ANY/ALL` → `_contains_any`/`_contains_all`.
   - `STARTSWITH(ANY)`/`ENDSWITH(ANY)` → `_startswith(_any)`/`_endswith(_any)`.
   - `NOT STARTSWITH` → `_not_startswith`; `NOT CONTAINS_ANY` → `_not_contains_any`; `NOT ENDSWITH_ANY` → `_not_endswith_any`.
   - `field MATCH(MATCHES)(ANY)` → `_match(_any)`; comparators `> >= < <=` → `gt/gte/lt/lte`.
   - Legacy normalizations: `STARTS_WITH_ANY`→`_startswith_any`, `ENDS_WITH_ANY`→`_endswith_any`, `!=`→`_not_in` single-element list; handle multiline string lists spanning lines.
3. **Block Parsing**: `ANY OF:` / named `selection_`/`filter_` blocks → nested `any_of`/`all_of` trees. (Present in rules like `etw-tampering.yaml`, `saml-response-anomaly.yaml`.)
4. **Flat Field Schema Guardrail**: check generated `match_when` keys against allowable flat fields (`command_line`, `file_path`, `user`, `source_image`, `registry_path`, `src_ip`, `dst_ip`, `dst_port`, `event_type`); flag non-emitted dotted OCSF paths as error or map to flat aliases.
5. **Vacuous Match Defense**: negation operators must not match when the target field is missing/null.
6. **Wire into `_record_compile`** (native_ruleset.py): dispatch by `rule.rule_type == "native"` → call `compile_native_to_match_when(rule.rule_body)`, else `compile_sigma_to_match_when(raw)` (unchanged).
7. **Wire into `compile_rule`** (compiler.py, line 59 — the console-write path): after the docstring, replace `result = compile_sigma_to_match_when(rule.rule_body or "")` with:
   ```python
   if getattr(rule, "rule_type", None) == "native":
       result = compile_native_to_match_when(rule.rule_body or "")
   else:
       result = compile_sigma_to_match_when(rule.rule_body or "")
   ```
   This is required so a console `PATCH` on a native rule compiles with the native compiler and does NOT flip `status` to `error` (which would broadcast `DISABLE` via `decide_reload_action` and evict the rule from Fusion).
8. **Compile-then-Broadcast on native rule**: `apply_compile_and_reload` broadcasts only when `rule.rule_language in _RELOAD_LANGUAGES` (`{"sigma","yaml"}`). Native rules seed as `rule_language="sigma"`, so a native rule's `error`→`compiled` transition still routes through the broadcast path and activates the rule. Confirm; if `rule_type` alone doesn't reach `apply_compile_and_reload`, add the `rule_type`-aware branch.

---

## Step 2 — Route Native Rules & State-Preserving Re-Seed

**Targets**: `services/api/app/services/detections/native_ruleset.py` (the `existing` upsert block ~lines 445-460) and `services/api/app/scripts/seed_native_detections.py`.

1. **State-Preserving Update (existing-branch)**: preserve operator ON/OFF `status`, `total_hits`, `confidence`, `last_triggered_at`; update all metadata (name, description, category, severity, mitre, tags, version, provenance, rule_type, file_path) and the compile output (`compiled_spec`, `compile_status`, `compile_error`); increment `version` by 1 and set `updated_at`.
   - **CRITICAL — refresh `rule_body`**: this same `existing` block must also set `existing.rule_body = raw` (the freshly-read YAML text). The current code updates `existing.name`/`existing.description`/`existing.severity` etc. but does **NOT** assign `existing.rule_body`, so a YAML file changed on disk is never reflected in the DB row. Without this, an operator re-adding `detections/.../rule.yaml` with a fixed condition keeps the old `rule_body`, and the native compiler runs against stale text on every subsequent reconcile/re-seed.
2. **Incremental Compile Trigger (existing branch)**: recompile when `existing.compiled_spec is None` OR `existing.compile_status in ("error","pending")` OR `compile_status == "unsupported_stateful"` (so previously-skip rules reclassify). Change detection is in-memory via `hashlib.md5(rule_body.encode()).hexdigest()` (no `rule_hash` column).
3. **Step-2 Report Assertion**: `seed_native_ruleset --dry-run` must report `compiled >= 840`, `unsupported_stateful == 25`, `error == 0`.

---

## Step 3 — Resolve Redis Pub/Sub Payload Drift & Reload Gaps

**Targets**: `services/api/app/services/detections/compiler.py`, `services/fusion/app/services/detection_reload.py`, `services/fusion/app/services/detection_engine.py`, `services/api/app/api/v1/endpoints/detection_rules.py`.

1. **Fix API Payload** (`broadcast_rule_reload` in compiler.py): emit `match_when` both at root and under `compiled_rule` (both set to `rule.compiled_spec`); add `category: rule.category` to `compiled_rule`.
2. **Fusion Consumer Tolerance** (`listen_detection_reload`): read `match_when = payload.get("match_when") or (payload.get("compiled_rule") or {}).get("match_when")`; build `metadata = {"name", "severity", "category"}` from `compiled_rule`, and pass `metadata` to `apply_reload`.
3. **Preserve Metadata in Engine** (`apply_reload`): accept a `metadata` param (fallback `{"name": rule_id, "severity": "medium", "category": "custom"}` when absent — never silently discard); string-cast `rule_id`.
4. **UUID Cast in Reconcile**: `reconcile_from_postgres` must `str(row["id"])` / `str(row["rid"])` before `apply_reload`.
   - **CRITICAL — SELECT the metadata columns**: the current query (`detection_reload.py` line 118) is `SELECT id AS rid, compiled_spec AS cspec FROM detection_rules WHERE status = 'active' AND compile_status = 'compiled'` — it does **NOT** fetch `name`/`severity`/`category`. On every Fusion restart, `apply_reload("UPDATE", ...)` is called with `metadata=None`, so all rule metadata resets to the fallback (`name=rule_id`, `severity="medium"`). Change the query to `SELECT id, name, severity, category, compiled_spec FROM detection_rules ...` and pass each row's metadata:
     ```python
     rows = await conn.fetch(
         "SELECT id, name, severity, category, compiled_spec "
         "FROM detection_rules WHERE status = 'active' AND compile_status = 'compiled'"
     )
     for row in rows:
         detector.apply_reload(
             "UPDATE",
             str(row["id"]),
             row["compiled_spec"],
             metadata={"name": row["name"], "severity": row["severity"], "category": row["category"]},
         )
     ```
5. **Broadcast on Delete** (`delete_rule` in detection_rules.py): after `db.delete(rule)` + `commit()`, call `await broadcast_rule_reload(rule, "DISABLE")` so Fusion removes the rule from memory.

---

## Step 4 — Decommission Legacy Pipeline A, Align Fusion Startup, Fix the Boot Race

**Targets**: `services/fusion/app/services/detection_engine.py`, `services/fusion/app/main.py`, `services/fusion/tests/test_detection_matcher_parity.py`, and file deletions below.

1. **Switch Fusion Startup to Postgres SSOT**: `DetectionEngine.__init__` sets `self._rules_map = {}` by default; remove `_load_ruleset()` and `_RULESET_PATH`.
2. **Fix the Boot Race (main.py)**: the current order starts `worker.start()` (line 125) as a background task before `_start_detection_reload` is scheduled (line 136), so events land with an empty rule map. Make reconciliation synchronous **before** the Kafka worker starts consuming: in `lifespan`, await `reconcile_from_postgres(settings.database_url, detector)` before `worker_task = asyncio.create_task(worker.start())`. Keep fail-soft retry (6 attempts, exponential backoff) inside `reconcile_from_postgres`; if Postgres is unreachable after the budget, raise `RuntimeError("Fusion startup aborted: Unable to load detection rules from database")` to crash-restart — do NOT silently boot with 0 rules.
3. **Delete Pipeline A Artifacts**:
   - Delete `services/fusion/app/data/detection_ruleset.json`.
   - Delete `scripts/export_detection_ruleset.py`.
   - Remove the `export_detection_ruleset.py --check` drift step from `.github/workflows/validate-detections.yml`.
   - **Retain** `scripts/detection_specs*.py` and `scripts/validate_detections.py` (CI and agents test import them).
4. **Fix `test_detection_matcher_parity.py`** (lines 37-39 and 70-72 hardcode `services/fusion/app/data/detection_ruleset.json`): replace the ruleset read with `scripts/detection_specs_index.all_specs()` (the retained spec source), keyed by `spec["slug"]` → `spec["match_when"]`, so the matcher-parity fixture test still compares vendored vs canonical matcher output without depending on the deleted artifact.

---

## Step 5 — (Removed) Mystery `block_untrusted_ssh` Alert

Not a real rule — absent from source and git history (workspace-wide and full-history `git grep` return nothing). No runtime-trace code, no remediation. Retained only as an informational note; implementer does nothing.

---

## Step 6 — Verification & E2E Validation

1. **Native DSL Compiler Unit Tests**:
   ```bash
   cd services/api && pytest tests/test_native_match_when.py -v
   ```
   - Assert all native YAML files parse without exceptions; exactly **25** rules return `unsupported_stateful`; all other rules compile into valid `match_when` dicts that pass `matches(...)` from `detection_matcher.py`.
2. **Reload & Payload Tests**:
   ```bash
   cd services/fusion && pytest tests/test_detection_engine.py -v
   cd services/api && pytest tests/test_sigma_match_when.py -v
   ```
   - `broadcast_rule_reload` payload ingested by `listen_detection_reload` without `ValueError`; metadata preserved.
3. **Console Native-Rule Patch Path** (covers compiler.py:59 fix): PATCH a native rule via the API; assert `compile_status` is `compiled` (not `error`) and Redis `rules:reload` carries `action=UPSERT` (not `DISABLE`); assert the rule remains in Fusion's `_rules_map`.
4. **Seed & DB State Check**:
   ```bash
   python3 -m app.scripts.seed_native_detections --dry-run
   ```
   - `compiled >= 840`, `unsupported_stateful == 25`, `error == 0`. SQL: `SELECT status, compile_status, COUNT(*) FROM detection_rules GROUP BY 1, 2;`.
5. **Fusion Restart Metadata Preservation** (covers Step 3.4): after a rule with non-default `name`/`severity` is reconciled, restart fusion and re-read the same rule's in-memory entry — assert `name`/`severity` are unchanged (not `name=rule_id`, `severity="medium"`).
6. **Re-Seed Reflects On-Disk YAML** (covers Step 2.1 `rule_body` refresh): modify a native rule's condition on disk, re-run the seed, and assert `SELECT rule_body FROM detection_rules WHERE id=<native_id>` returns the new YAML text (not the old string).
7. **Clean Cutover Verification**:
   ```bash
   grep -rn "detection_ruleset.json" services/ apps/ .github/ scripts/
   ```
   - No references except the retained `scripts/detection_specs*.py`/`validate_detections.py` import graph and the updated `test_detection_matcher_parity.py`.
8. **Full Test Suite**:
   ```bash
   cd services/api && python -m pytest tests/ -q
   cd services/fusion && python -m pytest tests/ -q
   cd services/agents && pytest tests/test_detection_fp_rate.py -v
   ```

---

## Assumptions & Contingencies

- **25-rule count is for the native executable set** (the 836-rule `detection_ruleset.json`). If the seed-derived `detection_rules` table yields a different aggregate count after native-rule routing, adjust Step 2/Step 6's `unsupported_stateful == 25` to the empirically observed count; the verification asserts the aggregate rules are classified `unsupported_stateful`, not a specific number.
- **If the native infix parser cannot faithfully reproduce the `match_when` grammar** produced by the retained `scripts/detection_specs*.py` builders, verify parity with the updated `tests/test_detection_matcher_parity.py` (native-compiler output vs `all_specs()` output) before deleting `scripts/export_detection_ruleset.py`. If parity fails on a subset, expand the flat-field guardrail / block parser rather than widening the `unsupported_stateful` classification.
- **Fusion boot-race fix must not block event ingestion if reconcile is slow.** If awaiting `reconcile_from_postgres` synchronously before `worker.start()` exceeds the ingestion latency budget in a large deployment, keep the wait but surface a warning instead of raising; the fail-fast raise remains the contract for the "Postgres unreachable" case, distinct from "reconcile still in progress".
