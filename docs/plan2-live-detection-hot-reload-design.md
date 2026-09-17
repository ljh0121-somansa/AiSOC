# Phase 2 — Live Detection Hot-Reload: Design Record

Executed under the plan at `local://phase2-live-detection-hot-reload-plan.md`.
Authoritative matcher source of truth: `services/fusion/app/services/detection_matcher.py`.
Verified flat field names against `services/fusion/app/data/detection_ruleset.json`.

## Key design decision (deviation from illustrative Check A — matcher is source of truth)

The matcher's `_eval_clause` (matcher.py:198) runs every key through `_split_op`,
which strips an operator *suffix* from a flat `field_op` string and compares the
**value** directly. A **nested** `match_when` like
`{"image_basename": {"in": ["regsvr32.exe"]}}` does NOT evaluate — the value is a
dict, compared against the field, always False. The shipped corpus and the matcher
use the **flat** grammar: `{field_op: value}` (+ optional `all_of`/`any_of` clause
lists). All transpiler output below targets that flat grammar.

## Section 1 — API model + migration
- `services/api/migrations/052_detection_rules_phase2.sql`: additive, idempotent
  (`ADD COLUMN IF NOT EXISTS`), partial index on `(status, compile_status) WHERE
  status='active'` for fusion startup reconciliation.
- `services/api/app/models/detection_rule.py`: added `compiled_spec` (JSONB null),
  `compile_status` (String(20) default 'pending'), `compile_error` (Text null).
  `version` column untouched.

## Section 2 — Transpiler `services/api/app/services/detections/sigma_match_when.py`
- `CompileResult = NamedTuple(status, match_when, error)`; statuses:
  `compiled` | `unsupported_stateful` | `error`.
- Uses `yaml.safe_load` (never `yaml.load`). No Sigma library.
- Field map (Sigma key → flat field, per real corpus `raw_data`):
  CommandLine/process.command_line → `command_line`
  Image/image_path/process.path → `file_path`
  SourceImage/process.parent_image → `source_image`
  User/user.name → `user`
  RegistryKey/registry.key → `registry_path`
  DestinationIp/destination.ip → `dst_ip`
  DestinationPort/destination.port → `dst_port`
  SourceIp/source.ip → `src_ip`
  EventCategory/event.category → `event_type`
  image_basename → `image_basename`
  Unmapped keys → skipped (soft-fail).
- Value shapes → flat `field_op`:
  list[str] → `{field}_in`
  wildcard string (`*`) → `{field}_contains`
  plain string → `{field}` (eq)
- selection combine: `all of selection*` / single `selection` → merge top-level (AND);
  `any of selection*` → emit `any_of: [ ...flats ...]` (real Sigma OR).
- filter → supported negation keys only:
  list → `{field}_not_in`
  wildcard string → `{field}_not_contains_any` (list operand)
  plain string → `{field}_not_startswith`
  unmapped field inside filter → `unsupported_stateful`.
- Stateful → `unsupported_stateful` (no broadcast): presence of `windows:`,
  `timeframe:`, `detection_actions`, or `count(`.
- Parse failure → `error`.

## Section 3 — Compile-on-save + Redis broadcast (API)
- New `services/api/app/services/detections/compiler.py`: async `compile_rule(...)`
  that (a) runs `compile_sigma_to_match_when`, (b) writes `compiled_spec`/
  `compile_status`/`compile_error`/increments `version`, (c) publishes to
  Redis channel `rules:reload`. Fail-soft (log+warn, never rollback DB).
- Hook into `detection_rules.py` (create_rule / update_rule) and
  `detection_compat.py` (create_rule_compat / update_rule_compat): after commit,
  in the `rule_language in ('sigma','yaml')` scope.
- Broadcast action logic: status→active+compiled=ENABLE; status→inactive=DISABLE
  (must broadcast so fusion removes the rule); active+body-changed=UPSERT.
- Payload `event_type: "RULE_STATE_CHANGED"`, `rule_id`, `action`, `version`,
  `compiled_rule: {id, name, severity, match_when}`; `rule_id` == inner `id`.
- `native_ruleset.py` seed: compile native rows where `compiled_spec IS NULL`
  during boot sync; uncompilable → `unsupported_stateful` with per-file error
  isolation. det-NNN rows authored only with `selection` sync into fusion memory.

## Section 4 — Fusion hot-reload
- `_rules_map: Dict[str, dict]` with Copy-on-Write atomic swap in
  `DetectionEngine`: build `new_map=dict(self._rules_map)`, pop/insert `rule_id`,
  `self._rules_map=new_map`. `evaluate()` stays pure/sync, zero locks, zero I/O.
- `main.py` lifespan: background task subscribing `rules:reload` on fusion Redis
  (`aioredis.from_url(settings.redis_url, decode_responses=True)`); route to swap.
- Startup reconciliation: query Postgres `status='active' AND compile_status='compiled'`
  (served by the partial index) to populate `_rules_map`; fall back to
  `detection_ruleset.json` WITHOUT halting `worker.start()`. Reuse AlertSink
  fail-soft pool; if Postgres unreachable, Pub/Sub reconciles on connect.

## Section 5 — Guardrails
- Reuse existing `Deduplicator` (`aisoc:fusion:dedup:{sha256_fingerprint}`,
  `dedup_window_seconds`=300). No competing per-rule secondary key.
- Tests: A transpiler unit (flat-field output + matches() verdict), B stateful
  isolation (unsupported_stateful, zero broadcast), C end-to-end compile→broadcast,
  D regression (migration idempotent, corpus unaffected, suites pass).
- Redis parity: pub/sub is channel-global, NOT scoped to a logical DB. API
  `REDIS_URL` (db 0) vs fusion `redis_url` (db 2) are DIFFERENT logical DBs —
  which is fine. Redis pub/sub broadcasts on a channel to every subscriber
  regardless of the logical DB the connection used. Only the host:port and the
  channel name (`rules:reload`) must match.
  Guardrail [A-3]: if host/port/channel diverge (not current state), publish on
  the channel fusion subscribes on, or add a shared channel knob for both services.

## Redis pub/sub parity (verified)
- API: `services/api/app/core/scheduler_lock.py` `_get_redis_client` →
  `from_url(str(settings.REDIS_URL), decode_responses=True)`,
  `settings.REDIS_URL = "redis://localhost:6379/0"`.
- Fusion: `aioredis.from_url(settings.redis_url, decode_responses=False)`,
  `settings.redis_url = "redis://localhost:6379/2"` (alias REDIS_URL).
- Same host/port, DIFFERENT logical DB — fine for pub/sub, which is channel-global.
  Publish on channel `rules:reload`; only host:port and the channel name must match.
