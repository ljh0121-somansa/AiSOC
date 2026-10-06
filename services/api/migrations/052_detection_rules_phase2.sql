-- 052_detection_rules_phase2.sql
--
-- Live detection hot-reload (Phase 2). Bridges the PostgreSQL ``detection_rules``
-- table with the fusion live-detection pipeline (services/fusion). The API compiles
-- a rule's Sigma ``selection``/``filter`` blocks into the flat ``match_when`` DSL the
-- fusion matcher reads (see app.services.detections.sigma_match_when) and caches the
-- result here so fusion never has to parse a rule body:
--
--   * compiled_spec  (JSONB)     — the compiled ``match_when`` for a ``compiled`` row,
--                                  else NULL.
--   * compile_status (VARCHAR 20) — 'pending' | 'compiled' | 'unsupported_stateful' | 'error'.
--   * compile_error  (TEXT)      — human-readable reason a row is not compilable.
--   * version (INTEGER)          — bumped on every body/status change so fusion can
--                                  detect a rule it has not yet seen. See the partial
--                                  index below.
--
-- The partial key index on (status, compile_status) filtered to status='active'
-- serves fusion's startup reconciliation query (which asks for exactly the rows it
-- should load) without touching the per-event hot path.
--
-- Fully additive and idempotent: every column uses ADD COLUMN IF NOT EXISTS and the
-- default on compile_status matches the model so re-running an already-applied
-- migration is a safe no-op. Column defaults mirror app.models.detection_rule so the
-- create_all dev lineage and this raw-SQL migration stay in sync.

BEGIN;

ALTER TABLE detection_rules
    ADD COLUMN IF NOT EXISTS compiled_spec JSONB;

ALTER TABLE detection_rules
    ADD COLUMN IF NOT EXISTS compile_status VARCHAR(20) NOT NULL DEFAULT 'pending';

ALTER TABLE detection_rules
    ADD COLUMN IF NOT EXISTS compile_error TEXT;

ALTER TABLE detection_rules
    ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 1;

CREATE INDEX IF NOT EXISTS idx_detection_rules_runtime_sync
    ON detection_rules (status, compile_status)
    WHERE status = 'active';

COMMIT;
