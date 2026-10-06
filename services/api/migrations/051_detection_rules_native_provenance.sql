-- 051_detection_rules_native_provenance.sql
--
-- Extend `detection_rules` so native (repo-built YAML) rules can be synced in
-- from `detections/<category>/*.yaml` and later identified as such in the
-- console. These columns are populated by `app.services.detections.native_ruleset`
-- (see `services/api/app/scripts/seed_native_detections.py` for the CLI entry).
--
-- What this migration does NOT do (by design): delete the two hardcoded
-- migration-050 built-in rows. That legacy cleanup happens in the native
-- sync step (Step 3) and is keyed on `name`, not `id` — the migration-050 rows
-- inserted a NULL `id` and rely on the auto uuid4 default, so their real `id`
-- is a random UUID. Deleting by `id::text IN ('det-…')` would be a silent no-op.
--
-- Column defaults mirror `app.models.detection_rule.DetectionRule` so the
-- `create_all` dev lineage and this raw-SQL migration stay consistent:
--   * rule_type DEFAULT 'custom' keeps every existing custom row correct.
--   * file_path is nullable (only native rows carry a path).
--
-- The index is idempotent and covers the (rule_type, is_builtin) filter the
-- Rules tab uses to split built-in vs authored rules.

BEGIN;

ALTER TABLE detection_rules
    ADD COLUMN IF NOT EXISTS rule_type VARCHAR(20) NOT NULL DEFAULT 'custom';

ALTER TABLE detection_rules
    ADD COLUMN IF NOT EXISTS file_path VARCHAR(512);

CREATE INDEX IF NOT EXISTS idx_detection_rules_type_builtin
    ON detection_rules (rule_type, is_builtin);

COMMIT;
