-- 046_detection_rules_schema_drift_fix.sql
--
-- Bring the `detection_rules` table in line with the ORM model defined in
-- services/api/app/models/detection_rule.py.
--
-- In development, SQLAlchemy's `create_all` runs first. However, if the database
-- was initialized under an older schema, existing tables are not modified by
-- `create_all`. This migration closes the gap by adding any missing columns
-- idempotently.

BEGIN;

-- 1. Rename legacy columns if they exist
DO $$
BEGIN
    -- Rename rule_type to rule_language if rule_type exists and rule_language does not
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'detection_rules' AND column_name = 'rule_type'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'detection_rules' AND column_name = 'rule_language'
    ) THEN
        ALTER TABLE detection_rules RENAME COLUMN rule_type TO rule_language;
    END IF;

    -- Rename rule_content to rule_body if rule_content exists and rule_body does not
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'detection_rules' AND column_name = 'rule_content'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'detection_rules' AND column_name = 'rule_body'
    ) THEN
        ALTER TABLE detection_rules RENAME COLUMN rule_content TO rule_body;
    END IF;
END $$;

-- 2. Add columns if they do not exist
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS rule_language      VARCHAR(30) NOT NULL DEFAULT 'sigma';
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS rule_body          TEXT NOT NULL DEFAULT '';
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS category           VARCHAR(100) NOT NULL DEFAULT 'uncategorized';
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS status             VARCHAR(20) NOT NULL DEFAULT 'testing';
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS confidence         INTEGER NOT NULL DEFAULT 50;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS fp_rate            DOUBLE PRECISION NOT NULL DEFAULT 0.0;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS suppression_config JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS threshold_config   JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS total_hits         INTEGER NOT NULL DEFAULT 0;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS last_triggered     TIMESTAMPTZ;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS is_builtin         BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS version            INTEGER NOT NULL DEFAULT 1;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS created_by_id       UUID;

-- 3. Create indices for newly introduced columns
CREATE INDEX IF NOT EXISTS idx_detection_rules_language ON detection_rules(rule_language);
CREATE INDEX IF NOT EXISTS idx_detection_rules_status ON detection_rules(status);
CREATE INDEX IF NOT EXISTS idx_detection_rules_is_builtin ON detection_rules(is_builtin);

COMMIT;
