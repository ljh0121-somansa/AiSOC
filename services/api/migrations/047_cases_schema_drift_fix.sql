-- 047_cases_schema_drift_fix.sql
--
-- Bring the `cases` table in line with the ORM model defined in
-- services/api/app/models/case.py.
--
-- The model defines metadata columns `resolution` and `lessons_learned`
-- which are currently missing in the database table `cases` schema, resulting
-- in column "resolution" of relation "cases" does not exist when seeding or using ORM models.
--
-- This migration is fully idempotent (all ADD COLUMN clauses use
-- `IF NOT EXISTS`) so it's safe to re-run.

BEGIN;

ALTER TABLE cases ADD COLUMN IF NOT EXISTS resolution TEXT;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS lessons_learned TEXT;

COMMIT;
