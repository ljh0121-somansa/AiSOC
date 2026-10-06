-- 050_detection_rules_builtin_platform.sql
--
-- Seed the two curated AiSOC built-in platform detection rules (Authentication
-- Brute-Force Burst + Burst of File-Extension Renames to Ransom Markers) into
-- the `detection_rules` table so they surface on the Rules tab
-- (`GET /api/v1/detection/rules` -> `list_rules_compat`).
--
-- The rules live verbatim in the on-disk corpus:
--   services/api/detections/identity/brute-force-login.yaml       (id: det-identity-001)
--   services/api/detections/endpoint/win-ransomware-ext-rename-burst.yaml  (id: det-endpoint-123)
-- This migration is the platform-wide seed path (see the corpus files for the
-- same text). It mirrors the shape the ORM model expects:
--   services/api/app/models/detection_rule.py
-- and what `list_rules_compat` renders:
--   services/api/app/api/v1/endpoints/detection_compat.py (`_to_frontend`).
--
-- Two schema blockers have to be resolved before a NULL-`tenant_id` built-in
-- row can exist AND be visible to a normal tenant-scoped request:
--
--   Blocker A: 001_init.sql created `detection_rules.tenant_id` as NOT NULL
--               with an FK to tenants(id) (auto-name detection_rules_tenant_id_fkey).
--               The ORM model allows NULL (platform-wide rule). The FK + NOT NULL
--               are dropped here; both statements are no-ops where the create_all
--               lineage already produced a nullable, constraint-free column.
--
--   Blocker B: 002_rls.sql gave `detection_rules` a policy
--               `USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)`.
--               During an app request `app.current_tenant_id` is always a real
--               UUID, so the policy collapses to `tenant_id='<user>'` and the
--               NULL-tenant rows are filtered out. The relaxed policy below adds
--               visibility for NULL-`tenant_id` rows only; tenant-owned-row
--               isolation (`tenant_id = current_tenant_id()`) is unchanged.

BEGIN;

-- ── Blocker A — drop FK + NOT NULL on tenant_id (idempotent) ─────────────────
ALTER TABLE detection_rules ALTER COLUMN tenant_id DROP NOT NULL;
DO $$
DECLARE
    constraint_name TEXT;
BEGIN
    SELECT conname INTO constraint_name
    FROM pg_constraint
    WHERE conrelid = 'detection_rules'::regclass AND contype = 'f'
      AND conname = 'detection_rules_tenant_id_fkey';
    IF constraint_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE detection_rules DROP CONSTRAINT %I', constraint_name);
    END IF;
END $$;

-- ── Blocker B — relax detection_rules RLS so platform rules are visible ──────
DROP POLICY IF EXISTS detection_rules_tenant ON detection_rules;
CREATE POLICY detection_rules_tenant ON detection_rules
    USING (
        tenant_id = current_tenant_id()
        OR current_tenant_id() IS NULL
        OR tenant_id IS NULL
    );

-- ── Seed built-in rule #1 — Authentication Brute-Force Burst (id: det-identity-001) ──
-- rule_language: 'sigma' to render the frontend LANG_LABEL badge
--   (apps/web .../DetectionsView.tsx knows sigma/yara/kql/eql/lucene/regex).
-- status: 'active' (the column default is 'testing'); status=='active' ⇒ enabled:true
--   per _to_frontend in detection_compat.py.
INSERT INTO detection_rules
    (tenant_id, name, description, rule_language, rule_body,
     category, status, severity, confidence, mitre_tactics, mitre_techniques,
     tags, is_builtin, provenance, version, created_at, updated_at)
SELECT
    NULL,
    'Authentication Brute-Force Burst',
    'Detects high-frequency failed authentication attempts against a single account, which is a classic indicator of credential-stuffing or password-spraying attempts. Threshold is intentionally conservative to reduce noise.',
    'sigma',
    $$id: det-identity-001
name: Authentication Brute-Force Burst
description: Detects high-frequency failed authentication attempts against a single account, which is
  a classic indicator of credential-stuffing or password-spraying attempts. Threshold is intentionally
  conservative to reduce noise.
version: 1.0.0
severity: high
tags:
- mitre.attack.t1110.001
- tlp.white
category: identity
log_source:
  product: okta
  service: system-log
detection:
  condition: |
    event_type == "user.session.start"
    AND outcome == "FAILURE"
    AND fail_count > 20
    AND time_window_minutes < 10
false_positives:
- Misconfigured client looping forever (rare; tag known cases)
playbook: tpl-account-compromise
enabled: true
author: AiSOC
created: '2026-05-03'
modified: '2026-05-03'$$,
    'identity', 'active', 'high', 80,
    '["credential-access"]', '["T1110.001"]',
    '["mitre.attack.t1110.001","tlp.white"]',
    TRUE, '{}'::jsonb, 1, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1 FROM detection_rules WHERE rule_language='sigma' AND name='Authentication Brute-Force Burst'
);

-- ── Seed built-in rule #2 — Burst Of File Extension Renames To Common Ransom Markers (id: det-endpoint-123) ──
INSERT INTO detection_rules
    (tenant_id, name, description, rule_language, rule_body,
     category, status, severity, confidence, mitre_tactics, mitre_techniques,
     tags, is_builtin, provenance, version, created_at, updated_at)
SELECT
    NULL,
    'Burst Of File Extension Renames To Common Ransom Markers',
    'AiSOC v1 curated detection. Triggers on the endpoint signal described by ''Burst Of File Extension Renames To Common Ransom Markers''.',
    'sigma',
    $$id: det-endpoint-123
name: Burst Of File Extension Renames To Common Ransom Markers
description: AiSOC v1 curated detection. Triggers on the endpoint signal described by 'Burst Of File Extension
  Renames To Common Ransom Markers'. Watch the 1 documented false-positive case before tuning.
version: 1.0.0
severity: critical
tags:
- mitre.attack.t1486
- tlp.white
category: endpoint
log_source:
  product: windows
  service: sysmon
detection:
  condition: |
    event_id == 11
    AND target_filename ENDSWITH_ANY [".locked", ".enc", ".crypt", ".lockbit", ".conti", ".royal"]
false_positives:
- Authorised red-team or penetration test
playbook: tpl-impact
enabled: true
author: AiSOC
created: '2026-05-03'
modified: '2026-05-03'$$,
    'endpoint', 'active', 'critical', 85,
    '["impact"]', '["T1486"]',
    '["mitre.attack.t1486","tlp.white"]',
    TRUE, '{}'::jsonb, 1, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1 FROM detection_rules WHERE rule_language='sigma' AND name='Burst Of File Extension Renames To Common Ransom Markers'
);

COMMIT;
