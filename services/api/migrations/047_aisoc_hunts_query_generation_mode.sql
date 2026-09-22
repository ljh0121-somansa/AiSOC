-- Migration 047: Add query_generation_mode and warnings to aisoc_hunts (T3.4)
-- Adds fields to track whether threat hunting queries were generated via AI
-- (Tier 1 / Tier 2) or fell back to deterministic templates (Tier 3) due to offline/airgap mode.

ALTER TABLE aisoc_hunts 
    ADD COLUMN IF NOT EXISTS query_generation_mode TEXT DEFAULT 'ai' 
    CHECK (query_generation_mode IN ('ai', 'fallback'));

ALTER TABLE aisoc_hunts 
    ADD COLUMN IF NOT EXISTS warnings TEXT DEFAULT NULL;
