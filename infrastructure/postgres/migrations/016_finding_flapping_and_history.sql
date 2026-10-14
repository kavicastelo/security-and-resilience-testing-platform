-- ==============================================================================
-- Security Lab: Phase 16 Finding Flapping, History & Retesting (016)
-- Adds flapping_score, is_flapping, and triage_history JSONB to findings
-- ==============================================================================

-- 1. Alter findings table: add flapping metrics and triage history
ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS flapping_score REAL DEFAULT 0.0,
  ADD COLUMN IF NOT EXISTS is_flapping BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS triage_history JSONB NOT NULL DEFAULT '[]'::jsonb;

-- 2. Indexes for fast filtering on flapping findings and target/fingerprint lookups
CREATE INDEX IF NOT EXISTS idx_findings_is_flapping ON findings(is_flapping);
CREATE INDEX IF NOT EXISTS idx_findings_target_fingerprint ON findings(target_id, fingerprint);
