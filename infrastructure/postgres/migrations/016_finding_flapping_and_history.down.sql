-- ==============================================================================
-- Security Lab: Phase 16 Rollback (016 Down)
-- Removes flapping_score, is_flapping, and triage_history JSONB from findings
-- ==============================================================================

DROP INDEX IF EXISTS idx_findings_target_fingerprint;
DROP INDEX IF EXISTS idx_findings_is_flapping;

ALTER TABLE findings
  DROP COLUMN IF EXISTS triage_history,
  DROP COLUMN IF EXISTS is_flapping,
  DROP COLUMN IF EXISTS flapping_score;
