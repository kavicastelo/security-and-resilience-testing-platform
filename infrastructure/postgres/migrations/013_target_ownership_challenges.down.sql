-- ==============================================================================
-- Rollback Migration: 013_target_ownership_challenges.down.sql
-- ==============================================================================

DROP VIEW IF EXISTS target_profiles;
DROP INDEX IF EXISTS idx_targets_verification_status;

ALTER TABLE targets
  DROP COLUMN IF EXISTS verification_method,
  DROP COLUMN IF EXISTS verified_at,
  DROP COLUMN IF EXISTS verification_status,
  DROP COLUMN IF EXISTS verification_token;
