-- ==============================================================================
-- Rollback Migration: 014_encrypted_target_credentials.down.sql
-- ==============================================================================

DROP VIEW IF EXISTS target_profiles;
DROP INDEX IF EXISTS idx_targets_encrypted_auth;

ALTER TABLE targets
  DROP COLUMN IF EXISTS encrypted_auth_data;

CREATE OR REPLACE VIEW target_profiles AS SELECT * FROM targets;
