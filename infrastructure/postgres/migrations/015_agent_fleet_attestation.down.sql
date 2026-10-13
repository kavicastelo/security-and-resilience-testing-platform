-- ==============================================================================
-- Rollback Migration: 015_agent_fleet_attestation.down.sql
-- ==============================================================================

DROP INDEX IF EXISTS idx_agents_fingerprint;
DROP INDEX IF EXISTS idx_agents_enrollment_token;
DROP INDEX IF EXISTS idx_agents_auth_mode;

ALTER TABLE agents
  DROP COLUMN IF EXISTS public_key,
  DROP COLUMN IF EXISTS fingerprint,
  DROP COLUMN IF EXISTS enrollment_token,
  DROP COLUMN IF EXISTS auth_mode;
