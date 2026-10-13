-- ==============================================================================
-- Security Lab: Enterprise Private Agent Fleet Management & Attestation (015)
-- Adds asymmetric public key attestation, fingerprint, auth_mode, and enrollment_token
-- ==============================================================================

-- 1. Alter agents table: add asymmetric attestation columns
ALTER TABLE agents
  ADD COLUMN IF NOT EXISTS public_key TEXT,
  ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(64),
  ADD COLUMN IF NOT EXISTS enrollment_token VARCHAR(64),
  ADD COLUMN IF NOT EXISTS auth_mode VARCHAR(20) NOT NULL DEFAULT 'token';

-- 2. Indexes for fingerprint, enrollment token, and auth mode lookups
CREATE INDEX IF NOT EXISTS idx_agents_fingerprint ON agents(fingerprint);
CREATE INDEX IF NOT EXISTS idx_agents_enrollment_token ON agents(enrollment_token);
CREATE INDEX IF NOT EXISTS idx_agents_auth_mode ON agents(auth_mode);
