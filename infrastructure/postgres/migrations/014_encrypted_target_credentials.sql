-- ==============================================================================
-- Security Lab: Encrypted Target Credentials & Secrets Vault Integration (014)
-- Adds encrypted_auth_data JSONB for AES-256-GCM envelope encryption at rest.
-- ==============================================================================

-- 1. Add encrypted_auth_data column to targets table
ALTER TABLE targets
  ADD COLUMN IF NOT EXISTS encrypted_auth_data JSONB;

-- 2. Index for filtering targets with encrypted credentials
CREATE INDEX IF NOT EXISTS idx_targets_encrypted_auth
  ON targets USING gin (encrypted_auth_data)
  WHERE encrypted_auth_data IS NOT NULL;

-- 3. Refresh compatibility view target_profiles
CREATE OR REPLACE VIEW target_profiles AS SELECT * FROM targets;
