-- ==============================================================================
-- Security Lab: Target Ownership Verification & Anti-Abuse Challenges (013)
-- Adds verification tokens, challenge status, and ownership proof records.
-- ==============================================================================

-- 1. Add verification challenge columns to targets table
ALTER TABLE targets
  ADD COLUMN IF NOT EXISTS verification_token VARCHAR(64),
  ADD COLUMN IF NOT EXISTS verification_status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
  ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS verification_method VARCHAR(32);

-- 2. Create index for fast status querying and active scan gating
CREATE INDEX IF NOT EXISTS idx_targets_verification_status ON targets(verification_status);

-- 3. Automatically mark local/loopback developer targets as VERIFIED
UPDATE targets
SET verification_status = 'VERIFIED',
    verified_at = NOW(),
    verification_method = 'loopback'
WHERE (base_url LIKE '%localhost%' OR base_url LIKE '%127.0.0.1%')
  AND verification_status = 'PENDING';

-- 4. Create compatibility view target_profiles
CREATE OR REPLACE VIEW target_profiles AS SELECT * FROM targets;
