-- ==============================================================================
-- Security Lab: Phase 11 Release Governance v2 Migration (0005)
-- Adds cryptographic evaluator hash and metadata audit storage to releases table
-- ==============================================================================

-- 1. Add evaluator_hash and metadata columns to releases table
ALTER TABLE releases
ADD COLUMN IF NOT EXISTS evaluator_hash VARCHAR(64),
ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

-- 2. Add required_profiles and waivers columns to policies table
ALTER TABLE policies
ADD COLUMN IF NOT EXISTS required_profiles JSONB NOT NULL DEFAULT '[]'::jsonb,
ADD COLUMN IF NOT EXISTS waivers JSONB NOT NULL DEFAULT '[]'::jsonb;

-- 3. Index for audit queries by evaluator hash
CREATE INDEX IF NOT EXISTS idx_releases_evaluator_hash ON releases(evaluator_hash);
