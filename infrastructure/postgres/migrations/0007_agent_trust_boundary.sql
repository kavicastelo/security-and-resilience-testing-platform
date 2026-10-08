-- ==============================================================================
-- Security Lab: Phase 16.1 Agent Identity & Trust Boundary Migration (0007)
-- Adds tenant_enrollment_keys table, agent token expiration, and revocation metadata
-- ==============================================================================

-- 1. Create tenant_enrollment_keys table
CREATE TABLE IF NOT EXISTS tenant_enrollment_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name VARCHAR(100) NOT NULL,
  key_hash VARCHAR(64) NOT NULL UNIQUE,
  key_prefix VARCHAR(32) NOT NULL,
  max_uses INTEGER,
  uses_count INTEGER NOT NULL DEFAULT 0,
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tek_tenant_id ON tenant_enrollment_keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tek_key_hash ON tenant_enrollment_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_tek_expires_at ON tenant_enrollment_keys(expires_at);

-- 2. Alter agents table: add expiration and revocation tracking
ALTER TABLE agents
ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

ALTER TABLE agents
ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

ALTER TABLE agents
ADD COLUMN IF NOT EXISTS revocation_reason VARCHAR(100);

-- Backfill existing agents with a 90-day expiration window if not already set
UPDATE agents
SET expires_at = NOW() + INTERVAL '90 days'
WHERE expires_at IS NULL;

-- 3. Create indexes on agents expiration and revocation
CREATE INDEX IF NOT EXISTS idx_agents_expires_at ON agents(expires_at);
CREATE INDEX IF NOT EXISTS idx_agents_revoked_at ON agents(revoked_at);
