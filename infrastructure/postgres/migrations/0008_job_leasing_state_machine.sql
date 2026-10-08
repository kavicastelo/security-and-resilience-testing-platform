-- ==============================================================================
-- Security Lab: Phase 16.3 Job Leasing, State Machine & Watchdog Reaper Migration (0008)
-- Adds lease tracking, attempt counting, and reaper indexes to agent_jobs
-- ==============================================================================

-- 1. Alter agent_jobs table: add leasing and attempt tracking columns
ALTER TABLE agent_jobs
ADD COLUMN IF NOT EXISTS lease_id UUID;

ALTER TABLE agent_jobs
ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;

ALTER TABLE agent_jobs
ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0;

ALTER TABLE agent_jobs
ADD COLUMN IF NOT EXISTS max_attempts INTEGER NOT NULL DEFAULT 3;

-- 2. Update default status for agent_jobs to 'queued'
ALTER TABLE agent_jobs
ALTER COLUMN status SET DEFAULT 'queued';

-- Backfill existing 'pending' jobs to 'queued'
UPDATE agent_jobs
SET status = 'queued'
WHERE status = 'pending';

-- 3. Create indexes for atomic claiming, reaper, and lease lookup
CREATE INDEX IF NOT EXISTS idx_agent_jobs_reaper ON agent_jobs(status, lease_expires_at);
CREATE INDEX IF NOT EXISTS idx_agent_jobs_lease_id ON agent_jobs(lease_id);
CREATE INDEX IF NOT EXISTS idx_agent_jobs_claim ON agent_jobs(tenant_id, status, attempts);
