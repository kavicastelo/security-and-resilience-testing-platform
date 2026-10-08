-- ==============================================================================
-- Security Lab: Phase 16.8 Capability & Tag Routing Migration (0009)
-- Adds required_capabilities and required_tags to agent_jobs with GIN indexes
-- ==============================================================================

-- 1. Alter agent_jobs table: add required_capabilities and required_tags columns
ALTER TABLE agent_jobs
ADD COLUMN IF NOT EXISTS required_capabilities JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE agent_jobs
ADD COLUMN IF NOT EXISTS required_tags JSONB NOT NULL DEFAULT '[]'::jsonb;

-- 2. Create GIN indexes for JSONB containment operations (<@)
CREATE INDEX IF NOT EXISTS idx_agent_jobs_required_capabilities ON agent_jobs USING GIN (required_capabilities);
CREATE INDEX IF NOT EXISTS idx_agent_jobs_required_tags ON agent_jobs USING GIN (required_tags);
