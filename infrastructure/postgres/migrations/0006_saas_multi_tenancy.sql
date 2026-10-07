-- ==============================================================================
-- Security Lab: Phase 15 SaaS Multi-Tenancy & Distributed Agent Migration (0006)
-- Adds tenants, agents, agent_jobs, and tenant_id isolation across core tables
-- ==============================================================================

-- 1. Create tenants table
CREATE TABLE IF NOT EXISTS tenants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(100) NOT NULL,
  slug VARCHAR(100) NOT NULL UNIQUE,
  plan VARCHAR(50) NOT NULL DEFAULT 'enterprise',
  settings JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default tenant for local single-tenant mode / backwards compatibility
INSERT INTO tenants (id, name, slug, plan, settings)
VALUES ('00000000-0000-0000-0000-000000000000', 'Default Organization', 'default', 'enterprise', '{}'::jsonb)
ON CONFLICT (id) DO NOTHING;

-- 2. Create agents table
CREATE TABLE IF NOT EXISTS agents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name VARCHAR(100) NOT NULL,
  token_hash VARCHAR(64) NOT NULL,
  status VARCHAR(30) NOT NULL DEFAULT 'offline',
  capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
  tags JSONB NOT NULL DEFAULT '[]'::jsonb,
  system_info JSONB NOT NULL DEFAULT '{}'::jsonb,
  last_heartbeat_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agents_tenant_id ON agents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_agents_token_hash ON agents(token_hash);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);

-- 3. Create agent_jobs table
CREATE TABLE IF NOT EXISTS agent_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  test_run_id UUID NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
  status VARCHAR(30) NOT NULL DEFAULT 'pending',
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  result JSONB,
  error TEXT,
  dispatched_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_jobs_agent_id ON agent_jobs(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_jobs_tenant_id ON agent_jobs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_agent_jobs_test_run_id ON agent_jobs(test_run_id);
CREATE INDEX IF NOT EXISTS idx_agent_jobs_status ON agent_jobs(status);

-- 4. Add tenant_id to projects, targets, policies, findings
ALTER TABLE projects
ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE DEFAULT '00000000-0000-0000-0000-000000000000';

ALTER TABLE targets
ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE DEFAULT '00000000-0000-0000-0000-000000000000';

ALTER TABLE policies
ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE DEFAULT '00000000-0000-0000-0000-000000000000';

ALTER TABLE findings
ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE DEFAULT '00000000-0000-0000-0000-000000000000';

-- Backfill any null tenant_id records
UPDATE projects SET tenant_id = '00000000-0000-0000-0000-000000000000' WHERE tenant_id IS NULL;
UPDATE targets SET tenant_id = '00000000-0000-0000-0000-000000000000' WHERE tenant_id IS NULL;
UPDATE policies SET tenant_id = '00000000-0000-0000-0000-000000000000' WHERE tenant_id IS NULL;
UPDATE findings SET tenant_id = '00000000-0000-0000-0000-000000000000' WHERE tenant_id IS NULL;

-- 5. Add tenant composite and filtering indexes
CREATE INDEX IF NOT EXISTS idx_projects_tenant_id ON projects(tenant_id);
CREATE INDEX IF NOT EXISTS idx_targets_tenant_id ON targets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_policies_tenant_id ON policies(tenant_id);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_id ON findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_projects_tenant_composite ON projects(tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_targets_tenant_composite ON targets(tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_composite ON findings(tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_policies_tenant_composite ON policies(tenant_id, id);
