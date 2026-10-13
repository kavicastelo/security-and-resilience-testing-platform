-- ==============================================================================
-- Security Lab: Phase 01 Core RBAC & Multi-User Workspaces Migration (012)
-- Adds workspaces, users, workspace_memberships, api_keys, audit_events
-- Links projects to workspaces with foreign key constraints
-- ==============================================================================

-- 1. Create workspaces table
CREATE TABLE IF NOT EXISTS workspaces (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(100) NOT NULL,
  slug VARCHAR(100) NOT NULL UNIQUE,
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default workspace for local single-tenant mode / backwards compatibility
INSERT INTO workspaces (id, name, slug, description)
VALUES ('00000000-0000-0000-0000-000000000000', 'Default Workspace', 'default-workspace', 'System default workspace')
ON CONFLICT (id) DO NOTHING;

-- 2. Create users table
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) NOT NULL UNIQUE,
  name VARCHAR(100) NOT NULL,
  password_hash VARCHAR(255),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default admin user
INSERT INTO users (id, email, name, password_hash)
VALUES ('00000000-0000-0000-0000-000000000001', 'admin@security-lab.local', 'Default Administrator', NULL)
ON CONFLICT (id) DO NOTHING;

-- 3. Create workspace_memberships table
CREATE TABLE IF NOT EXISTS workspace_memberships (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role VARCHAR(30) NOT NULL DEFAULT 'ENGINEER',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT unique_workspace_user UNIQUE (workspace_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_workspace_memberships_workspace_id ON workspace_memberships(workspace_id);
CREATE INDEX IF NOT EXISTS idx_workspace_memberships_user_id ON workspace_memberships(user_id);

-- Assign default admin to default workspace with ADMIN role
INSERT INTO workspace_memberships (workspace_id, user_id, role)
VALUES ('00000000-0000-0000-0000-000000000000', '00000000-0000-0000-0000-000000000001', 'ADMIN')
ON CONFLICT ON CONSTRAINT unique_workspace_user DO NOTHING;

-- 4. Create api_keys table
CREATE TABLE IF NOT EXISTS api_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(100) NOT NULL,
  key_hash VARCHAR(64) NOT NULL UNIQUE,
  key_prefix VARCHAR(16) NOT NULL,
  role VARCHAR(30) NOT NULL DEFAULT 'ENGINEER',
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_workspace_id ON api_keys(workspace_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);

-- 5. Create general audit_events table
CREATE TABLE IF NOT EXISTS audit_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
  actor_id VARCHAR(100) NOT NULL,
  event_type VARCHAR(100) NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  ip_address VARCHAR(45),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_events_workspace_id ON audit_events(workspace_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor_id ON audit_events(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events(event_type);

-- Also add workspace_id to agent_audit_events if table exists
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'agent_audit_events') THEN
    ALTER TABLE agent_audit_events ADD COLUMN IF NOT EXISTS workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE;
  END IF;
END $$;

-- 6. Add nullable workspace_id to projects, backfill default workspace, and enforce NOT NULL
ALTER TABLE projects
ADD COLUMN IF NOT EXISTS workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE;

UPDATE projects
SET workspace_id = '00000000-0000-0000-0000-000000000000'
WHERE workspace_id IS NULL;

ALTER TABLE projects
ALTER COLUMN workspace_id SET DEFAULT '00000000-0000-0000-0000-000000000000';

ALTER TABLE projects
ALTER COLUMN workspace_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_projects_workspace_id ON projects(workspace_id);
CREATE INDEX IF NOT EXISTS idx_projects_workspace_composite ON projects(workspace_id, id);
