-- ==============================================================================
-- Security Lab: Initial Database Schema Migration (0000_initial_schema.sql)
-- Defines core foundational entities: Project, Environment, Target, TestRun
-- ==============================================================================

-- Enable UUID generation extension if not available natively
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. Projects Table
CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Environments Table
CREATE TABLE IF NOT EXISTS environments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    type VARCHAR(30) NOT NULL DEFAULT 'development',
    variables JSONB NOT NULL DEFAULT '{}'::jsonb,
    headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_project_env_name UNIQUE (project_id, name)
);

CREATE INDEX IF NOT EXISTS idx_environments_project_id ON environments(project_id);

-- 3. Targets Table (Enforces explicit security boundaries)
CREATE TABLE IF NOT EXISTS targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    base_url TEXT NOT NULL,
    scope JSONB NOT NULL DEFAULT '{
        "allowedHosts": [],
        "allowedPorts": [80, 443],
        "excludedPaths": [],
        "testing": { "activeScanning": false, "loadTesting": false, "chaosTesting": false },
        "limits": { "maxRps": 100, "maxConcurrency": 20, "maxDuration": "10m" }
    }'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_project_target_name UNIQUE (project_id, name)
);

CREATE INDEX IF NOT EXISTS idx_targets_project_id ON targets(project_id);

-- 4. Test Runs Table
CREATE TABLE IF NOT EXISTS test_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
    environment_id UUID REFERENCES environments(id) ON DELETE SET NULL,
    profile_id VARCHAR(100),
    status VARCHAR(30) NOT NULL DEFAULT 'pending',
    triggered_by VARCHAR(30) NOT NULL DEFAULT 'manual',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    summary JSONB NOT NULL DEFAULT '{
        "totalTests": 0,
        "passedTests": 0,
        "failedTests": 0,
        "errorTests": 0,
        "findingsCount": { "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0 }
    }'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_test_runs_project_id ON test_runs(project_id);
CREATE INDEX IF NOT EXISTS idx_test_runs_target_id ON test_runs(target_id);
CREATE INDEX IF NOT EXISTS idx_test_runs_status ON test_runs(status);

-- 5. Helper trigger for updated_at maintenance
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trg_projects_updated_at BEFORE UPDATE ON projects FOR EACH ROW EXECUTE FUNCTION update_timestamp();
CREATE OR REPLACE TRIGGER trg_environments_updated_at BEFORE UPDATE ON environments FOR EACH ROW EXECUTE FUNCTION update_timestamp();
CREATE OR REPLACE TRIGGER trg_targets_updated_at BEFORE UPDATE ON targets FOR EACH ROW EXECUTE FUNCTION update_timestamp();
CREATE OR REPLACE TRIGGER trg_test_runs_updated_at BEFORE UPDATE ON test_runs FOR EACH ROW EXECUTE FUNCTION update_timestamp();
