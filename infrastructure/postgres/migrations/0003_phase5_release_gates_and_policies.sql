-- ==============================================================================
-- Security Lab: Phase 5 Release Gates, Policies & Enterprise Reporting Migration
-- Adds policies and releases tables for automated CI/CD gating
-- ==============================================================================

-- 1. Policies Table
CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    rules JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policies_name ON policies(name);

CREATE OR REPLACE TRIGGER trg_policies_updated_at
BEFORE UPDATE ON policies
FOR EACH ROW EXECUTE FUNCTION update_timestamp();

-- 2. Releases Table
CREATE TABLE IF NOT EXISTS releases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    version VARCHAR(100) NOT NULL,
    git_commit VARCHAR(100),
    git_branch VARCHAR(100),
    test_run_id UUID REFERENCES test_runs(id) ON DELETE SET NULL,
    policy_id UUID REFERENCES policies(id) ON DELETE SET NULL,
    decision VARCHAR(30) NOT NULL DEFAULT 'warning',
    reason TEXT,
    evaluated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_releases_project_id ON releases(project_id);
CREATE INDEX IF NOT EXISTS idx_releases_test_run_id ON releases(test_run_id);
CREATE INDEX IF NOT EXISTS idx_releases_decision ON releases(decision);

CREATE OR REPLACE TRIGGER trg_releases_updated_at
BEFORE UPDATE ON releases
FOR EACH ROW EXECUTE FUNCTION update_timestamp();
