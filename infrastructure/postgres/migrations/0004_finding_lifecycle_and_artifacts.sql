-- ==============================================================================
-- Security Lab: Phase 10 Database Hardening, Finding Lifecycle & Artifacts Migration
-- Adds test_definitions, reports, artifacts, identity_profiles, credentials tables,
-- evidence immutability triggers, finding lifecycle columns, and relational indexes.
-- ==============================================================================

-- 1. Test Definitions Table (Stores declarative test suites & OpenAPI schemas)
CREATE TABLE IF NOT EXISTS test_definitions (
    id VARCHAR(100) PRIMARY KEY,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    version VARCHAR(50) NOT NULL DEFAULT '1.0.0',
    category VARCHAR(50) NOT NULL DEFAULT 'http_security',
    description TEXT,
    content_yaml TEXT NOT NULL,
    parsed_content JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_test_definitions_project_id ON test_definitions(project_id);
CREATE INDEX IF NOT EXISTS idx_test_definitions_category ON test_definitions(category);

CREATE OR REPLACE TRIGGER trg_test_definitions_updated_at
BEFORE UPDATE ON test_definitions
FOR EACH ROW EXECUTE FUNCTION update_timestamp();

-- 2. Reports Table (Stores generated JUnit XML, SARIF, and HTML executive reports)
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_run_id UUID NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
    format VARCHAR(30) NOT NULL,
    filename VARCHAR(255) NOT NULL,
    content_type VARCHAR(100) NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reports_test_run_id ON reports(test_run_id);
CREATE INDEX IF NOT EXISTS idx_reports_format ON reports(format);

-- 3. Artifacts Table (Stores logs, scanner dumps, PCAPs, and raw files with SHA-256 hash)
CREATE TABLE IF NOT EXISTS artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_run_id UUID NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
    execution_id UUID REFERENCES test_executions(id) ON DELETE SET NULL,
    name VARCHAR(200) NOT NULL,
    type VARCHAR(50) NOT NULL,
    mime_type VARCHAR(100) NOT NULL DEFAULT 'application/octet-stream',
    size_bytes INTEGER NOT NULL DEFAULT 0,
    sha256 VARCHAR(64) NOT NULL,
    storage_path TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_artifacts_test_run_id ON artifacts(test_run_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_execution_id ON artifacts(execution_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_sha256 ON artifacts(sha256);
CREATE INDEX IF NOT EXISTS idx_artifacts_type ON artifacts(type);

-- 4. Identity Profiles Table (Stores test personas for BOLA/IDOR/RBAC testing)
CREATE TABLE IF NOT EXISTS identity_profiles (
    id VARCHAR(100) PRIMARY KEY,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    is_guest BOOLEAN NOT NULL DEFAULT FALSE,
    headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_identity_profiles_project_id ON identity_profiles(project_id);
CREATE INDEX IF NOT EXISTS idx_identity_profiles_role ON identity_profiles(role);

CREATE OR REPLACE TRIGGER trg_identity_profiles_updated_at
BEFORE UPDATE ON identity_profiles
FOR EACH ROW EXECUTE FUNCTION update_timestamp();

-- 5. Credentials Table (Stores encrypted test credentials with AES-256-GCM metadata)
CREATE TABLE IF NOT EXISTS credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    type VARCHAR(50) NOT NULL,
    encrypted_value TEXT NOT NULL,
    iv VARCHAR(64) NOT NULL,
    auth_tag VARCHAR(64) NOT NULL,
    key_id VARCHAR(50) NOT NULL DEFAULT 'default',
    description TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_project_credential_name UNIQUE (project_id, name)
);

CREATE INDEX IF NOT EXISTS idx_credentials_project_id ON credentials(project_id);
CREATE INDEX IF NOT EXISTS idx_credentials_type ON credentials(type);

CREATE OR REPLACE TRIGGER trg_credentials_updated_at
BEFORE UPDATE ON credentials
FOR EACH ROW EXECUTE FUNCTION update_timestamp();

-- 6. Finding Lifecycle & Occurrence Tracking Enhancements
ALTER TABLE findings
ADD COLUMN IF NOT EXISTS occurrence_count INTEGER NOT NULL DEFAULT 1,
ADD COLUMN IF NOT EXISTS fixed_in_run_id UUID REFERENCES test_runs(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_fixed_in_run_id ON findings(fixed_in_run_id);
CREATE INDEX IF NOT EXISTS idx_findings_target_fingerprint ON findings(target_id, fingerprint);

-- 7. Forensic Evidence Immutability Enforcement (Rule 13)
-- Strict database-level trigger aborts any attempted UPDATE or DELETE on evidence_records
CREATE OR REPLACE FUNCTION prevent_evidence_tamper()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'EVIDENCE_TAMPER_PROTECTION: Evidence records are immutable and append-only. UPDATE and DELETE operations are forbidden.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_evidence_immutable ON evidence_records;
CREATE TRIGGER trg_evidence_immutable
BEFORE UPDATE OR DELETE ON evidence_records
FOR EACH ROW
EXECUTE FUNCTION prevent_evidence_tamper();
