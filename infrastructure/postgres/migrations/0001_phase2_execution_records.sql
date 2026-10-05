-- ==============================================================================
-- Security Lab: Phase 2 Execution Records, Evidence & Findings Migration
-- Adds test_executions, evidence_records, and findings tables
-- ==============================================================================

-- 1. Test Executions Table
CREATE TABLE IF NOT EXISTS test_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_run_id UUID NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
    engine_id VARCHAR(100) NOT NULL,
    execution_class VARCHAR(50) NOT NULL DEFAULT 'class_a_native',
    status VARCHAR(30) NOT NULL DEFAULT 'pending',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_ms INTEGER,
    exit_code INTEGER,
    error_message TEXT,
    raw_result JSONB,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_test_executions_test_run_id ON test_executions(test_run_id);
CREATE INDEX IF NOT EXISTS idx_test_executions_status ON test_executions(status);
CREATE INDEX IF NOT EXISTS idx_test_executions_engine_id ON test_executions(engine_id);

CREATE OR REPLACE TRIGGER trg_test_executions_updated_at
BEFORE UPDATE ON test_executions
FOR EACH ROW EXECUTE FUNCTION update_timestamp();

-- 2. Evidence Records Table (Forensic, immutable snapshot)
CREATE TABLE IF NOT EXISTS evidence_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_run_id UUID NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
    execution_id UUID NOT NULL REFERENCES test_executions(id) ON DELETE CASCADE,
    request JSONB,
    response JSONB,
    expected JSONB,
    actual JSONB,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    environment VARCHAR(100) NOT NULL DEFAULT 'default',
    application_version VARCHAR(100),
    git_commit VARCHAR(100),
    immutable_hash VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_records_test_run_id ON evidence_records(test_run_id);
CREATE INDEX IF NOT EXISTS idx_evidence_records_execution_id ON evidence_records(execution_id);
CREATE INDEX IF NOT EXISTS idx_evidence_records_immutable_hash ON evidence_records(immutable_hash);

-- 3. Findings Table (Normalized Security Findings)
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint VARCHAR(128) NOT NULL,
    title VARCHAR(200) NOT NULL,
    category VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    confidence VARCHAR(20) NOT NULL DEFAULT 'firm',
    status VARCHAR(30) NOT NULL DEFAULT 'open',
    description TEXT NOT NULL,
    risk TEXT,
    recommendation TEXT,
    test_definition_id VARCHAR(100) NOT NULL,
    test_run_id UUID NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
    execution_id UUID NOT NULL REFERENCES test_executions(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    release_id UUID,
    evidence_id UUID REFERENCES evidence_records(id) ON DELETE SET NULL,
    first_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    fixed_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_findings_test_run_id ON findings(test_run_id);
CREATE INDEX IF NOT EXISTS idx_findings_target_id ON findings(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
