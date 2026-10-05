-- ==============================================================================
-- Security Lab: Phase 4 Metrics & Resilience Migration (0002_phase4_metrics_and_resilience.sql)
-- Adds metrics table for quantitative latency SLAs, throughput, and soak metrics
-- ==============================================================================

CREATE TABLE IF NOT EXISTS metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_run_id UUID NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
    execution_id UUID NOT NULL REFERENCES test_executions(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    value DOUBLE PRECISION NOT NULL,
    unit VARCHAR(20) NOT NULL DEFAULT 'ms',
    tags JSONB NOT NULL DEFAULT '{}'::jsonb,
    threshold JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_metrics_test_run_id ON metrics(test_run_id);
CREATE INDEX IF NOT EXISTS idx_metrics_execution_id ON metrics(execution_id);
CREATE INDEX IF NOT EXISTS idx_metrics_name ON metrics(name);
