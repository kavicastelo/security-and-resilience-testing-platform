-- ==============================================================================
-- Security Lab: Phase 16.9 Agent Security Audit Events Migration (0010)
-- Adds agent_audit_events table with composite indexes and immutability triggers
-- ==============================================================================

-- 1. Create agent_audit_events table
CREATE TABLE IF NOT EXISTS agent_audit_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
  event_type VARCHAR(50) NOT NULL,
  actor_type VARCHAR(30) NOT NULL,
  actor_id VARCHAR(100) NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  ip_address VARCHAR(45),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Create composite and single-column indexes for fast querying and filtering
CREATE INDEX IF NOT EXISTS idx_agent_audit_events_tenant_created ON agent_audit_events(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_audit_events_agent_created ON agent_audit_events(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_audit_events_event_type ON agent_audit_events(event_type);

-- 3. Strict immutability enforcement: audit events are append-only (Rule 20)
CREATE OR REPLACE FUNCTION prevent_agent_audit_event_tamper()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'AUDIT_LOG_IMMUTABLE: Audit events are append-only. UPDATE and DELETE operations are forbidden.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_agent_audit_events_immutable ON agent_audit_events;
CREATE TRIGGER trg_agent_audit_events_immutable
BEFORE UPDATE OR DELETE ON agent_audit_events
FOR EACH ROW
EXECUTE FUNCTION prevent_agent_audit_event_tamper();
