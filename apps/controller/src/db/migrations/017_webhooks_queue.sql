-- ==============================================================================
-- Security Lab: Phase 19 Webhooks Queue & Ecosystem Integrations (017)
-- Adds webhooks configuration and reliable webhook_deliveries queue
-- ==============================================================================

-- 1. Create webhooks table (endpoints and encrypted secret tokens)
CREATE TABLE IF NOT EXISTS webhooks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  description TEXT,
  secret TEXT NOT NULL, -- Encrypted at rest (AES-256-GCM envelope or raw secret)
  events JSONB NOT NULL DEFAULT '["*"]'::jsonb, -- e.g. ["finding.created", "test_run.completed", "release.blocked"]
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  headers JSONB NOT NULL DEFAULT '{}'::jsonb, -- Custom headers (e.g. Authorization or custom tokens)
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhooks_workspace_id ON webhooks(workspace_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_is_active ON webhooks(is_active);

-- 2. Create webhook_deliveries table (persistent delivery queue with retry tracking)
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  webhook_id UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  event_type VARCHAR(100) NOT NULL,
  payload JSONB NOT NULL,
  status VARCHAR(30) NOT NULL DEFAULT 'pending', -- pending, delivering, succeeded, failed, dead_letter
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  next_retry_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_attempt_at TIMESTAMPTZ,
  response_status_code INTEGER,
  response_body TEXT,
  last_error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook_id ON webhook_deliveries(webhook_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status_retry ON webhook_deliveries(status, next_retry_at);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_workspace_id ON webhook_deliveries(workspace_id);
