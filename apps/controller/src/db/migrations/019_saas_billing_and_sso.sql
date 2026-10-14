-- ==============================================================================
-- Security Lab: Phase 21 Multi-Tenant SaaS Control Plane & Governance Migration (019)
-- Adds SSO configuration, Stripe customer ID, subscription tier, quotas, and usage to workspaces
-- ==============================================================================

ALTER TABLE workspaces
ADD COLUMN IF NOT EXISTS sso_config JSONB DEFAULT NULL,
ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(128) DEFAULT NULL,
ADD COLUMN IF NOT EXISTS subscription_tier VARCHAR(64) NOT NULL DEFAULT 'free',
ADD COLUMN IF NOT EXISTS quota_limits JSONB NOT NULL DEFAULT '{"maxExecutionMinutesPerMonth": 100, "maxActiveTargets": 2, "maxConcurrentRuns": 1}'::jsonb,
ADD COLUMN IF NOT EXISTS usage_minutes INT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_workspaces_stripe_customer ON workspaces(stripe_customer_id);
CREATE INDEX IF NOT EXISTS idx_workspaces_subscription_tier ON workspaces(subscription_tier);
