DROP INDEX IF EXISTS idx_workspaces_subscription_tier;
DROP INDEX IF EXISTS idx_workspaces_stripe_customer;

ALTER TABLE workspaces
DROP COLUMN IF EXISTS usage_minutes,
DROP COLUMN IF EXISTS quota_limits,
DROP COLUMN IF EXISTS subscription_tier,
DROP COLUMN IF EXISTS stripe_customer_id,
DROP COLUMN IF EXISTS sso_config;
