-- ==============================================================================
-- Security Lab: Phase 19 Rollback (017 Down)
-- Drops webhook_deliveries and webhooks tables
-- ==============================================================================

DROP TABLE IF EXISTS webhook_deliveries CASCADE;
DROP TABLE IF EXISTS webhooks CASCADE;
