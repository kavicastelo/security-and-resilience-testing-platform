-- Rollback for 012_workspaces_and_rbac.sql
ALTER TABLE projects DROP COLUMN IF EXISTS workspace_id;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'agent_audit_events' AND column_name = 'workspace_id') THEN
    ALTER TABLE agent_audit_events DROP COLUMN workspace_id;
  END IF;
END $$;
DROP TABLE IF EXISTS audit_events CASCADE;
DROP TABLE IF EXISTS api_keys CASCADE;
DROP TABLE IF EXISTS workspace_memberships CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS workspaces CASCADE;
DELETE FROM _schema_migrations WHERE version = '012_workspaces_and_rbac.sql';
