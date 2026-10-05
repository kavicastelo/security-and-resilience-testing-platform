-- ==============================================================================
-- Security Lab: Initial Development Seed Data
-- Creates default project, environment, and sample authorized target for testing
-- ==============================================================================

DO $$
DECLARE
    v_project_id UUID;
    v_env_id UUID;
    v_target_id UUID;
BEGIN
    -- Insert Default Demo Project
    INSERT INTO projects (name, description)
    VALUES ('Enterprise Demo App', 'Local reference project for security and resilience baseline testing')
    ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description
    RETURNING id INTO v_project_id;

    -- Insert Default Staging Environment
    INSERT INTO environments (project_id, name, type, variables, headers)
    VALUES (
        v_project_id,
        'local-dev',
        'development',
        '{"APP_PORT": "8080"}'::jsonb,
        '{"X-Security-Test-Actor": "security-lab"}'::jsonb
    )
    ON CONFLICT (project_id, name) DO NOTHING
    RETURNING id INTO v_env_id;

    -- Insert Sample Authorized Local Target
    INSERT INTO targets (project_id, name, base_url, scope)
    VALUES (
        v_project_id,
        'local-test-app',
        'http://localhost:8080',
        '{
            "allowedHosts": ["localhost", "127.0.0.1"],
            "allowedPorts": [8080, 8443],
            "excludedPaths": ["/admin/reset-db"],
            "testing": {
                "activeScanning": true,
                "loadTesting": true,
                "chaosTesting": false
            },
            "limits": {
                "maxRps": 50,
                "maxConcurrency": 10,
                "maxDuration": "5m"
            }
        }'::jsonb
    )
    ON CONFLICT (project_id, name) DO NOTHING;
END $$;
