import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../src/app/index.js';
import { closeDatabase, getDatabase } from '../src/services/db.js';
import {
  signJwt,
  DEFAULT_WORKSPACE_ID,
} from '../src/services/auth-token.service.js';
import { workspacesService } from '../src/services/workspaces.service.js';

describe('Phase 01: Core RBAC & Multi-User Workspaces', () => {
  let app: FastifyInstance;

  // Workspace identifiers
  let workspaceAlphaId: string;
  let workspaceBetaId: string;

  // Users in Workspace Alpha
  let adminUserAlphaId: string;
  let engineerUserAlphaId: string;
  let auditorUserAlphaId: string;

  // Users in Workspace Beta
  let engineerUserBetaId: string;

  // JWT Tokens
  let tokenAdminAlpha: string;
  let tokenEngineerAlpha: string;
  let tokenAuditorAlpha: string;
  let tokenEngineerBeta: string;

  // Scoped API Key for Workspace Alpha
  let scopedEngineerKey: string;

  // Test Resources in Workspace Alpha
  let projectAlphaId: string;
  let targetAlphaId: string;

  // Test Resources in Workspace Beta
  let projectBetaId: string;

  beforeAll(async () => {
    // Initialize controller app with strict authentication enforced
    app = buildApp({
      disableLogging: true,
      enableReaper: false,
      bypassAuth: false,
    });
    await app.ready();

    // 1. Create Workspace Alpha & Beta
    const wsAlpha = await workspacesService.createWorkspace({
      name: 'Alpha Cybersec Corp',
      slug: `alpha-${Date.now()}`,
      description: 'Workspace Alpha for enterprise penetration testing',
    });
    workspaceAlphaId = wsAlpha.id;

    const wsBeta = await workspacesService.createWorkspace({
      name: 'Beta Defensive Labs',
      slug: `beta-${Date.now()}`,
      description: 'Workspace Beta for client audits',
    });
    workspaceBetaId = wsBeta.id;

    // 2. Create Users in Workspace Alpha
    const adminAlpha = await workspacesService.createUser({
      email: `admin-alpha-${Date.now()}@alpha.local`,
      name: 'Alpha Admin',
      password: 'StrongAdminPassword123!',
      workspaceId: workspaceAlphaId,
      role: 'ADMIN',
    });
    adminUserAlphaId = adminAlpha.id;

    const engineerAlpha = await workspacesService.createUser({
      email: `eng-alpha-${Date.now()}@alpha.local`,
      name: 'Alpha Engineer',
      password: 'StrongEngPassword123!',
      workspaceId: workspaceAlphaId,
      role: 'ENGINEER',
    });
    engineerUserAlphaId = engineerAlpha.id;

    const auditorAlpha = await workspacesService.createUser({
      email: `auditor-alpha-${Date.now()}@alpha.local`,
      name: 'Alpha Auditor',
      password: 'StrongAuditPassword123!',
      workspaceId: workspaceAlphaId,
      role: 'AUDITOR',
    });
    auditorUserAlphaId = auditorAlpha.id;

    // 3. Create User in Workspace Beta
    const engineerBeta = await workspacesService.createUser({
      email: `eng-beta-${Date.now()}@beta.local`,
      name: 'Beta Engineer',
      password: 'StrongBetaPassword123!',
      workspaceId: workspaceBetaId,
      role: 'ENGINEER',
    });
    engineerUserBetaId = engineerBeta.id;

    // 4. Generate Valid JWTs
    tokenAdminAlpha = signJwt({
      sub: adminUserAlphaId,
      email: adminAlpha.email,
      name: adminAlpha.name,
      role: 'ADMIN',
      workspaceId: workspaceAlphaId,
    });

    tokenEngineerAlpha = signJwt({
      sub: engineerUserAlphaId,
      email: engineerAlpha.email,
      name: engineerAlpha.name,
      role: 'ENGINEER',
      workspaceId: workspaceAlphaId,
    });

    tokenAuditorAlpha = signJwt({
      sub: auditorUserAlphaId,
      email: auditorAlpha.email,
      name: auditorAlpha.name,
      role: 'AUDITOR',
      workspaceId: workspaceAlphaId,
    });

    tokenEngineerBeta = signJwt({
      sub: engineerUserBetaId,
      email: engineerBeta.email,
      name: engineerBeta.name,
      role: 'ENGINEER',
      workspaceId: workspaceBetaId,
    });

    // 5. Generate Scoped API Key in Workspace Alpha
    const apiKeyRecord = await workspacesService.createApiKey(workspaceAlphaId, {
      userId: engineerUserAlphaId,
      name: 'CI/CD Pipeline Key',
      role: 'ENGINEER',
      expiresInDays: 30,
    });
    scopedEngineerKey = apiKeyRecord.secretKey;
  });

  afterAll(async () => {
    const { sql } = getDatabase();
    try {
      if (workspaceAlphaId) {
        await sql`DELETE FROM api_keys WHERE workspace_id = ${workspaceAlphaId}`;
        await sql`DELETE FROM workspace_memberships WHERE workspace_id = ${workspaceAlphaId}`;
        await sql`DELETE FROM test_runs WHERE project_id IN (SELECT id FROM projects WHERE workspace_id = ${workspaceAlphaId})`;
        await sql`DELETE FROM targets WHERE project_id IN (SELECT id FROM projects WHERE workspace_id = ${workspaceAlphaId})`;
        await sql`DELETE FROM projects WHERE workspace_id = ${workspaceAlphaId}`;
        await sql`DELETE FROM users WHERE id IN (${adminUserAlphaId}, ${engineerUserAlphaId}, ${auditorUserAlphaId})`;
        await sql`DELETE FROM workspaces WHERE id = ${workspaceAlphaId}`;
      }
      if (workspaceBetaId) {
        await sql`DELETE FROM workspace_memberships WHERE workspace_id = ${workspaceBetaId}`;
        await sql`DELETE FROM test_runs WHERE project_id IN (SELECT id FROM projects WHERE workspace_id = ${workspaceBetaId})`;
        await sql`DELETE FROM targets WHERE project_id IN (SELECT id FROM projects WHERE workspace_id = ${workspaceBetaId})`;
        await sql`DELETE FROM projects WHERE workspace_id = ${workspaceBetaId}`;
        await sql`DELETE FROM users WHERE id = ${engineerUserBetaId}`;
        await sql`DELETE FROM workspaces WHERE id = ${workspaceBetaId}`;
      }
    } catch {
      // Ignore cleanup error
    }

    await app.close();
    await closeDatabase();
  });

  // ===========================================================================
  // 1. Unauthenticated and Malformed Request Rejection (401)
  // ===========================================================================
  describe('Authentication Enforcement & Negative Security Tests', () => {
    it('rejects unauthenticated request to /api/v1/projects with 401 Unauthorized', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/projects',
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('rejects unauthenticated request to /api/v1/workspaces with 401 Unauthorized', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/workspaces',
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('rejects request with malformed or tampered JWT signature with 401 Unauthorized', async () => {
      const tamperedToken = tokenAdminAlpha.slice(0, -6) + 'abcdef';
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/projects',
        headers: { authorization: `Bearer ${tamperedToken}` },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('rejects expired JWT token with 401 Unauthorized', async () => {
      const expiredToken = signJwt(
        {
          sub: adminUserAlphaId,
          email: 'expired@alpha.local',
          name: 'Expired User',
          role: 'ADMIN',
          workspaceId: workspaceAlphaId,
        },
        undefined,
        -3600, // expired 1 hour ago
      );

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/projects',
        headers: { authorization: `Bearer ${expiredToken}` },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('rejects invalid or non-existent API key with 401 Unauthorized', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/projects',
        headers: { 'x-api-key': 'sec_key_nonexistent_random_token_123456789' },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });
  });

  // ===========================================================================
  // 2. Scoped API Key Authentication & Verification
  // ===========================================================================
  describe('Scoped API Key Authentication', () => {
    it('authenticates successfully using X-Api-Key header with hashed database lookup', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/projects',
        headers: { 'x-api-key': scopedEngineerKey },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(Array.isArray(body.data)).toBe(true);
    });

    it('authenticates successfully using Authorization: Bearer <apiKey>', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/projects',
        headers: { authorization: `Bearer ${scopedEngineerKey}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
    });

    it('verifies API keys are stored hashed (SHA-256) and never in plaintext', async () => {
      const { sql } = getDatabase();
      const rows = await sql<{ key_hash: string }[]>`
        SELECT key_hash FROM api_keys WHERE workspace_id = ${workspaceAlphaId}
      `;

      expect(rows.length).toBeGreaterThanOrEqual(1);
      for (const row of rows) {
        expect(row.key_hash).not.toContain('sec_key_');
        expect(row.key_hash.length).toBe(64); // SHA-256 hex string length
      }
    });
  });

  // ===========================================================================
  // 3. RBAC Role Matrix Enforcement (ADMIN, ENGINEER, AUDITOR)
  // ===========================================================================
  describe('Role-Based Access Control (RBAC) Permissions Matrix', () => {
    // Setup projects & targets in Workspace Alpha
    it('permits ENGINEER to create project in their workspace', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/projects',
        headers: { authorization: `Bearer ${tokenEngineerAlpha}` },
        payload: {
          name: 'Alpha Core API Service',
          description: 'Primary backend microservices for Alpha Corp',
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.id).toBeDefined();
      projectAlphaId = body.data.id;
    });

    it('permits ENGINEER to create target in their project', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/projects/${projectAlphaId}/targets`,
        headers: { authorization: `Bearer ${tokenEngineerAlpha}` },
        payload: {
          name: 'Alpha Target',
          baseUrl: 'http://127.0.0.1:4000',
          allowedHosts: ['127.0.0.1', 'localhost'],
          allowedPorts: [4000],
          testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
          limits: { maxConcurrency: 2, maxRps: 10, maxDuration: '2m' },
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      targetAlphaId = body.data.id;
    });

    it('permits ENGINEER to create test plan / trigger test run in their workspace', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        headers: { authorization: `Bearer ${tokenEngineerAlpha}` },
        payload: {
          projectId: projectAlphaId,
          targetId: targetAlphaId,
          profileId: 'quick-security',
          type: 'adhoc',
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.id).toBeDefined();
    });

    it('rejects AUDITOR attempting to create project with 403 Forbidden', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/projects',
        headers: { authorization: `Bearer ${tokenAuditorAlpha}` },
        payload: {
          name: 'Auditor Rogue Project',
          description: 'Should be rejected',
        },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.error.message).toContain('Insufficient permissions');
    });

    it('rejects AUDITOR attempting to trigger test run (POST /api/v1/test-runs) with 403 Forbidden', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        headers: { authorization: `Bearer ${tokenAuditorAlpha}` },
        payload: {
          projectId: projectAlphaId,
          targetId: targetAlphaId,
          profileId: 'quick-security',
          type: 'adhoc',
        },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.error.message).toContain('Insufficient permissions');
    });

    it('permits AUDITOR read-only access to list projects and get target by ID', async () => {
      const listRes = await app.inject({
        method: 'GET',
        url: '/api/v1/projects',
        headers: { authorization: `Bearer ${tokenAuditorAlpha}` },
      });
      expect(listRes.statusCode).toBe(200);

      const targetRes = await app.inject({
        method: 'GET',
        url: `/api/v1/targets/${targetAlphaId}`,
        headers: { authorization: `Bearer ${tokenAuditorAlpha}` },
      });
      expect(targetRes.statusCode).toBe(200);
    });

    it('rejects ENGINEER attempting target deletion with 403 Forbidden (requires ADMIN)', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/targets/${targetAlphaId}`,
        headers: { authorization: `Bearer ${tokenEngineerAlpha}` },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('permits ADMIN to create custom policies', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/policies',
        headers: { authorization: `Bearer ${tokenAdminAlpha}` },
        payload: {
          name: 'Alpha Strict Security Policy',
          description: 'Production zero-critical-findings gate',
          rules: [
            {
              id: 'rule-no-critical',
              name: 'No Critical Vulnerabilities',
              description: 'Zero critical findings permitted',
              severity: 'critical',
              maxAllowed: 0,
              blocking: true,
            },
          ],
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
    });

    it('permits ADMIN to delete targets', async () => {
      // Create a temporary target to delete
      const createRes = await app.inject({
        method: 'POST',
        url: `/api/v1/projects/${projectAlphaId}/targets`,
        headers: { authorization: `Bearer ${tokenAdminAlpha}` },
        payload: {
          name: 'Alpha Ephemeral Target',
          baseUrl: 'http://127.0.0.1:4001',
          allowedHosts: ['127.0.0.1'],
          allowedPorts: [4001],
          testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
          limits: { maxConcurrency: 2, maxRps: 10, maxDuration: '2m' },
        },
      });
      expect(createRes.statusCode).toBe(201);
      const tempTargetId = JSON.parse(createRes.payload).data.id;

      const deleteRes = await app.inject({
        method: 'DELETE',
        url: `/api/v1/targets/${tempTargetId}`,
        headers: { authorization: `Bearer ${tokenAdminAlpha}` },
      });
      expect(deleteRes.statusCode).toBe(200);
      expect(JSON.parse(deleteRes.payload).data.deleted).toBe(true);
    });
  });

  // ===========================================================================
  // 4. Multi-Tenant Workspace Partitioning & Cross-Tenant Isolation
  // ===========================================================================
  describe('Workspace Tenant Partitioning & Anti-Leakage Isolation', () => {
    beforeAll(async () => {
      // Seed Project in Workspace Beta
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/projects',
        headers: { authorization: `Bearer ${tokenEngineerBeta}` },
        payload: {
          name: 'Beta Protected Service',
          description: 'Secret internal service for Beta organization',
        },
      });
      expect(res.statusCode).toBe(201);
      projectBetaId = JSON.parse(res.payload).data.id;
    });

    it('lists only Workspace Alpha projects for Alpha user without leaking Beta projects', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/projects',
        headers: { authorization: `Bearer ${tokenEngineerAlpha}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      const projectIds = body.data.map((p: { id: string }) => p.id);

      expect(projectIds).toContain(projectAlphaId);
      expect(projectIds).not.toContain(projectBetaId);
    });

    it('lists only Workspace Beta projects for Beta user without leaking Alpha projects', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/projects',
        headers: { authorization: `Bearer ${tokenEngineerBeta}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      const projectIds = body.data.map((p: { id: string }) => p.id);

      expect(projectIds).toContain(projectBetaId);
      expect(projectIds).not.toContain(projectAlphaId);
    });

    it('returns 404 Not Found when User from Workspace Alpha requests Project from Workspace Beta by ID', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/projects/${projectBetaId}`,
        headers: { authorization: `Bearer ${tokenEngineerAlpha}` },
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('PROJECT_NOT_FOUND');
    });

    it('returns 404 Not Found when User from Workspace Alpha attempts to update Project from Workspace Beta', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/projects/${projectBetaId}`,
        headers: { authorization: `Bearer ${tokenEngineerAlpha}` },
        payload: {
          description: 'Malicious modification across workspace boundaries',
        },
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.payload);
      expect(body.error.code).toBe('PROJECT_NOT_FOUND');
    });

    it('blocks cross-workspace header spoofing attempt with 403 Forbidden', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/projects',
        headers: {
          authorization: `Bearer ${tokenEngineerAlpha}`,
          'x-workspace-id': workspaceBetaId,
        },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('WORKSPACE_ACCESS_DENIED');
    });
  });

  // ===========================================================================
  // 5. Workspace CRUD & Membership Management
  // ===========================================================================
  describe('Workspace Management Endpoints (/api/v1/workspaces)', () => {
    let testWorkspaceId: string;

    it('allows ADMIN to create new workspace via POST /api/v1/workspaces', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/workspaces',
        headers: { authorization: `Bearer ${tokenAdminAlpha}` },
        payload: {
          name: 'Gamma Security Operations',
          slug: `gamma-ops-${Date.now()}`,
          description: 'Operations workspace',
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.id).toBeDefined();
      testWorkspaceId = body.data.id;
    });

    it('rejects ENGINEER attempting to create new workspace with 403 Forbidden', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/workspaces',
        headers: { authorization: `Bearer ${tokenEngineerAlpha}` },
        payload: {
          name: 'Rogue Workspace',
          slug: `rogue-${Date.now()}`,
        },
      });

      expect(res.statusCode).toBe(403);
    });

    it('allows ADMIN to list workspaces via GET /api/v1/workspaces', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/workspaces',
        headers: { authorization: `Bearer ${tokenAdminAlpha}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(Array.isArray(body.data)).toBe(true);
    });

    it('allows ADMIN to create scoped API key via POST /api/v1/workspaces/:id/api-keys', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/workspaces/${workspaceAlphaId}/api-keys`,
        headers: { authorization: `Bearer ${tokenAdminAlpha}` },
        payload: {
          name: 'Staging Automation Key',
          role: 'AUDITOR',
          expiresInDays: 7,
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.secretKey).toMatch(/^sec_key_/);
      expect(body.data.apiKey.role).toBe('AUDITOR');
    });

    it('rejects ENGINEER attempting to create API key with 403 Forbidden', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/workspaces/${workspaceAlphaId}/api-keys`,
        headers: { authorization: `Bearer ${tokenEngineerAlpha}` },
        payload: {
          name: 'Unauthorized Key Attempt',
          role: 'ADMIN',
        },
      });

      expect(res.statusCode).toBe(403);
    });

    it('records workspace creation in audit_events with actor_id and workspace_id', async () => {
      const { sql } = getDatabase();
      const rows = await sql<{ event_type: string; actor_id: string; workspace_id: string }[]>`
        SELECT event_type, actor_id, workspace_id
        FROM audit_events
        WHERE workspace_id = ${testWorkspaceId}
      `;

      expect(rows.length).toBeGreaterThanOrEqual(1);
      expect(rows[0]?.event_type).toBe('workspace.created');
      expect(rows[0]?.actor_id).toBe(adminUserAlphaId);
    });
  });
});
