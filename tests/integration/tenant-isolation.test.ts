import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { getDatabase, closeDatabase } from '../../apps/controller/src/services/db.js';
import { findingsService } from '../../apps/controller/src/services/findings.service.js';
import crypto from 'node:crypto';

describe('Trusted Tenant Isolation & Spoofing Elimination (REM-02)', () => {
  let app: FastifyInstance;

  const tenantAId = 'a0000000-0000-0000-0000-000000000001';
  const tenantBId = 'b0000000-0000-0000-0000-000000000002';

  const tenantAKey = 'tenant-a-test-key-32chars-long-abc';
  const tenantBKey = 'tenant-b-test-key-32chars-long-xyz';
  const adminKey = 'test-admin-secret-key-32chars-long';

  let projectAId: string;
  let projectBId: string;
  let targetAId: string;
  let targetBId: string;
  let testRunBId: string;
  let findingBId: string;
  let policyBId: string;

  beforeAll(async () => {
    const { sql } = getDatabase();

    // Ensure tenants exist in the database
    const slugA = `tenant-a-${Date.now()}`;
    const slugB = `tenant-b-${Date.now()}`;
    await sql`
      INSERT INTO tenants (id, name, slug)
      VALUES (${tenantAId}, 'Tenant Alpha Corp', ${slugA}),
             (${tenantBId}, 'Tenant Beta Corp', ${slugB})
      ON CONFLICT (id) DO NOTHING;
    `;

    // Build the Fastify app configured with tenant-bound keys
    app = buildApp({
      disableLogging: true,
      enableReaper: false,
      bypassAuth: false,
      adminKey,
      tenantKeyMap: {
        [tenantAKey]: { role: 'operator', tenantId: tenantAId },
        [tenantBKey]: { role: 'operator', tenantId: tenantBId },
      },
    });

    await app.ready();
  });

  afterAll(async () => {
    const { sql } = getDatabase();
    // Cleanup created test resources
    try {
      if (findingBId) await sql`DELETE FROM findings WHERE id = ${findingBId}`;
      if (testRunBId) await sql`DELETE FROM test_runs WHERE id = ${testRunBId}`;
      if (targetAId) await sql`DELETE FROM targets WHERE id = ${targetAId}`;
      if (targetBId) await sql`DELETE FROM targets WHERE id = ${targetBId}`;
      if (projectAId) await sql`DELETE FROM projects WHERE id = ${projectAId}`;
      if (projectBId) await sql`DELETE FROM projects WHERE id = ${projectBId}`;
      if (policyBId) await sql`DELETE FROM policies WHERE id = ${policyBId}`;
      await sql`DELETE FROM tenants WHERE id = ${tenantAId} OR id = ${tenantBId}`;
    } catch {
      // Best effort cleanup
    }

    await app.close();
    await closeDatabase();
  });

  // ---------------------------------------------------------------------------
  // 1. Header Spoofing Elimination
  // ---------------------------------------------------------------------------
  describe('Header Spoofing Elimination & Fail-Closed Guard', () => {
    it('rejects operator request with 403 Forbidden (TENANT_MISMATCH) when supplying conflicting x-tenant-id', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/projects',
        headers: {
          authorization: `Bearer ${tenantAKey}`,
          'x-tenant-id': tenantBId,
        },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('TENANT_MISMATCH');
    });

    it('rejects target creation when operator attempts to impersonate another tenant via header', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/projects/00000000-0000-0000-0000-000000000000/targets',
        headers: {
          authorization: `Bearer ${tenantAKey}`,
          'x-tenant-id': tenantBId,
        },
        payload: {
          name: 'Spoofed Target',
          baseUrl: 'http://example.com',
          allowedHosts: ['example.com'],
        },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.payload);
      expect(body.error.code).toBe('TENANT_MISMATCH');
    });

    it('rejects finding queries when operator attempts to impersonate another tenant via header', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/findings',
        headers: {
          authorization: `Bearer ${tenantAKey}`,
          'x-tenant-id': tenantBId,
        },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.payload);
      expect(body.error.code).toBe('TENANT_MISMATCH');
    });

    it('rejects agent queries when operator attempts to impersonate another tenant via header', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/agents',
        headers: {
          authorization: `Bearer ${tenantAKey}`,
          'x-tenant-id': tenantBId,
        },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.payload);
      expect(body.error.code).toBe('TENANT_MISMATCH');
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Project Isolation
  // ---------------------------------------------------------------------------
  describe('Project Tenant Scoping & Isolation', () => {
    it('creates project strictly bound to authenticated tenant A', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/projects',
        headers: { authorization: `Bearer ${tenantAKey}` },
        payload: {
          name: `Project Alpha ${Date.now()}`,
          description: 'Tenant A Project',
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.id).toBeDefined();
      projectAId = body.data.id;
    });

    it('creates project strictly bound to authenticated tenant B', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/projects',
        headers: { authorization: `Bearer ${tenantBKey}` },
        payload: {
          name: `Project Beta ${Date.now()}`,
          description: 'Tenant B Project',
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.id).toBeDefined();
      projectBId = body.data.id;
    });

    it('lists projects for tenant A without leaking tenant B projects', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/projects',
        headers: { authorization: `Bearer ${tenantAKey}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      const ids = body.data.map((p: { id: string }) => p.id);
      expect(ids).toContain(projectAId);
      expect(ids).not.toContain(projectBId);
    });

    it('lists projects for tenant B without leaking tenant A projects', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/projects',
        headers: { authorization: `Bearer ${tenantBKey}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      const ids = body.data.map((p: { id: string }) => p.id);
      expect(ids).toContain(projectBId);
      expect(ids).not.toContain(projectAId);
    });

    it('returns 404 Not Found when tenant A requests tenant B project by ID', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/projects/${projectBId}`,
        headers: { authorization: `Bearer ${tenantAKey}` },
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.payload);
      expect(body.error.code).toBe('PROJECT_NOT_FOUND');
    });

    it('returns 404 Not Found when tenant A attempts to update tenant B project', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: `/api/v1/projects/${projectBId}`,
        headers: { authorization: `Bearer ${tenantAKey}` },
        payload: {
          description: 'Hacked description',
        },
      });

      expect(res.statusCode).toBe(404);
    });

    it('returns 404 Not Found when tenant A attempts to delete tenant B project', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/projects/${projectBId}`,
        headers: { authorization: `Bearer ${tenantAKey}` },
      });

      expect(res.statusCode).toBe(404);
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Target Isolation
  // ---------------------------------------------------------------------------
  describe('Target Tenant Scoping & Isolation', () => {
    it('creates target in project A bound to tenant A', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/projects/${projectAId}/targets`,
        headers: { authorization: `Bearer ${tenantAKey}` },
        payload: {
          name: 'Target Alpha',
          baseUrl: 'http://alpha.internal',
          allowedHosts: ['alpha.internal'],
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      targetAId = body.data.id;
      expect(targetAId).toBeDefined();
    });

    it('creates target in project B bound to tenant B', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/projects/${projectBId}/targets`,
        headers: { authorization: `Bearer ${tenantBKey}` },
        payload: {
          name: 'Target Beta',
          baseUrl: 'http://beta.internal',
          allowedHosts: ['beta.internal'],
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      targetBId = body.data.id;
      expect(targetBId).toBeDefined();
    });

    it('rejects target creation when tenant A attempts to create target inside tenant B project', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/projects/${projectBId}/targets`,
        headers: { authorization: `Bearer ${tenantAKey}` },
        payload: {
          name: 'Malicious Target In Project B',
          baseUrl: 'http://malicious.internal',
          allowedHosts: ['malicious.internal'],
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.payload);
      expect(body.error.message).toMatch(/not found or access denied/i);
    });

    it('lists all targets for tenant A without leaking tenant B targets', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/targets',
        headers: { authorization: `Bearer ${tenantAKey}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      const ids = body.data.map((t: { id: string }) => t.id);
      expect(ids).toContain(targetAId);
      expect(ids).not.toContain(targetBId);
    });

    it('returns 404 Not Found when tenant A accesses target B by ID', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/targets/${targetBId}`,
        headers: { authorization: `Bearer ${tenantAKey}` },
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.payload);
      expect(body.error.code).toBe('TARGET_NOT_FOUND');
    });

    it('returns 404 Not Found when tenant A attempts to validate scope on target B', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/targets/${targetBId}/validate-scope`,
        headers: { authorization: `Bearer ${tenantAKey}` },
        payload: {
          candidateUrl: 'http://beta.internal/test',
        },
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.payload);
      expect(body.error.code).toBe('TARGET_NOT_FOUND');
    });

    it('returns 404 Not Found when tenant A attempts to update target B', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/targets/${targetBId}`,
        headers: { authorization: `Bearer ${tenantAKey}` },
        payload: {
          name: 'Compromised Target Name',
        },
      });

      expect(res.statusCode).toBe(404);
    });

    it('returns 404 Not Found when tenant A attempts to delete target B', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/targets/${targetBId}`,
        headers: { authorization: `Bearer ${tenantAKey}` },
      });

      expect(res.statusCode).toBe(404);
    });
  });

  // ---------------------------------------------------------------------------
  // 4. TestRun & Finding Isolation
  // ---------------------------------------------------------------------------
  describe('TestRun & Finding Tenant Scoping & Isolation', () => {
    it('creates a test run for Tenant B', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        headers: { authorization: `Bearer ${tenantBKey}` },
        payload: {
          projectId: projectBId,
          targetId: targetBId,
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      testRunBId = body.data.id;
      expect(testRunBId).toBeDefined();
    });

    it('rejects test run creation when Tenant A references Target B', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        headers: { authorization: `Bearer ${tenantAKey}` },
        payload: {
          projectId: projectAId,
          targetId: targetBId,
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.payload);
      expect(body.error.message).toMatch(/not found or access denied/i);
    });

    it('prevents Tenant A from listing Tenant B test runs', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/test-runs',
        headers: { authorization: `Bearer ${tenantAKey}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      const ids = body.data.map((r: { id: string }) => r.id);
      expect(ids).not.toContain(testRunBId);
    });

    it('returns 404 Not Found when Tenant A requests Tenant B test run by ID', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/test-runs/${testRunBId}`,
        headers: { authorization: `Bearer ${tenantAKey}` },
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.payload);
      expect(body.error.code).toBe('TESTRUN_NOT_FOUND');
    });

    it('returns 404 Not Found when Tenant A tries to execute or cancel Tenant B test run', async () => {
      const execRes = await app.inject({
        method: 'POST',
        url: `/api/v1/test-runs/${testRunBId}/execute`,
        headers: { authorization: `Bearer ${tenantAKey}` },
      });
      expect(execRes.statusCode).toBe(404);

      const cancelRes = await app.inject({
        method: 'POST',
        url: `/api/v1/test-runs/${testRunBId}/cancel`,
        headers: { authorization: `Bearer ${tenantAKey}` },
      });
      expect(cancelRes.statusCode).toBe(404);
    });

    it('creates a finding directly for Tenant B and verifies Tenant A cannot view or update it', async () => {
      const testExecutionId = crypto.randomUUID();
      const { sql } = getDatabase();

      await sql`
        INSERT INTO test_executions (id, test_run_id, engine_id, status)
        VALUES (${testExecutionId}, ${testRunBId}, 'engine-mock', 'completed')
      `;

      // Seed finding directly for Tenant B
      const insertedFinding = await findingsService.saveFinding({
        tenantId: tenantBId,
        targetId: targetBId,
        testRunId: testRunBId,
        executionId: testExecutionId,
        fingerprint: 'test-fingerprint-tenant-b-unique',
        title: 'SQL Injection in Tenant B',
        category: 'injection',
        severity: 'critical',
        status: 'open',
        description: 'Sensitive finding belonging to Tenant B',
        testDefinitionId: 'sql-injection-check',
      });

      findingBId = insertedFinding.id;

      // 1. List findings as Tenant A: must not include Tenant B finding
      const listRes = await app.inject({
        method: 'GET',
        url: '/api/v1/findings',
        headers: { authorization: `Bearer ${tenantAKey}` },
      });

      expect(listRes.statusCode).toBe(200);
      const listBody = JSON.parse(listRes.payload);
      const findingIds = listBody.data.map((f: { id: string }) => f.id);
      expect(findingIds).not.toContain(findingBId);

      // 2. Get finding by ID as Tenant A: must return 404 Not Found
      const getRes = await app.inject({
        method: 'GET',
        url: `/api/v1/findings/${findingBId}`,
        headers: { authorization: `Bearer ${tenantAKey}` },
      });

      expect(getRes.statusCode).toBe(404);
      const getBody = JSON.parse(getRes.payload);
      expect(getBody.error.code).toBe('FINDING_NOT_FOUND');

      // 3. Triage / update finding as Tenant A: must return 404 Not Found
      const updateRes = await app.inject({
        method: 'PATCH',
        url: `/api/v1/findings/${findingBId}`,
        headers: { authorization: `Bearer ${tenantAKey}` },
        payload: {
          status: 'resolved',
          notes: 'Unauthorized resolution attempt',
        },
      });

      expect(updateRes.statusCode).toBe(404);

      // 4. Delete finding as Tenant A: must return 404 Not Found
      const deleteRes = await app.inject({
        method: 'DELETE',
        url: `/api/v1/findings/${findingBId}`,
        headers: { authorization: `Bearer ${tenantAKey}` },
      });

      expect(deleteRes.statusCode).toBe(404);

      // 5. Tenant B can successfully read their own finding
      const tenantBRes = await app.inject({
        method: 'GET',
        url: `/api/v1/findings/${findingBId}`,
        headers: { authorization: `Bearer ${tenantBKey}` },
      });

      expect(tenantBRes.statusCode).toBe(200);
      const tenantBBody = JSON.parse(tenantBRes.payload);
      expect(tenantBBody.data.id).toBe(findingBId);
      expect(tenantBBody.data.title).toBe('SQL Injection in Tenant B');
    });
  });

  // ---------------------------------------------------------------------------
  // 5. Policy Isolation
  // ---------------------------------------------------------------------------
  describe('Policy Tenant Scoping & Isolation', () => {
    it('creates custom policy for Tenant B', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/policies',
        headers: { authorization: `Bearer ${tenantBKey}` },
        payload: {
          name: 'Tenant B Custom Security Gate',
          rules: [],
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      policyBId = body.data.id;
      expect(policyBId).toBeDefined();
    });

    it('prevents Tenant A from seeing or accessing Tenant B custom policy', async () => {
      // 1. List policies as Tenant A: must not include Policy B
      const listRes = await app.inject({
        method: 'GET',
        url: '/api/v1/policies',
        headers: { authorization: `Bearer ${tenantAKey}` },
      });

      expect(listRes.statusCode).toBe(200);
      const listBody = JSON.parse(listRes.payload);
      const policyIds = listBody.data.map((p: { id: string }) => p.id);
      expect(policyIds).not.toContain(policyBId);

      // 2. Get Policy B by ID as Tenant A: must return 404 Not Found
      const getRes = await app.inject({
        method: 'GET',
        url: `/api/v1/policies/${policyBId}`,
        headers: { authorization: `Bearer ${tenantAKey}` },
      });

      expect(getRes.statusCode).toBe(404);

      // 3. Update Policy B as Tenant A: must return 404 Not Found
      const updateRes = await app.inject({
        method: 'PUT',
        url: `/api/v1/policies/${policyBId}`,
        headers: { authorization: `Bearer ${tenantAKey}` },
        payload: {
          name: 'Tampered Policy',
        },
      });

      expect(updateRes.statusCode).toBe(404);

      // 4. Delete Policy B as Tenant A: must return 404 Not Found
      const deleteRes = await app.inject({
        method: 'DELETE',
        url: `/api/v1/policies/${policyBId}`,
        headers: { authorization: `Bearer ${tenantAKey}` },
      });

      expect(deleteRes.statusCode).toBe(404);
    });
  });

  // ---------------------------------------------------------------------------
  // 6. Admin Multi-Tenant Impersonation
  // ---------------------------------------------------------------------------
  describe('Admin Multi-Tenant Impersonation', () => {
    it('allows admin with explicit x-tenant-id to view and manage Tenant B projects', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/projects',
        headers: {
          authorization: `Bearer ${adminKey}`,
          'x-tenant-id': tenantBId,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      const ids = body.data.map((p: { id: string }) => p.id);
      expect(ids).toContain(projectBId);
      expect(ids).not.toContain(projectAId);
    });

    it('allows admin with explicit x-tenant-id to view Tenant B target by ID', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/targets/${targetBId}`,
        headers: {
          authorization: `Bearer ${adminKey}`,
          'x-tenant-id': tenantBId,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.data.id).toBe(targetBId);
    });

    it('allows admin with explicit x-tenant-id to view Tenant B finding by ID', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/findings/${findingBId}`,
        headers: {
          authorization: `Bearer ${adminKey}`,
          'x-tenant-id': tenantBId,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.data.id).toBe(findingBId);
    });
  });
});
