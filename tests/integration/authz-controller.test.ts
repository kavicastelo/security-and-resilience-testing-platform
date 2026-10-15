import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { webhookQueueService } from '../../apps/controller/src/services/webhook-queue.js';
import { signJwt, DEFAULT_WORKSPACE_ID } from '../../apps/controller/src/services/auth-token.service.js';
import { getDatabase } from '../../apps/controller/src/services/db.js';
import { findings, evidenceRecords, targets, testRuns, testExecutions } from '../../apps/controller/src/services/db/schema.js';

describe('PR-05 Integration: BOLA / BFLA Access Matrix Dynamic Aggregation', () => {
  let app: FastifyInstance;
  let authToken: string;
  let cleanTargetId: string;
  let targetWithFindingsId: string;
  let projectId: string;
  let createdFindingId: string;

  beforeAll(async () => {
    app = buildApp({
      disableLogging: true,
      enableReaper: false,
      bypassAuth: false,
    });
    await app.ready();

    authToken = signJwt({
      userId: 'test-authz-architect',
      workspaceId: DEFAULT_WORKSPACE_ID,
      role: 'engineer',
    });

    // 1. Create a project
    const projRes = await app.inject({
      method: 'POST',
      url: '/api/v1/projects',
      headers: {
        authorization: `Bearer ${authToken}`,
      },
      payload: {
        name: `Authz Matrix Project ${Date.now()}`,
        description: 'Integration test target project for BOLA/BFLA matrix',
      },
    });
    const projBody = JSON.parse(projRes.body);
    projectId = projBody.data.id;

    // 2. Create a clean target with 0 findings
    const cleanTargetRes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectId}/targets`,
      headers: {
        authorization: `Bearer ${authToken}`,
      },
      payload: {
        name: 'Clean Hardened API Target',
        baseUrl: 'https://clean-api.security-lab.local',
        allowedHosts: ['clean-api.security-lab.local'],
        allowedPorts: [443],
        excludedPaths: [],
        testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
        limits: { maxRps: 50, maxConcurrency: 10 },
      },
    });
    cleanTargetId = JSON.parse(cleanTargetRes.body).data.id;

    // 3. Create a target with BOLA/BFLA findings
    const vulTargetRes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectId}/targets`,
      headers: {
        authorization: `Bearer ${authToken}`,
      },
      payload: {
        name: 'Vulnerable Multi-Tenant SaaS API',
        baseUrl: 'https://saas-api.security-lab.local',
        allowedHosts: ['saas-api.security-lab.local'],
        allowedPorts: [443],
        excludedPaths: [],
        testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
        limits: { maxRps: 50, maxConcurrency: 10 },
      },
    });
    targetWithFindingsId = JSON.parse(vulTargetRes.body).data.id;

    // 4. Seed BOLA and BFLA findings with evidence in database
    const { db } = getDatabase();

    const [run] = await db
      .insert(testRuns)
      .values({
        projectId,
        targetId: targetWithFindingsId,
        status: 'completed',
        triggeredBy: 'manual',
      })
      .returning();

    const [exec] = await db
      .insert(testExecutions)
      .values({
        testRunId: run.id,
        engineId: 'engine-authz-matrix',
        status: 'completed',
      })
      .returning();

    const [evBOLA] = await db
      .insert(evidenceRecords)
      .values({
        testRunId: run.id,
        executionId: exec.id,
        request: {
          url: 'https://saas-api.security-lab.local/api/v1/invoices/inv-900',
          method: 'GET',
          headers: {
            'Authorization': 'Bearer [USER_B_TOKEN]',
            'X-Tenant-ID': 'tenant-beta',
          },
        },
        response: {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ id: 'inv-900', amount: 50000, tenantId: 'tenant-alpha' }),
        },
        expected: { statusCode: 403 },
        actual: { statusCode: 200 },
        metadata: {
          actorPersona: 'user_b',
          actorRole: 'compliance_auditor',
          ownerPersona: 'user_a',
          targetResourceId: 'inv-900',
          curlCommand: 'curl -X GET https://saas-api.security-lab.local/api/v1/invoices/inv-900',
        },
        immutableHash: 'hash-bola-001',
      })
      .returning();

    const [evBFLA] = await db
      .insert(evidenceRecords)
      .values({
        testRunId: run.id,
        executionId: exec.id,
        request: {
          url: 'https://saas-api.security-lab.local/api/v1/admin/audit-logs',
          method: 'GET',
          headers: {
            'Authorization': 'Bearer [USER_A_TOKEN]',
            'X-Tenant-ID': 'tenant-alpha',
          },
        },
        response: {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ logs: [{ action: 'PURGE_ALL' }] }),
        },
        expected: { statusCode: 403 },
        actual: { statusCode: 200 },
        metadata: {
          actorPersona: 'user_a',
          actorRole: 'finance_manager',
          ownerPersona: 'admin',
          targetResourceId: 'audit-logs',
          curlCommand: 'curl -X GET https://saas-api.security-lab.local/api/v1/admin/audit-logs',
        },
        immutableHash: 'hash-bfla-001',
      })
      .returning();

    const [fBOLA] = await db
      .insert(findings)
      .values({
        fingerprint: `fp-bola-${Date.now()}`,
        title: 'Broken Object Level Authorization (BOLA/IDOR) on GET /api/v1/invoices/:id',
        category: 'authorization',
        severity: 'critical',
        confidence: 'certain',
        status: 'open',
        description: 'Tenant Beta was able to read invoice owned by Tenant Alpha.',
        recommendation: 'Enforce tenant isolation checks.',
        testDefinitionId: 'engine-authz-matrix',
        testRunId: run.id,
        executionId: exec.id,
        targetId: targetWithFindingsId,
        evidenceId: evBOLA.id,
        metadata: {
          violationType: 'BOLA_HORIZONTAL_IDOR',
          endpoint: '/api/v1/invoices/:id',
          method: 'GET',
          actorPersonaId: 'user_b',
          targetResourceId: 'inv-900',
        },
      })
      .returning();
    createdFindingId = fBOLA.id;

    await db.insert(findings).values({
      fingerprint: `fp-bfla-${Date.now()}`,
      title: 'Broken Function Level Authorization (BFLA) on GET /api/v1/admin/audit-logs',
      category: 'authorization',
      severity: 'high',
      confidence: 'certain',
      status: 'open',
      description: 'Standard member was able to access administrative audit logs.',
      recommendation: 'Enforce RBAC middleware.',
      testDefinitionId: 'engine-authz-matrix',
      testRunId: run.id,
      executionId: exec.id,
      targetId: targetWithFindingsId,
      evidenceId: evBFLA.id,
      metadata: {
        violationType: 'BFLA_VERTICAL_ESCALATION',
        endpoint: '/api/v1/admin/audit-logs',
        method: 'GET',
        actorPersonaId: 'user_a',
      },
    });
  });

  afterAll(async () => {
    webhookQueueService.stopWorker();
    await app.close();
  });

  describe('GET /api/v1/authz/matrix', () => {
    it('returns data: null (clean empty state) when target has zero BOLA findings', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/authz/matrix?targetId=${cleanTargetId}`,
        headers: {
          authorization: `Bearer ${authToken}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.success).toBe(true);
      expect(body.data).toBeNull();
    });

    it('returns dynamically assembled AuthzMatrixDataset when target has authorization findings', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/authz/matrix?targetId=${targetWithFindingsId}`,
        headers: {
          authorization: `Bearer ${authToken}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.success).toBe(true);
      expect(body.data).not.toBeNull();

      const dataset = body.data;
      expect(dataset.targetId).toBe(targetWithFindingsId);
      expect(dataset.targetName).toContain('Vulnerable Multi-Tenant SaaS');
      expect(dataset.personas.length).toBeGreaterThanOrEqual(3);
      expect(dataset.routes.length).toBeGreaterThanOrEqual(2);
      expect(dataset.cells.length).toBeGreaterThanOrEqual(6);

      // Verify BOLA violation cell is identified
      const bolaCell = dataset.cells.find(
        (c: any) => c.endpoint === '/api/v1/invoices/:id' && c.personaId === 'user_b',
      );
      expect(bolaCell).toBeDefined();
      expect(bolaCell.status).toBe('VIOLATION_BOLA');
      expect(bolaCell.httpStatus).toBe(200);

      // Verify BFLA violation cell is identified
      const bflaCell = dataset.cells.find(
        (c: any) => c.endpoint === '/api/v1/admin/audit-logs' && c.personaId === 'user_a',
      );
      expect(bflaCell).toBeDefined();
      expect(bflaCell.status).toBe('VIOLATION_BFLA');

      // Verify cross-tenant breaches list
      expect(dataset.crossTenantBreaches.length).toBeGreaterThan(0);
      const breach = dataset.crossTenantBreaches[0];
      expect(breach.sourceTenant).toBe('tenant-beta');
      expect(breach.targetTenant).toBe('tenant-alpha');
      expect(breach.endpoint).toBe('/api/v1/invoices/:id');

      // Verify evidenceMap contains details
      expect(dataset.evidenceMap[createdFindingId]).toBeDefined();
      const ev = dataset.evidenceMap[createdFindingId];
      expect(ev.violationType).toBe('BOLA_HORIZONTAL_IDOR');
      expect(ev.actualStatusCode).toBe(200);
      expect(ev.expectedStatusCode).toBe(403);
    });

    it('returns data: null when no targetId or testRunId is provided', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/authz/matrix',
        headers: {
          authorization: `Bearer ${authToken}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.success).toBe(true);
      expect(body.data).toBeNull();
    });
  });

  describe('Retest Error Handling (/api/v1/findings/:id/retest)', () => {
    it('returns 404 error when finding does not exist without fabricating fake 403', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/findings/00000000-0000-0000-0000-000000000000/retest',
        headers: {
          authorization: `Bearer ${authToken}`,
        },
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('FINDING_NOT_FOUND');
    });
  });
});
