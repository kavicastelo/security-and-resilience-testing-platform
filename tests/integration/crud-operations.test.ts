import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth } from '../../apps/controller/src/services/db.js';
import { FastifyInstance } from 'fastify';

describe('Comprehensive Data CRUD Operations API', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;

  beforeAll(async () => {
    app = buildApp({ disableLogging: true });
    const health = await checkDatabaseHealth();
    isDbAvailable = health === 'up';
  });

  afterAll(async () => {
    await app.close();
    await closeDatabase();
  });

  it('verifies database connectivity is healthy before executing CRUD integration tests', () => {
    expect(isDbAvailable).toBe(true);
  });

  // ==========================================
  // 1. Projects CRUD
  // ==========================================
  describe('Projects CRUD Operations', () => {
    let projectId: string;
    const randomSuffix = Math.floor(Math.random() * 100000);

    it('CREATE: POST /api/v1/projects creates a new project', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/projects',
        payload: {
          name: `CRUD Test Project ${randomSuffix}`,
          description: 'Initial description for CRUD testing',
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.id).toBeDefined();
      expect(body.data.name).toBe(`CRUD Test Project ${randomSuffix}`);
      projectId = body.data.id;
    });

    it('READ: GET /api/v1/projects/:id retrieves the created project', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/projects/${projectId}`,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.id).toBe(projectId);
      expect(body.data.name).toBe(`CRUD Test Project ${randomSuffix}`);
    });

    it('UPDATE: PUT /api/v1/projects/:id updates project details', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: `/api/v1/projects/${projectId}`,
        payload: {
          name: `Updated CRUD Project ${randomSuffix}`,
          description: 'Updated project description',
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.name).toBe(`Updated CRUD Project ${randomSuffix}`);
      expect(body.data.description).toBe('Updated project description');
    });

    it('UPDATE: PATCH /api/v1/projects/:id partially updates project details', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/projects/${projectId}`,
        payload: {
          description: 'Partially updated description',
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.description).toBe('Partially updated description');
    });

    it('DELETE: DELETE /api/v1/projects/:id deletes the project', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/projects/${projectId}`,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.deleted).toBe(true);

      // Verify it no longer exists
      const getRes = await app.inject({
        method: 'GET',
        url: `/api/v1/projects/${projectId}`,
      });
      expect(getRes.statusCode).toBe(404);
    });
  });

  // ==========================================
  // 2. Targets & Scope CRUD
  // ==========================================
  describe('Targets & Scope CRUD Operations', () => {
    let testProjectId: string;
    let targetId: string;

    beforeAll(async () => {
      const projRes = await app.inject({
        method: 'POST',
        url: '/api/v1/projects',
        payload: { name: 'Target Lifecycle Test Project' },
      });
      const projBody = JSON.parse(projRes.payload);
      testProjectId = projBody.data.id;
    });

    afterAll(async () => {
      if (testProjectId) {
        await app.inject({ method: 'DELETE', url: `/api/v1/projects/${testProjectId}` });
      }
    });

    it('CREATE: POST /api/v1/projects/:projectId/targets creates a new target with strict scope', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/projects/${testProjectId}/targets`,
        payload: {
          name: 'CRUD Service Alpha',
          baseUrl: 'https://alpha.example.com',
          allowedHosts: ['alpha.example.com', '*.alpha.example.com'],
          allowedPorts: [443],
          testing: {
            activeScanning: false,
            loadTesting: false,
            chaosTesting: false,
          },
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.id).toBeDefined();
      expect(body.data.scope.allowedHosts).toContain('alpha.example.com');
      targetId = body.data.id;
    });

    it('READ: GET /api/v1/targets/:id retrieves the target', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/targets/${targetId}`,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.name).toBe('CRUD Service Alpha');
    });

    it('UPDATE: PUT /api/v1/targets/:id updates target name, scope, and authorizes active scanning', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: `/api/v1/targets/${targetId}`,
        payload: {
          name: 'CRUD Service Alpha (Updated)',
          baseUrl: 'https://alpha.example.com',
          scope: {
            allowedHosts: ['alpha.example.com', 'api.alpha.example.com'],
            allowedPorts: [443, 8443],
            testing: {
              activeScanning: true,
              loadTesting: true,
              chaosTesting: false,
            },
            limits: {
              maxRps: 100,
              maxConcurrency: 25,
              maxDuration: '2h',
            },
          },
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.name).toBe('CRUD Service Alpha (Updated)');
      expect(body.data.scope.allowedPorts).toContain(8443);
      expect(body.data.scope.testing.activeScanning).toBe(true);
      expect(body.data.scope.limits.maxRps).toBe(100);
    });

    it('VERIFY: POST /api/v1/targets/:id/validate-scope evaluates updated boundary', async () => {
      // 1. Authorized URL on allowed port
      const authRes = await app.inject({
        method: 'POST',
        url: `/api/v1/targets/${targetId}/validate-scope`,
        payload: {
          candidateUrl: 'https://api.alpha.example.com:8443/v1/health',
          capability: 'activeScanning',
        },
      });
      const authBody = JSON.parse(authRes.payload);
      expect(authBody.data.valid).toBe(true);

      // 2. Unauthorized host rejected
      const unauthRes = await app.inject({
        method: 'POST',
        url: `/api/v1/targets/${targetId}/validate-scope`,
        payload: {
          candidateUrl: 'https://evil.attacker.com/leak',
        },
      });
      const unauthBody = JSON.parse(unauthRes.payload);
      expect(unauthBody.data.valid).toBe(false);
    });

    it('DELETE: DELETE /api/v1/targets/:id deletes the target and cascades cleanly', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/targets/${targetId}`,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.deleted).toBe(true);

      const getRes = await app.inject({
        method: 'GET',
        url: `/api/v1/targets/${targetId}`,
      });
      expect(getRes.statusCode).toBe(404);
    });
  });

  // ==========================================
  // 3. Environments CRUD
  // ==========================================
  describe('Environments CRUD Operations', () => {
    let testProjectId: string;
    let envId: string;

    beforeAll(async () => {
      const projRes = await app.inject({
        method: 'POST',
        url: '/api/v1/projects',
        payload: { name: 'Environment Test Project' },
      });
      const projBody = JSON.parse(projRes.payload);
      testProjectId = projBody.data.id;
    });

    afterAll(async () => {
      if (testProjectId) {
        await app.inject({ method: 'DELETE', url: `/api/v1/projects/${testProjectId}` });
      }
    });

    it('CREATE: POST /api/v1/projects/:projectId/environments registers an environment', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/projects/${testProjectId}/environments`,
        payload: {
          name: 'staging-eu-west',
          type: 'staging',
          variables: { REGION: 'eu-west-1', CLUSTER: 'eks-01' },
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.id).toBeDefined();
      expect(body.data.name).toBe('staging-eu-west');
      envId = body.data.id;
    });

    it('READ: GET /api/v1/environments/:id retrieves environment details', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/environments/${envId}`,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.id).toBe(envId);
      expect(body.data.variables.REGION).toBe('eu-west-1');
    });

    it('UPDATE: PUT /api/v1/environments/:id updates environment attributes', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: `/api/v1/environments/${envId}`,
        payload: {
          name: 'production-eu-west',
          type: 'production',
          variables: { REGION: 'eu-west-1', CLUSTER: 'eks-prod-01' },
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.name).toBe('production-eu-west');
      expect(body.data.type).toBe('production');
      expect(body.data.variables.CLUSTER).toBe('eks-prod-01');
    });

    it('DELETE: DELETE /api/v1/environments/:id removes the environment', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/environments/${envId}`,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.deleted).toBe(true);

      const getRes = await app.inject({
        method: 'GET',
        url: `/api/v1/environments/${envId}`,
      });
      expect(getRes.statusCode).toBe(404);
    });
  });

  // ==========================================
  // 4. Policies CRUD & Immutability Protection
  // ==========================================
  describe('Policies CRUD & Baseline Protection', () => {
    let customPolicyId: string;
    const defaultBaselinePolicyId = '00000000-0000-0000-0000-000000000001';

    it('READ: GET /api/v1/policies lists policies including default enterprise baseline', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/policies',
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.data.some((p: { id: string }) => p.id === defaultBaselinePolicyId)).toBe(true);
    });

    it('IMMUTABILITY: DELETE default baseline policy returns 403 Forbidden', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/policies/${defaultBaselinePolicyId}`,
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.payload);
      expect(body.error.message).toContain('Cannot delete the enterprise baseline default policy');
    });

    it('IMMUTABILITY: PUT default baseline policy returns 403 Forbidden', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: `/api/v1/policies/${defaultBaselinePolicyId}`,
        payload: {
          name: 'Attempted Override',
          rules: [],
        },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.payload);
      expect(body.error.message).toContain('Cannot modify the enterprise baseline default policy');
    });

    it('CREATE: POST /api/v1/policies creates custom gating policy', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/policies',
        payload: {
          name: 'Custom High-Assurance Release Policy',
          description: 'Strict policy for financial endpoints',
          rules: [
            {
              id: 'rule-zero-high',
              name: 'Zero High Severity Allowed',
              condition: {
                maxCountBySeverity: { critical: 0, high: 0, medium: 2 },
              },
              action: 'block_release',
            },
          ],
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.id).toBeDefined();
      expect(body.data.name).toBe('Custom High-Assurance Release Policy');
      customPolicyId = body.data.id;
    });

    it('UPDATE: PUT /api/v1/policies/:id updates custom gating policy', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: `/api/v1/policies/${customPolicyId}`,
        payload: {
          name: 'Updated High-Assurance Policy',
          description: 'Adjusted medium tolerance',
          rules: [
            {
              id: 'rule-zero-high-v2',
              name: 'Zero Critical / Zero High',
              condition: {
                maxCountBySeverity: { critical: 0, high: 0, medium: 5 },
                maxP95LatencyMs: 300,
              },
              action: 'block_release',
            },
          ],
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.name).toBe('Updated High-Assurance Policy');
      expect(body.data.rules[0].condition.maxP95LatencyMs).toBe(300);
    });

    it('DELETE: DELETE /api/v1/policies/:id deletes custom policy successfully', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/policies/${customPolicyId}`,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.deleted).toBe(true);

      const getRes = await app.inject({
        method: 'GET',
        url: `/api/v1/policies/${customPolicyId}`,
      });
      expect(getRes.statusCode).toBe(404);
    });
  });

  // ==========================================
  // 5. Test Runs, Findings & Releases CRUD
  // ==========================================
  describe('Test Runs, Findings & Release Audit CRUD Operations', () => {
    let testProjectId: string;
    let targetId: string;
    let testRunId: string;
    let findingId: string;
    let releaseId: string;

    beforeAll(async () => {
      const projRes = await app.inject({
        method: 'POST',
        url: '/api/v1/projects',
        payload: { name: 'Full Lifecycle Project' },
      });
      const projBody = JSON.parse(projRes.payload);
      testProjectId = projBody.data.id;

      const targetRes = await app.inject({
        method: 'POST',
        url: `/api/v1/projects/${testProjectId}/targets`,
        payload: {
          name: 'Lifecycle Target',
          baseUrl: 'https://lifecycle.example.com',
          allowedHosts: ['lifecycle.example.com'],
          allowedPorts: [443],
          testing: { activeScanning: true, loadTesting: true, chaosTesting: false },
        },
      });
      const targetBody = JSON.parse(targetRes.payload);
      targetId = targetBody.data.id;
    });

    afterAll(async () => {
      if (testProjectId) {
        await app.inject({ method: 'DELETE', url: `/api/v1/projects/${testProjectId}` });
      }
    });

    it('CREATE: POST /api/v1/test-runs starts an execution run', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        payload: {
          projectId: testProjectId,
          targetId,
          profileId: 'default',
          engines: ['engine-native-headers'],
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.id).toBeDefined();
      testRunId = body.data.id;
    });

    it('READ: GET /api/v1/findings fetches findings associated with the execution', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/findings',
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(Array.isArray(body.data)).toBe(true);

      const runFinding = body.data.find((f: { testRunId: string }) => f.testRunId === testRunId);
      if (runFinding) {
        findingId = runFinding.id;
        expect(runFinding.status).toBe('open');
      }
    });

    it('UPDATE: PATCH /api/v1/findings/:id triages finding status to resolved', async () => {
      if (!findingId) return;

      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/findings/${findingId}`,
        payload: {
          status: 'resolved',
          notes: 'Remediated missing CSP and HSTS headers in nginx gateway',
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.status).toBe('resolved');
      expect(body.data.fixedAt).toBeDefined();
    });

    it('CREATE: POST /api/v1/releases/evaluate records release gate evaluation', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/releases/evaluate',
        payload: {
          projectId: testProjectId,
          name: 'v2.1.0-release',
          version: '2.1.0',
          testRunId,
          gitCommit: 'abc12345',
          gitBranch: 'main',
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.decision).toBeDefined();
      expect(body.data.release?.id).toBeDefined();
      releaseId = body.data.release.id;
    });

    it('DELETE: DELETE /api/v1/releases/:id deletes the release audit record', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/releases/${releaseId}`,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.deleted).toBe(true);
    });

    it('DELETE: DELETE /api/v1/findings/:id deletes finding record', async () => {
      if (!findingId) return;

      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/findings/${findingId}`,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.deleted).toBe(true);
    });

    it('DELETE: DELETE /api/v1/test-runs/:id deletes the test run and cascades', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/test-runs/${testRunId}`,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.deleted).toBe(true);

      const getRes = await app.inject({
        method: 'GET',
        url: `/api/v1/test-runs/${testRunId}`,
      });
      expect(getRes.statusCode).toBe(404);
    });
  });
});
