import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, getDatabase } from '../../apps/controller/src/services/db.js';
import { SharedRateLimitStore } from '../../apps/controller/src/services/rate-limit-store.js';

describe('Rate Limiting & Resource Exhaustion Controls (REM-10)', () => {
  let app: FastifyInstance;
  const tenantAId = 'c1000000-0000-0000-0000-000000000001';
  const tenantBId = 'c2000000-0000-0000-0000-000000000002';

  const apiKeyA = 'test-rate-limit-operator-key-alpha-32';
  const apiKeyB = 'test-rate-limit-operator-key-beta--32';
  const adminKey = 'test-rate-limit-admin-secret-key-32';

  let projectAId: string;
  let targetAId: string;
  let testRunAId: string;

  let projectBId: string;
  let targetBId: string;
  let testRunBId: string;

  beforeAll(async () => {
    SharedRateLimitStore.reset();
    const { sql } = getDatabase();

    // Ensure test tenants exist in PostgreSQL
    const slugA = `tenant-rl-a-${Date.now()}`;
    const slugB = `tenant-rl-b-${Date.now()}`;
    await sql`
      INSERT INTO tenants (id, name, slug)
      VALUES (${tenantAId}, 'Rate Limit Tenant Alpha', ${slugA}),
             (${tenantBId}, 'Rate Limit Tenant Beta', ${slugB})
      ON CONFLICT (id) DO NOTHING;
    `;

    app = buildApp({
      disableLogging: true,
      enableReaper: false,
      bypassAuth: false,
      rateLimitOverrides: {
        generalMax: 50,
        scanMax: 10,
        purgeMax: 3,
      },
      apiKey: apiKeyA,
      adminKey: adminKey,
      tenantKeyMap: {
        [apiKeyA]: { role: 'operator', tenantId: tenantAId },
        [apiKeyB]: { role: 'operator', tenantId: tenantBId },
        [adminKey]: { role: 'admin', tenantId: '00000000-0000-0000-0000-000000000000' },
      },
    });

    await app.ready();

    // Clean up any stale records from previous runs
    try {
      await sql`DELETE FROM test_runs WHERE project_id IN (SELECT id FROM projects WHERE tenant_id IN (${tenantAId}, ${tenantBId}))`;
      await sql`DELETE FROM targets WHERE project_id IN (SELECT id FROM projects WHERE tenant_id IN (${tenantAId}, ${tenantBId}))`;
      await sql`DELETE FROM projects WHERE tenant_id IN (${tenantAId}, ${tenantBId})`;
    } catch {
      // Ignore
    }

    const testNonce = Math.random().toString(36).substring(7);

    // 1. Seed Tenant A Project, Target, Run
    const projARes = await app.inject({
      method: 'POST',
      url: '/api/v1/projects',
      headers: { authorization: `Bearer ${apiKeyA}` },
      payload: { name: `Rate Limit Project A ${testNonce}`, description: 'Tenant A test project' },
    });
    expect(projARes.statusCode).toBe(201);
    projectAId = JSON.parse(projARes.body).data.id;

    const targetARes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectAId}/targets`,
      headers: { authorization: `Bearer ${apiKeyA}` },
      payload: {
        name: 'Target A',
        baseUrl: 'http://127.0.0.1:4000',
        allowedHosts: ['127.0.0.1', 'localhost'],
        allowedPorts: [4000],
        testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
        limits: { maxConcurrency: 2, maxRps: 10, maxDuration: '2m' },
      },
    });
    expect(targetARes.statusCode).toBe(201);
    targetAId = JSON.parse(targetARes.body).data.id;

    const runARes = await app.inject({
      method: 'POST',
      url: '/api/v1/test-runs',
      headers: { authorization: `Bearer ${apiKeyA}` },
      payload: { projectId: projectAId, targetId: targetAId, profileId: 'quick-security', type: 'scheduled' },
    });
    expect(runARes.statusCode).toBe(201);
    testRunAId = JSON.parse(runARes.body).data.id;

    // 2. Seed Tenant B Project, Target, Run
    const projBRes = await app.inject({
      method: 'POST',
      url: '/api/v1/projects',
      headers: { authorization: `Bearer ${apiKeyB}` },
      payload: { name: `Rate Limit Project B ${testNonce}`, description: 'Tenant B test project' },
    });
    expect(projBRes.statusCode).toBe(201);
    projectBId = JSON.parse(projBRes.body).data.id;

    const targetBRes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectBId}/targets`,
      headers: { authorization: `Bearer ${apiKeyB}` },
      payload: {
        name: 'Target B',
        baseUrl: 'http://127.0.0.1:4000',
        allowedHosts: ['127.0.0.1', 'localhost'],
        allowedPorts: [4000],
        testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
        limits: { maxConcurrency: 2, maxRps: 10, maxDuration: '2m' },
      },
    });
    expect(targetBRes.statusCode).toBe(201);
    targetBId = JSON.parse(targetBRes.body).data.id;

    const runBRes = await app.inject({
      method: 'POST',
      url: '/api/v1/test-runs',
      headers: { authorization: `Bearer ${apiKeyB}` },
      payload: { projectId: projectBId, targetId: targetBId, profileId: 'quick-security', type: 'scheduled' },
    });
    expect(runBRes.statusCode).toBe(201);
    testRunBId = JSON.parse(runBRes.body).data.id;
  });

  afterAll(async () => {
    const { sql } = getDatabase();
    try {
      if (testRunAId) await sql`DELETE FROM test_runs WHERE id = ${testRunAId}`;
      if (testRunBId) await sql`DELETE FROM test_runs WHERE id = ${testRunBId}`;
      if (targetAId) await sql`DELETE FROM targets WHERE id = ${targetAId}`;
      if (targetBId) await sql`DELETE FROM targets WHERE id = ${targetBId}`;
      if (projectAId) await sql`DELETE FROM projects WHERE id = ${projectAId}`;
      if (projectBId) await sql`DELETE FROM projects WHERE id = ${projectBId}`;
    } catch {
      // Ignore cleanup errors
    }
    await app.close();
    await closeDatabase();
  });

  // ===========================================================================
  // 1. Scan Execution Throttling & Burst Testing (10 req/min)
  // ===========================================================================
  describe('Expensive Scan Execution Throttling', () => {
    it('enforces a strict limit of 10 scan executions per minute and returns standard RFC 6585 429', async () => {
      // runARes in beforeAll was request 1 for apiKeyA under tenantA
      // Execute 9 more times (requests 2 to 10)
      for (let i = 2; i <= 10; i++) {
        const res = await app.inject({
          method: 'POST',
          url: `/api/v1/test-runs/${testRunAId}/execute`,
          headers: { authorization: `Bearer ${apiKeyA}` },
          payload: { wait: false },
        });
        expect([200, 202]).toContain(res.statusCode);
      }

      // 11th request must be throttled with HTTP 429
      const throttledRes = await app.inject({
        method: 'POST',
        url: `/api/v1/test-runs/${testRunAId}/execute`,
        headers: { authorization: `Bearer ${apiKeyA}` },
        payload: { wait: false },
      });

      expect(throttledRes.statusCode).toBe(429);

      const body = JSON.parse(throttledRes.body);
      expect(body.statusCode).toBe(429);
      expect(body.error).toBe('Too Many Requests');
      expect(body.message).toContain('Rate limit exceeded for scan execution');
      expect(body.retryAfter).toBeGreaterThan(0);

      // Verify RFC 6585 Retry-After header
      const retryAfterHeader = throttledRes.headers['retry-after'];
      expect(retryAfterHeader).toBeDefined();
      expect(Number(retryAfterHeader)).toBeGreaterThan(0);
    });

    it('applies the scan execution rate limit to POST /api/v1/test-runs/execute alias', async () => {
      const throttledRes = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs/execute',
        headers: { authorization: `Bearer ${apiKeyA}` },
        payload: { testRunId: testRunAId, wait: false },
      });

      // Since tenant A has reached its scan limit, alias is also blocked with 429
      expect(throttledRes.statusCode).toBe(429);
      const body = JSON.parse(throttledRes.body);
      expect(body.statusCode).toBe(429);
      expect(body.message).toContain('Rate limit exceeded for scan execution');
    });
  });

  // ===========================================================================
  // 2. Anti-Header Tampering & Tenant Isolation
  // ===========================================================================
  describe('Anti-Header Tampering & Tenant Isolation', () => {
    it('does NOT permit rate limit bypass by cycling arbitrary client IP or custom headers', async () => {
      // apiKeyA has reached its scan limit. Sending varying spoofed IP headers must still be throttled with 429
      for (const spoofedIp of ['10.0.0.1', '192.168.1.50', '172.16.0.22', '127.0.0.2']) {
        const res = await app.inject({
          method: 'POST',
          url: `/api/v1/test-runs/${testRunAId}/execute`,
          headers: {
            authorization: `Bearer ${apiKeyA}`,
            'x-forwarded-for': spoofedIp,
            'x-real-ip': spoofedIp,
          },
          payload: { wait: false },
        });

        expect(res.statusCode).toBe(429);
        const body = JSON.parse(res.body);
        expect(body.statusCode).toBe(429);
        expect(body.error).toBe('Too Many Requests');
      }
    });

    it('blocks spoofed x-tenant-id attempts without bypassing rate limits', async () => {
      // Non-admin operator attempting to cycle arbitrary x-tenant-id headers is blocked (403 or 429)
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/test-runs/${testRunAId}/execute`,
        headers: {
          authorization: `Bearer ${apiKeyA}`,
          'x-tenant-id': '00000000-0000-0000-0000-000000000000',
        },
        payload: { wait: false },
      });

      expect([403, 429]).toContain(res.statusCode);
    });

    it('isolates rate limit buckets between distinct authenticated credentials', async () => {
      // apiKeyA is throttled, but apiKeyB has only used 1 scan creation and should succeed
      const resB = await app.inject({
        method: 'POST',
        url: `/api/v1/test-runs/${testRunBId}/execute`,
        headers: { authorization: `Bearer ${apiKeyB}` },
        payload: { wait: false },
      });

      expect([200, 202]).toContain(resB.statusCode);
      expect(resB.statusCode).not.toBe(429);
    });
  });

  // ===========================================================================
  // 3. Administrative Purge Throttling (3 req / 5 min)
  // ===========================================================================
  describe('Administrative Purge Throttling', () => {
    it('enforces a strict limit of 3 purge requests per 5 minutes and returns 429 on 4th', async () => {
      // 3 purge requests with Admin key
      for (let i = 1; i <= 3; i++) {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/management/purge',
          headers: { authorization: `Bearer ${adminKey}` },
          payload: {
            mode: 'test_runs',
            confirmation: 'INVALID_CONFIRMATION', // fails payload validation (400) but consumes rate counter
          },
        });

        expect(res.statusCode).toBe(400); // validated, not throttled
      }

      // 4th purge request must return 429
      const throttledRes = await app.inject({
        method: 'POST',
        url: '/api/v1/management/purge',
        headers: { authorization: `Bearer ${adminKey}` },
        payload: {
          mode: 'test_runs',
          confirmation: 'INVALID_CONFIRMATION',
        },
      });

      expect(throttledRes.statusCode).toBe(429);
      const body = JSON.parse(throttledRes.body);
      expect(body.statusCode).toBe(429);
      expect(body.error).toBe('Too Many Requests');
      expect(body.message).toContain('Rate limit exceeded for administrative purge operations');
      expect(throttledRes.headers['retry-after']).toBeDefined();
    });
  });

  // ===========================================================================
  // 4. SSE Telemetry Stream Exemption
  // ===========================================================================
  describe('SSE Telemetry Stream Exemption', () => {
    it('exempts /api/v1/test-runs/:id/stream from rate limits, allowing repeated connections', async () => {
      // Client accesses stream 25 consecutive times with apiKeyA (which is currently throttled on scan execution)
      for (let i = 0; i < 25; i++) {
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/test-runs/${testRunAId}/stream?snapshot=true`,
          headers: { authorization: `Bearer ${apiKeyA}` },
        });

        // Must NOT return 429
        expect(res.statusCode).not.toBe(429);
        expect(res.statusCode).toBe(200);
        expect(res.headers['content-type']).toContain('text/event-stream');
        expect(res.body).toContain('event: init');
      }
    });
  });
});
