import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { webhookQueueService } from '../../apps/controller/src/services/webhook-queue.js';
import { signJwt, DEFAULT_WORKSPACE_ID } from '../../apps/controller/src/services/auth-token.service.js';

describe('PR-04 Integration: Resilience & Chaos Workbench Controller APIs', () => {
  let app: FastifyInstance;
  let authToken: string;
  let testTargetId: string;
  let strictTargetId: string;

  beforeAll(async () => {
    app = buildApp({
      disableLogging: true,
      enableReaper: false,
      bypassAuth: false,
    });
    await app.ready();

    authToken = signJwt({
      userId: 'test-resilience-architect',
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
        name: `Resilience Project ${Date.now()}`,
        description: 'Integration test target project',
      },
    });
    const projBody = JSON.parse(projRes.body);
    const projectId = projBody.data.id;

    // 2. Create an authorized test target with defined scope limits
    const targetRes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectId}/targets`,
      headers: {
        authorization: `Bearer ${authToken}`,
      },
      payload: {
        name: 'Resilience Test Core API',
        baseUrl: 'https://staging.security-lab.local',
        allowedHosts: ['staging.security-lab.local'],
        allowedPorts: [443],
        excludedPaths: ['/admin/*'],
        testing: {
          activeScanning: true,
          loadTesting: true,
          chaosTesting: true,
        },
        limits: {
          maxRps: 100,
          maxConcurrency: 25,
        },
      },
    });
    const targetBody = JSON.parse(targetRes.body);
    testTargetId = targetBody.data.id;

    // 3. Create a strict target with chaosTesting disabled
    const strictRes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectId}/targets`,
      headers: {
        authorization: `Bearer ${authToken}`,
      },
      payload: {
        name: 'Strict Target No Chaos',
        baseUrl: 'https://strict.internal.local',
        allowedHosts: ['strict.internal.local'],
        allowedPorts: [443],
        excludedPaths: ['/admin/*'],
        testing: {
          chaosTesting: false,
        },
        limits: {
          maxRps: 10,
          maxConcurrency: 2,
        },
      },
    });
    const strictBody = JSON.parse(strictRes.body);
    strictTargetId = strictBody.data.id;
  });

  afterAll(async () => {
    webhookQueueService.stopWorker();
    await app.close();
  });

  describe('Chaos Fault Injection API (/api/v1/resilience/chaos/execute)', () => {
    it('executes live fault injection simulation within target scope limits', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/resilience/chaos/execute',
        headers: {
          authorization: `Bearer ${authToken}`,
        },
        payload: {
          targetId: testTargetId,
          targetEndpoint: '/api/v1/checkout',
          latencyMs: 120,
          jitterMs: 25,
          packetDropRate: 5,
          errorInjectionRate: 15,
          errorStatusCode: 503,
          circuitBreakerEnabled: true,
          circuitBreakerThreshold: 5,
          activePreset: 'slow_3g',
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.success).toBe(true);
      expect(body.stats).toBeDefined();
      expect(body.stats.status).toBe('completed');
      expect(body.stats.circuitBreakerState).toBe('CLOSED');
      expect(body.stats.totalRequests).toBe(100);
      expect(body.stats.resilienceScore).toBeGreaterThanOrEqual(0);
      expect(body.timeline).toBeDefined();
      expect(body.timeline.length).toBeGreaterThan(0);
    });

    it('enforces safety circuit breaker when error injection rate exceeds 50%', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/resilience/chaos/execute',
        headers: {
          authorization: `Bearer ${authToken}`,
        },
        payload: {
          targetId: testTargetId,
          targetEndpoint: '/api/v1/orders',
          latencyMs: 500,
          jitterMs: 100,
          packetDropRate: 20,
          errorInjectionRate: 65, // > 50% must trip circuit breaker
          errorStatusCode: 500,
          circuitBreakerEnabled: true,
          circuitBreakerThreshold: 3,
          activePreset: 'dependency_outage',
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.success).toBe(true);
      expect(body.stats.status).toBe('tripped');
      expect(body.stats.circuitBreakerState).toBe('HALF_OPEN');
      expect(body.message).toContain('Safety circuit breaker activated');
    });

    it('blocks execution when target policy has chaos testing disabled', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/resilience/chaos/execute',
        headers: {
          authorization: `Bearer ${authToken}`,
        },
        payload: {
          targetId: strictTargetId,
          targetEndpoint: '/api/v1/payments',
          latencyMs: 100,
        },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('CHAOS_TESTING_DISABLED');
    });
  });

  describe('Business Logic State Machine API (/api/v1/resilience/business-logic/state-machine)', () => {
    it('executes state machine verification and detects bypass opportunities', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/resilience/business-logic/state-machine',
        headers: {
          authorization: `Bearer ${authToken}`,
        },
        payload: {
          targetId: testTargetId,
          workflowName: 'E-Commerce Order Checkout',
          states: [
            { id: 'cart', name: 'Initialize Cart', method: 'POST', path: '/api/cart', order: 0 },
            { id: 'items', name: 'Add Items', method: 'PUT', path: '/api/cart/items', order: 1 },
            { id: 'pay', name: 'Process Payment', method: 'POST', path: '/api/cart/checkout', order: 2, isPaymentOrTerminal: true },
            { id: 'fulfill', name: 'Fulfill Order', method: 'POST', path: '/api/cart/fulfill', order: 3, isTerminal: true },
          ],
          transitions: [
            { fromStepId: 'cart', toStepId: 'items', isAllowed: true },
            { fromStepId: 'items', toStepId: 'pay', isAllowed: true },
            { fromStepId: 'pay', toStepId: 'fulfill', isAllowed: true },
            { fromStepId: 'items', toStepId: 'fulfill', isAllowed: false }, // Illegal skip
          ],
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.success).toBe(true);
      expect(body.data.workflowId).toBeDefined();
      expect(body.data.states.length).toBe(4);
      expect(body.data.transitions.length).toBe(4);
      expect(body.data.bypassExploits).toBeDefined();
    });

    it('GET /api/v1/resilience/business-logic/state-machine returns model', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/resilience/business-logic/state-machine',
        headers: {
          authorization: `Bearer ${authToken}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.success).toBe(true);
      expect(body.data).toBeDefined();
      expect(body.data.states).toBeDefined();
    });
  });

  describe('Synchronized Socket Race Condition API (/api/v1/resilience/business-logic/race-condition)', () => {
    it('rejects burst when concurrency exceeds target maxConcurrency limit', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/resilience/business-logic/race-condition',
        headers: {
          authorization: `Bearer ${authToken}`,
        },
        payload: {
          targetId: testTargetId,
          endpoint: '/api/v1/coupons/redeem',
          method: 'POST',
          concurrency: 50, // Limit is 25 in target scope
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('CONCURRENCY_EXCEEDS_LIMIT');
      expect(body.error.message).toContain('exceeds target scope maximum allowable concurrency of 25');
    });

    it('executes synchronized burst test within concurrency limits', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/resilience/business-logic/race-condition',
        headers: {
          authorization: `Bearer ${authToken}`,
        },
        payload: {
          targetId: testTargetId,
          endpoint: '/api/v1/coupons/redeem',
          method: 'POST',
          concurrency: 10,
          payload: { couponCode: 'PROMO-ZERO-COST' },
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.success).toBe(true);
      expect(body.data.concurrency).toBe(10);
      expect(body.data.requests.length).toBe(10);
      expect(body.data.barrierReleaseJitterMs).toBeDefined();
      expect(body.data.remediation).toBeDefined();
    });

    it('GET /api/v1/resilience/business-logic/race-condition returns model', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/resilience/business-logic/race-condition',
        headers: {
          authorization: `Bearer ${authToken}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.success).toBe(true);
      expect(body.data).toBeDefined();
    });
  });

  describe('Chaos Experiments History API (/api/v1/resilience/experiments)', () => {
    it('returns history of executed chaos experiments for workspace', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/resilience/experiments',
        headers: {
          authorization: `Bearer ${authToken}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.success).toBe(true);
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.data.length).toBeGreaterThan(0);
      expect(body.data[0].stats).toBeDefined();
    });
  });
});
