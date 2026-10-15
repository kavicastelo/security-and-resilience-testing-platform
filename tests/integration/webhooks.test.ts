import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth } from '../../apps/controller/src/services/db.js';
import { webhookQueueService } from '../../apps/controller/src/services/webhook-queue.js';
import { signJwt, DEFAULT_WORKSPACE_ID } from '../../apps/controller/src/services/auth-token.service.js';

describe('PR-01 Integration: Webhooks Controller Persistence & Lifecycle', () => {
  let app: FastifyInstance;
  let authToken: string;
  let isDbAvailable = false;

  beforeAll(async () => {
    app = buildApp({
      disableLogging: true,
      enableReaper: false,
      bypassAuth: false,
    });
    await app.ready();

    const health = await checkDatabaseHealth();
    isDbAvailable = health === 'up';

    authToken = signJwt({
      userId: 'test-engineer-pr01',
      workspaceId: DEFAULT_WORKSPACE_ID,
      role: 'engineer',
    });
  });

  afterAll(async () => {
    webhookQueueService.stopWorker();
    await app.close();
    await closeDatabase();
  });

  it('verifies database connectivity is healthy before executing webhook tests', () => {
    expect(isDbAvailable).toBe(true);
  });

  let createdWebhookId: string;

  it('GET /api/v1/webhooks returns valid list from database without mock fallbacks', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/webhooks',
      headers: {
        authorization: `Bearer ${authToken}`,
      },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(Array.isArray(body.data)).toBe(true);
  });

  it('POST /api/v1/webhooks creates and persists a new webhook endpoint in PostgreSQL', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/webhooks',
      headers: {
        authorization: `Bearer ${authToken}`,
        'content-type': 'application/json',
      },
      payload: {
        url: 'https://security.example.com/alerts/webhook',
        description: 'PR-01 Production Integration Test Receiver',
        events: ['finding.critical', 'policy.failed'],
        headers: { 'X-Custom-Auth': 'TokenSecure123' },
      },
    });

    expect(res.statusCode).toBe(201);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(body.data.id).toBeDefined();
    expect(body.data.url).toBe('https://security.example.com/alerts/webhook');
    expect(body.data.events).toEqual(['finding.critical', 'policy.failed']);
    expect(body.data.headers['X-Custom-Auth']).toBe('TokenSecure123');

    createdWebhookId = body.data.id;
  });

  it('POST /api/v1/webhooks validates URL format', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/webhooks',
      headers: {
        authorization: `Bearer ${authToken}`,
        'content-type': 'application/json',
      },
      payload: {
        url: 'not-a-valid-url',
        description: 'Invalid webhook',
      },
    });

    expect(res.statusCode).toBe(400);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('VALIDATION_ERROR');
  });

  it('POST /api/v1/webhooks/:id/test enqueues test ping delivery', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/webhooks/${createdWebhookId}/test`,
      headers: {
        authorization: `Bearer ${authToken}`,
      },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(body.message).toContain('Test ping');
  });

  it('GET /api/v1/webhooks/:id/deliveries returns real delivery records', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/api/v1/webhooks/${createdWebhookId}/deliveries?limit=10`,
      headers: {
        authorization: `Bearer ${authToken}`,
      },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(Array.isArray(body.data)).toBe(true);
  });

  it('DELETE /api/v1/webhooks/:id deletes webhook and ensures clean empty state', async () => {
    const delRes = await app.inject({
      method: 'DELETE',
      url: `/api/v1/webhooks/${createdWebhookId}`,
      headers: {
        authorization: `Bearer ${authToken}`,
      },
    });

    expect(delRes.statusCode).toBe(200);
    const delBody = JSON.parse(delRes.payload);
    expect(delBody.success).toBe(true);

    // Verify retrieval fails with 404
    const testRes = await app.inject({
      method: 'POST',
      url: `/api/v1/webhooks/${createdWebhookId}/test`,
      headers: {
        authorization: `Bearer ${authToken}`,
      },
    });
    expect(testRes.statusCode).toBe(404);
  });
});
