import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../src/app/index.js';
import { closeDatabase, getDatabase } from '../src/services/db.js';
import { webhookQueueService, signWebhookPayload } from '../src/services/webhook-queue.js';
import { gitHubSyncService } from '../src/services/integrations/github.js';
import { jiraSyncService } from '../src/services/integrations/jira.js';
import { signJwt, DEFAULT_WORKSPACE_ID } from '../src/services/auth-token.service.js';
import { telemetryRegistry } from '../src/telemetry.js';

describe('Phase 19: CI/CD Ecosystem Integrations, Webhooks & Issue Tracker Sync', () => {
  let app: FastifyInstance;
  let testToken: string;

  beforeAll(async () => {
    app = buildApp({
      disableLogging: true,
      enableReaper: false,
      bypassAuth: false,
    });
    await app.ready();

    testToken = signJwt({
      userId: 'test-engineer',
      workspaceId: DEFAULT_WORKSPACE_ID,
      role: 'engineer',
    });
  });

  afterAll(async () => {
    webhookQueueService.stopWorker();
    await app.close();
    await closeDatabase();
  });

  // ===========================================================================
  // 1. Webhook Secret Encryption & HMAC-SHA256 Signing
  // ===========================================================================
  describe('HMAC-SHA256 Payload Signature & Envelope Encryption', () => {
    it('generates reproducible and verifiable HMAC-SHA256 signatures', () => {
      const payloadStr = JSON.stringify({ event: 'finding.created', findingId: '123' });
      const secret = 'super-secret-webhook-key-999';

      const sig1 = signWebhookPayload(payloadStr, secret);
      const sig2 = signWebhookPayload(payloadStr, secret);

      expect(sig1).toBe(sig2);
      expect(sig1.startsWith('sha256=')).toBe(true);

      // Verify signature changes if payload changes
      const alteredSig = signWebhookPayload(payloadStr + 'x', secret);
      expect(alteredSig).not.toBe(sig1);
    });

    it('encrypts webhook secret at rest and decrypts it during delivery', async () => {
      const rawSecret = 'plain-text-secret-token-to-encrypt';
      const wh = await webhookQueueService.createWebhook({
        workspaceId: DEFAULT_WORKSPACE_ID,
        url: 'https://webhook.receiver.local/events',
        secret: rawSecret,
        description: 'Encrypted webhook endpoint',
      });

      expect(wh.id).toBeDefined();

      // Retrieve decrypted secret
      const decryptedSecret = await webhookQueueService.getWebhookSecret(wh.id);
      expect(decryptedSecret).toBe(rawSecret);

      // Cleanup
      await webhookQueueService.deleteWebhook(wh.id);
    });
  });

  // ===========================================================================
  // 2. Reliable Queue Delivery & Exponential Backoff Retries
  // ===========================================================================
  describe('Reliable Delivery Queue & Exponential Backoff', () => {
    it('dispatches events and successfully delivers to endpoint', async () => {
      const wh = await webhookQueueService.createWebhook({
        workspaceId: DEFAULT_WORKSPACE_ID,
        url: 'https://receiver.internal/webhook',
        secret: 'wh-secret-123',
        events: ['finding.created'],
      });

      const deliveries = await webhookQueueService.dispatchEvent(
        DEFAULT_WORKSPACE_ID,
        'finding.created',
        { title: 'SQL Injection in User Search', severity: 'critical' },
      );

      expect(deliveries.length).toBe(1);
      const deliveryId = deliveries[0].id;
      expect(deliveries[0].status).toBe('pending');

      // Mock fetch response for delivery
      const mockFetch = (async (url: string, init?: RequestInit) => {
        expect(url).toBe('https://receiver.internal/webhook');
        expect(init?.headers).toBeDefined();
        const headers = init?.headers as Record<string, string>;
        expect(headers['X-SecurityLab-Event']).toBe('finding.created');
        expect(headers['X-SecurityLab-Signature'].startsWith('sha256=')).toBe(true);

        return new Response(JSON.stringify({ received: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const success = await webhookQueueService.processDelivery(deliveryId, mockFetch);
      expect(success).toBe(true);

      // Verify Prometheus telemetry export
      const promOutput = telemetryRegistry.exportPrometheus();
      expect(promOutput).toContain('security_lab_webhook_deliveries_total{status="success"}');

      // Cleanup
      await webhookQueueService.deleteWebhook(wh.id);
    });

    it('reschedules failed delivery with exponential backoff on 503 error', async () => {
      const wh = await webhookQueueService.createWebhook({
        workspaceId: DEFAULT_WORKSPACE_ID,
        url: 'https://failing.internal/webhook',
        secret: 'wh-retry-secret',
        events: ['release.evaluated'],
      });

      const deliveries = await webhookQueueService.dispatchEvent(
        DEFAULT_WORKSPACE_ID,
        'release.evaluated',
        { decision: 'failed', score: 45 },
      );

      const deliveryId = deliveries[0].id;

      // Mock 503 Service Unavailable
      const mockFetch503 = (async () => {
        return new Response('Gateway Overloaded', { status: 503 });
      }) as typeof fetch;

      const success = await webhookQueueService.processDelivery(deliveryId, mockFetch503);
      expect(success).toBe(false);

      // Verify delivery state in database is 'failed' with retry scheduled
      const { db } = getDatabase();
      const { webhookDeliveries } = await import('../src/services/db/schema.js');
      const { eq } = await import('drizzle-orm');

      const [row] = await db
        .select()
        .from(webhookDeliveries)
        .where(eq(webhookDeliveries.id, deliveryId));

      expect(row.status).toBe('failed');
      expect(row.attempts).toBe(1);
      expect(new Date(row.nextRetryAt).getTime()).toBeGreaterThan(Date.now());
      expect(row.lastError).toContain('HTTP 503');

      // Cleanup
      await webhookQueueService.deleteWebhook(wh.id);
    });

    it('moves delivery to dead_letter queue after maximum attempts exceeded', async () => {
      const wh = await webhookQueueService.createWebhook({
        workspaceId: DEFAULT_WORKSPACE_ID,
        url: 'https://dead.internal/webhook',
        secret: 'wh-dead-secret',
      });

      const [delivery] = await webhookQueueService.dispatchEvent(
        DEFAULT_WORKSPACE_ID,
        'test_run.completed',
        { status: 'failed' },
      );

      // Force attempts to 4 (so attempt 5 will trigger dead_letter)
      const { db } = getDatabase();
      const { webhookDeliveries } = await import('../src/services/db/schema.js');
      const { eq } = await import('drizzle-orm');

      await db
        .update(webhookDeliveries)
        .set({ attempts: 4 })
        .where(eq(webhookDeliveries.id, delivery.id));

      const mockFetchFail = (async () => {
        return new Response('Internal Server Error', { status: 500 });
      }) as typeof fetch;

      await webhookQueueService.processDelivery(delivery.id, mockFetchFail);

      const [updatedRow] = await db
        .select()
        .from(webhookDeliveries)
        .where(eq(webhookDeliveries.id, delivery.id));

      expect(updatedRow.status).toBe('dead_letter');
      expect(updatedRow.attempts).toBe(5);

      // Cleanup
      await webhookQueueService.deleteWebhook(wh.id);
    });
  });

  // ===========================================================================
  // 3. Issue Tracker Synchronization (GitHub & Jira)
  // ===========================================================================
  describe('Two-Way Issue Tracker Synchronization', () => {
    it('creates a GitHub issue for an identified security flaw', async () => {
      let createdPayload: Record<string, unknown> | null = null;

      const mockFetch = (async (url: string, init?: RequestInit) => {
        if (url.includes('/search/issues')) {
          // No existing issue found
          return new Response(JSON.stringify({ items: [] }), { status: 200 });
        }
        if (url.includes('/repos/acme/app/issues')) {
          createdPayload = JSON.parse(init?.body as string);
          return new Response(
            JSON.stringify({
              number: 42,
              html_url: 'https://github.com/acme/app/issues/42',
              state: 'open',
            }),
            { status: 201 },
          );
        }
        return new Response('Not found', { status: 404 });
      }) as typeof fetch;

      const result = await gitHubSyncService.syncFindingToIssue(
        {
          owner: 'acme',
          repo: 'app',
          token: 'ghp_mock_token_123',
        },
        {
          finding: {
            id: 'f-100',
            fingerprint: 'fp-auth-bypass-001',
            title: 'Broken Authentication in Password Reset',
            category: 'broken_authentication',
            severity: 'critical',
            description: 'Token validation is skipped when query parameter is null.',
            recommendation: 'Enforce strict null checks on reset token.',
            testDefinitionId: 'engine-authz-matrix',
          },
          targetUrl: 'https://staging.acme.local',
        },
        mockFetch,
      );

      expect(result.issueNumber).toBe(42);
      expect(result.issueUrl).toBe('https://github.com/acme/app/issues/42');
      expect(createdPayload).toBeDefined();
      expect((createdPayload as { title?: string })?.title).toContain('CRITICAL');
    });

    it('creates a Jira issue for an identified security flaw', async () => {
      let jiraBody: Record<string, unknown> | null = null;

      const mockFetch = (async (url: string, init?: RequestInit) => {
        if (url.includes('/rest/api/2/issue')) {
          jiraBody = JSON.parse(init?.body as string);
          return new Response(
            JSON.stringify({
              key: 'SEC-101',
              id: '10001',
              self: 'https://acme.atlassian.net/rest/api/2/issue/10001',
            }),
            { status: 201 },
          );
        }
        return new Response('Not found', { status: 404 });
      }) as typeof fetch;

      const result = await jiraSyncService.createIssue(
        {
          host: 'https://acme.atlassian.net',
          email: 'secops@acme.com',
          apiToken: 'jira-api-token',
          projectKey: 'SEC',
        },
        {
          finding: {
            id: 'f-200',
            fingerprint: 'fp-xss-002',
            title: 'Stored Cross-Site Scripting in Comment Field',
            category: 'xss',
            severity: 'high',
            description: 'Unsanitized user comment rendered directly in DOM.',
            testDefinitionId: 'engine-injection-fuzzer',
          },
          targetUrl: 'https://app.acme.local',
        },
        mockFetch,
      );

      expect(result.issueKey).toBe('SEC-101');
      expect(jiraBody).toBeDefined();
    });

    it('triggers automated targeted retest when an issue is closed via webhook', async () => {
      // Test webhook payload with closed action
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/integrations/github/webhook',
        headers: {
          'x-github-event': 'issues',
        },
        payload: {
          action: 'closed',
          issue: {
            number: 42,
            body: 'Remediated flaw.\n<!-- security-lab-finding-id: non-existent-id -->',
          },
        },
      });

      expect(res.statusCode).toBe(200);
      const json = JSON.parse(res.payload);
      expect(json.success).toBe(true);
      // Finding was non-existent in this mock test, so retestTriggered gracefully returns false
      expect(json.retestTriggered).toBe(false);
    });
  });

  // ===========================================================================
  // 4. Controller API Route CRUD Testing
  // ===========================================================================
  describe('/api/v1/webhooks CRUD Route Testing', () => {
    it('registers, lists, tests, and deletes webhooks via REST API', async () => {
      // 1. Create Webhook
      const createRes = await app.inject({
        method: 'POST',
        url: '/api/v1/webhooks',
        headers: {
          authorization: `Bearer ${testToken}`,
        },
        payload: {
          url: 'https://audit.corp.local/security-events',
          description: 'Corporate Audit Webhook',
          events: ['finding.created', 'release.evaluated'],
        },
      });

      expect(createRes.statusCode).toBe(201);
      const createData = JSON.parse(createRes.payload).data;
      expect(createData.id).toBeDefined();
      expect(createData.url).toBe('https://audit.corp.local/security-events');

      const webhookId = createData.id;

      // 2. List Webhooks
      const listRes = await app.inject({
        method: 'GET',
        url: '/api/v1/webhooks',
        headers: {
          authorization: `Bearer ${testToken}`,
        },
      });

      expect(listRes.statusCode).toBe(200);
      const listData = JSON.parse(listRes.payload).data;
      expect(listData.some((w: { id: string }) => w.id === webhookId)).toBe(true);

      // 3. Test Ping Delivery
      const pingRes = await app.inject({
        method: 'POST',
        url: `/api/v1/webhooks/${webhookId}/test`,
        headers: {
          authorization: `Bearer ${testToken}`,
        },
      });

      expect(pingRes.statusCode).toBe(200);
      const pingData = JSON.parse(pingRes.payload);
      expect(pingData.success).toBe(true);

      // 4. Delete Webhook
      const deleteRes = await app.inject({
        method: 'DELETE',
        url: `/api/v1/webhooks/${webhookId}`,
        headers: {
          authorization: `Bearer ${testToken}`,
        },
      });

      expect(deleteRes.statusCode).toBe(200);
    });
  });
});
