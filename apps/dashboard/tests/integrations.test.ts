import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  generateHmacSecret,
  generateGitHubActionYaml,
  createWebhook,
  deleteWebhook,
  testWebhookPing,
  dispatchTestPing,
  fetchWebhooks,
  fetchWebhookDeliveries,
  WorkflowGeneratorOptions,
  WebhookRecord,
  WebhookDeliveryRecord,
} from '../src/api/webhooks.js';

describe('Phase UI-16 / PR-01: CI/CD Integrations Hub, HMAC-SHA256 Webhook Manager & Issue Sync Console', () => {
  describe('Cryptographic HMAC Secret Generation', () => {
    it('generates a 64-character hexadecimal signing secret', () => {
      const secret = generateHmacSecret();
      expect(secret).toHaveLength(64);
      expect(/^[0-9a-f]{64}$/.test(secret)).toBe(true);
    });

    it('generates unique keys on successive invocations', () => {
      const s1 = generateHmacSecret();
      const s2 = generateHmacSecret();
      const s3 = generateHmacSecret();

      expect(s1).not.toBe(s2);
      expect(s2).not.toBe(s3);
      expect(s1).not.toBe(s3);
    });
  });

  describe('GitHub Actions Workflow YAML Generator', () => {
    const baseOptions: WorkflowGeneratorOptions = {
      triggerEvents: ['push', 'pull_request', 'workflow_dispatch'],
      targetUrl: 'https://api.acme-corp.internal',
      policyId: 'strict-zero-tolerance',
      failOnPolicyBreach: true,
      uploadSarif: true,
      postPrComment: true,
      runnerMode: 'controller-api',
      scanTimeoutMinutes: 20,
    };

    it('generates a valid, complete GitHub Actions YAML workflow document', () => {
      const yaml = generateGitHubActionYaml(baseOptions);

      expect(yaml).toContain('name: Security Lab Continuous Verification');
      expect(yaml).toContain('push:');
      expect(yaml).toContain('pull_request:');
      expect(yaml).toContain('workflow_dispatch:');
      expect(yaml).toContain('runs-on: ubuntu-latest');
      expect(yaml).toContain('timeout-minutes: 20');
      expect(yaml).toContain("target-url: ${{ github.event.inputs.target_override || 'https://api.acme-corp.internal' }}");
      expect(yaml).toContain("policy-id: 'strict-zero-tolerance'");
      expect(yaml).toContain("fail-on-breach: 'true'");
    });

    it('includes SARIF upload step when uploadSarif is true', () => {
      const yaml = generateGitHubActionYaml({ ...baseOptions, uploadSarif: true });
      expect(yaml).toContain('uses: github/codeql-action/upload-sarif@v3');
      expect(yaml).toContain("category: 'security-lab-suite'");
    });

    it('omits SARIF upload step when uploadSarif is false', () => {
      const yaml = generateGitHubActionYaml({ ...baseOptions, uploadSarif: false });
      expect(yaml).not.toContain('uses: github/codeql-action/upload-sarif@v3');
    });

    it('includes PR comment bot step when postPrComment is true', () => {
      const yaml = generateGitHubActionYaml({ ...baseOptions, postPrComment: true });
      expect(yaml).toContain('uses: actions/github-script@v7');
      expect(yaml).toContain('github.rest.issues.createComment');
      expect(yaml).toContain('Security Lab Verification Gate Summary');
    });

    it('omits PR comment bot step when postPrComment is false', () => {
      const yaml = generateGitHubActionYaml({ ...baseOptions, postPrComment: false });
      expect(yaml).not.toContain('actions/github-script@v7');
    });

    it('includes cron schedule trigger when schedule is enabled', () => {
      const yaml = generateGitHubActionYaml({
        ...baseOptions,
        triggerEvents: ['schedule'],
      });
      expect(yaml).toContain('schedule:');
      expect(yaml).toContain("cron: '0 2 * * *'");
      expect(yaml).not.toContain('push:');
      expect(yaml).not.toContain('pull_request:');
    });
  });

  describe('Webhook Manager Controller API Operations (Zero In-Memory Mock)', () => {
    let originalFetch: typeof globalThis.fetch;

    beforeEach(() => {
      originalFetch = globalThis.fetch;
    });

    afterEach(() => {
      globalThis.fetch = originalFetch;
      vi.restoreAllMocks();
    });

    it('lists registered webhooks from controller API and returns empty array on clean database', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ success: true, data: [] }),
      });

      const list = await fetchWebhooks();
      expect(Array.isArray(list)).toBe(true);
      expect(list).toHaveLength(0); // Clean empty state without ghost mock items
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/webhooks'),
        expect.any(Object),
      );
    });

    it('throws descriptive error on server failure without reverting to synthetic data', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        json: async () => ({
          success: false,
          error: { message: 'Database connection failed' },
        }),
      });

      await expect(fetchWebhooks()).rejects.toThrow('Database connection failed');
    });

    it('creates a new webhook endpoint via POST /api/v1/webhooks', async () => {
      const mockCreated: WebhookRecord = {
        id: 'wh-prod-001',
        workspaceId: '00000000-0000-0000-0000-000000000000',
        url: 'https://security.webhook.site/v1/test',
        description: 'Automated Test Receiver',
        events: ['run.completed', 'finding.critical'],
        isActive: true,
        headers: { 'X-Environment': 'IntegrationTest' },
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 201,
        json: async () => ({ success: true, data: mockCreated }),
      });

      const secret = generateHmacSecret();
      const created = await createWebhook({
        url: 'https://security.webhook.site/v1/test',
        description: 'Automated Test Receiver',
        secret,
        events: ['run.completed', 'finding.critical'],
        headers: { 'X-Environment': 'IntegrationTest' },
      });

      expect(created.id).toBe('wh-prod-001');
      expect(created.url).toBe('https://security.webhook.site/v1/test');
      expect(created.events).toEqual(['run.completed', 'finding.critical']);
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/webhooks'),
        expect.objectContaining({
          method: 'POST',
        }),
      );
    });

    it('dispatches test ping and parses server delivery record', async () => {
      const mockDelivery: WebhookDeliveryRecord = {
        id: 'del-test-001',
        webhookId: 'wh-prod-001',
        workspaceId: '00000000-0000-0000-0000-000000000000',
        eventType: 'ping',
        payload: { event: 'ping', message: 'Test Ping' },
        status: 'succeeded',
        attempts: 1,
        maxAttempts: 5,
        nextRetryAt: new Date().toISOString(),
        lastAttemptAt: new Date().toISOString(),
        responseStatusCode: 200,
        responseBody: 'ok',
        lastError: null,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          success: true,
          message: 'Test ping enqueued for delivery',
          data: mockDelivery,
        }),
      });

      const result = await testWebhookPing('wh-prod-001');
      expect(result.success).toBe(true);
      expect(result.delivery?.id).toBe('del-test-001');
      expect(result.delivery?.responseStatusCode).toBe(200);

      // Verify dispatchTestPing alias functions identically
      const aliasResult = await dispatchTestPing('wh-prod-001');
      expect(aliasResult.success).toBe(true);
    });

    it('deletes an existing webhook endpoint via DELETE /api/v1/webhooks/:id', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ success: true, message: 'Webhook deleted successfully' }),
      });

      const deleted = await deleteWebhook('wh-prod-001');
      expect(deleted).toBe(true);
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/webhooks/wh-prod-001'),
        expect.objectContaining({
          method: 'DELETE',
        }),
      );
    });

    it('fetches real deliveries from controller API with limit parameter', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          success: true,
          data: [
            {
              id: 'del-01',
              webhookId: 'wh-prod-001',
              workspaceId: '00000000-0000-0000-0000-000000000000',
              eventType: 'finding.critical',
              payload: { findingId: 'f-1' },
              status: 'succeeded',
              attempts: 1,
              maxAttempts: 5,
              nextRetryAt: new Date().toISOString(),
              createdAt: new Date().toISOString(),
              updatedAt: new Date().toISOString(),
            },
          ],
        }),
      });

      const deliveries = await fetchWebhookDeliveries('wh-prod-001', 25);
      expect(deliveries).toHaveLength(1);
      expect(deliveries[0].eventType).toBe('finding.critical');
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/webhooks/wh-prod-001/deliveries?limit=25'),
        expect.any(Object),
      );
    });
  });
});
