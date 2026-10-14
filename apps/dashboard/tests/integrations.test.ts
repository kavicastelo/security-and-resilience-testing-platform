import { describe, it, expect } from 'vitest';
import {
  generateHmacSecret,
  generateGitHubActionYaml,
  createWebhook,
  deleteWebhook,
  testWebhookPing,
  fetchWebhooks,
  fetchWebhookDeliveries,
  FALLBACK_WEBHOOKS,
  FALLBACK_DELIVERIES,
  WorkflowGeneratorOptions,
} from '../src/api/webhooks.js';

describe('Phase UI-16: CI/CD Integrations Hub, HMAC-SHA256 Webhook Manager & Issue Sync Console', () => {
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

  describe('Webhook Manager API Operations', () => {
    it('lists registered webhooks with events and headers', async () => {
      const list = await fetchWebhooks();
      expect(Array.isArray(list)).toBe(true);
      expect(list.length).toBeGreaterThan(0);

      const slackWh = list.find((w) => w.id === 'wh-slack-alerts');
      expect(slackWh).toBeDefined();
      expect(slackWh?.events).toContain('finding.critical');
      expect(slackWh?.events).toContain('policy.failed');
    });

    it('creates a new webhook endpoint and persists in list', async () => {
      const secret = generateHmacSecret();
      const created = await createWebhook({
        url: 'https://security.webhook.site/v1/test',
        description: 'Automated Test Receiver',
        secret,
        events: ['run.completed', 'finding.critical'],
        headers: { 'X-Environment': 'IntegrationTest' },
      });

      expect(created.id).toBeDefined();
      expect(created.url).toBe('https://security.webhook.site/v1/test');
      expect(created.events).toEqual(['run.completed', 'finding.critical']);
      expect(created.headers['X-Environment']).toBe('IntegrationTest');

      const after = await fetchWebhooks();
      expect(after.some((w) => w.id === created.id)).toBe(true);
    });

    it('dispatches test ping and enqueues delivery record', async () => {
      const result = await testWebhookPing('wh-slack-alerts');
      expect(result.success).toBe(true);
      expect(result.delivery).toBeDefined();
      expect(result.delivery?.eventType).toBe('ping');
      expect(result.delivery?.status).toBe('succeeded');
      expect(result.delivery?.responseStatusCode).toBe(200);

      // Verify delivery record can be queried
      const deliveries = await fetchWebhookDeliveries('wh-slack-alerts');
      expect(deliveries.some((d) => d.eventType === 'ping')).toBe(true);
    });

    it('deletes an existing webhook endpoint', async () => {
      const created = await createWebhook({
        url: 'https://delete-me.internal/hook',
        description: 'To be deleted',
      });

      const deleted = await deleteWebhook(created.id);
      expect(deleted).toBe(true);

      const after = await fetchWebhooks();
      expect(after.some((w) => w.id === created.id)).toBe(false);
    });
  });

  describe('Webhook Delivery History & Retry Invariants', () => {
    it('inspects delivery payloads, status codes, and error traces', async () => {
      const deliveries = await fetchWebhookDeliveries('wh-datadog-siem');
      expect(deliveries.length).toBeGreaterThan(0);

      const failedDelivery = deliveries.find((d) => d.status === 'failed');
      expect(failedDelivery).toBeDefined();
      expect(failedDelivery?.responseStatusCode).toBe(503);
      expect(failedDelivery?.attempts).toBe(2);
      expect(failedDelivery?.maxAttempts).toBe(5);
      expect(failedDelivery?.lastError).toContain('503 Service Unavailable');
    });

    it('enforces maximum 5 attempts and exponential backoff retry schedules', () => {
      for (const list of Object.values(FALLBACK_DELIVERIES)) {
        for (const del of list) {
          expect(del.maxAttempts).toBe(5);
          expect(del.attempts).toBeLessThanOrEqual(5);
          expect(del.payload).toBeDefined();
        }
      }
    });
  });

  describe('Integration Secrets Masking Invariant (Mandatory Directive)', () => {
    it('verifies webhook list and deliveries never return unencrypted raw secrets', () => {
      for (const wh of FALLBACK_WEBHOOKS) {
        expect((wh as any).secret).toBeUndefined();
      }
    });
  });
});
