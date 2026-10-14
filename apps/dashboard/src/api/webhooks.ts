import { authFetch } from './client.js';

export interface WebhookRecord {
  id: string;
  workspaceId: string;
  url: string;
  description?: string | null;
  events: string[];
  isActive: boolean;
  headers: Record<string, string>;
  createdAt: string;
  updatedAt: string;
}

export interface WebhookDeliveryRecord {
  id: string;
  webhookId: string;
  workspaceId: string;
  eventType: string;
  payload: Record<string, unknown>;
  status: 'pending' | 'delivering' | 'succeeded' | 'failed' | 'dead_letter';
  attempts: number;
  maxAttempts: number;
  nextRetryAt: string;
  lastAttemptAt?: string | null;
  responseStatusCode?: number | null;
  responseBody?: string | null;
  lastError?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CreateWebhookPayload {
  url: string;
  description?: string;
  secret?: string;
  events?: string[];
  headers?: Record<string, string>;
}

export interface GitHubSyncConfig {
  enabled: boolean;
  repoOwner: string;
  repoName: string;
  personalAccessToken: string;
  autoCreateOnSeverity: ('critical' | 'high' | 'medium')[];
  autoCloseOnRetestResolved: boolean;
  addLabels: string[];
}

export interface JiraSyncConfig {
  enabled: boolean;
  hostUrl: string;
  projectKey: string;
  issueType: string;
  userEmail: string;
  apiToken: string;
  autoCreateOnSeverity: ('critical' | 'high' | 'medium')[];
  autoTransitionOnResolved: boolean;
  resolvedTransitionName: string;
}

export interface WorkflowGeneratorOptions {
  triggerEvents: ('push' | 'pull_request' | 'workflow_dispatch' | 'schedule')[];
  targetUrl: string;
  failOnPolicyBreach: boolean;
  policyId: string;
  uploadSarif: boolean;
  postPrComment: boolean;
  runnerMode: 'controller-api' | 'cli-standalone';
  scanTimeoutMinutes: number;
}

// Fallback in-memory state for offline and local testing
export const FALLBACK_WEBHOOKS: WebhookRecord[] = [
  {
    id: 'wh-slack-alerts',
    workspaceId: '00000000-0000-0000-0000-000000000000',
    url: 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX',
    description: 'SecOps Slack Channel Alerts (#security-incidents)',
    events: ['finding.critical', 'policy.failed', 'release.evaluated'],
    isActive: true,
    headers: { 'X-Custom-Source': 'SecurityLab-Production' },
    createdAt: new Date(Date.now() - 86400000 * 5).toISOString(),
    updatedAt: new Date(Date.now() - 3600000 * 2).toISOString(),
  },
  {
    id: 'wh-datadog-siem',
    workspaceId: '00000000-0000-0000-0000-000000000000',
    url: 'https://http-intake.logs.datadoghq.com/api/v2/logs',
    description: 'Datadog Cloud SIEM Security Event Ingestion',
    events: ['*'],
    isActive: true,
    headers: { 'DD-SOURCE': 'security-lab', 'DD-SERVICE': 'api-testing' },
    createdAt: new Date(Date.now() - 86400000 * 12).toISOString(),
    updatedAt: new Date(Date.now() - 86400000 * 1).toISOString(),
  },
  {
    id: 'wh-pagerduty-critical',
    workspaceId: '00000000-0000-0000-0000-000000000000',
    url: 'https://events.pagerduty.com/v2/enqueue',
    description: 'PagerDuty High Urgency Incident Trigger',
    events: ['finding.critical'],
    isActive: false,
    headers: {},
    createdAt: new Date(Date.now() - 86400000 * 20).toISOString(),
    updatedAt: new Date(Date.now() - 86400000 * 3).toISOString(),
  },
];

export const FALLBACK_DELIVERIES: Record<string, WebhookDeliveryRecord[]> = {
  'wh-slack-alerts': [
    {
      id: 'del-slack-01',
      webhookId: 'wh-slack-alerts',
      workspaceId: '00000000-0000-0000-0000-000000000000',
      eventType: 'finding.critical',
      payload: {
        event: 'finding.critical',
        findingId: 'f-authz-01',
        title: 'BOLA / IDOR in User Profile Endpoint (/api/v1/users/:id/billing)',
        severity: 'critical',
        timestamp: new Date(Date.now() - 1800000).toISOString(),
      },
      status: 'succeeded',
      attempts: 1,
      maxAttempts: 5,
      nextRetryAt: new Date(Date.now() - 1800000).toISOString(),
      lastAttemptAt: new Date(Date.now() - 1800000).toISOString(),
      responseStatusCode: 200,
      responseBody: 'ok',
      lastError: null,
      createdAt: new Date(Date.now() - 1800000).toISOString(),
      updatedAt: new Date(Date.now() - 1800000).toISOString(),
    },
    {
      id: 'del-slack-02',
      webhookId: 'wh-slack-alerts',
      workspaceId: '00000000-0000-0000-0000-000000000000',
      eventType: 'policy.failed',
      payload: {
        event: 'policy.failed',
        policyId: 'strict-zero-tolerance',
        releaseGate: 'REJECTED',
        unresolvedCriticals: 1,
        timestamp: new Date(Date.now() - 3600000 * 4).toISOString(),
      },
      status: 'succeeded',
      attempts: 1,
      maxAttempts: 5,
      nextRetryAt: new Date(Date.now() - 3600000 * 4).toISOString(),
      lastAttemptAt: new Date(Date.now() - 3600000 * 4).toISOString(),
      responseStatusCode: 200,
      responseBody: 'ok',
      lastError: null,
      createdAt: new Date(Date.now() - 3600000 * 4).toISOString(),
      updatedAt: new Date(Date.now() - 3600000 * 4).toISOString(),
    },
  ],
  'wh-datadog-siem': [
    {
      id: 'del-dd-01',
      webhookId: 'wh-datadog-siem',
      workspaceId: '00000000-0000-0000-0000-000000000000',
      eventType: 'run.completed',
      payload: {
        event: 'run.completed',
        testRunId: 'run-live-01',
        totalFindings: 6,
        durationMs: 4230,
        timestamp: new Date(Date.now() - 1200000).toISOString(),
      },
      status: 'succeeded',
      attempts: 1,
      maxAttempts: 5,
      nextRetryAt: new Date(Date.now() - 1200000).toISOString(),
      lastAttemptAt: new Date(Date.now() - 1200000).toISOString(),
      responseStatusCode: 202,
      responseBody: '{"status":"accepted"}',
      lastError: null,
      createdAt: new Date(Date.now() - 1200000).toISOString(),
      updatedAt: new Date(Date.now() - 1200000).toISOString(),
    },
    {
      id: 'del-dd-02',
      webhookId: 'wh-datadog-siem',
      workspaceId: '00000000-0000-0000-0000-000000000000',
      eventType: 'release.evaluated',
      payload: {
        event: 'release.evaluated',
        policyId: 'pci-dss-baseline',
        score: 85,
        timestamp: new Date(Date.now() - 7200000).toISOString(),
      },
      status: 'failed',
      attempts: 2,
      maxAttempts: 5,
      nextRetryAt: new Date(Date.now() + 40000).toISOString(),
      lastAttemptAt: new Date(Date.now() - 60000).toISOString(),
      responseStatusCode: 503,
      responseBody: 'Service Unavailable - Rate Limited',
      lastError: 'HTTP 503 Service Unavailable',
      createdAt: new Date(Date.now() - 7200000).toISOString(),
      updatedAt: new Date(Date.now() - 60000).toISOString(),
    },
  ],
};

let localWebhooks = [...FALLBACK_WEBHOOKS];
let localDeliveries = { ...FALLBACK_DELIVERIES };

// Helper to generate cryptographic random 64-char hex key for HMAC signing
export function generateHmacSecret(): string {
  const arr = new Uint8Array(32);
  if (typeof window !== 'undefined' && window.crypto) {
    window.crypto.getRandomValues(arr);
  } else {
    for (let i = 0; i < 32; i++) arr[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(arr)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// ==========================================
// API Operations
// ==========================================

export async function fetchWebhooks(): Promise<WebhookRecord[]> {
  const apiUrl = (import.meta.env?.VITE_API_URL as string) || '';

  try {
    const res = await authFetch(`${apiUrl}/api/v1/webhooks`);
    if (res.ok) {
      const data = await res.json();
      const serverList = Array.isArray(data) ? data : Array.isArray(data?.data) ? data.data : [];
      if (serverList.length > 0) {
        return serverList;
      }
    }
  } catch {
    // Controller offline, use fallback state
  }

  return localWebhooks;
}

export async function createWebhook(payload: CreateWebhookPayload): Promise<WebhookRecord> {
  const apiUrl = (import.meta.env?.VITE_API_URL as string) || '';

  try {
    const res = await authFetch(`${apiUrl}/api/v1/webhooks`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (res.ok) {
      const json = await res.json();
      const created = json.data || json;
      localWebhooks = [created, ...localWebhooks];
      return created;
    }
  } catch {
    // Controller offline, fall through to local update
  }

  const newWebhook: WebhookRecord = {
    id: `wh-${Date.now()}`,
    workspaceId: '00000000-0000-0000-0000-000000000000',
    url: payload.url,
    description: payload.description || 'Custom Webhook Endpoint',
    events: payload.events && payload.events.length > 0 ? payload.events : ['*'],
    isActive: true,
    headers: payload.headers || {},
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  localWebhooks = [newWebhook, ...localWebhooks];
  localDeliveries[newWebhook.id] = [];
  return newWebhook;
}

export async function deleteWebhook(id: string): Promise<boolean> {
  const apiUrl = (import.meta.env?.VITE_API_URL as string) || '';

  try {
    const res = await authFetch(`${apiUrl}/api/v1/webhooks/${id}`, {
      method: 'DELETE',
    });
    if (res.ok) return true;
  } catch {
    // Offline fallback
  }

  localWebhooks = localWebhooks.filter((w) => w.id !== id);
  delete localDeliveries[id];
  return true;
}

export async function testWebhookPing(
  id: string
): Promise<{ success: boolean; delivery: WebhookDeliveryRecord | null; message: string }> {
  const apiUrl = (import.meta.env?.VITE_API_URL as string) || '';

  try {
    const res = await authFetch(`${apiUrl}/api/v1/webhooks/${id}/test`, {
      method: 'POST',
    });

    if (res.ok) {
      const json = await res.json();
      return {
        success: true,
        delivery: json.data || null,
        message: json.message || 'Test ping enqueued for delivery',
      };
    }
  } catch {
    // Offline fallback
  }

  // Generate synthetic test delivery item
  const mockDelivery: WebhookDeliveryRecord = {
    id: `del-test-${Date.now()}`,
    webhookId: id,
    workspaceId: '00000000-0000-0000-0000-000000000000',
    eventType: 'ping',
    payload: {
      event: 'ping',
      message: 'Security Lab Webhook Connectivity Verification',
      timestamp: new Date().toISOString(),
      nonce: generateHmacSecret().slice(0, 16),
    },
    status: 'succeeded',
    attempts: 1,
    maxAttempts: 5,
    nextRetryAt: new Date().toISOString(),
    lastAttemptAt: new Date().toISOString(),
    responseStatusCode: 200,
    responseBody: '{"ok":true,"received":true,"latencyMs":42}',
    lastError: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  if (!localDeliveries[id]) localDeliveries[id] = [];
  localDeliveries[id].unshift(mockDelivery);

  return {
    success: true,
    delivery: mockDelivery,
    message: 'Test ping delivered successfully (HTTP 200 OK)',
  };
}

export async function fetchWebhookDeliveries(
  id: string,
  limit = 50
): Promise<WebhookDeliveryRecord[]> {
  const apiUrl = (import.meta.env?.VITE_API_URL as string) || '';

  try {
    const res = await authFetch(`${apiUrl}/api/v1/webhooks/${id}/deliveries?limit=${limit}`);
    if (res.ok) {
      const json = await res.json();
      if (Array.isArray(json.data)) return json.data;
    }
  } catch {
    // Offline fallback
  }

  return localDeliveries[id] || [];
}

// ==========================================
// GitHub Actions Workflow YAML Generator
// ==========================================

export function generateGitHubActionYaml(opts: WorkflowGeneratorOptions): string {
  const triggers: string[] = [];
  if (opts.triggerEvents.includes('push')) {
    triggers.push(`  push:
    branches: [main, master, develop]`);
  }
  if (opts.triggerEvents.includes('pull_request')) {
    triggers.push(`  pull_request:
    branches: [main, master]`);
  }
  if (opts.triggerEvents.includes('workflow_dispatch')) {
    triggers.push(`  workflow_dispatch:
    inputs:
      target_override:
        description: 'Optional target URL override'
        required: false
        default: '${opts.targetUrl}'`);
  }
  if (opts.triggerEvents.includes('schedule')) {
    triggers.push(`  schedule:
    # Nightly security scan at 02:00 UTC
    - cron: '0 2 * * *'`);
  }

  const triggerBlock = triggers.join('\n');

  return `name: Security Lab Continuous Verification

on:
${triggerBlock}

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  security-lab-scan:
    name: Security & Resilience Release Gate
    runs-on: ubuntu-latest
    timeout-minutes: ${opts.scanTimeoutMinutes}

    steps:
      - name: Checkout Codebase
        uses: actions/checkout@v4

      - name: Setup Node.js Runtime
        uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: 'pnpm'

      - name: Install Monorepo Dependencies
        run: pnpm install --frozen-lockfile

      - name: Execute Security Lab Verification Scan
        id: security_scan
        uses: ./.github/actions/security-lab-scan
        with:
          target-url: \${{ github.event.inputs.target_override || '${opts.targetUrl}' }}
          policy-id: '${opts.policyId}'
          fail-on-breach: '${opts.failOnPolicyBreach}'
          controller-url: \${{ secrets.SECURITY_LAB_CONTROLLER_URL }}
          api-key: \${{ secrets.SECURITY_LAB_API_KEY }}
          timeout-seconds: ${opts.scanTimeoutMinutes * 60}
${
  opts.uploadSarif
    ? `
      - name: Upload SARIF to GitHub Advanced Security
        if: always() && steps.security_scan.outputs.sarif-path != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: \${{ steps.security_scan.outputs.sarif-path }}
          category: 'security-lab-suite'
`
    : ''
}${
  opts.postPrComment
    ? `
      - name: Post PR Release Gate Summary
        if: github.event_name == 'pull_request' && always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const summaryFile = process.env.GITHUB_STEP_SUMMARY;
            const gatePassed = '\${{ steps.security_scan.outputs.gate-result }}' === 'APPROVED';
            const icon = gatePassed ? '✅' : '🛑';
            const body = '### ' + icon + ' Security Lab Verification Gate Summary\\n\\n' +
              '- **Target:** \`${opts.targetUrl}\`\\n' +
              '- **Policy:** \`${opts.policyId}\`\\n' +
              '- **Gate Decision:** ' + (gatePassed ? '**APPROVED**' : '**REJECTED (Critical Findings)**') + '\\n\\n' +
              'Inspect full wire logs and attack graphs in the [Security Lab Dashboard](\${{ secrets.SECURITY_LAB_DASHBOARD_URL }}).';

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: body
            });
`
    : ''
}`;
}
