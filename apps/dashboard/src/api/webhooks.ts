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
// API Operations (Strict Controller Persistence)
// ==========================================

export async function fetchWebhooks(): Promise<WebhookRecord[]> {
  const apiUrl = (import.meta.env?.VITE_API_URL as string) || '';
  const res = await authFetch(`${apiUrl}/api/v1/webhooks`);
  if (!res.ok) {
    const errorBody = await res.json().catch(() => null);
    throw new Error(errorBody?.error?.message || `Failed to fetch webhooks (HTTP ${res.status})`);
  }
  const json = await res.json();
  const list = Array.isArray(json) ? json : json?.data;
  return Array.isArray(list) ? list : [];
}

export async function createWebhook(payload: CreateWebhookPayload): Promise<WebhookRecord> {
  const apiUrl = (import.meta.env?.VITE_API_URL as string) || '';
  const res = await authFetch(`${apiUrl}/api/v1/webhooks`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const errorBody = await res.json().catch(() => null);
    throw new Error(errorBody?.error?.message || `Failed to create webhook (HTTP ${res.status})`);
  }
  const json = await res.json();
  return json.data || json;
}

export async function deleteWebhook(id: string): Promise<boolean> {
  const apiUrl = (import.meta.env?.VITE_API_URL as string) || '';
  const res = await authFetch(`${apiUrl}/api/v1/webhooks/${id}`, {
    method: 'DELETE',
  });
  if (!res.ok) {
    const errorBody = await res.json().catch(() => null);
    throw new Error(errorBody?.error?.message || `Failed to delete webhook (HTTP ${res.status})`);
  }
  return true;
}

export async function dispatchTestPing(
  id: string
): Promise<{ success: boolean; delivery: WebhookDeliveryRecord | null; message: string }> {
  const apiUrl = (import.meta.env?.VITE_API_URL as string) || '';
  const res = await authFetch(`${apiUrl}/api/v1/webhooks/${id}/test`, {
    method: 'POST',
  });
  if (!res.ok) {
    const errorBody = await res.json().catch(() => null);
    throw new Error(errorBody?.error?.message || `Failed to dispatch test ping (HTTP ${res.status})`);
  }
  const json = await res.json();
  return {
    success: true,
    delivery: json.data || null,
    message: json.message || 'Test ping enqueued for delivery',
  };
}

export const testWebhookPing = dispatchTestPing;

export async function fetchWebhookDeliveries(
  id: string,
  limit = 50
): Promise<WebhookDeliveryRecord[]> {
  const apiUrl = (import.meta.env?.VITE_API_URL as string) || '';
  const res = await authFetch(`${apiUrl}/api/v1/webhooks/${id}/deliveries?limit=${limit}`);
  if (!res.ok) {
    const errorBody = await res.json().catch(() => null);
    throw new Error(errorBody?.error?.message || `Failed to fetch deliveries (HTTP ${res.status})`);
  }
  const json = await res.json();
  return Array.isArray(json.data) ? json.data : [];
}

export async function fetchGitHubSyncConfig(): Promise<GitHubSyncConfig> {
  const apiUrl = (import.meta.env?.VITE_API_URL as string) || '';
  try {
    const res = await authFetch(`${apiUrl}/api/v1/workspaces/settings/github-sync`);
    if (res.ok) {
      const json = await res.json();
      if (json.data) return json.data;
    }
  } catch {
    // Check localStorage fallback
  }
  if (typeof window !== 'undefined' && window.localStorage) {
    const stored = window.localStorage.getItem('security_lab_gh_sync');
    if (stored) {
      try {
        return JSON.parse(stored);
      } catch {
        // invalid JSON
      }
    }
  }
  return {
    enabled: false,
    repoOwner: '',
    repoName: '',
    personalAccessToken: '',
    autoCreateOnSeverity: ['critical', 'high'],
    autoCloseOnRetestResolved: true,
    addLabels: ['security-lab'],
  };
}

export async function updateGitHubSyncConfig(config: GitHubSyncConfig): Promise<GitHubSyncConfig> {
  const apiUrl = (import.meta.env?.VITE_API_URL as string) || '';
  if (typeof window !== 'undefined' && window.localStorage) {
    window.localStorage.setItem('security_lab_gh_sync', JSON.stringify(config));
  }
  try {
    const res = await authFetch(`${apiUrl}/api/v1/workspaces/settings/github-sync`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
    if (res.ok) {
      const json = await res.json();
      return json.data || config;
    }
  } catch {
    // Persisted to storage
  }
  return config;
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
