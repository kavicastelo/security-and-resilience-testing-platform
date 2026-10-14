import { logger } from '@security-lab/logger';
import { retesterService } from '../retester.js';

export interface GitHubIssueConfig {
  owner: string;
  repo: string;
  token: string;
  apiUrl?: string;
}

export interface SyncFindingToIssueInput {
  finding: {
    id: string;
    fingerprint: string;
    title: string;
    category: string;
    severity: string;
    description: string;
    risk?: string;
    recommendation?: string;
    testDefinitionId: string;
  };
  targetUrl: string;
}

export interface GitHubIssueResult {
  issueNumber: number;
  issueUrl: string;
  title: string;
  state: 'open' | 'closed';
}

export class GitHubSyncService {
  /**
   * Creates or updates a GitHub issue for a security finding.
   */
  async syncFindingToIssue(
    config: GitHubIssueConfig,
    input: SyncFindingToIssueInput,
    customFetch?: typeof fetch,
  ): Promise<GitHubIssueResult> {
    const fetchFn = customFetch || globalThis.fetch;
    const baseUrl = config.apiUrl || 'https://api.github.com';
    const { finding, targetUrl } = input;

    const issueTitle = `[Security-Lab] [${finding.severity.toUpperCase()}] ${finding.title}`;
    const issueBody = `## Security Vulnerability Notice: ${finding.title}

- **Severity**: \`${finding.severity.toUpperCase()}\`
- **Category**: \`${finding.category}\`
- **Engine**: \`${finding.testDefinitionId}\`
- **Target URL**: \`${targetUrl}\`
- **Fingerprint**: \`${finding.fingerprint}\`
- **Internal ID**: \`${finding.id}\`

### Vulnerability Description
${finding.description}

${finding.risk ? `### Risk Assessment\n${finding.risk}\n` : ''}
${finding.recommendation ? `### Remediation Steps\n${finding.recommendation}\n` : ''}

---
*Reported automatically by [Security & Resilience Testing Platform](https://github.com/security-lab).*
<!-- security-lab-fingerprint: ${finding.fingerprint} -->
<!-- security-lab-finding-id: ${finding.id} -->
`;

    // 1. Search for existing issue by fingerprint tag
    const searchUrl = `${baseUrl}/search/issues?q=${encodeURIComponent(
      `repo:${config.owner}/${config.repo} "${finding.fingerprint}" in:body is:issue`,
    )}`;

    const searchRes = await fetchFn(searchUrl, {
      method: 'GET',
      headers: {
        Accept: 'application/vnd.github.v3+json',
        Authorization: `Bearer ${config.token}`,
        'User-Agent': 'Security-Lab-Sync-Service',
      },
    });

    if (searchRes.ok) {
      const searchData = (await searchRes.json()) as { items?: { number: number; html_url: string; state: string }[] };
      const existing = searchData.items?.[0];

      if (existing) {
        // Issue exists, update comment or state
        logger.info(
          { issueNumber: existing.number, fingerprint: finding.fingerprint },
          'GitHub issue already exists for finding fingerprint',
        );
        return {
          issueNumber: existing.number,
          issueUrl: existing.html_url,
          title: issueTitle,
          state: existing.state as 'open' | 'closed',
        };
      }
    }

    // 2. Create new issue
    const createUrl = `${baseUrl}/repos/${config.owner}/${config.repo}/issues`;
    const labels = ['security', `severity:${finding.severity}`, 'automated-audit'];

    const createRes = await fetchFn(createUrl, {
      method: 'POST',
      headers: {
        Accept: 'application/vnd.github.v3+json',
        Authorization: `Bearer ${config.token}`,
        'Content-Type': 'application/json',
        'User-Agent': 'Security-Lab-Sync-Service',
      },
      body: JSON.stringify({
        title: issueTitle,
        body: issueBody,
        labels,
      }),
    });

    if (!createRes.ok) {
      const errText = await createRes.text().catch(() => '');
      throw new Error(`Failed to create GitHub issue: HTTP ${createRes.status} - ${errText}`);
    }

    const created = (await createRes.json()) as { number: number; html_url: string; state: string };
    logger.info({ issueNumber: created.number, repo: `${config.owner}/${config.repo}` }, 'Created GitHub issue for security finding');

    return {
      issueNumber: created.number,
      issueUrl: created.html_url,
      title: issueTitle,
      state: created.state as 'open' | 'closed',
    };
  }

  /**
   * Handles incoming GitHub webhook event (e.g. issues closed).
   * When an issue tagged with a finding ID or fingerprint is closed, automatically triggers a targeted retest.
   */
  async handleGitHubWebhook(
    event: string,
    payload: Record<string, unknown>,
    tenantId?: string,
  ): Promise<{ retestTriggered: boolean; findingId?: string; retestStatus?: string }> {
    if (event !== 'issues') {
      return { retestTriggered: false };
    }

    const action = payload.action as string;
    const issue = payload.issue as { body?: string; number?: number } | undefined;

    if (action !== 'closed' || !issue?.body) {
      return { retestTriggered: false };
    }

    // Extract embedded finding ID
    const match = issue.body.match(/<!-- security-lab-finding-id:\s*([a-f0-9-]+)\s*-->/i);
    if (!match || !match[1]) {
      return { retestTriggered: false };
    }

    const findingId = match[1];
    logger.info({ findingId, issueNumber: issue.number }, 'GitHub issue closed. Triggering automated verification retest.');

    try {
      const retestResult = await retesterService.retestFinding(findingId, tenantId, 10000);
      return {
        retestTriggered: true,
        findingId,
        retestStatus: retestResult.status,
      };
    } catch (err: unknown) {
      logger.warn({ err, findingId }, 'Failed to execute retest for closed GitHub issue');
      return {
        retestTriggered: false,
        findingId,
      };
    }
  }
}

export const gitHubSyncService = new GitHubSyncService();
