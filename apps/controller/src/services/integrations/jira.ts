import { logger } from '@security-lab/logger';
import { retesterService } from '../retester.js';
import { SyncFindingToIssueInput } from './github.js';

export interface JiraConfig {
  host: string; // e.g. "https://yourcompany.atlassian.net"
  email: string;
  apiToken: string;
  projectKey: string;
  issueType?: string; // default "Bug"
}

export interface JiraIssueResult {
  issueKey: string;
  issueId: string;
  selfUrl: string;
}

export class JiraSyncService {
  /**
   * Creates a Jira ticket for an identified security flaw.
   */
  async createIssue(
    config: JiraConfig,
    input: SyncFindingToIssueInput,
    customFetch?: typeof fetch,
  ): Promise<JiraIssueResult> {
    const fetchFn = customFetch || globalThis.fetch;
    const { finding, targetUrl } = input;
    const authHeader = `Basic ${Buffer.from(`${config.email}:${config.apiToken}`).toString('base64')}`;

    const priorityMap: Record<string, string> = {
      critical: 'Highest',
      high: 'High',
      medium: 'Medium',
      low: 'Low',
      info: 'Lowest',
    };

    const description = `*Vulnerability:* ${finding.title}
*Severity:* ${finding.severity.toUpperCase()}
*Category:* ${finding.category}
*Target URL:* ${targetUrl}
*Engine:* ${finding.testDefinitionId}

h3. Description
${finding.description}

${finding.risk ? `h3. Risk Assessment\n${finding.risk}\n` : ''}
${finding.recommendation ? `h3. Remediation\n${finding.recommendation}\n` : ''}

----
*Fingerprint:* {{${finding.fingerprint}}}
*Finding ID:* {{${finding.id}}}`;

    const payload = {
      fields: {
        project: { key: config.projectKey },
        summary: `[Security] [${finding.severity.toUpperCase()}] ${finding.title}`,
        description,
        issuetype: { name: config.issueType || 'Bug' },
        priority: { name: priorityMap[finding.severity] || 'Medium' },
        labels: ['security-lab', `severity-${finding.severity}`, 'vulnerability'],
      },
    };

    const res = await fetchFn(`${config.host}/rest/api/2/issue`, {
      method: 'POST',
      headers: {
        Authorization: authHeader,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`Failed to create Jira issue: HTTP ${res.status} - ${errText}`);
    }

    const json = (await res.json()) as { key: string; id: string; self: string };
    logger.info({ issueKey: json.key, projectKey: config.projectKey }, 'Jira issue created for finding');

    return {
      issueKey: json.key,
      issueId: json.id,
      selfUrl: json.self,
    };
  }

  /**
   * Processes Jira issue status change webhooks (jira:issue_updated).
   * If ticket is transitioned to 'Done' or 'Resolved', triggers an isolated verification retest.
   */
  async handleJiraWebhook(
    payload: Record<string, unknown>,
    tenantId?: string,
  ): Promise<{ retestTriggered: boolean; findingId?: string; retestStatus?: string }> {
    const issue = payload.issue as {
      fields?: {
        description?: string;
        status?: { name?: string; statusCategory?: { key?: string } };
      };
      key?: string;
    } | undefined;

    if (!issue?.fields?.description) {
      return { retestTriggered: false };
    }

    const statusCategory = issue.fields.status?.statusCategory?.key;
    const statusName = issue.fields.status?.name?.toLowerCase();

    const isResolved = statusCategory === 'done' || statusName === 'resolved' || statusName === 'closed';
    if (!isResolved) {
      return { retestTriggered: false };
    }

    // Extract Finding ID from description
    const match = issue.fields.description.match(/\*Finding ID:\*\s*\{\{([a-f0-9-]+)\}\}/i);
    if (!match || !match[1]) {
      return { retestTriggered: false };
    }

    const findingId = match[1];
    logger.info({ findingId, jiraKey: issue.key }, 'Jira ticket resolved. Triggering automated single-finding retest.');

    try {
      const result = await retesterService.retestFinding(findingId, tenantId, 10000);
      return {
        retestTriggered: true,
        findingId,
        retestStatus: result.status,
      };
    } catch (err: unknown) {
      logger.warn({ err, findingId }, 'Failed to trigger retest from Jira webhook');
      return {
        retestTriggered: false,
        findingId,
      };
    }
  }
}

export const jiraSyncService = new JiraSyncService();
