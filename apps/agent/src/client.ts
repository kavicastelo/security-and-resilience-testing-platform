import {
  AgentRegistrationRequest,
  AgentRegistrationResponse,
  AgentHeartbeatResponse,
  AgentJobDispatch,
  AgentJobCompletionReport,
  RotateAgentTokenResponse,
} from '@security-lab/contracts';
import { logger } from '@security-lab/logger';

export class AgentClient {
  private readonly baseUrl: string;
  private token?: string;

  constructor(baseUrl: string, token?: string) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.token = token;
  }

  setToken(token: string) {
    this.token = token;
  }

  getToken(): string | undefined {
    return this.token;
  }

  private getHeaders(tenantId?: string): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    if (tenantId) {
      headers['x-tenant-id'] = tenantId;
    }
    return headers;
  }

  async register(
    input: AgentRegistrationRequest,
    enrollmentKey?: string,
    tenantId?: string,
  ): Promise<AgentRegistrationResponse> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (enrollmentKey) {
      headers['Authorization'] = `Bearer ${enrollmentKey}`;
    } else if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    if (tenantId) {
      headers['x-tenant-id'] = tenantId;
    }

    const res = await fetch(`${this.baseUrl}/api/v1/agents/register`, {
      method: 'POST',
      headers,
      body: JSON.stringify(input),
    });

    const json = (await res.json()) as {
      success: boolean;
      data?: AgentRegistrationResponse;
      error?: { code?: string; message: string };
    };
    if (!res.ok || !json.success || !json.data) {
      throw new Error(json.error?.message || `Registration failed with status ${res.status}`);
    }

    this.token = json.data.token;
    return json.data;
  }

  async rotateToken(): Promise<RotateAgentTokenResponse> {
    const res = await fetch(`${this.baseUrl}/api/v1/agents/rotate-token`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({}),
    });

    const json = (await res.json()) as {
      success: boolean;
      data?: RotateAgentTokenResponse;
      error?: { code?: string; message: string };
    };
    if (!res.ok || !json.success || !json.data) {
      throw new Error(json.error?.message || `Token rotation failed with status ${res.status}`);
    }

    this.token = json.data.token;
    return json.data;
  }

  async heartbeat(
    agentId: string,
    status: 'online' | 'busy' | 'draining' | 'offline' = 'online',
    metrics?: { cpuUsagePercent?: number; memoryUsageMb?: number; activeJobsCount: number },
    leaseId?: string,
    activeLeaseIds?: string[],
  ): Promise<AgentHeartbeatResponse> {
    const res = await fetch(`${this.baseUrl}/api/v1/agents/heartbeat`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ agentId, status, metrics, leaseId, activeLeaseIds }),
    });

    if (!res.ok) {
      logger.warn(`Heartbeat rejected with status ${res.status}`);
      return { acknowledged: false, timestamp: new Date().toISOString(), command: 'continue', renewedLeases: [] };
    }

    return (await res.json()) as AgentHeartbeatResponse;
  }

  async poll(
    agentId: string,
    capabilities: string[] = [],
    tags: string[] = [],
    maxJobs = 1,
  ): Promise<AgentJobDispatch[]> {
    const res = await fetch(`${this.baseUrl}/api/v1/agents/poll`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ agentId, capabilities, tags, maxJobs }),
    });

    if (!res.ok) {
      const err = await res.text();
      logger.warn(`Poll request failed (${res.status}): ${err}`);
      return [];
    }

    const data = (await res.json()) as { jobs: AgentJobDispatch[] };
    return data.jobs || [];
  }

  async reportProgress(
    jobId: string,
    testRunId: string,
    percent: number,
    message: string,
    engineId?: string,
  ): Promise<void> {
    try {
      await fetch(`${this.baseUrl}/api/v1/agents/jobs/${jobId}/progress`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ jobId, testRunId, percent, message, engineId }),
      });
    } catch (err: unknown) {
      logger.warn({ err, jobId }, 'Failed to transmit progress update to controller');
    }
  }

  async reportCompletion(
    jobId: string,
    report: AgentJobCompletionReport,
  ): Promise<void> {
    const res = await fetch(`${this.baseUrl}/api/v1/agents/jobs/${jobId}/complete`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(report),
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Failed to transmit completion report to controller: ${err}`);
    }
  }

  async reportFailure(jobId: string, error: string): Promise<void> {
    try {
      await fetch(`${this.baseUrl}/api/v1/agents/jobs/${jobId}/fail`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ error }),
      });
    } catch (err: unknown) {
      logger.error({ err, jobId }, 'Failed to transmit failure report to controller');
    }
  }
}
