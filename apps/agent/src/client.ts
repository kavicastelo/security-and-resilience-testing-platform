import {
  AgentRegistrationRequest,
  AgentRegistrationResponse,
  AgentHeartbeatResponse,
  AgentJobDispatch,
  AgentJobCompletionReport,
  RotateAgentTokenResponse,
  CURRENT_PROTOCOL_VERSION,
  AGENT_VERSION,
  HEADER_PROTOCOL_VERSION,
  HEADER_AGENT_VERSION,
} from '@security-lab/contracts';
import { logger } from '@security-lab/logger';

export class IncompatibleProtocolError extends Error {
  readonly statusCode: number;
  readonly code: string;

  constructor(message: string, statusCode = 426, code = 'PROTOCOL_INCOMPATIBLE') {
    super(message);
    this.name = 'IncompatibleProtocolError';
    this.statusCode = statusCode;
    this.code = code;
  }
}

export class AgentClient {
  private readonly baseUrl: string;
  private token?: string;
  private protocolVersion: string = CURRENT_PROTOCOL_VERSION;
  private agentVersion: string = AGENT_VERSION;

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

  setProtocolVersion(version: string) {
    this.protocolVersion = version;
  }

  getProtocolVersion(): string {
    return this.protocolVersion;
  }

  setAgentVersion(version: string) {
    this.agentVersion = version;
  }

  getAgentVersion(): string {
    return this.agentVersion;
  }

  private getHeaders(tenantId?: string): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      [HEADER_PROTOCOL_VERSION]: this.protocolVersion,
      [HEADER_AGENT_VERSION]: this.agentVersion,
    };
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    if (tenantId) {
      headers['x-tenant-id'] = tenantId;
    }
    return headers;
  }

  private async checkProtocolError(res: Response): Promise<void> {
    if (res.status === 426) {
      const errJson = (await res.json().catch(() => ({}))) as {
        error?: { message?: string; code?: string };
        code?: string;
      };
      throw new IncompatibleProtocolError(
        errJson.error?.message || 'Agent protocol version is incompatible with controller. Upgrade required.',
        426,
        errJson.error?.code || errJson.code || 'PROTOCOL_INCOMPATIBLE',
      );
    }
  }

  async register(
    input: AgentRegistrationRequest,
    enrollmentKey?: string,
    tenantId?: string,
  ): Promise<AgentRegistrationResponse> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      [HEADER_PROTOCOL_VERSION]: this.protocolVersion,
      [HEADER_AGENT_VERSION]: this.agentVersion,
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

    await this.checkProtocolError(res);

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

    await this.checkProtocolError(res);

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

    await this.checkProtocolError(res);

    if (!res.ok) {
      logger.warn(`Heartbeat rejected with status ${res.status}`);
      return {
        acknowledged: false,
        timestamp: new Date().toISOString(),
        command: 'continue',
        renewedLeases: [],
        cancelledJobIds: [],
      };
    }

    const data = (await res.json()) as AgentHeartbeatResponse;
    return {
      ...data,
      cancelledJobIds: data.cancelledJobIds || [],
    };
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

    await this.checkProtocolError(res);

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
      const res = await fetch(`${this.baseUrl}/api/v1/agents/jobs/${jobId}/progress`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ jobId, testRunId, percent, message, engineId }),
      });
      await this.checkProtocolError(res);
    } catch (err: unknown) {
      if (err instanceof IncompatibleProtocolError) throw err;
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

    await this.checkProtocolError(res);

    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Failed to transmit completion report to controller: ${err}`);
    }
  }

  async reportFailure(jobId: string, error: string): Promise<void> {
    try {
      const res = await fetch(`${this.baseUrl}/api/v1/agents/jobs/${jobId}/fail`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ error }),
      });
      await this.checkProtocolError(res);
    } catch (err: unknown) {
      if (err instanceof IncompatibleProtocolError) throw err;
      logger.error({ err, jobId }, 'Failed to transmit failure report to controller');
    }
  }

  async acknowledgeCancellation(jobId: string): Promise<void> {
    try {
      const res = await fetch(`${this.baseUrl}/api/v1/agents/jobs/${jobId}/cancel-ack`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({}),
      });
      await this.checkProtocolError(res);
      if (!res.ok) {
        logger.warn({ jobId, status: res.status }, 'Controller rejected cancel-ack request');
      }
    } catch (err: unknown) {
      if (err instanceof IncompatibleProtocolError) throw err;
      logger.warn({ err, jobId }, 'Failed to transmit cancel-ack to controller');
    }
  }
}
