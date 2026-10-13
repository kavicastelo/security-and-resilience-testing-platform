import {
  AgentRegistrationRequest,
  AgentRegistrationResponse,
  AgentEnrollmentRequest,
  AgentEnrollmentResponse,
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
import { AgentKeypair, signAgentRequest } from './crypto-attestation.js';
import { createTraceparent } from './telemetry.js';

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

export interface HeaderSigningOptions {
  method?: string;
  path?: string;
  body?: unknown;
  tenantId?: string;
}

export class AgentClient {
  private readonly baseUrl: string;
  private token?: string;
  private agentId?: string;
  private keypair?: AgentKeypair;
  private protocolVersion: string = CURRENT_PROTOCOL_VERSION;
  private agentVersion: string = AGENT_VERSION;

  constructor(baseUrl: string, token?: string, keypair?: AgentKeypair, agentId?: string) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.token = token;
    this.keypair = keypair;
    this.agentId = agentId;
  }

  setToken(token: string) {
    this.token = token;
  }

  getToken(): string | undefined {
    return this.token;
  }

  setKeypair(keypair: AgentKeypair) {
    this.keypair = keypair;
  }

  getKeypair(): AgentKeypair | undefined {
    return this.keypair;
  }

  setAgentId(agentId: string) {
    this.agentId = agentId;
  }

  getAgentId(): string | undefined {
    return this.agentId;
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

  private getHeaders(options?: HeaderSigningOptions): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      [HEADER_PROTOCOL_VERSION]: this.protocolVersion,
      [HEADER_AGENT_VERSION]: this.agentVersion,
      traceparent: createTraceparent(),
    };

    // If asymmetric keypair and agentId are available, attach cryptographic signature headers
    if (this.keypair && this.agentId) {
      const timestamp = Date.now().toString();
      const method = (options?.method || 'POST').toUpperCase();
      const cleanPath = (options?.path || '/').split('?')[0] || '/';
      const signature = signAgentRequest(this.keypair.privateKey, {
        method,
        path: cleanPath,
        timestamp,
        body: options?.body,
      });

      headers['x-agent-id'] = this.agentId;
      headers['x-agent-timestamp'] = timestamp;
      headers['x-agent-signature'] = signature;
    }

    // Always include Bearer token if present (for dual-mode or legacy fallback)
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    if (options?.tenantId) {
      headers['x-tenant-id'] = options.tenantId;
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
      traceparent: createTraceparent(),
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
    this.agentId = json.data.agentId;
    return json.data;
  }

  async enroll(
    input: AgentEnrollmentRequest,
    enrollmentKey?: string,
    tenantId?: string,
  ): Promise<AgentEnrollmentResponse> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      [HEADER_PROTOCOL_VERSION]: this.protocolVersion,
      [HEADER_AGENT_VERSION]: this.agentVersion,
      traceparent: createTraceparent(),
    };
    if (enrollmentKey) {
      headers['Authorization'] = `Bearer ${enrollmentKey}`;
    } else if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    if (tenantId) {
      headers['x-tenant-id'] = tenantId;
    }

    const res = await fetch(`${this.baseUrl}/api/v1/agents/enroll`, {
      method: 'POST',
      headers,
      body: JSON.stringify(input),
    });

    await this.checkProtocolError(res);

    const json = (await res.json()) as {
      success: boolean;
      data?: AgentEnrollmentResponse;
      error?: { code?: string; message: string };
    };
    if (!res.ok || !json.success || !json.data) {
      throw new Error(json.error?.message || `Agent enrollment failed with status ${res.status}`);
    }

    this.agentId = json.data.agentId;
    return json.data;
  }

  async rotateToken(): Promise<RotateAgentTokenResponse> {
    const body = {};
    const res = await fetch(`${this.baseUrl}/api/v1/agents/rotate-token`, {
      method: 'POST',
      headers: this.getHeaders({ method: 'POST', path: '/api/v1/agents/rotate-token', body }),
      body: JSON.stringify(body),
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
    const path = '/api/v1/agents/heartbeat';
    const body = { agentId, status, metrics, leaseId, activeLeaseIds };
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: this.getHeaders({ method: 'POST', path, body }),
      body: JSON.stringify(body),
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
    const path = '/api/v1/agents/poll';
    const body = { agentId, capabilities, tags, maxJobs };
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: this.getHeaders({ method: 'POST', path, body }),
      body: JSON.stringify(body),
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
    const path = `/api/v1/agents/jobs/${jobId}/progress`;
    const body = { jobId, testRunId, percent, message, engineId };
    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers: this.getHeaders({ method: 'POST', path, body }),
        body: JSON.stringify(body),
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
    const path = `/api/v1/agents/jobs/${jobId}/complete`;
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: this.getHeaders({ method: 'POST', path, body: report }),
      body: JSON.stringify(report),
    });

    await this.checkProtocolError(res);

    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Failed to transmit completion report to controller: ${err}`);
    }
  }

  async reportFailure(jobId: string, error: string): Promise<void> {
    const path = `/api/v1/agents/jobs/${jobId}/fail`;
    const body = { error };
    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers: this.getHeaders({ method: 'POST', path, body }),
        body: JSON.stringify(body),
      });
      await this.checkProtocolError(res);
    } catch (err: unknown) {
      if (err instanceof IncompatibleProtocolError) throw err;
      logger.error({ err, jobId }, 'Failed to transmit failure report to controller');
    }
  }

  async acknowledgeCancellation(jobId: string): Promise<void> {
    const path = `/api/v1/agents/jobs/${jobId}/cancel-ack`;
    const body = {};
    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers: this.getHeaders({ method: 'POST', path, body }),
        body: JSON.stringify(body),
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
