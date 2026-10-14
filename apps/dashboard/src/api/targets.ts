import { authFetch } from './client.js';

export interface TargetLimits {
  maxRps: number;
  maxConcurrency: number;
  maxDuration: string;
}

export interface TargetTestingCapabilities {
  activeScanning: boolean;
  loadTesting: boolean;
  chaosTesting: boolean;
}

export interface TargetScope {
  allowedHosts: string[];
  allowedPorts: number[];
  excludedPaths: string[];
  testing: TargetTestingCapabilities;
  limits: TargetLimits;
  allowPrivateIps?: boolean;
}

export type VerificationStatus = 'PENDING' | 'VERIFIED' | 'FAILED' | 'REVOKED';
export type VerificationMethod = 'DNS_TXT' | 'HTTP_WELL_KNOWN' | 'AUTO' | 'LOCAL_OVERRIDE' | 'MANUAL';

export interface Target {
  id: string;
  projectId: string;
  name: string;
  baseUrl: string;
  scope: TargetScope;
  verificationToken?: string | null;
  verificationStatus?: VerificationStatus;
  verifiedAt?: string | null;
  verificationMethod?: VerificationMethod | null;
  authConfigured?: boolean;
  authType?: string;
  createdAt: string;
  updatedAt?: string;
}

export interface ChallengeInstructions {
  targetId: string;
  token: string;
  status: VerificationStatus;
  verifiedAt?: string | null;
  verificationMethod?: string | null;
  dns: {
    recordType: 'TXT';
    recordName: string;
    recordValue: string;
    alternativeRecordName: string;
  };
  http: {
    url: string;
    expectedContent: string;
  };
}

export interface VerificationResult {
  verified: boolean;
  status: VerificationStatus;
  method?: string;
  message: string;
  details?: Record<string, unknown>;
}

export interface ScopeValidationResult {
  targetId?: string;
  targetName?: string;
  candidateUrl: string;
  valid: boolean;
  violations: string[];
  matchedHost?: string;
  normalizedUrl?: string;
  scope?: TargetScope;
}

export interface CreateTargetPayload {
  name: string;
  baseUrl: string;
  allowedHosts: string[];
  allowedPorts?: number[];
  excludedPaths?: string[];
  testing?: Partial<TargetTestingCapabilities>;
  limits?: Partial<TargetLimits>;
  allowPrivateIps?: boolean;
}

export interface UpdateTargetPayload {
  name?: string;
  baseUrl?: string;
  allowedHosts?: string[];
  allowedPorts?: number[];
  excludedPaths?: string[];
  testing?: Partial<TargetTestingCapabilities>;
  limits?: Partial<TargetLimits>;
  scope?: Partial<TargetScope>;
}

const getApiUrl = () => import.meta.env.VITE_API_URL || 'http://localhost:4000';

export const targetsApi = {
  /**
   * List all targets accessible in tenant scope
   */
  async listTargets(): Promise<Target[]> {
    const res = await authFetch(`${getApiUrl()}/api/v1/targets`);
    if (!res.ok) throw new Error('Failed to fetch targets');
    const json = await res.json();
    return json.data || [];
  },

  /**
   * Get single target by ID
   */
  async getTarget(id: string): Promise<Target> {
    const res = await authFetch(`${getApiUrl()}/api/v1/targets/${id}`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error?.message || `Target ${id} not found`);
    }
    const json = await res.json();
    return json.data;
  },

  /**
   * Create a new target inside a project
   */
  async createTarget(projectId: string, payload: CreateTargetPayload): Promise<Target> {
    const res = await authFetch(`${getApiUrl()}/api/v1/projects/${projectId}/targets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...payload,
        allowedPorts: payload.allowedPorts && payload.allowedPorts.length > 0 ? payload.allowedPorts : [80, 443],
        excludedPaths: payload.excludedPaths || [],
        testing: {
          activeScanning: payload.testing?.activeScanning ?? false,
          loadTesting: payload.testing?.loadTesting ?? false,
          chaosTesting: payload.testing?.chaosTesting ?? false,
        },
        limits: {
          maxRps: payload.limits?.maxRps ?? 100,
          maxConcurrency: payload.limits?.maxConcurrency ?? 20,
          maxDuration: payload.limits?.maxDuration ?? '10m',
        },
      }),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error?.message || 'Failed to create target');
    return json.data;
  },

  /**
   * Update an existing target
   */
  async updateTarget(id: string, payload: UpdateTargetPayload): Promise<Target> {
    const res = await authFetch(`${getApiUrl()}/api/v1/targets/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error?.message || 'Failed to update target');
    return json.data;
  },

  /**
   * Delete a target
   */
  async deleteTarget(id: string): Promise<{ id: string; deleted: boolean }> {
    const res = await authFetch(`${getApiUrl()}/api/v1/targets/${id}`, {
      method: 'DELETE',
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error?.message || 'Failed to delete target');
    return json.data;
  },

  /**
   * Retrieve cryptographic challenge instructions (DNS TXT & HTTP token)
   */
  async getChallenge(targetId: string): Promise<ChallengeInstructions> {
    const res = await authFetch(`${getApiUrl()}/api/v1/targets/${targetId}/challenge`);
    if (!res.ok) {
      const json = await res.json().catch(() => ({}));
      throw new Error(json.error?.message || 'Failed to retrieve verification challenge');
    }
    const json = await res.json();
    return json.data;
  },

  /**
   * Trigger cryptographic ownership verification check on backend
   */
  async verifyOwnership(
    targetId: string,
    method: 'DNS_TXT' | 'HTTP_WELL_KNOWN' | 'AUTO' = 'AUTO',
  ): Promise<VerificationResult> {
    const res = await authFetch(`${getApiUrl()}/api/v1/targets/${targetId}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method }),
    });

    const json = await res.json();
    if (!res.ok) {
      // 422 or 400 indicates verification failure with diagnostic details
      const errorMsg = json.error?.message || 'Ownership verification failed';
      return {
        verified: false,
        status: 'FAILED',
        method,
        message: errorMsg,
        details: json.error?.details,
      };
    }

    return json.data;
  },

  /**
   * Pre-flight simulation check: validate candidate URL against target scope and anti-SSRF protections
   */
  async validateScope(
    targetId: string,
    candidateUrl: string,
    options?: {
      capability?: 'activeScanning' | 'loadTesting' | 'chaosTesting';
      requestedRps?: number;
      requestedConcurrency?: number;
    },
  ): Promise<ScopeValidationResult> {
    const res = await authFetch(`${getApiUrl()}/api/v1/targets/${targetId}/validate-scope`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        candidateUrl,
        capability: options?.capability,
        requestedRps: options?.requestedRps,
        requestedConcurrency: options?.requestedConcurrency,
      }),
    });

    const json = await res.json();
    if (!res.ok) {
      throw new Error(json.error?.message || 'Scope validation request failed');
    }

    return json.data;
  },
};
