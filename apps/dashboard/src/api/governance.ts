import { authFetch } from './client.js';

export interface WorkspaceMember {
  userId: string;
  name: string;
  email: string;
  role: 'OWNER' | 'ADMIN' | 'ENGINEER' | 'AUDITOR';
  createdAt: string;
}

export interface WorkspaceAuditRecord {
  id: string;
  workspaceId: string;
  actorId: string;
  action: string;
  entityType?: string;
  entityId?: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
  createdAt: string;
}

export interface WorkspaceSsoConfig {
  enabled: boolean;
  provider: 'saml' | 'oidc';
  defaultRole: 'ADMIN' | 'ENGINEER' | 'AUDITOR';
  saml?: {
    entryPoint: string;
    issuer: string;
    cert: string;
    signatureAlgorithm?: string;
    wantAuthnResponseSigned?: boolean;
  };
  oidc?: {
    issuer: string;
    clientId: string;
    clientSecret?: string;
    authorizationEndpoint?: string;
    tokenEndpoint?: string;
    userInfoEndpoint?: string;
    scopes?: string[];
  };
}

export interface WorkspaceBillingInfo {
  tier: 'free' | 'pro' | 'enterprise';
  stripeCustomerId?: string;
  stripeSubscriptionId?: string;
  subscriptionStatus?: string;
  quotas: {
    maxMonthlyRuns: number;
    maxConcurrentRuns: number;
    maxTargets: number;
    maxStorageMb: number;
  };
  usage: {
    monthlyRunsCount: number;
    concurrentRunsCount: number;
    activeTargetsCount: number;
    storageBytesUsed: number;
  };
  quotaBreached?: boolean;
}

export interface ScimUserRecord {
  id: string;
  userName: string;
  name?: { formatted?: string; givenName?: string; familyName?: string };
  emails?: Array<{ value: string; primary?: boolean }>;
  active?: boolean;
  roles?: Array<{ value: string }>;
  meta?: { created?: string; lastModified?: string };
}

export const governanceApi = {
  // Members
  async getMembers(workspaceId: string): Promise<WorkspaceMember[]> {
    const res = await authFetch(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/members`);
    if (!res.ok) return [];
    const json = await res.json();
    return Array.isArray(json.data) ? json.data : [];
  },

  async addMember(
    workspaceId: string,
    data: { email: string; name?: string; role: 'OWNER' | 'ADMIN' | 'ENGINEER' | 'AUDITOR' }
  ): Promise<WorkspaceMember> {
    const res = await authFetch(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/members`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error?.message || 'Failed to add member');
    return json.data;
  },

  async removeMember(workspaceId: string, userId: string): Promise<void> {
    const res = await authFetch(
      `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/members/${encodeURIComponent(userId)}`,
      { method: 'DELETE' }
    );
    if (!res.ok) {
      const json = await res.json().catch(() => ({}));
      throw new Error(json.error?.message || 'Failed to remove member');
    }
  },

  // SSO
  async getSsoConfig(workspaceId: string): Promise<WorkspaceSsoConfig> {
    const res = await authFetch(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/sso`);
    if (!res.ok) {
      return { enabled: false, provider: 'saml', defaultRole: 'ENGINEER' };
    }
    const json = await res.json();
    return json.data || { enabled: false, provider: 'saml', defaultRole: 'ENGINEER' };
  },

  async updateSsoConfig(workspaceId: string, config: WorkspaceSsoConfig): Promise<WorkspaceSsoConfig> {
    const res = await authFetch(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/sso`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error?.message || 'Failed to update SSO configuration');
    return json.data;
  },

  // Billing & Quotas
  async getBilling(workspaceId: string): Promise<WorkspaceBillingInfo | null> {
    const res = await authFetch(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/billing`);
    if (!res.ok) return null;
    const json = await res.json();
    return json.data;
  },

  async updateBillingTier(
    workspaceId: string,
    tier: 'free' | 'pro' | 'enterprise'
  ): Promise<WorkspaceBillingInfo> {
    const res = await authFetch(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/billing`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tier }),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error?.message || 'Failed to update billing tier');
    return json.data;
  },

  // SCIM
  async getScimUsers(workspaceId?: string): Promise<ScimUserRecord[]> {
    const url = workspaceId
      ? `/scim/v2/Users?workspaceId=${encodeURIComponent(workspaceId)}`
      : '/scim/v2/Users';
    const res = await authFetch(url);
    if (!res.ok) return [];
    const json = await res.json();
    return Array.isArray(json.Resources) ? json.Resources : [];
  },

  // Audit Events
  async getAuditEvents(workspaceId: string): Promise<WorkspaceAuditRecord[]> {
    const res = await authFetch(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/audit-events`);
    if (!res.ok) return [];
    const json = await res.json();
    return Array.isArray(json.data) ? json.data : [];
  },
};
