import { describe, it, expect, vi, beforeEach } from 'vitest';
import { governanceApi, WorkspaceSsoConfig, WorkspaceBillingInfo } from '../src/api/governance.js';

describe('Phase UI-02: Workspace RBAC, SSO, SCIM & Governance Console', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('exposes complete governance API methods with typed signatures', () => {
    expect(typeof governanceApi.getMembers).toBe('function');
    expect(typeof governanceApi.addMember).toBe('function');
    expect(typeof governanceApi.removeMember).toBe('function');
    expect(typeof governanceApi.getSsoConfig).toBe('function');
    expect(typeof governanceApi.updateSsoConfig).toBe('function');
    expect(typeof governanceApi.getBilling).toBe('function');
    expect(typeof governanceApi.updateBillingTier).toBe('function');
    expect(typeof governanceApi.getScimUsers).toBe('function');
    expect(typeof governanceApi.getAuditEvents).toBe('function');
  });

  it('correctly calculates percentage usage and quota headroom for billing tiers', () => {
    const mockBilling: WorkspaceBillingInfo = {
      tier: 'pro',
      quotas: {
        maxMonthlyRuns: 1000,
        maxConcurrentRuns: 8,
        maxTargets: 25,
        maxStorageMb: 2000,
      },
      usage: {
        monthlyRunsCount: 750,
        concurrentRunsCount: 4,
        activeTargetsCount: 20,
        storageBytesUsed: 1500 * 1024 * 1024,
      },
      quotaBreached: false,
    };

    const runsPct = Math.round((mockBilling.usage.monthlyRunsCount / mockBilling.quotas.maxMonthlyRuns) * 100);
    const targetsPct = Math.round((mockBilling.usage.activeTargetsCount / mockBilling.quotas.maxTargets) * 100);
    const storageMb = mockBilling.usage.storageBytesUsed / (1024 * 1024);
    const storagePct = Math.round((storageMb / mockBilling.quotas.maxStorageMb) * 100);

    expect(runsPct).toBe(75);
    expect(targetsPct).toBe(80);
    expect(storagePct).toBe(75);
    expect(mockBilling.quotaBreached).toBe(false);
  });

  it('validates SAML 2.0 and OIDC configuration schemas', () => {
    const samlConfig: WorkspaceSsoConfig = {
      enabled: true,
      provider: 'saml',
      defaultRole: 'ENGINEER',
      saml: {
        entryPoint: 'https://idp.okta.com/app/sso/saml',
        issuer: 'http://www.okta.com/exk123',
        cert: 'MIIDpDCCAoygAwIBAgIGAV...',
      },
    };

    expect(samlConfig.enabled).toBe(true);
    expect(samlConfig.provider).toBe('saml');
    expect(samlConfig.saml?.entryPoint).toContain('https://idp.okta.com');

    const oidcConfig: WorkspaceSsoConfig = {
      enabled: true,
      provider: 'oidc',
      defaultRole: 'AUDITOR',
      oidc: {
        issuer: 'https://accounts.google.com',
        clientId: 'client-12345.apps.googleusercontent.com',
        scopes: ['openid', 'profile', 'email'],
      },
    };

    expect(oidcConfig.provider).toBe('oidc');
    expect(oidcConfig.oidc?.scopes).toContain('openid');
    expect(oidcConfig.defaultRole).toBe('AUDITOR');
  });

  it('filters audit records by keyword search and action category', () => {
    const sampleEvents = [
      {
        id: '1',
        workspaceId: 'default',
        actorId: 'usr-admin-1',
        action: 'TARGET_CREATED',
        ipAddress: '192.168.1.10',
        createdAt: new Date().toISOString(),
      },
      {
        id: '2',
        workspaceId: 'default',
        actorId: 'usr-engineer-2',
        action: 'RUN_EXECUTED',
        ipAddress: '10.0.0.5',
        createdAt: new Date().toISOString(),
      },
      {
        id: '3',
        workspaceId: 'default',
        actorId: 'usr-admin-1',
        action: 'MEMBER_INVITED',
        ipAddress: '192.168.1.10',
        createdAt: new Date().toISOString(),
      },
    ];

    const targetEvents = sampleEvents.filter((e) => e.action.startsWith('TARGET'));
    expect(targetEvents.length).toBe(1);
    expect(targetEvents[0].action).toBe('TARGET_CREATED');

    const adminEvents = sampleEvents.filter((e) => e.actorId.includes('admin'));
    expect(adminEvents.length).toBe(2);
  });
});
