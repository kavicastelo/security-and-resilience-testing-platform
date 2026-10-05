import { describe, it, expect } from 'vitest';
import { validateUrlAgainstScope, TargetScope } from '@security-lab/domain';

describe('Scope Security Boundary Engine', () => {
  const baseScope: TargetScope = {
    allowedHosts: ['staging.example.com', '*.api.example.com'],
    allowedPorts: [80, 443],
    excludedPaths: ['/admin/reset-db', '/billing/charge'],
    testing: {
      activeScanning: false, // Default defensive safe setting
      loadTesting: false,
      chaosTesting: false,
    },
    limits: {
      maxRps: 50,
      maxConcurrency: 10,
      maxDuration: '5m',
    },
  };

  it('permits valid in-scope URLs on allowed host and port', () => {
    const res = validateUrlAgainstScope('https://staging.example.com/api/v1/users', baseScope);
    expect(res.valid).toBe(true);
    expect(res.violations).toHaveLength(0);
    expect(res.matchedHost).toBe('staging.example.com');
  });

  it('permits wildcard subdomain matches', () => {
    const res = validateUrlAgainstScope('https://v1.api.example.com/health', baseScope);
    expect(res.valid).toBe(true);
    expect(res.violations).toHaveLength(0);
  });

  it('blocks unauthorized hostnames (SSRF / Scope Traversal defense)', () => {
    const res = validateUrlAgainstScope('https://unauthorized-domain.com/secret', baseScope);
    expect(res.valid).toBe(false);
    expect(res.violations[0]).toContain('not within the authorized scope allowedHosts');
  });

  it('blocks unauthorized network ports', () => {
    const res = validateUrlAgainstScope('https://staging.example.com:8443/login', baseScope);
    expect(res.valid).toBe(false);
    expect(res.violations[0]).toContain('Port "8443" is not within authorized scope');
  });

  it('strictly blocks AWS / GCP / Azure Cloud Metadata IP (169.254.169.254)', () => {
    const res = validateUrlAgainstScope('http://169.254.169.254/latest/meta-data/', baseScope);
    expect(res.valid).toBe(false);
    expect(res.violations.some((v) => v.includes('cloud metadata IP/host'))).toBe(true);
  });

  it('strictly blocks excluded sensitive paths', () => {
    const res = validateUrlAgainstScope('https://staging.example.com/admin/reset-db', baseScope);
    expect(res.valid).toBe(false);
    expect(res.violations.some((v) => v.includes('matches excluded sensitive path'))).toBe(true);

    const subpathRes = validateUrlAgainstScope('https://staging.example.com/admin/reset-db/confirm', baseScope);
    expect(subpathRes.valid).toBe(false);
  });

  it('blocks active scanning when testing.activeScanning is false', () => {
    const res = validateUrlAgainstScope('https://staging.example.com/api/v1/login', baseScope, {
      requestedCapability: 'activeScanning',
    });
    expect(res.valid).toBe(false);
    expect(res.violations.some((v) => v.includes('activeScanning" is disabled for this target'))).toBe(true);
  });

  it('allows active scanning when target scope explicitly authorizes it', () => {
    const activeScope: TargetScope = {
      ...baseScope,
      testing: {
        ...baseScope.testing,
        activeScanning: true,
      },
    };

    const res = validateUrlAgainstScope('https://staging.example.com/api/v1/login', activeScope, {
      requestedCapability: 'activeScanning',
    });
    expect(res.valid).toBe(true);
    expect(res.violations).toHaveLength(0);
  });

  it('enforces safety clamps on requested RPS and concurrency', () => {
    const res = validateUrlAgainstScope('https://staging.example.com/api/v1/items', baseScope, {
      requestedRps: 150, // limit is 50
      requestedConcurrency: 25, // limit is 10
    });
    expect(res.valid).toBe(false);
    expect(res.violations.some((v) => v.includes('exceeds target scope limit of 50 RPS'))).toBe(true);
    expect(res.violations.some((v) => v.includes('exceeds target scope limit of 10'))).toBe(true);
  });
});
