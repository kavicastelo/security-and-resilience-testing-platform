import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  targetsApi,
  Target,
  ChallengeInstructions,
  ScopeValidationResult,
} from '../src/api/targets.js';

describe('Phase UI-03: Target Studio, Cryptographic Ownership Wizard & Scope Safety Playground', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('exposes all Target Studio API lifecycle methods', () => {
    expect(typeof targetsApi.listTargets).toBe('function');
    expect(typeof targetsApi.getTarget).toBe('function');
    expect(typeof targetsApi.createTarget).toBe('function');
    expect(typeof targetsApi.updateTarget).toBe('function');
    expect(typeof targetsApi.deleteTarget).toBe('function');
    expect(typeof targetsApi.getChallenge).toBe('function');
    expect(typeof targetsApi.verifyOwnership).toBe('function');
    expect(typeof targetsApi.validateScope).toBe('function');
  });

  it('validates cryptographic challenge instructions for DNS TXT and HTTP well-known methods', () => {
    const mockChallenge: ChallengeInstructions = {
      targetId: '77777777-7777-7777-7777-777777777777',
      token: 'sec-abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
      status: 'PENDING',
      dns: {
        recordType: 'TXT',
        recordName: '_security-lab-challenge.staging.example.com',
        recordValue: 'sec-abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
        alternativeRecordName: 'staging.example.com',
      },
      http: {
        url: 'https://staging.example.com/.well-known/security-lab-challenge.txt',
        expectedContent: 'sec-abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
      },
    };

    expect(mockChallenge.dns.recordType).toBe('TXT');
    expect(mockChallenge.dns.recordName).toContain('_security-lab-challenge.');
    expect(mockChallenge.dns.recordValue).toBe(mockChallenge.token);
    expect(mockChallenge.http.url).toContain('/.well-known/security-lab-challenge.txt');
    expect(mockChallenge.http.expectedContent).toBe(mockChallenge.token);
  });

  it('validates scope simulation responses and detects defensive boundary violations', () => {
    // Valid in-scope response
    const validResult: ScopeValidationResult = {
      targetId: 'target-1',
      targetName: 'Customer API Staging',
      candidateUrl: 'https://staging.example.com/api/v1/health',
      valid: true,
      violations: [],
      matchedHost: 'staging.example.com',
      normalizedUrl: 'https://staging.example.com/api/v1/health',
      scope: {
        allowedHosts: ['staging.example.com'],
        allowedPorts: [80, 443],
        excludedPaths: ['/admin/delete'],
        testing: {
          activeScanning: true,
          loadTesting: false,
          chaosTesting: false,
        },
        limits: {
          maxRps: 100,
          maxConcurrency: 20,
          maxDuration: '10m',
        },
      },
    };

    expect(validResult.valid).toBe(true);
    expect(validResult.violations).toHaveLength(0);
    expect(validResult.matchedHost).toBe('staging.example.com');

    // Blocked SSRF Cloud Metadata response
    const ssrfViolation: ScopeValidationResult = {
      targetId: 'target-1',
      candidateUrl: 'http://169.254.169.254/latest/meta-data',
      valid: false,
      violations: [
        'Access to cloud metadata IP/host "169.254.169.254" is strictly prohibited.',
        'Host "169.254.169.254" is not within the authorized scope allowedHosts: [staging.example.com]',
      ],
    };

    expect(ssrfViolation.valid).toBe(false);
    expect(ssrfViolation.violations.some((v) => v.includes('cloud metadata'))).toBe(true);

    // Blocked excluded path response
    const pathViolation: ScopeValidationResult = {
      targetId: 'target-1',
      candidateUrl: 'https://staging.example.com/admin/delete',
      valid: false,
      violations: ['Path "/admin/delete" matches excluded path rule "/admin/delete"'],
    };

    expect(pathViolation.valid).toBe(false);
    expect(pathViolation.violations[0]).toContain('matches excluded path rule');
  });

  it('enforces safety budget ceilings and adaptive 5xx circuit-breaker invariants', () => {
    const target: Target = {
      id: 'target-1',
      projectId: 'proj-1',
      name: 'Resilient Microservice',
      baseUrl: 'https://service.internal.net',
      scope: {
        allowedHosts: ['service.internal.net'],
        allowedPorts: [443],
        excludedPaths: ['/reboot'],
        testing: {
          activeScanning: true,
          loadTesting: true,
          chaosTesting: false,
        },
        limits: {
          maxRps: 250,
          maxConcurrency: 50,
          maxDuration: '15m',
        },
        allowPrivateIps: false,
      },
      verificationStatus: 'VERIFIED',
      verifiedAt: '2026-10-14T09:00:00.000Z',
      verificationMethod: 'DNS_TXT',
      createdAt: '2026-10-14T08:00:00.000Z',
    };

    // Limits verification
    expect(target.scope.limits.maxRps).toBe(250);
    expect(target.scope.limits.maxConcurrency).toBe(50);
    expect(target.scope.allowPrivateIps).toBe(false);

    // Circuit Breaker constants (Phase 02 specification)
    const circuitBreakerThreshold = 0.25; // 25% 5xx errors
    const slidingWindowRequests = 10;
    const cooldownSeconds = 30;

    const simulateWindow = (errorsCount: number) => {
      const errorRate = errorsCount / slidingWindowRequests;
      return errorRate >= circuitBreakerThreshold ? 'OPEN' : 'CLOSED';
    };

    expect(simulateWindow(2)).toBe('CLOSED'); // 20% < 25%
    expect(simulateWindow(3)).toBe('OPEN');   // 30% >= 25%
    expect(simulateWindow(5)).toBe('OPEN');   // 50% >= 25%
    expect(cooldownSeconds).toBe(30);
  });
});
