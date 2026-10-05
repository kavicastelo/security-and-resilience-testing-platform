import { describe, it, expect } from 'vitest';
import { TargetScopeSchema, Finding } from '@security-lab/domain';
import { createImmutableEvidence, computeEvidenceHash } from '@security-lab/evidence';
import { calculatePostureScore } from '@security-lab/scoring';
import { evaluatePolicy } from '@security-lab/policy-engine';

describe('Domain Contracts & Safety Boundary Tests', () => {
  it('validates Target Scope boundaries accurately', () => {
    const validScope = {
      allowedHosts: ['api.example.com'],
      allowedPorts: [443],
      excludedPaths: ['/admin'],
      testing: {
        activeScanning: true,
        loadTesting: false,
        chaosTesting: false,
      },
      limits: {
        maxRps: 50,
        maxConcurrency: 10,
        maxDuration: '5m',
      },
    };

    const parsed = TargetScopeSchema.safeParse(validScope);
    expect(parsed.success).toBe(true);

    // Empty allowedHosts must fail validation (security boundary)
    const invalidScope = {
      ...validScope,
      allowedHosts: [],
    };
    const failedParse = TargetScopeSchema.safeParse(invalidScope);
    expect(failedParse.success).toBe(false);
  });

  it('generates immutable, tamper-detectable evidence with cryptographic hash', () => {
    const evidence = createImmutableEvidence({
      id: '00000000-0000-0000-0000-000000000001',
      testRunId: '00000000-0000-0000-0000-000000000002',
      executionId: '00000000-0000-0000-0000-000000000003',
      environment: 'staging',
      request: {
        method: 'GET',
        url: 'https://staging.example.com/health',
        headers: {},
      },
      response: {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
      },
      timestamp: new Date('2026-01-01T00:00:00.000Z'),
    });

    expect(evidence.immutableHash).toBeDefined();
    expect(evidence.immutableHash).toHaveLength(64); // SHA-256 length

    // Tampering test: verify computed hash changes if content differs
    const modifiedPayload = {
      ...evidence,
      environment: 'production',
    };
    const modifiedHash = computeEvidenceHash(modifiedPayload);
    expect(modifiedHash).not.toBe(evidence.immutableHash);

    // Verify object immutability (frozen)
    expect(() => {
      // @ts-expect-error Attempting mutation on readonly/frozen object
      evidence.environment = 'hacked';
    }).toThrow();
  });

  it('calculates security posture score and grade correctly', () => {
    const findings: Finding[] = [
      {
        id: '1',
        fingerprint: 'fp-1',
        title: 'Missing HSTS',
        category: 'headers',
        severity: 'medium',
        confidence: 'certain',
        status: 'open',
        description: 'No HSTS header present',
        testDefinitionId: 'test-1',
        testRunId: '2',
        executionId: '3',
        targetId: '4',
        firstDetectedAt: new Date(),
        lastDetectedAt: new Date(),
        metadata: {},
      },
    ];

    const result = calculatePostureScore(findings);
    expect(result.findingCounts.medium).toBe(1);
    expect(result.score).toBe(95); // 100 - 5 = 95
    expect(result.grade).toBe('A');
  });

  it('evaluates policy release gate and blocks release on critical finding', () => {
    const policy = {
      id: 'gate-1',
      name: 'Default Gate',
      rules: [
        {
          id: 'rule-zero-crit',
          name: 'Zero Critical Findings',
          condition: {
            maxCountBySeverity: {
              critical: 0,
            },
          },
          action: 'block_release' as const,
        },
      ],
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const findings: Finding[] = [
      {
        id: 'crit-1',
        fingerprint: 'fp-crit',
        title: 'Critical Auth Bypass',
        category: 'authentication',
        severity: 'critical',
        confidence: 'certain',
        status: 'open',
        description: 'Admin endpoint accessible without auth token',
        testDefinitionId: 'test-auth',
        testRunId: 'run-1',
        executionId: 'exec-1',
        targetId: 'tgt-1',
        firstDetectedAt: new Date(),
        lastDetectedAt: new Date(),
        metadata: {},
      },
    ];

    const verdict = evaluatePolicy(policy, findings);
    expect(verdict.passed).toBe(false);
    expect(verdict.decision).toBe('failed');
    expect(verdict.violations.length).toBe(1);
    expect(verdict.violations[0]?.action).toBe('block_release');
  });
});
