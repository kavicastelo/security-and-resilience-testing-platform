import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth } from '../../apps/controller/src/services/db.js';
import { validateUrlAgainstScope, TargetScope, Finding } from '@security-lab/domain';
import { computeEvidenceHash } from '@security-lab/evidence';
import { evaluatePolicy } from '@security-lab/policy-engine';
import { ENTERPRISE_DEFAULT_POLICY } from '../../apps/controller/src/services/policies.service.js';

describe('Platform Self-Security & Defense Hardening Tests', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;

  const standardScope: TargetScope = {
    allowedHosts: ['staging.example.com', '*.api.example.com'],
    allowedPorts: [80, 443],
    excludedPaths: ['/admin/secret', '/billing/keys'],
    testing: {
      activeScanning: false,
      loadTesting: false,
      chaosTesting: false,
    },
    limits: {
      maxRps: 50,
      maxConcurrency: 10,
      maxDuration: '5m',
    },
  };

  beforeAll(async () => {
    app = buildApp({ disableLogging: true });
    const health = await checkDatabaseHealth();
    isDbAvailable = health === 'up';
  });

  afterAll(async () => {
    await app.close();
    await closeDatabase();
  });

  it('confirms database health for security test execution', () => {
    expect(isDbAvailable).toBe(true);
  });

  describe('1. Defensive Security Boundary & SSRF Shielding', () => {
    it('blocks dangerous cloud provider metadata endpoints (AWS, GCP, Azure)', () => {
      // AWS / generic link-local metadata
      const awsResult = validateUrlAgainstScope('http://169.254.169.254/latest/meta-data/', standardScope);
      expect(awsResult.valid).toBe(false);
      expect(
        awsResult.violations.some((v) =>
          v.toLowerCase().includes('metadata') || v.toLowerCase().includes('prohibited')
        ),
      ).toBe(true);

      // GCP metadata
      const gcpResult = validateUrlAgainstScope('http://metadata.google.internal/computeMetadata/v1/', standardScope);
      expect(gcpResult.valid).toBe(false);
      expect(
        gcpResult.violations.some((v) =>
          v.toLowerCase().includes('metadata') || v.toLowerCase().includes('prohibited')
        ),
      ).toBe(true);
    });

    it('strictly forbids unauthorized external domains and unlisted hosts', () => {
      const unauthorizedHosts = [
        'http://evil-attacker.com/steal',
        'http://unauthorized-domain.com:8080/api',
        'http://10.0.0.1:80',
      ];

      for (const url of unauthorizedHosts) {
        const result = validateUrlAgainstScope(url, standardScope);
        expect(result.valid).toBe(false);
        expect(result.violations.length).toBeGreaterThan(0);
      }
    });

    it('rejects unsafe protocol schemes (file://, ftp://, gopher://, javascript:)', () => {
      const unsafeProtocols = [
        'file:///etc/passwd',
        'ftp://internal.backup.local/data',
        'gopher://127.0.0.1:70',
        'javascript:alert(1)',
      ];

      for (const url of unsafeProtocols) {
        const result = validateUrlAgainstScope(url, standardScope);
        expect(result.valid).toBe(false);
      }
    });

    it('forbids access to excluded paths even on authorized hosts', () => {
      const excludedPathUrl = 'https://staging.example.com/admin/secret/reset';
      const result = validateUrlAgainstScope(excludedPathUrl, standardScope);
      expect(result.valid).toBe(false);
      expect(result.violations.some((v) => v.toLowerCase().includes('excluded'))).toBe(true);
    });

    it('blocks active scanning when testing capability is disabled in scope', () => {
      const testUrl = 'https://staging.example.com/api/v1/test';
      const result = validateUrlAgainstScope(testUrl, standardScope, {
        requestedCapability: 'activeScanning',
      });
      expect(result.valid).toBe(false);
      expect(result.violations.some((v) => v.toLowerCase().includes('activescanning'))).toBe(true);
    });
  });

  describe('2. Controller Error Sanitization & Information Disclosure Shielding', () => {
    it('returns sanitized error response when querying non-existent UUID without leaking DB stack traces', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/targets/00000000-0000-0000-0000-999999999999',
      });

      expect(res.statusCode).toBe(404);
      const json = JSON.parse(res.body);
      expect(json.success).toBe(false);
      expect(json.error).toBeDefined();
      expect(json.error.message).toBeDefined();

      // Ensure no stack trace, database table name, or internal paths leaked
      expect(res.body).not.toContain('node_modules');
      expect(res.body).not.toContain('drizzle');
      expect(res.body).not.toContain('SELECT * FROM');
      expect(res.body).not.toContain('at Object.');
    });

    it('handles malformed payload in release evaluation safely without 500 server crash', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/releases/evaluate',
        payload: {
          testRunId: '', // missing / invalid param
        },
      });

      expect(res.statusCode).toBe(400);
      const json = JSON.parse(res.body);
      expect(json.success).toBe(false);
      expect(json.error.code).toBe('MISSING_PARAM');
      expect(res.body).not.toContain('stack');
    });

    it('handles non-existent testRunId in release evaluation gracefully', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/releases/evaluate',
        payload: {
          testRunId: '00000000-0000-0000-0000-000000000099',
        },
      });

      expect(res.statusCode).toBe(400);
      const json = JSON.parse(res.body);
      expect(json.success).toBe(false);
      expect(json.error.code).toBe('EVALUATION_FAILED');
      expect(json.error.message).toContain('not found');
      expect(res.body).not.toContain('drizzle');
    });

    it('health check endpoint reports status without leaking DB credentials or connection strings', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/health',
      });

      expect(res.statusCode).toBe(200);
      const json = JSON.parse(res.body);
      expect(json.status).toBe('ok');
      expect(res.body).not.toContain('postgres://');
      expect(res.body).not.toContain('password');
      expect(res.body).not.toContain('secret');
    });
  });

  describe('3. Forensic Evidence Integrity & Tamper Detection', () => {
    it('produces cryptographic SHA-256 hash that changes upon single byte alteration', () => {
      const originalPayload = {
        id: 'ev-test-1',
        testRunId: '00000000-0000-0000-0000-000000000001',
        executionId: 'exec-test-1',
        environment: 'local',
        timestamp: new Date('2026-10-06T00:00:00.000Z'),
        response: {
          statusCode: 200,
          headers: {
            'x-powered-by': 'Express',
          },
        },
      };

      const tamperedPayload = {
        ...originalPayload,
        response: {
          statusCode: 200,
          headers: {
            'x-powered-by': 'Express!', // 1 character difference
          },
        },
      };

      const originalHash = computeEvidenceHash(originalPayload);
      const tamperedHash = computeEvidenceHash(tamperedPayload);

      expect(originalHash).toMatch(/^[a-f0-9]{64}$/);
      expect(tamperedHash).toMatch(/^[a-f0-9]{64}$/);
      expect(originalHash).not.toBe(tamperedHash);
    });

    it('calculates deterministic hashes for identical evidence records', () => {
      const payloadA = {
        id: 'ev-test-det',
        testRunId: '00000000-0000-0000-0000-000000000001',
        executionId: 'exec-test-det',
        environment: 'staging',
        timestamp: new Date('2026-10-06T12:00:00.000Z'),
      };

      const payloadB = {
        ...payloadA,
      };

      const hashA = computeEvidenceHash(payloadA);
      const hashB = computeEvidenceHash(payloadB);

      expect(hashA).toBe(hashB);
    });
  });

  describe('4. Policy Engine Fail-Safe Gating Assertions', () => {
    it('always blocks release when zero-tolerance critical vulnerability is present', () => {
      const criticalFinding: Finding = {
        id: 'finding-crit-1',
        testRunId: '00000000-0000-0000-0000-000000000001',
        ruleId: 'SEC-RCE-001',
        title: 'Remote Code Execution Vulnerability',
        description: 'Unauthenticated remote code execution detected',
        severity: 'critical',
        status: 'open',
        category: 'injection',
        evidence: [],
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = evaluatePolicy(ENTERPRISE_DEFAULT_POLICY, [criticalFinding], []);
      expect(result.decision).toBe('failed');
      expect(result.passed).toBe(false);
      expect(result.violations.length).toBeGreaterThan(0);
      expect(result.violations[0].action).toBe('block_release');
    });

    it('blocks release when P95 latency violates the enterprise SLA threshold', () => {
      const slaMetrics = [
        {
          id: 'm1',
          testRunId: '00000000-0000-0000-0000-000000000001',
          name: 'http_req_duration_p95',
          value: 750, // exceeds 500ms SLA
          unit: 'ms',
          metricType: 'gauge' as const,
          timestamp: new Date(),
        },
      ];

      const result = evaluatePolicy(ENTERPRISE_DEFAULT_POLICY, [], slaMetrics);
      expect(result.decision).toBe('failed');
      expect(result.passed).toBe(false);
      expect(result.violations.some((v) => v.ruleName.includes('Latency') || v.reason.includes('750ms'))).toBe(true);
    });
  });
});
