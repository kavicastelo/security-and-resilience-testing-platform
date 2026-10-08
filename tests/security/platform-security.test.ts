import http from 'node:http';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth } from '../../apps/controller/src/services/db.js';
import { validateUrlAgainstScope, TargetScope, Finding } from '@security-lab/domain';
import { computeEvidenceHash } from '@security-lab/evidence';
import { evaluatePolicy } from '@security-lab/policy-engine';
import { ENTERPRISE_DEFAULT_POLICY } from '../../apps/controller/src/services/policies.service.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import YAML from 'yaml';
import {
  safeFetch,
  SecurityBoundaryError,
  HeadersSecurityEngine,
  CorsSecurityEngine,
  RateLimitResilienceEngine,
  DeclarativeTestEngine,
  ExecutionContext,
  isApprovedImage,
  extractImageDigest,
  PINNED_SCANNER_DIGESTS,
  validateVolumePath,
  validateNetworkMode,
  enforceContainerSecurityPolicy,
  ContainerSecurityError,
  MANDATORY_DOCKER_SECURITY_FLAGS,
} from '@security-lab/test-sdk';
import { logger } from '@security-lab/logger';

describe('Platform Self-Security & Defense Hardening Tests', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;
  let mockServer: http.Server;
  let mockPort: number;
  let mockBaseUrl: string;

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

    // Start local redirect test server to verify redirect interception and SSRF shielding
    mockServer = http.createServer((req, res) => {
      if (req.url === '/redirect-to-metadata') {
        res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
        res.end();
        return;
      }

      if (req.url === '/redirect-to-unauthorized-port') {
        res.writeHead(302, { Location: `http://127.0.0.1:5432/` });
        res.end();
        return;
      }

      if (req.url === '/redirect-to-external') {
        res.writeHead(302, { Location: 'http://evil-attacker.com/steal-creds' });
        res.end();
        return;
      }

      if (req.url === '/redirect-loop') {
        res.writeHead(302, { Location: '/redirect-loop' });
        res.end();
        return;
      }

      if (req.url === '/redirect-safe') {
        res.writeHead(302, { Location: '/safe-destination' });
        res.end();
        return;
      }

      if (req.url === '/safe-destination') {
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'X-Redirect-Followed': 'true',
        });
        res.end(JSON.stringify({ status: 'ok', safe: true }));
        return;
      }

      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('Mock Server OK');
    });

    await new Promise<void>((resolve) => {
      mockServer.listen(0, '127.0.0.1', () => {
        const addr = mockServer.address();
        if (addr && typeof addr === 'object') {
          mockPort = addr.port;
          mockBaseUrl = `http://127.0.0.1:${mockPort}`;
        }
        resolve();
      });
    });
  });

  afterAll(async () => {
    await app.close();
    await closeDatabase();
    await new Promise<void>((resolve, reject) => {
      mockServer.close((err) => (err ? reject(err) : resolve()));
    });
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
          v.toLowerCase().includes('metadata') || v.toLowerCase().includes('prohibited'),
        ),
      ).toBe(true);

      // GCP metadata
      const gcpResult = validateUrlAgainstScope('http://metadata.google.internal/computeMetadata/v1/', standardScope);
      expect(gcpResult.valid).toBe(false);
      expect(
        gcpResult.violations.some((v) =>
          v.toLowerCase().includes('metadata') || v.toLowerCase().includes('prohibited'),
        ),
      ).toBe(true);
    });

    it('strictly blocks alternative numeric, hex, and octal IP encodings targeting metadata', () => {
      const maliciousVariants = [
        'http://2852039166/latest/meta-data/', // Decimal integer
        'http://0xa9fea9fe/latest/meta-data/', // Hexadecimal
        'http://0251.0376.0251.0376/latest/meta-data/', // Octal
        'http://[::ffff:169.254.169.254]/', // IPv4-mapped IPv6 dotted
        'http://[::ffff:a9fe:a9fe]/', // IPv4-mapped IPv6 hex
        'http://[fd00:ec2::254]/', // AWS IPv6 metadata
      ];

      for (const url of maliciousVariants) {
        const result = validateUrlAgainstScope(url, standardScope);
        expect(result.valid).toBe(false);
        expect(
          result.violations.some((v) =>
            v.toLowerCase().includes('metadata') || v.toLowerCase().includes('prohibited'),
          ),
        ).toBe(true);
      }
    });

    it('strictly forbids unauthorized external domains and unlisted hosts', () => {
      const unauthorizedHosts = [
        'http://evil-attacker.com/steal',
        'http://unauthorized-domain.com:8080/api',
        'http://10.0.0.1:80',
        'http://172.16.0.1:80',
        'http://192.168.1.1:80',
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

    it('enforces exact subdomain wildcard matching (protects against prefix and suffix confusion)', () => {
      // Valid matching subdomains
      expect(validateUrlAgainstScope('https://auth.api.example.com/login', standardScope).valid).toBe(true);
      expect(validateUrlAgainstScope('https://v2.api.example.com/login', standardScope).valid).toBe(true);

      // Suffix confusion: evil-api.example.com must NOT match *.api.example.com
      const evilSuffix = validateUrlAgainstScope('https://evil-api.example.com/login', standardScope);
      expect(evilSuffix.valid).toBe(false);
      expect(evilSuffix.violations[0]).toContain('not within the authorized scope allowedHosts');

      // TLD / host append: api.example.com.attacker.com must NOT match *.api.example.com
      const evilAppend = validateUrlAgainstScope('https://api.example.com.attacker.com/login', standardScope);
      expect(evilAppend.valid).toBe(false);
    });
  });

  const getAuthorizedLocalScope = (): TargetScope => ({
    allowedHosts: ['127.0.0.1'],
    allowedPorts: [mockPort],
    excludedPaths: [],
    testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
    limits: { maxRps: 50, maxConcurrency: 5, maxDuration: '1m' },
  });

  describe('2. Hardened safeFetch & HTTP Redirect Interception', () => {
    it('intercepts 302 redirect to cloud metadata IP and throws SecurityBoundaryError', async () => {
      await expect(
        safeFetch(`${mockBaseUrl}/redirect-to-metadata`, {
          scope: getAuthorizedLocalScope(),
        }),
      ).rejects.toThrowError(SecurityBoundaryError);
    });

    it('intercepts 302 redirect to unauthorized port and throws SecurityBoundaryError', async () => {
      await expect(
        safeFetch(`${mockBaseUrl}/redirect-to-unauthorized-port`, {
          scope: getAuthorizedLocalScope(),
        }),
      ).rejects.toThrowError(SecurityBoundaryError);
    });

    it('intercepts 302 redirect to unauthorized external host and throws SecurityBoundaryError', async () => {
      await expect(
        safeFetch(`${mockBaseUrl}/redirect-to-external`, {
          scope: getAuthorizedLocalScope(),
        }),
      ).rejects.toThrowError(SecurityBoundaryError);
    });

    it('detects redirect loops and terminates after exceeding maxRedirects threshold', async () => {
      await expect(
        safeFetch(`${mockBaseUrl}/redirect-loop`, {
          scope: getAuthorizedLocalScope(),
          maxRedirects: 3,
        }),
      ).rejects.toThrowError(/Exceeded maximum allowed redirect hops/i);
    });

    it('successfully follows valid in-scope relative redirect', async () => {
      const res = await safeFetch(`${mockBaseUrl}/redirect-safe`, {
        scope: getAuthorizedLocalScope(),
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.status).toBe('ok');
      expect(json.safe).toBe(true);
    });
  });

  describe('3. Native Engines Safe Dispatch & SSRF Resistance', () => {
    const makeContext = (url: string): ExecutionContext => ({
      correlationId: 'sec-test-corr-1',
      testRunId: '00000000-0000-0000-0000-000000000001',
      executionId: '00000000-0000-0000-0000-000000000002',
      target: {
        id: '00000000-0000-0000-0000-000000000003',
        name: 'Redirect Target',
        baseUrl: url,
        scope: getAuthorizedLocalScope(),
      },
      logger,
      abortSignal: new AbortController().signal,
      reportProgress: () => {},
    });

    it('HeadersSecurityEngine safely fails when target attempts redirect to metadata IP', async () => {
      const engine = new HeadersSecurityEngine();
      const redirectUrl = `${mockBaseUrl}/redirect-to-metadata`;
      const result = await engine.execute({ targetUrl: redirectUrl }, makeContext(redirectUrl));

      expect(result.success).toBe(false);
      expect(result.error).toContain('security boundary');
    });

    it('CorsSecurityEngine safely fails when target attempts redirect to metadata IP', async () => {
      const engine = new CorsSecurityEngine();
      const redirectUrl = `${mockBaseUrl}/redirect-to-metadata`;
      const result = await engine.execute({ targetUrl: redirectUrl }, makeContext(redirectUrl));

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('RateLimitResilienceEngine safely handles target redirecting to metadata without leaking requests', async () => {
      const engine = new RateLimitResilienceEngine();
      const redirectUrl = `${mockBaseUrl}/redirect-to-metadata`;
      const result = await engine.execute({ targetUrl: redirectUrl }, makeContext(redirectUrl));

      expect(result.success).toBe(true);
      expect(result.rawOutput).toBeDefined();
      expect((result.rawOutput as { successfulResponses: number }).successfulResponses).toBe(0);
    });

    it('DeclarativeTestEngine rejects out-of-scope absolute URLs before network dispatch', async () => {
      const engine = new DeclarativeTestEngine();
      const maliciousYaml = `
id: ssrf-attempt-spec
name: SSRF Injection Attack Test
version: 1.0.0
category: api_schema
description: Attempts to target AWS metadata via absolute URL
target:
  endpoint: /
  requiredCapabilities: []
tests:
  - id: metadata-ssrf-probe
    name: Probe Metadata Endpoint
    path: http://169.254.169.254/latest/meta-data/
    method: GET
    expectedStatus: [200]
    assertions: []
`;
      const result = await engine.execute(
        { targetUrl: mockBaseUrl, options: { yaml: maliciousYaml } },
        makeContext(mockBaseUrl),
      );

      expect(result.success).toBe(false);
      const boundaryViolation = result.findings.find((f) =>
        f.title.includes('Security Boundary Violation'),
      );
      expect(boundaryViolation).toBeDefined();
      expect(boundaryViolation?.severity).toBe('critical');
      expect(boundaryViolation?.description).toContain('out-of-scope absolute URL');
    });
  });

  describe('4. Controller Error Sanitization & Information Disclosure Shielding', () => {
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

  describe('5. Forensic Evidence Integrity & Tamper Detection', () => {
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

  describe('6. Policy Engine Fail-Safe Gating Assertions', () => {
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

  describe('7. Docker Sandbox & Host Boundary Hardening (Phase 16.7)', () => {
    it('validates Kubernetes deployment manifest enforces zero Docker socket exposure and strict least-privilege', () => {
      const manifestPath = path.resolve(__dirname, '../../infrastructure/k8s/agent.yaml');
      expect(fs.existsSync(manifestPath)).toBe(true);

      const content = fs.readFileSync(manifestPath, 'utf8');
      const docs = YAML.parseAllDocuments(content).map((doc) => doc.toJSON());

      // 1. Textual audit
      expect(content).not.toContain('/var/run/docker.sock');
      expect(content).not.toContain('docker.sock');
      expect(content).not.toContain('docker_engine');

      // 2. Structural AST audit of Deployment spec
      interface K8sPodSpec {
        securityContext?: { runAsNonRoot?: boolean; runAsUser?: number };
        volumes?: Array<{ name?: string; hostPath?: unknown; emptyDir?: unknown }>;
        containers?: Array<{
          securityContext?: {
            readOnlyRootFilesystem?: boolean;
            allowPrivilegeEscalation?: boolean;
            privileged?: boolean;
            capabilities?: { drop?: string[] };
          };
          volumeMounts?: Array<{ name?: string; mountPath?: string }>;
        }>;
      }
      interface K8sDeployment {
        kind?: string;
        spec?: { template?: { spec?: K8sPodSpec } };
      }

      const deployment = (docs as unknown[]).find(
        (d): d is K8sDeployment => (d as K8sDeployment)?.kind === 'Deployment',
      );
      expect(deployment).toBeDefined();

      const podSpec = deployment?.spec?.template?.spec;
      expect(podSpec).toBeDefined();

      // Pod securityContext checks
      expect(podSpec.securityContext?.runAsNonRoot).toBe(true);
      expect(podSpec.securityContext?.runAsUser).toBe(10001);

      // Volume checks: no hostPath socket mounts
      const volumes = podSpec.volumes || [];
      for (const vol of volumes) {
        expect(vol.hostPath).toBeUndefined();
      }
      expect(volumes.length).toBeGreaterThan(0);
      expect(volumes[0].name).toBe('tmp-dir');
      expect(volumes[0].emptyDir).toBeDefined();

      // Container securityContext checks
      const container = podSpec.containers?.[0];
      expect(container).toBeDefined();
      expect(container.securityContext?.readOnlyRootFilesystem).toBe(true);
      expect(container.securityContext?.allowPrivilegeEscalation).toBe(false);
      expect(container.securityContext?.privileged).toBe(false);
      expect(container.securityContext?.capabilities?.drop).toContain('ALL');

      // Container volumeMounts checks
      const volumeMounts = container.volumeMounts || [];
      for (const vm of volumeMounts) {
        expect(vm.name).not.toContain('docker');
        expect(vm.mountPath).not.toContain('docker');
      }
      expect(volumeMounts.some((vm: Record<string, unknown>) => vm.mountPath === '/tmp')).toBe(true);
    });

    it('enforces OCI image allowlist and cryptographic SHA-256 digest pinning', () => {
      // Approved scanner images with standard tags
      expect(isApprovedImage('zaproxy/zaproxy:2.14.0')).toBe(true);
      expect(isApprovedImage('owasp/zap2docker-stable:latest')).toBe(true);
      expect(isApprovedImage('aquasec/trivy:0.49.1')).toBe(true);
      expect(isApprovedImage('grafana/k6:0.50.0')).toBe(true);

      // Approved scanner images with SHA-256 digest pinning
      expect(isApprovedImage(`zaproxy/zaproxy@${PINNED_SCANNER_DIGESTS['zaproxy/zaproxy']}`)).toBe(true);
      expect(isApprovedImage(`aquasec/trivy:0.49.1@${PINNED_SCANNER_DIGESTS['aquasec/trivy']}`)).toBe(true);
      expect(isApprovedImage(`grafana/k6@${PINNED_SCANNER_DIGESTS['grafana/k6']}`)).toBe(true);
      expect(isApprovedImage('ghcr.io/zaproxy/zaproxy:latest@sha256:4d603a1184ff5d9e5b53d463d12d4d5e277636e2f170f3f619730592e3ca914a')).toBe(true);

      // Unapproved images must be rejected
      expect(isApprovedImage('ubuntu:latest')).toBe(false);
      expect(isApprovedImage('alpine:3.19')).toBe(false);
      expect(isApprovedImage('attacker/custom-miner:latest')).toBe(false);
      expect(isApprovedImage('evil-zaproxy/zaproxy:latest')).toBe(false);

      // Injection and malformed characters must be rejected
      expect(isApprovedImage('zaproxy/zaproxy; rm -rf /')).toBe(false);
      expect(isApprovedImage('zaproxy/zaproxy || bash')).toBe(false);
      expect(isApprovedImage('zaproxy/zaproxy$(whoami)')).toBe(false);
      expect(isApprovedImage('aquasec/trivy@sha256:shortdigest')).toBe(false);

      // Digest extractor verification
      const sampleDigest = '4d603a1184ff5d9e5b53d463d12d4d5e277636e2f170f3f619730592e3ca914a';
      expect(extractImageDigest(`zaproxy/zaproxy@sha256:${sampleDigest}`)).toBe(sampleDigest);
      expect(extractImageDigest(`zaproxy/zaproxy:2.14.0@sha256:${sampleDigest.toUpperCase()}`)).toBe(sampleDigest);
      expect(extractImageDigest('zaproxy/zaproxy:2.14.0')).toBeNull();
    });

    it('enforces network isolation and strictly rejects host networking', () => {
      expect(() => validateNetworkMode('host')).toThrow(ContainerSecurityError);
      expect(() => validateNetworkMode('--network=host')).toThrow(ContainerSecurityError);
      expect(() => validateNetworkMode('--net host')).toThrow(ContainerSecurityError);
      expect(() => validateNetworkMode('container:target-victim')).toThrow(ContainerSecurityError);

      // Isolated bridge networks are permitted
      expect(() => validateNetworkMode('bridge')).not.toThrow();
      expect(() => validateNetworkMode('custom-isolated-net')).not.toThrow();
      expect(() => validateNetworkMode(undefined)).not.toThrow();
    });

    it('strictly rejects volume mounts attempting Docker socket or host directory escape', () => {
      // Direct Docker socket paths
      expect(validateVolumePath('/var/run/docker.sock').valid).toBe(false);
      expect(validateVolumePath('/run/docker.sock').valid).toBe(false);
      expect(validateVolumePath('//./pipe/docker_engine').valid).toBe(false);

      // Directory traversal attempts toward Docker socket or host roots
      expect(validateVolumePath('/tmp/../var/run/docker.sock').valid).toBe(false);
      expect(validateVolumePath('/tmp/../../etc').valid).toBe(false);
      expect(validateVolumePath('/etc').valid).toBe(false);
      expect(validateVolumePath('/root').valid).toBe(false);
      expect(validateVolumePath('/').valid).toBe(false);

      // Valid scratch directory inside os.tmpdir()
      const validScratch = path.join(os.tmpdir(), `security-lab-test-${Date.now()}`);
      expect(validateVolumePath(validScratch).valid).toBe(true);
    });

    it('enforces full container security policy validation with enforceContainerSecurityPolicy', () => {
      const validScratch = path.join(os.tmpdir(), 'valid-scratch-dir');

      // Valid policy options
      expect(() =>
        enforceContainerSecurityPolicy({
          image: 'zaproxy/zaproxy:2.14.0',
          network: 'bridge',
          volumes: [{ hostPath: validScratch, containerPath: '/zap/wrk', mode: 'rw' }],
        }),
      ).not.toThrow();

      // Policy violation: unapproved image
      expect(() =>
        enforceContainerSecurityPolicy({
          image: 'ubuntu:22.04',
        }),
      ).toThrow(ContainerSecurityError);

      // Policy violation: host network
      expect(() =>
        enforceContainerSecurityPolicy({
          image: 'aquasec/trivy:0.49.1',
          network: 'host',
        }),
      ).toThrow(ContainerSecurityError);

      // Policy violation: Docker socket volume mount
      expect(() =>
        enforceContainerSecurityPolicy({
          image: 'grafana/k6:0.50.0',
          volumes: [{ hostPath: '/var/run/docker.sock', containerPath: '/var/run/docker.sock' }],
        }),
      ).toThrow(ContainerSecurityError);

      // Verify mandatory CIS benchmark flags are present
      expect(MANDATORY_DOCKER_SECURITY_FLAGS).toContain('--security-opt=no-new-privileges:true');
      expect(MANDATORY_DOCKER_SECURITY_FLAGS).toContain('--cap-drop=ALL');
      expect(MANDATORY_DOCKER_SECURITY_FLAGS).toContain('--read-only');
      expect(MANDATORY_DOCKER_SECURITY_FLAGS).toContain('--pids-limit=100');
    });
  });
});
