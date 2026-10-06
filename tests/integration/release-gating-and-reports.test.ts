import http from 'node:http';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth } from '../../apps/controller/src/services/db.js';
import { FastifyInstance } from 'fastify';
import {
  generateJUnitXml,
  generateSarifReport,
  generateHtmlExecutiveReport,
  ReportInput,
} from '@security-lab/contracts';
import { evaluatePolicy } from '@security-lab/policy-engine';
import { calculatePostureScore } from '@security-lab/scoring';
import { Finding, TestRun, Policy } from '@security-lab/domain';

describe('Phase 5: Release Gating & Enterprise Reporting Pipeline', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;
  let server: http.Server;
  let serverPort: number;
  let serverUrl: string;

  beforeAll(async () => {
    app = buildApp({ disableLogging: true });
    const health = await checkDatabaseHealth();
    isDbAvailable = health === 'up';

    server = http.createServer((_req, res) => {
      // Insecure server response (missing headers, disclosure)
      res.writeHead(200, {
        'Content-Type': 'text/plain',
        Server: 'nginx/1.18.0',
      });
      res.end('Test Target Operational');
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        if (addr && typeof addr === 'object') {
          serverPort = addr.port;
          serverUrl = `http://127.0.0.1:${serverPort}`;
        }
        resolve();
      });
    });
  });

  afterAll(async () => {
    await app.close();
    await closeDatabase();
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  it('confirms database availability', () => {
    expect(isDbAvailable).toBe(true);
  });

  describe('1. Report Generation Engines (JUnit XML, SARIF v2.1.0, HTML)', () => {
    const mockTestRun: TestRun = {
      id: '11111111-1111-1111-1111-111111111111',
      projectId: '22222222-2222-2222-2222-222222222222',
      targetId: '33333333-3333-3333-3333-333333333333',
      profileId: 'native-class-a',
      status: 'completed',
      summary: {
        totalTests: 2,
        passedTests: 1,
        failedTests: 1,
        errorTests: 0,
        findingsCount: { critical: 0, high: 1, medium: 1, low: 0, info: 0 },
      },
      metadata: {},
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const mockFindings: Finding[] = [
      {
        id: 'finding-1',
        fingerprint: 'fp-1',
        title: 'Missing Content-Security-Policy <CSP>',
        category: 'http_headers',
        severity: 'high',
        confidence: 'firm',
        status: 'open',
        description: 'Endpoint does not emit Content-Security-Policy header & allows XSS injection',
        recommendation: 'Configure CSP header: default-src \'self\'',
        testDefinitionId: 'engine-native-headers',
        testRunId: mockTestRun.id,
        executionId: 'exec-1',
        targetId: mockTestRun.targetId,
        firstDetectedAt: new Date(),
        lastDetectedAt: new Date(),
        metadata: {},
      },
      {
        id: 'finding-2',
        fingerprint: 'fp-2',
        title: 'Insecure CORS Wildcard Reflection',
        category: 'cors',
        severity: 'medium',
        confidence: 'firm',
        status: 'open',
        description: 'Endpoint reflects arbitrary Origin headers with credentials allowed',
        recommendation: 'Specify exact trusted origin domain whitelist',
        testDefinitionId: 'engine-native-cors',
        testRunId: mockTestRun.id,
        executionId: 'exec-2',
        targetId: mockTestRun.targetId,
        firstDetectedAt: new Date(),
        lastDetectedAt: new Date(),
        metadata: {},
      },
    ];

    const mockInput: ReportInput = {
      testRun: mockTestRun,
      target: { id: mockTestRun.targetId, name: 'Production API Gateway', baseUrl: 'https://api.example.com' },
      executions: [
        { id: 'exec-1', engineId: 'engine-native-headers', executionClass: 'class_a_native', status: 'completed', durationMs: 120 },
        { id: 'exec-2', engineId: 'engine-native-cors', executionClass: 'class_a_native', status: 'completed', durationMs: 85 },
      ],
      findings: mockFindings,
      metrics: [
        { id: 'm-1', testRunId: mockTestRun.id, executionId: 'exec-1', name: 'http_req_duration_p95', value: 240, unit: 'ms', tags: {}, timestamp: new Date() },
        { id: 'm-2', testRunId: mockTestRun.id, executionId: 'exec-1', name: 'http_req_duration_p99', value: 310, unit: 'ms', tags: {}, timestamp: new Date() },
        { id: 'm-3', testRunId: mockTestRun.id, executionId: 'exec-1', name: 'http_rps', value: 125.5, unit: 'rps', tags: {}, timestamp: new Date() },
      ],
      posture: calculatePostureScore(mockFindings),
    };

    it('generates valid JUnit XML with testsuites, testcases, and escaped XML entities', () => {
      const xml = generateJUnitXml(mockInput);

      expect(xml).toContain('<?xml version="1.0" encoding="UTF-8"?>');
      expect(xml).toContain('<testsuites name="Security Lab: Production API Gateway"');
      expect(xml).toContain('<testsuite id="exec-1" name="engine-native-headers"');
      expect(xml).toContain('<testcase classname="engine-native-headers" name="Missing Content-Security-Policy &lt;CSP&gt;"');
      expect(xml).toContain('<failure type="http_headers" message="Missing Content-Security-Policy &lt;CSP&gt; [HIGH]">');
      expect(xml).toContain('Recommendation: Configure CSP header: default-src \'self\'');
    });

    it('generates compliant SARIF v2.1.0 JSON with rules, results, and locations', () => {
      const sarif = generateSarifReport(mockInput);

      expect(sarif.version).toBe('2.1.0');
      expect(sarif.$schema).toContain('sarif-schema-2.1.0.json');
      expect(sarif.runs.length).toBe(1);

      const run = sarif.runs[0]!;
      expect(run.tool.driver.name).toBe('Security Lab');
      expect(run.tool.driver.rules.length).toBeGreaterThanOrEqual(2);

      const highResult = run.results.find((r) => r.level === 'error');
      expect(highResult).toBeDefined();
      expect(highResult?.message.text).toContain('[HIGH]');
      expect(highResult?.locations?.[0]?.physicalLocation.artifactLocation.uri).toBe('https://api.example.com');

      const medResult = run.results.find((r) => r.level === 'warning');
      expect(medResult).toBeDefined();
      expect(medResult?.message.text).toContain('[MEDIUM]');
    });

    it('generates self-contained executive HTML report with posture score & latency telemetry', () => {
      const html = generateHtmlExecutiveReport(mockInput);

      expect(html).toContain('<!DOCTYPE html>');
      expect(html).toContain('SECURITY LAB');
      expect(html).toContain('Production API Gateway');
      expect(html).toContain('Security Posture Assessment');
      expect(html).toContain('Posture Score');
      expect(html).toContain('P95 Response Latency');
      expect(html).toContain('240 ms');
      expect(html).toContain('Missing Content-Security-Policy &lt;CSP&gt;');
      expect(html).toContain('Insecure CORS Wildcard Reflection');
    });
  });

  describe('2. Policy Engine & Release Gate Evaluation', () => {
    const testPolicy: Policy = {
      id: 'test-policy-1',
      name: 'Strict Deployment Gate',
      description: 'Zero critical findings and max 500ms P95 latency SLA',
      rules: [
        {
          id: 'rule-zero-crit',
          name: 'Zero Critical Findings',
          condition: { maxAllowedSeverity: 'high' },
          action: 'block_release',
        },
        {
          id: 'rule-sla',
          name: 'Latency SLA Rule',
          condition: { maxP95LatencyMs: 500 },
          action: 'block_release',
        },
      ],
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    it('approves compliant test results when no policy rules are violated', () => {
      const findings: Finding[] = [
        {
          id: 'f-1',
          fingerprint: 'fp-1',
          title: 'Missing X-Frame-Options',
          category: 'headers',
          severity: 'medium',
          confidence: 'firm',
          status: 'open',
          description: 'Clickjacking protection header is absent',
          testDefinitionId: 'native-headers',
          testRunId: 'r-1',
          executionId: 'e-1',
          targetId: 't-1',
          firstDetectedAt: new Date(),
          lastDetectedAt: new Date(),
          metadata: {},
        },
      ];

      const metrics = [
        { id: 'm-1', testRunId: 'r-1', executionId: 'e-1', name: 'http_req_duration_p95', value: 180, unit: 'ms', tags: {}, timestamp: new Date() },
      ];

      const result = evaluatePolicy(testPolicy, findings, metrics);
      expect(result.passed).toBe(true);
      expect(result.decision).toBe('passed');
      expect(result.violations.length).toBe(0);
    });

    it('blocks release when a critical finding is detected', () => {
      const findings: Finding[] = [
        {
          id: 'f-2',
          fingerprint: 'fp-2',
          title: 'Remote Code Execution Vector',
          category: 'injection',
          severity: 'critical',
          confidence: 'firm',
          status: 'open',
          description: 'Unauthenticated command injection vulnerability',
          testDefinitionId: 'zap-scanner',
          testRunId: 'r-2',
          executionId: 'e-2',
          targetId: 't-2',
          firstDetectedAt: new Date(),
          lastDetectedAt: new Date(),
          metadata: {},
        },
      ];

      const result = evaluatePolicy(testPolicy, findings, []);
      expect(result.passed).toBe(false);
      expect(result.decision).toBe('failed');
      expect(result.violations.some((v) => v.ruleName === 'Zero Critical Findings')).toBe(true);
    });

    it('blocks release when latency SLA threshold is breached under concurrent load', () => {
      const metrics = [
        { id: 'm-2', testRunId: 'r-3', executionId: 'e-3', name: 'http_req_duration_p95', value: 850, unit: 'ms', tags: {}, timestamp: new Date() },
      ];

      const result = evaluatePolicy(testPolicy, [], metrics);
      expect(result.passed).toBe(false);
      expect(result.decision).toBe('failed');
      expect(result.violations.some((v) => v.reason.includes('exceeds maximum allowed policy threshold of 500ms'))).toBe(true);
    });
  });

  describe('3. Controller Reports & Release Gating API Endpoints', () => {
    let projectId: string;
    let targetId: string;
    let testRunId: string;

    it('sets up project, target, and executes baseline test suite', async () => {
      const randomSuffix = Math.floor(Math.random() * 100000);

      // Create project
      const projRes = await app.inject({
        method: 'POST',
        url: '/api/v1/projects',
        payload: {
          name: `Phase 5 Project ${randomSuffix}`,
          description: 'Validating reporting and release gating',
        },
      });
      expect(projRes.statusCode).toBe(201);
      projectId = JSON.parse(projRes.payload).data.id;

      // Create target
      const targetRes = await app.inject({
        method: 'POST',
        url: `/api/v1/projects/${projectId}/targets`,
        payload: {
          name: `Phase 5 Target ${randomSuffix}`,
          baseUrl: serverUrl,
          allowedHosts: ['127.0.0.1'],
          allowedPorts: [serverPort],
          testing: {
            activeScanning: true,
            loadTesting: true,
            chaosTesting: false,
          },
        },
      });
      expect(targetRes.statusCode).toBe(201);
      targetId = JSON.parse(targetRes.payload).data.id;

      // Create TestRun
      const runRes = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        payload: {
          projectId,
          targetId,
          profileId: 'native-class-a',
          triggeredBy: 'manual',
        },
      });
      expect(runRes.statusCode).toBe(201);
      testRunId = JSON.parse(runRes.payload).data.id;

      // Execute TestRun
      const execRes = await app.inject({
        method: 'POST',
        url: `/api/v1/test-runs/${testRunId}/execute?wait=true`,
      });
      expect(execRes.statusCode).toBe(200);
    });

    it('serves JUnit XML report via GET /api/v1/test-runs/:id/report?format=junit', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/test-runs/${testRunId}/report?format=junit`,
      });
      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toContain('application/xml');
      expect(res.payload).toContain('<?xml version="1.0" encoding="UTF-8"?>');
      expect(res.payload).toContain('<testsuites');
    });

    it('serves SARIF v2.1.0 report via GET /api/v1/test-runs/:id/report?format=sarif', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/test-runs/${testRunId}/report?format=sarif`,
      });
      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toContain('application/sarif+json');

      const sarif = JSON.parse(res.payload);
      expect(sarif.version).toBe('2.1.0');
      expect(sarif.$schema).toContain('sarif-schema-2.1.0.json');
      expect(Array.isArray(sarif.runs)).toBe(true);
    });

    it('serves Executive HTML report via GET /api/v1/test-runs/:id/report?format=html', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/test-runs/${testRunId}/report?format=html`,
      });
      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toContain('text/html');
      expect(res.payload).toContain('<!DOCTYPE html>');
      expect(res.payload).toContain('SECURITY LAB');
    });

    it('evaluates release gate and persists release record via POST /api/v1/releases/evaluate', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/releases/evaluate',
        payload: {
          testRunId,
          name: 'Release-1.0.0',
          version: '1.0.0',
          gitCommit: 'a1b2c3d4e5',
        },
      });
      expect(res.statusCode).toBe(200);

      const json = JSON.parse(res.payload);
      expect(json.success).toBe(true);
      expect(json.data.decision).toBeDefined();
      expect(typeof json.data.passed).toBe('boolean');
      expect(json.data.score).toBeDefined();
      expect(json.data.score.score).toBeGreaterThanOrEqual(0);
      expect(json.data.policy).toBeDefined();
      expect(json.data.release).toBeDefined();
      expect(json.data.release.name).toBe('Release-1.0.0');
    });

    it('lists security policies via GET /api/v1/policies', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/policies',
      });
      expect(res.statusCode).toBe(200);

      const json = JSON.parse(res.payload);
      expect(json.success).toBe(true);
      expect(Array.isArray(json.data)).toBe(true);
      expect(json.data.length).toBeGreaterThan(0);
      expect(json.data[0].rules.length).toBeGreaterThan(0);
    });
  });

  describe('4. Policy Engine v2 & Release Governance Pipeline', () => {
    const baseTestPolicy: Policy = {
      id: 'p-v2-test',
      name: 'Policy v2 Governance Baseline',
      description: 'Tests required profiles, waivers, and endpoint SLAs',
      requiredProfiles: ['engine-native-tls', 'engine-native-authorization'],
      rules: [
        {
          id: 'rule-zero-critical',
          name: 'Zero Critical Vulnerabilities',
          condition: {
            maxAllowedSeverity: 'high',
          },
          action: 'block_release',
        },
      ],
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    it('blocks release when a required test profile was omitted from execution', () => {
      const result = evaluatePolicy(baseTestPolicy, [], [], {
        executedProfiles: ['engine-native-headers'],
      });

      expect(result.passed).toBe(false);
      expect(result.decision).toBe('failed');
      const missingProfiles = result.violations.filter((v) => v.category === 'required_profile');
      expect(missingProfiles.length).toBe(2);
      expect(missingProfiles.some((v) => v.reason.includes('engine-native-tls'))).toBe(true);
      expect(missingProfiles.some((v) => v.reason.includes('engine-native-authorization'))).toBe(true);
    });

    it('passes required profile check when all mandatory test profiles are executed', () => {
      const result = evaluatePolicy(baseTestPolicy, [], [], {
        executedProfiles: ['engine-native-tls', 'engine-native-authorization', 'engine-native-headers'],
      });

      const missingProfiles = result.violations.filter((v) => v.category === 'required_profile');
      expect(missingProfiles.length).toBe(0);
      expect(result.passed).toBe(true);
    });

    it('allows release when a critical finding is covered by a valid unexpired waiver', () => {
      const critFinding: Finding = {
        id: 'crit-1',
        fingerprint: 'fp-sha256-critical-target-login',
        title: 'Legacy SQL Injection on Migration Staging',
        category: 'injection',
        severity: 'critical',
        confidence: 'certain',
        status: 'open',
        description: 'Vulnerability in legacy table slated for migration',
        testDefinitionId: 'engine-native-contract',
        testRunId: 'run-v2-1',
        executionId: 'exec-v2-1',
        targetId: 'tgt-v2-1',
        firstDetectedAt: new Date(),
        lastDetectedAt: new Date(),
        metadata: {},
      };

      const policyWithValidWaiver: Policy = {
        ...baseTestPolicy,
        requiredProfiles: [],
        waivers: [
          {
            fingerprint: 'fp-sha256-critical-target-login',
            reason: 'Temporary waiver approved during active cloud migration window',
            approvedBy: 'security-lead@company.internal',
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days in future
          },
        ],
      };

      const result = evaluatePolicy(policyWithValidWaiver, [critFinding], []);
      expect(result.passed).toBe(true);
      expect(result.decision).toBe('passed');
      expect(result.waivedFindings.length).toBe(1);
      expect(result.waivedFindings[0]?.fingerprint).toBe('fp-sha256-critical-target-login');
      expect(result.waivedFindings[0]?.approvedBy).toBe('security-lead@company.internal');
      expect(result.violations.length).toBe(0);
    });

    it('strictly blocks release when a finding waiver has expired', () => {
      const critFinding: Finding = {
        id: 'crit-2',
        fingerprint: 'fp-sha256-expired-waiver-item',
        title: 'Unpatched Remote Code Execution',
        category: 'injection',
        severity: 'critical',
        confidence: 'certain',
        status: 'open',
        description: 'Previously waived issue whose time has expired',
        testDefinitionId: 'engine-native-contract',
        testRunId: 'run-v2-2',
        executionId: 'exec-v2-2',
        targetId: 'tgt-v2-2',
        firstDetectedAt: new Date(),
        lastDetectedAt: new Date(),
        metadata: {},
      };

      const policyWithExpiredWaiver: Policy = {
        ...baseTestPolicy,
        requiredProfiles: [],
        waivers: [
          {
            fingerprint: 'fp-sha256-expired-waiver-item',
            reason: 'Expired exemption',
            approvedBy: 'security-lead@company.internal',
            expiresAt: new Date(Date.now() - 24 * 60 * 60 * 1000), // Expired 24 hours ago
          },
        ],
      };

      const result = evaluatePolicy(policyWithExpiredWaiver, [critFinding], []);
      expect(result.passed).toBe(false);
      expect(result.decision).toBe('failed');
      expect(result.expiredWaivers.length).toBe(1);
      expect(result.expiredWaivers[0]?.fingerprint).toBe('fp-sha256-expired-waiver-item');

      const expiredViolation = result.violations.find((v) => v.ruleId === 'waiver-expired');
      expect(expiredViolation).toBeDefined();
      expect(expiredViolation?.action).toBe('block_release');
      expect(expiredViolation?.category).toBe('waiver');

      // Assert finding was also evaluated as active and violated zero-critical
      const severityViolation = result.violations.find((v) => v.category === 'severity');
      expect(severityViolation).toBeDefined();
    });

    it('enforces per-endpoint latency SLAs', () => {
      const policyWithEndpointSlas: Policy = {
        ...baseTestPolicy,
        requiredProfiles: [],
        rules: [
          {
            id: 'rule-endpoint-sla',
            name: 'API Endpoint SLAs',
            condition: {
              endpointSlas: [
                { path: '/api/v1/checkout', maxP95LatencyMs: 150 },
                { path: '/api/v1/health', maxP95LatencyMs: 50 },
              ],
            },
            action: 'block_release',
          },
        ],
      };

      const metrics = [
        {
          id: 'm-sla-1',
          testRunId: 'r-1',
          executionId: 'e-1',
          name: 'http_req_duration_p95',
          value: 230, // Breaches 150ms SLA
          unit: 'ms',
          tags: { path: '/api/v1/checkout' },
          timestamp: new Date(),
        },
        {
          id: 'm-sla-2',
          testRunId: 'r-1',
          executionId: 'e-1',
          name: 'http_req_duration_p95',
          value: 30, // Within 50ms SLA
          unit: 'ms',
          tags: { path: '/api/v1/health' },
          timestamp: new Date(),
        },
      ];

      const result = evaluatePolicy(policyWithEndpointSlas, [], metrics);
      expect(result.passed).toBe(false);
      expect(result.decision).toBe('failed');
      const slaViolation = result.violations.find((v) => v.category === 'endpoint_sla');
      expect(slaViolation).toBeDefined();
      expect(slaViolation?.reason).toContain('/api/v1/checkout');
      expect(slaViolation?.reason).toContain('230ms');
    });

    it('persists cryptographically sealed release records with evaluatorHash in PostgreSQL', async () => {
      // 1. Create minimal project & test run for release gating evaluation
      const { getDatabase } = await import('../../apps/controller/src/services/db.js');
      const { sql } = getDatabase();

      const [proj] = await sql`
        INSERT INTO projects (name, description)
        VALUES (${'Release Governance Sealed Audit ' + Date.now()}, 'Audit Trail Testing')
        RETURNING id
      `;
      const [tgt] = await sql`
        INSERT INTO targets (project_id, name, base_url, scope)
        VALUES (${proj.id}, 'Audit Target', 'http://127.0.0.1:8080', '{"allowedHosts": ["127.0.0.1"]}'::jsonb)
        RETURNING id
      `;
      const [tr] = await sql`
        INSERT INTO test_runs (project_id, target_id, profile_id, status)
        VALUES (${proj.id}, ${tgt.id}, 'native-class-a', 'completed')
        RETURNING id
      `;

      // 2. Evaluate release gate via API
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/releases/evaluate',
        payload: {
          testRunId: tr.id,
          name: 'v2.0.0-governance-audit',
          version: '2.0.0',
          gitCommit: '7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e',
          gitBranch: 'main',
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.evaluatorHash).toBeDefined();
      expect(body.data.evaluatorHash).toHaveLength(64); // Valid SHA-256 hex string

      // 3. Verify PostgreSQL persistence of evaluator_hash and metadata
      const [releaseRow] = await sql`
        SELECT id, name, version, git_commit, git_branch, evaluator_hash, metadata
        FROM releases
        WHERE id = ${body.data.release.id}
      `;

      expect(releaseRow).toBeDefined();
      expect(releaseRow.evaluator_hash).toBe(body.data.evaluatorHash);
      expect(releaseRow.git_commit).toBe('7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e');
      expect(releaseRow.metadata).toBeDefined();
      expect(releaseRow.metadata.evaluatorHash).toBe(body.data.evaluatorHash);
      expect(releaseRow.metadata.executedProfiles).toBeDefined();
    });
  });
});

