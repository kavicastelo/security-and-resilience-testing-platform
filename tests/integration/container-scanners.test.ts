import http from 'node:http';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth } from '../../apps/controller/src/services/db.js';
import {
  ZapScannerEngine,
  TrivyScannerEngine,
  ExecutionContext,
} from '@security-lab/test-sdk';
import { logger } from '@security-lab/logger';
import { FastifyInstance } from 'fastify';

describe('Class B Container Scanners Pipeline (OWASP ZAP & Aqua Trivy)', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;
  let server: http.Server;
  let serverPort: number;
  let serverUrl: string;

  let projectId: string;
  let targetId: string;
  let testRunId: string;

  beforeAll(async () => {
    // 1. Controller Fastify instance
    app = buildApp({ disableLogging: true });
    const health = await checkDatabaseHealth();
    isDbAvailable = health === 'up';

    // 2. Mock HTTP target
    server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', service: 'container-audit-target' }));
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

  const createDummyContext = (activeScanning = false): ExecutionContext => ({
    correlationId: 'test-container-corr-1',
    testRunId: '00000000-0000-0000-0000-000000000010',
    executionId: '00000000-0000-0000-0000-000000000011',
    target: {
      id: '00000000-0000-0000-0000-000000000012',
      name: 'Container Audit Target',
      baseUrl: serverUrl,
      scope: {
        allowedHosts: ['127.0.0.1'],
        allowedPorts: [serverPort],
        excludedPaths: [],
        testing: { activeScanning, loadTesting: false, chaosTesting: false },
        limits: { maxRps: 100, maxConcurrency: 10, maxDuration: '1m' },
      },
    },
    logger,
    abortSignal: new AbortController().signal,
    reportProgress: () => {},
  });

  describe('ZapScannerEngine Unit Checks', () => {
    const zapEngine = new ZapScannerEngine();

    it('exposes Class B scanner capabilities', () => {
      expect(zapEngine.id).toBe('engine-container-zap');
      const caps = zapEngine.capabilities();
      expect(caps.some((c) => c.id === 'zap_baseline')).toBe(true);
      expect(caps.some((c) => c.id === 'zap_active')).toBe(true);
    });

    it('blocks active scan when target scope forbids activeScanning', async () => {
      const result = await zapEngine.execute(
        {
          targetUrl: serverUrl,
          options: { activeScan: true },
        },
        createDummyContext(false), // activeScanning = false
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Active scanning is strictly disabled in target security scope');
    });

    it('executes passive baseline scan in simulated container mode', async () => {
      const result = await zapEngine.execute(
        {
          targetUrl: serverUrl,
          options: { simulated: true },
        },
        createDummyContext(false),
      );

      expect(result.success).toBe(true);
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.engineId).toBe('engine-container-zap');
    });
  });

  describe('TrivyScannerEngine Unit Checks', () => {
    const trivyEngine = new TrivyScannerEngine();

    it('exposes Trivy SCA and misconfiguration capabilities', () => {
      expect(trivyEngine.id).toBe('engine-container-trivy');
      const caps = trivyEngine.capabilities();
      expect(caps.some((c) => c.id === 'trivy_sca')).toBe(true);
    });

    it('executes Trivy scan in simulated container mode and yields CVE findings', async () => {
      const result = await trivyEngine.execute(
        {
          targetUrl: serverUrl,
          options: { simulated: true },
        },
        createDummyContext(false),
      );

      expect(result.findings.length).toBeGreaterThan(0);
      const cveFinding = result.findings.find((f) => f.title.includes('CVE-2024-24790'));
      expect(cveFinding).toBeDefined();
      expect(cveFinding?.category).toBe('software_composition_analysis');
    });
  });

  describe('Controller End-to-End Class B Execution & Forensic Persistence', () => {
    it('sets up project and target for containerized scanner tests', async () => {
      expect(isDbAvailable).toBe(true);
      const randomSuffix = Math.floor(Math.random() * 100000);

      // Create Project
      const projRes = await app.inject({
        method: 'POST',
        url: '/api/v1/projects',
        payload: {
          name: `Container Pipeline Project ${randomSuffix}`,
          description: 'Class B scanner testing project',
        },
      });
      expect(projRes.statusCode).toBe(201);
      projectId = JSON.parse(projRes.payload).data.id;

      // Create Target
      const targetRes = await app.inject({
        method: 'POST',
        url: `/api/v1/projects/${projectId}/targets`,
        payload: {
          name: `Container Target ${randomSuffix}`,
          baseUrl: serverUrl,
          allowedHosts: ['127.0.0.1'],
          allowedPorts: [serverPort],
          excludedPaths: [],
          testing: {
            activeScanning: false, // passive only
            loadTesting: false,
            chaosTesting: false,
          },
          limits: {
            maxRps: 50,
            maxConcurrency: 5,
            maxDuration: '2m',
          },
        },
      });
      expect(targetRes.statusCode).toBe(201);
      targetId = JSON.parse(targetRes.payload).data.id;
    });

    it('creates TestRun with profile "class-b-scanners"', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        payload: {
          projectId,
          targetId,
          profileId: 'class-b-scanners',
          triggeredBy: 'manual',
          metadata: {
            simulated: true, // fast execution mode for testing
          },
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      testRunId = body.data.id;
    });

    it('dispatches Class B execution and records class_b_container in test_executions', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/test-runs/${testRunId}/execute`,
        payload: {
          engineIds: ['engine-container-zap', 'engine-container-trivy'],
          options: {
            simulated: true,
          },
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);

      const { executions, findings } = body.data;
      expect(executions).toHaveLength(2);

      const zapExec = executions.find((e: { engineId: string }) => e.engineId === 'engine-container-zap');
      expect(zapExec).toBeDefined();
      expect(zapExec.status).toBe('completed');

      const trivyExec = executions.find((e: { engineId: string }) => e.engineId === 'engine-container-trivy');
      expect(trivyExec).toBeDefined();
      expect(trivyExec.status).toBe('completed');

      // Findings verification
      expect(findings.length).toBeGreaterThan(0);
      for (const finding of findings) {
        expect(finding.fingerprint).toBeDefined();
        expect(finding.testRunId).toBe(testRunId);
        expect(finding.targetId).toBe(targetId);
      }
    });

    it('retrieves normalized findings for Class B scanners via GET /api/v1/test-runs/:id/findings', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/test-runs/${testRunId}/findings`,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.length).toBeGreaterThan(0);

      // Verify presence of ZAP or Trivy normalized categories
      const categories = body.data.map((f: { category: string }) => f.category);
      expect(
        categories.includes('web_application_security') ||
          categories.includes('software_composition_analysis') ||
          categories.includes('infrastructure_as_code'),
      ).toBe(true);
    });

    it('verifies immutable forensic evidence records with SHA-256 for container findings', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/test-runs/${testRunId}/evidence`,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.length).toBeGreaterThan(0);

      for (const record of body.data) {
        expect(record.immutableHash).toMatch(/^[a-f0-9]{64}$/);
        expect(record.testRunId).toBe(testRunId);
      }
    });
  });
});
