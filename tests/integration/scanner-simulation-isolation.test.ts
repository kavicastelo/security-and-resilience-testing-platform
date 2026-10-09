import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth } from '../../apps/controller/src/services/db.js';
import { testRunnerService } from '../../apps/controller/src/services/runner.service.js';
import {
  ZapScannerEngine,
  TrivyScannerEngine,
  K6ResilienceEngine,
  DockerRunner,
  DockerExecutionError,
  EngineExecutionError,
  IDockerRunner,
  ExecutionContext,
  engineRegistry,
  SAMPLE_ZAP_BASELINE_REPORT,
} from '@security-lab/test-sdk';
import { logger } from '@security-lab/logger';

describe('Scanner Simulation Isolation & Anti-Fabrication (REM-04)', () => {
  let app: FastifyInstance;
  let server: http.Server;
  let serverPort: number;
  let serverUrl: string;

  let projectId: string;
  let targetId: string;
  let testRunId: string;

  const originalEnv = { ...process.env };

  beforeAll(async () => {
    app = buildApp({ disableLogging: true });
    const health = await checkDatabaseHealth();
    expect(health).toBe('up');

    server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', service: 'simulation-isolation-target' }));
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

    // Create a base project and target
    const projRes = await app.inject({
      method: 'POST',
      url: '/api/v1/projects',
      payload: {
        name: `Simulation Isolation Project ${Date.now()}`,
        description: 'Testing anti-fabrication of scanner reports',
      },
    });
    expect(projRes.statusCode).toBe(201);
    projectId = JSON.parse(projRes.payload).data.id;

    const targetRes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectId}/targets`,
      payload: {
        name: `Simulation Isolation Target ${Date.now()}`,
        baseUrl: serverUrl,
        allowedHosts: ['127.0.0.1'],
        allowedPorts: [serverPort],
        excludedPaths: [],
        testing: {
          activeScanning: false,
          loadTesting: true,
          chaosTesting: false,
        },
        limits: {
          maxRps: 50,
          maxConcurrency: 10,
          maxDuration: '2m',
        },
      },
    });
    expect(targetRes.statusCode).toBe(201);
    targetId = JSON.parse(targetRes.payload).data.id;
  });

  afterAll(async () => {
    await app.close();
    await closeDatabase();
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
    process.env = { ...originalEnv };
  });

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  const createDummyContext = (): ExecutionContext => ({
    correlationId: 'test-sim-isolation-corr',
    testRunId: '00000000-0000-0000-0000-000000000099',
    executionId: '00000000-0000-0000-0000-000000000098',
    target: {
      id: targetId,
      name: 'Simulation Isolation Target',
      baseUrl: serverUrl,
      scope: {
        allowedHosts: ['127.0.0.1'],
        allowedPorts: [serverPort],
        excludedPaths: [],
        testing: { activeScanning: false, loadTesting: true, chaosTesting: false },
        limits: { maxRps: 50, maxConcurrency: 10, maxDuration: '2m' },
      },
    },
    logger,
    abortSignal: new AbortController().signal,
    reportProgress: () => {},
  });

  // =========================================================================
  // Battery 1: API Simulation Rejection (HTTP 400 Bad Request)
  // =========================================================================
  describe('Battery 1: API Simulation Rejection (HTTP 400 Bad Request)', () => {
    it('rejects POST /api/v1/test-runs with options.simulated: true', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        payload: {
          projectId,
          targetId,
          profileId: 'zap',
          options: {
            simulated: true,
          },
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(false);
      expect(body.error.message).toContain('Simulation options are not permitted via the public API');
    });

    it('rejects POST /api/v1/test-runs with top-level simulated: true', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        payload: {
          projectId,
          targetId,
          profileId: 'zap',
          simulated: true,
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(false);
      expect(body.error.message).toContain('Simulation options are not permitted via the public API');
    });

    it('rejects POST /api/v1/test-runs with options.mockReport', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        payload: {
          projectId,
          targetId,
          profileId: 'trivy',
          options: {
            mockReport: { fake: 'report' },
          },
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(false);
      expect(body.error.message).toContain('Simulation options are not permitted via the public API');
    });

    it('rejects POST /api/v1/test-runs with options.skipVerification', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        payload: {
          projectId,
          targetId,
          profileId: 'zap',
          options: {
            skipVerification: true,
          },
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(false);
      expect(body.error.message).toContain('Simulation options are not permitted via the public API');
    });

    it('creates a legitimate TestRun without simulation options', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        payload: {
          projectId,
          targetId,
          profileId: 'zap',
          triggeredBy: 'manual',
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      testRunId = body.data.id;
    });

    it('rejects POST /api/v1/test-runs/:id/execute with options.simulated: true', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/test-runs/${testRunId}/execute`,
        payload: {
          options: {
            simulated: true,
          },
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(false);
      expect(body.error.message).toContain('Simulation options are not permitted via the public API');
    });

    it('rejects POST /api/v1/test-runs/:id/execute with options.mockReport', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/test-runs/${testRunId}/execute`,
        payload: {
          options: {
            mockReport: { evil: true },
          },
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(false);
      expect(body.error.message).toContain('Simulation options are not permitted via the public API');
    });
  });

  // =========================================================================
  // Battery 2: Metadata Sanitization in Runner Service
  // =========================================================================
  describe('Battery 2: Metadata Sanitization in Runner Service', () => {
    it('sanitizes metadata: { simulated: true } so runner.service does NOT execute mock generator', async () => {
      // 1. Create a TestRun with metadata containing simulated: true
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        payload: {
          projectId,
          targetId,
          profileId: 'zap',
          triggeredBy: 'manual',
          metadata: {
            simulated: true,
            arbitraryTag: 'test-sanitization',
          },
        },
      });

      expect(res.statusCode).toBe(201);
      const runWithMetaId = JSON.parse(res.payload).data.id;

      // 2. Set up a tracking runner to observe whether simulated was passed
      const originalZap = engineRegistry.get('engine-container-zap')!;
      let capturedOptions: Record<string, unknown> | undefined;
      const trackingRunner: IDockerRunner = {
        execute: async (options) => {
          capturedOptions = options as unknown as Record<string, unknown>;
          return {
            exitCode: 1,
            stdout: '',
            stderr: 'Docker daemon unavailable',
            durationMs: 10,
            simulated: false,
          };
        },
      };

      try {
        engineRegistry.register(new ZapScannerEngine(trackingRunner));

        const execResult = await testRunnerService.executeTestRun(runWithMetaId, {
          engineIds: ['engine-container-zap'],
        });

        // The execution must have run without simulated: true
        expect(execResult).toBeDefined();
        // Captured options to runner must NOT have simulated: true
        expect(capturedOptions?.simulated).toBeFalsy();
        // TestRun must NOT have succeeded with fake findings
        expect(execResult.findings).toHaveLength(0);
      } finally {
        engineRegistry.register(originalZap);
      }
    });
  });

  // =========================================================================
  // Battery 3: Engine-Level Isolation & Production Fail-Closed
  // =========================================================================
  describe('Battery 3: Production Mode Engine Rejection (Fail-Closed)', () => {
    it('ZAP: throws EngineExecutionError when simulated: true in production mode', async () => {
      process.env.NODE_ENV = 'production';
      const engine = new ZapScannerEngine();

      await expect(
        engine.execute(
          {
            targetUrl: serverUrl,
            options: { simulated: true },
          },
          createDummyContext(),
        ),
      ).rejects.toThrowError(EngineExecutionError);

      await expect(
        engine.execute(
          {
            targetUrl: serverUrl,
            options: { simulated: true },
          },
          createDummyContext(),
        ),
      ).rejects.toThrow('Simulated scanner execution is disabled in production');
    });

    it('Trivy: throws EngineExecutionError when simulated: true in production mode', async () => {
      process.env.NODE_ENV = 'production';
      const engine = new TrivyScannerEngine();

      await expect(
        engine.execute(
          {
            targetUrl: serverUrl,
            options: { simulated: true },
          },
          createDummyContext(),
        ),
      ).rejects.toThrowError(EngineExecutionError);

      await expect(
        engine.execute(
          {
            targetUrl: serverUrl,
            options: { simulated: true },
          },
          createDummyContext(),
        ),
      ).rejects.toThrow('Simulated scanner execution is disabled in production');
    });

    it('k6: throws EngineExecutionError when simulated: true in production mode', async () => {
      process.env.NODE_ENV = 'production';
      const engine = new K6ResilienceEngine();

      await expect(
        engine.execute(
          {
            targetUrl: serverUrl,
            options: { simulated: true },
          },
          createDummyContext(),
        ),
      ).rejects.toThrowError(EngineExecutionError);

      await expect(
        engine.execute(
          {
            targetUrl: serverUrl,
            options: { simulated: true },
          },
          createDummyContext(),
        ),
      ).rejects.toThrow('Simulated scanner execution is disabled in production');
    });

    it('DockerRunner: throws ContainerSecurityError when simulated: true in production mode', async () => {
      process.env.NODE_ENV = 'production';
      const runner = new DockerRunner();

      await expect(
        runner.execute({
          image: 'ghcr.io/zaproxy/zaproxy:stable',
          simulated: true,
        }),
      ).rejects.toThrow('Simulated container execution is disabled outside of test environment');
    });
  });

  // =========================================================================
  // Battery 4: Docker CLI Failure & Anti-Fabrication Fail-Closed
  // =========================================================================
  describe('Battery 4: Docker CLI Failure Handling & No Silent Fallback', () => {
    it('DockerRunner throws DockerExecutionError on process spawn failure', async () => {
      // With an invalid command/spawn failure, it must reject with DockerExecutionError
      // We test this by passing a runner that fails to spawn or image execution
      const failingRunner: IDockerRunner = {
        execute: async () => {
          throw new DockerExecutionError('Failed to spawn Docker process: spawn docker ENOENT');
        },
      };

      const zap = new ZapScannerEngine(failingRunner);

      // With throwOnError: true, throws DockerExecutionError
      await expect(
        zap.execute(
          {
            targetUrl: serverUrl,
            options: { throwOnError: true },
          },
          createDummyContext(),
        ),
      ).rejects.toThrowError(DockerExecutionError);

      // Without throwOnError: returns success: false, findings: [] and NEVER returns SAMPLE_ZAP_BASELINE_REPORT
      const result = await zap.execute(
        {
          targetUrl: serverUrl,
        },
        createDummyContext(),
      );

      expect(result.success).toBe(false);
      expect(result.findings).toHaveLength(0);
      expect(result.error).toContain('Failed to spawn Docker process');
      expect(result.rawOutput).toBeUndefined();
    });

    it('Trivy fails closed and does not return SAMPLE_TRIVY_REPORT on container crash', async () => {
      const failingRunner: IDockerRunner = {
        execute: async () => ({
          exitCode: 137,
          stdout: '',
          stderr: 'Container OOMKilled',
          durationMs: 25,
          simulated: false,
        }),
      };

      const trivy = new TrivyScannerEngine(failingRunner);

      const result = await trivy.execute(
        {
          targetUrl: serverUrl,
        },
        createDummyContext(),
      );

      expect(result.success).toBe(false);
      expect(result.findings).toHaveLength(0);
      expect(result.error).toContain('failed to produce report.json');
    });
  });

  // =========================================================================
  // Battery 5: Dependency Injection of Mock Runners
  // =========================================================================
  describe('Battery 5: Clean Mock Runner Dependency Injection', () => {
    it('allows pure unit test dependency injection without global environment flags', async () => {
      const injectedRunner: IDockerRunner = {
        execute: async (opts) => {
          const reportPath = path.join(opts.volumes![0].hostPath, 'report.json');
          await fs.promises.writeFile(reportPath, JSON.stringify(SAMPLE_ZAP_BASELINE_REPORT), 'utf-8');
          return {
            exitCode: 0,
            stdout: '',
            stderr: '',
            durationMs: 40,
            simulated: false,
          };
        },
      };

      const zap = new ZapScannerEngine(injectedRunner);
      const result = await zap.execute({ targetUrl: serverUrl }, createDummyContext());

      expect(result.success).toBe(true);
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.engineId).toBe('engine-container-zap');
    });
  });
});
