import http from 'node:http';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth } from '../../apps/controller/src/services/db.js';
import { FastifyInstance } from 'fastify';
import {
  engineRegistry,
  TestEngine,
} from '@security-lab/test-sdk';

describe('TestRun Execution, Forensic Evidence & Normalized Findings Pipeline', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;
  let server: http.Server;
  let serverPort: number;
  let serverUrl: string;

  let projectId: string;
  let targetId: string;
  let testRunId: string;

  beforeAll(async () => {
    // 1. Initialize Fastify controller app
    app = buildApp({ disableLogging: true });
    const health = await checkDatabaseHealth();
    isDbAvailable = health === 'up';

    // 2. Start mock HTTP target
    server = http.createServer((req, res) => {
      // Insecure target response missing HSTS, CSP, and disclosing server banner
      if (req.method === 'OPTIONS') {
        res.writeHead(200, {
          'Access-Control-Allow-Origin': req.headers.origin || '*',
          'Access-Control-Allow-Credentials': 'true',
        });
        res.end();
        return;
      }

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

  it('sets up project and authorized target within strict boundary', async () => {
    const randomSuffix = Math.floor(Math.random() * 100000);

    // 1. Create project
    const projRes = await app.inject({
      method: 'POST',
      url: '/api/v1/projects',
      payload: {
        name: `Execution Pipeline Project ${randomSuffix}`,
        description: 'Test Run pipeline validation project',
      },
    });
    expect(projRes.statusCode).toBe(201);
    projectId = JSON.parse(projRes.payload).data.id;

    // 2. Create authorized target with exact port and host
    const targetRes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectId}/targets`,
      payload: {
        name: `Pipeline Target ${randomSuffix}`,
        baseUrl: serverUrl,
        allowedHosts: ['127.0.0.1'],
        allowedPorts: [serverPort],
        excludedPaths: ['/internal/admin'],
        testing: {
          activeScanning: true,
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

  it('creates and queues a new TestRun', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/test-runs',
      payload: {
        projectId,
        targetId,
        profileId: 'native-class-a',
        triggeredBy: 'manual',
      },
    });

    expect(res.statusCode).toBe(201);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(body.data.id).toBeDefined();
    expect(body.data.status).toBe('queued');
    testRunId = body.data.id;
  });

  it('executes TestRun across native Class A engines and persists evidence (synchronous wait mode)', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/test-runs/${testRunId}/execute?wait=true`,
      payload: {
        engineIds: ['engine-native-headers', 'engine-native-cors', 'engine-native-tls'],
      },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);

    const { testRun, executions, findings } = body.data;
    expect(testRun.id).toBe(testRunId);
    expect(['completed', 'failed']).toContain(testRun.status);

    // Verify executions created for all 3 engines
    expect(executions.length).toBe(3);
    const engineIds = executions.map((e: { engineId: string }) => e.engineId);
    expect(engineIds).toContain('engine-native-headers');
    expect(engineIds).toContain('engine-native-cors');
    expect(engineIds).toContain('engine-native-tls');

    // Verify findings were identified and normalized
    expect(findings.length).toBeGreaterThan(0);
    for (const finding of findings) {
      expect(finding.fingerprint).toBeDefined();
      expect(finding.severity).toBeDefined();
      expect(finding.testRunId).toBe(testRunId);
      expect(finding.targetId).toBe(targetId);
    }
  });

  it('retrieves normalized findings via GET /api/v1/test-runs/:id/findings', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/api/v1/test-runs/${testRunId}/findings`,
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(body.data.length).toBeGreaterThan(0);

    const first = body.data[0];
    expect(first.title).toBeDefined();
    expect(first.category).toBeDefined();
  });

  it('retrieves immutable forensic evidence records with SHA-256 hash', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/api/v1/test-runs/${testRunId}/evidence`,
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(body.data.length).toBeGreaterThan(0);

    for (const record of body.data) {
      expect(record.immutableHash).toBeDefined();
      expect(record.immutableHash).toMatch(/^[a-f0-9]{64}$/); // Standard SHA-256 hex string
      expect(record.testRunId).toBe(testRunId);
    }
  });

  it('enforces boundary security: blocks execution if target is outside authorized scope', async () => {
    // 1. Create an out-of-scope target (e.g. cloud metadata IP)
    const outOfScopeTargetRes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectId}/targets`,
      payload: {
        name: 'Prohibited Target',
        baseUrl: 'http://169.254.169.254',
        allowedHosts: ['169.254.169.254'],
        allowedPorts: [80],
        excludedPaths: [],
      },
    });

    // Target creation itself is blocked by pre-flight scope validator
    expect(outOfScopeTargetRes.statusCode).toBe(400);
    const body = JSON.parse(outOfScopeTargetRes.payload);
    expect(body.error.message).toContain('cloud metadata');
  });

  it('dispatches asynchronous execution returning 202 Accepted and polls to completion', async () => {
    // 1. Create a new test run
    const createRes = await app.inject({
      method: 'POST',
      url: '/api/v1/test-runs',
      payload: {
        projectId,
        targetId,
        profileId: 'native-class-a',
        triggeredBy: 'manual',
      },
    });
    expect(createRes.statusCode).toBe(201);
    const asyncRunId = JSON.parse(createRes.payload).data.id;

    // 2. Dispatch execution asynchronously without ?wait=true
    const dispatchRes = await app.inject({
      method: 'POST',
      url: `/api/v1/test-runs/${asyncRunId}/execute`,
      payload: {
        engineIds: ['engine-native-headers'],
      },
    });

    expect(dispatchRes.statusCode).toBe(202);
    const dispatchBody = JSON.parse(dispatchRes.payload);
    expect(dispatchBody.success).toBe(true);
    expect(dispatchBody.data.status).toBe('queued');
    expect(dispatchBody.data.testRunId).toBe(asyncRunId);
    expect(dispatchBody.data.pollingUrl).toBe(`/api/v1/test-runs/${asyncRunId}`);

    // 3. Poll until completion
    let finishedRun: { status: string } | undefined;
    for (let i = 0; i < 30; i++) {
      await new Promise((r) => setTimeout(r, 100));
      const pollRes = await app.inject({
        method: 'GET',
        url: `/api/v1/test-runs/${asyncRunId}`,
      });
      expect(pollRes.statusCode).toBe(200);
      const pollBody = JSON.parse(pollRes.payload);
      if (['completed', 'failed'].includes(pollBody.data.status)) {
        finishedRun = pollBody.data;
        break;
      }
    }

    expect(finishedRun).toBeDefined();
    expect(['completed', 'failed']).toContain(finishedRun?.status);
  });

  it('cancels an in-flight or queued test run in under 2 seconds and updates status to cancelled', async () => {
    // 1. Create a new test run
    const createRes = await app.inject({
      method: 'POST',
      url: '/api/v1/test-runs',
      payload: {
        projectId,
        targetId,
        profileId: 'native-class-a',
        triggeredBy: 'manual',
      },
    });
    expect(createRes.statusCode).toBe(201);
    const cancelRunId = JSON.parse(createRes.payload).data.id;

    // 2. Enqueue execution
    const execRes = await app.inject({
      method: 'POST',
      url: `/api/v1/test-runs/${cancelRunId}/execute`,
      payload: {
        engineIds: ['engine-native-headers', 'engine-native-cors', 'engine-native-tls'],
      },
    });
    expect(execRes.statusCode).toBe(202);

    // 3. Measure cancellation response time (< 2 seconds)
    const cancelStart = Date.now();
    const cancelRes = await app.inject({
      method: 'POST',
      url: `/api/v1/test-runs/${cancelRunId}/cancel`,
    });
    const cancelDurationMs = Date.now() - cancelStart;

    expect(cancelDurationMs).toBeLessThan(2000);
    expect(cancelRes.statusCode).toBe(200);
    const cancelBody = JSON.parse(cancelRes.payload);
    expect(cancelBody.success).toBe(true);
    expect(cancelBody.data.status).toBe('cancelled');
    expect(cancelBody.data.testRunId).toBe(cancelRunId);

    // 4. Verify test run in database has status cancelled
    const pollRes = await app.inject({
      method: 'GET',
      url: `/api/v1/test-runs/${cancelRunId}`,
    });
    expect(pollRes.statusCode).toBe(200);
    const pollBody = JSON.parse(pollRes.payload);
    expect(pollBody.data.status).toBe('cancelled');
  });

  it('rejects cancelling an already completed test run with 400', async () => {
    const cancelRes = await app.inject({
      method: 'POST',
      url: `/api/v1/test-runs/${testRunId}/cancel`,
    });

    expect(cancelRes.statusCode).toBe(400);
    const body = JSON.parse(cancelRes.payload);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('TESTRUN_NOT_CANCELLABLE');
  });

  it('rejects cancelling a non-existent test run with 404', async () => {
    const nonExistentId = '00000000-0000-0000-0000-000000000000';
    const cancelRes = await app.inject({
      method: 'POST',
      url: `/api/v1/test-runs/${nonExistentId}/cancel`,
    });

    expect(cancelRes.statusCode).toBe(404);
    const body = JSON.parse(cancelRes.payload);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('TESTRUN_NOT_FOUND');
  });

  describe('EngineRegistry Dynamic Discovery and Lifecycle Hooks', () => {
    it('initializes default EngineRegistry with all standard Class A, B, and C engines', () => {
      const engines = engineRegistry.getAll();
      expect(engines.length).toBeGreaterThanOrEqual(8);

      const engineIds = engines.map((e) => e.id);
      expect(engineIds).toContain('engine-native-headers');
      expect(engineIds).toContain('engine-native-cors');
      expect(engineIds).toContain('engine-native-tls');
      expect(engineIds).toContain('engine-native-declarative');
      expect(engineIds).toContain('engine-native-resilience');
      expect(engineIds).toContain('engine-container-zap');
      expect(engineIds).toContain('engine-container-trivy');
      expect(engineIds).toContain('engine-worker-k6');
    });

    it('queries engines by execution class', () => {
      const nativeEngines = engineRegistry.findByExecutionClass('class_a_native');
      expect(nativeEngines.length).toBeGreaterThanOrEqual(5);

      const containerEngines = engineRegistry.findByExecutionClass('class_b_container');
      expect(containerEngines.some((e) => e.id === 'engine-container-zap')).toBe(true);
      expect(containerEngines.some((e) => e.id === 'engine-container-trivy')).toBe(true);

      const workerEngines = engineRegistry.findByExecutionClass('class_c_worker');
      expect(workerEngines.some((e) => e.id === 'engine-worker-k6')).toBe(true);
    });

    it('queries engines by capability and capability category', () => {
      const headerEngines = engineRegistry.findByCapability('headers_audit');
      expect(headerEngines.length).toBe(1);
      expect(headerEngines[0].id).toBe('engine-native-headers');

      const passiveEngines = engineRegistry.findByCategory('passive_analysis');
      expect(passiveEngines.length).toBeGreaterThan(0);
      expect(passiveEngines.some((e) => e.id === 'engine-native-headers')).toBe(true);

      const caps = engineRegistry.listCapabilities();
      expect(caps.length).toBeGreaterThan(0);
      expect(caps.some((c) => c.capability.id === 'headers_audit')).toBe(true);
    });

    it('supports dynamic engine registration, controller execution, and unregistration', async () => {
      let initCalled = false;
      let cleanupCalled = false;

      const mockEngine: TestEngine = {
        id: 'engine-dynamic-mock',
        version: '1.0.0',
        executionClass: 'class_a_native',
        capabilities: () => [
          {
            id: 'mock_audit',
            name: 'Mock Security Audit',
            category: 'passive_analysis',
            description: 'Dynamically registered test engine',
            isDisruptive: false,
          },
        ],
        validate: () => ({ valid: true }),
        execute: async () => ({
          engineId: 'engine-dynamic-mock',
          durationMs: 15,
          success: true,
          findings: [
            {
              title: 'Dynamic Engine Finding',
              category: 'configuration',
              severity: 'low',
              description: 'Generated by dynamically registered engine',
              recommendation: 'None',
            },
          ],
        }),
        init: async () => {
          initCalled = true;
        },
        healthCheck: async () => true,
        cleanup: async () => {
          cleanupCalled = true;
        },
      };

      // Register mock engine
      engineRegistry.register(mockEngine);
      expect(engineRegistry.has('engine-dynamic-mock')).toBe(true);

      // Verify lifecycle hooks
      await engineRegistry.initAll();
      expect(initCalled).toBe(true);

      const health = await engineRegistry.healthCheckAll();
      expect(health['engine-dynamic-mock']).toBe(true);

      // Create test run and execute dynamic engine via controller
      const createRes = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        payload: {
          projectId,
          targetId,
          profileId: 'custom',
          triggeredBy: 'manual',
        },
      });
      const dynRunId = JSON.parse(createRes.payload).data.id;

      const execRes = await app.inject({
        method: 'POST',
        url: `/api/v1/test-runs/${dynRunId}/execute?wait=true`,
        payload: {
          engineIds: ['engine-dynamic-mock'],
        },
      });
      expect(execRes.statusCode).toBe(200);
      const execBody = JSON.parse(execRes.payload);
      expect(execBody.data.executions[0].engineId).toBe('engine-dynamic-mock');
      expect(execBody.data.findings.some((f: { title: string }) => f.title === 'Dynamic Engine Finding')).toBe(true);

      // Cleanup & unregister
      await engineRegistry.cleanupAll();
      expect(cleanupCalled).toBe(true);

      engineRegistry.unregister('engine-dynamic-mock');
      expect(engineRegistry.has('engine-dynamic-mock')).toBe(false);
    });
  });
});
