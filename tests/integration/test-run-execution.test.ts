import http from 'node:http';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth } from '../../apps/controller/src/services/db.js';
import { FastifyInstance } from 'fastify';

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

  it('executes TestRun across native Class A engines and persists evidence', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/test-runs/${testRunId}/execute`,
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
});
