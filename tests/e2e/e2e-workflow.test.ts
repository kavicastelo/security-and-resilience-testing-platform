import http from 'node:http';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth } from '../../apps/controller/src/services/db.js';

describe('End-to-End (E2E) Full Lifecycle Security QA Workflow', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;
  let mockServer: http.Server;
  let mockServerPort: number;
  let mockServerUrl: string;

  beforeAll(async () => {
    app = buildApp({ disableLogging: true });
    const health = await checkDatabaseHealth();
    isDbAvailable = health === 'up';

    mockServer = http.createServer((_req, res) => {
      // Insecure test target revealing headers
      res.writeHead(200, {
        'Content-Type': 'application/json',
        Server: 'Apache/2.4.41 (Ubuntu)',
        'X-Powered-By': 'PHP/7.4.3',
      });
      res.end(JSON.stringify({ status: 'ok', service: 'order-api' }));
    });

    await new Promise<void>((resolve) => {
      mockServer.listen(0, '127.0.0.1', () => {
        const addr = mockServer.address();
        if (addr && typeof addr === 'object') {
          mockServerPort = addr.port;
          mockServerUrl = `http://127.0.0.1:${mockServerPort}`;
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

  it('confirms infrastructure readiness', () => {
    expect(isDbAvailable).toBe(true);
    expect(mockServerUrl).toBeDefined();
  });

  it('executes full end-to-end workflow: Target -> Run -> Findings -> Release Gate -> Reports -> Audit Trail', async () => {
    const randomSuffix = Math.floor(Math.random() * 100000);

    // 1. Create Project
    const projectRes = await app.inject({
      method: 'POST',
      url: '/api/v1/projects',
      payload: {
        name: `E2E Flow Project ${randomSuffix}`,
        description: 'End-to-End Enterprise Gating Test Project',
      },
    });
    expect(projectRes.statusCode).toBe(201);
    const projectId = JSON.parse(projectRes.body).data.id;
    expect(projectId).toBeDefined();

    // 2. Register Authorized Target
    const targetRes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectId}/targets`,
      payload: {
        name: `Order Service Target ${randomSuffix}`,
        baseUrl: mockServerUrl,
        allowedHosts: ['127.0.0.1'],
        allowedPorts: [mockServerPort],
        testing: {
          activeScanning: false,
          loadTesting: false,
          chaosTesting: false,
        },
      },
    });
    expect(targetRes.statusCode).toBe(201);
    const targetId = JSON.parse(targetRes.body).data.id;
    expect(targetId).toBeDefined();

    // 3. Initiate TestRun
    const createRunRes = await app.inject({
      method: 'POST',
      url: '/api/v1/test-runs',
      payload: {
        projectId,
        targetId,
        profileId: 'e2e-baseline-profile',
      },
    });
    expect(createRunRes.statusCode).toBe(201);
    const testRunId = JSON.parse(createRunRes.body).data.id;
    expect(testRunId).toBeDefined();

    // 4. Execute TestRun with Native Class A Engines
    const execRes = await app.inject({
      method: 'POST',
      url: `/api/v1/test-runs/${testRunId}/execute?wait=true`,
      payload: {
        engineIds: ['engine-native-headers', 'engine-native-cors'],
      },
    });
    expect(execRes.statusCode).toBe(200);
    const execJson = JSON.parse(execRes.body);
    expect(execJson.data.testRun.status).toBe('completed');
    expect(execJson.data.testRun.summary.totalTests).toBeGreaterThan(0);

    // 5. Verify Findings were Recorded & Normalized
    const findingsRes = await app.inject({
      method: 'GET',
      url: `/api/v1/findings?testRunId=${testRunId}`,
    });
    expect(findingsRes.statusCode).toBe(200);
    const findings = JSON.parse(findingsRes.body).data;
    expect(Array.isArray(findings)).toBe(true);

    // 6. Evaluate Release Gate against Enterprise Baseline Policy
    const gateRes = await app.inject({
      method: 'POST',
      url: '/api/v1/releases/evaluate',
      payload: {
        testRunId,
        projectId,
        name: `Order Service E2E Release ${randomSuffix}`,
        version: 'v2.1.0-e2e',
        gitCommit: '9c5b2a1',
        gitBranch: 'release/v2.1',
      },
    });
    expect(gateRes.statusCode).toBe(200);
    const gateJson = JSON.parse(gateRes.body);
    expect(gateJson.success).toBe(true);
    expect(gateJson.data.decision).toBeDefined();
    expect(gateJson.data.score).toBeDefined();
    expect(gateJson.data.score.grade).toMatch(/^[A-F]$/);
    expect(gateJson.data.score.score).toBeGreaterThanOrEqual(0);
    expect(gateJson.data.release).toBeDefined();
    const releaseId = gateJson.data.release.id;
    expect(releaseId).toBeDefined();

    // 7. Verify Enterprise HTML Report Generation
    const htmlRes = await app.inject({
      method: 'GET',
      url: `/api/v1/test-runs/${testRunId}/report?format=html`,
    });
    expect(htmlRes.statusCode).toBe(200);
    expect(htmlRes.headers['content-type']).toContain('text/html');
    expect(htmlRes.body).toContain('Security QA for Enterprise Applications');
    expect(htmlRes.body).toContain('Executive Security & Resilience Report');
    expect(htmlRes.body).toContain('Posture Score');

    // 8. Verify JUnit XML Report Generation
    const junitRes = await app.inject({
      method: 'GET',
      url: `/api/v1/test-runs/${testRunId}/report?format=junit`,
    });
    expect(junitRes.statusCode).toBe(200);
    expect(junitRes.headers['content-type']).toContain('application/xml');
    expect(junitRes.body).toContain('<testsuites');
    expect(junitRes.body).toContain('</testsuites>');

    // 9. Verify SARIF v2.1.0 Report Generation
    const sarifRes = await app.inject({
      method: 'GET',
      url: `/api/v1/test-runs/${testRunId}/report?format=sarif`,
    });
    expect(sarifRes.statusCode).toBe(200);
    expect(sarifRes.headers['content-type']).toContain('application/sarif+json');
    const sarifJson = JSON.parse(sarifRes.body);
    expect(sarifJson.version).toBe('2.1.0');
    expect(sarifJson.$schema).toContain('sarif-schema-2.1.0.json');
    expect(sarifJson.runs[0].tool.driver.name).toBe('Security Lab');

    // 10. Verify Release Audit History in Database
    const auditRes = await app.inject({
      method: 'GET',
      url: `/api/v1/releases/${releaseId}`,
    });
    expect(auditRes.statusCode).toBe(200);
    const auditRecord = JSON.parse(auditRes.body).data;
    expect(auditRecord.id).toBe(releaseId);
    expect(auditRecord.name).toContain('Order Service E2E Release');
    expect(auditRecord.version).toBe('v2.1.0-e2e');
    expect(auditRecord.gitCommit).toBe('9c5b2a1');
    expect(auditRecord.testRunId).toBe(testRunId);
  });
});
