import http from 'node:http';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth } from '../../apps/controller/src/services/db.js';
import { FastifyInstance } from 'fastify';

describe('Phase 14: Web Dashboard Real-Time Telemetry & Finding Triage Integration', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;
  let server: http.Server;
  let serverPort: number;
  let serverUrl: string;

  let projectId: string;
  let targetId: string;
  let testRunId: string;
  let policyId: string;
  let findingId: string;

  beforeAll(async () => {
    app = buildApp({ disableLogging: true });
    const health = await checkDatabaseHealth();
    isDbAvailable = health === 'up';

    server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain', Server: 'nginx/1.18.0' });
      res.end('Mock Server OK');
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
    await new Promise<void>((resolve) => server.close(() => resolve()));
    if (isDbAvailable) {
      await closeDatabase();
    }
  });

  it('1. Sets up test infrastructure (Project, Target, Policy, TestRun with Findings)', async () => {
    const randomSuffix = Math.floor(Math.random() * 100000);

    // 1. Create Project
    const projRes = await app.inject({
      method: 'POST',
      url: '/api/v1/projects',
      payload: { name: `Phase 14 Telemetry Test ${randomSuffix}`, description: 'Testing SSE and Triage' },
    });
    expect(projRes.statusCode).toBe(201);
    projectId = projRes.json().data.id;

    // 2. Create Target with boundary validation
    const targetRes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectId}/targets`,
      payload: {
        name: `Telemetry Target ${randomSuffix}`,
        baseUrl: serverUrl,
        allowedHosts: ['127.0.0.1'],
        allowedPorts: [serverPort],
        testing: {
          activeScanning: true,
          loadTesting: false,
          chaosTesting: false,
        },
      },
    });
    expect(targetRes.statusCode).toBe(201);
    targetId = targetRes.json().data.id;

    // 3. Create Baseline Policy
    const polRes = await app.inject({
      method: 'POST',
      url: '/api/v1/policies',
      payload: {
        name: 'Telemetry Gating Policy',
        description: 'Policy with profile requirements and waivers',
        requiredProfiles: ['engine-native-headers'],
        rules: [
          {
            name: 'Zero Criticals',
            condition: { maxCountBySeverity: { critical: 0, high: 2 } },
            action: 'block_release',
          },
        ],
      },
    });
    expect(polRes.statusCode).toBe(201);
    policyId = polRes.json().data.id;

    // 4. Create & Execute Test Run
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
    testRunId = runRes.json().data.id;

    // Execute with wait=true to complete synchronously
    const execRes = await app.inject({
      method: 'POST',
      url: `/api/v1/test-runs/${testRunId}/execute?wait=true`,
      payload: {
        engineIds: ['engine-native-headers'],
      },
    });
    expect(execRes.statusCode).toBe(200);

    // Retrieve generated findings
    const findingsRes = await app.inject({
      method: 'GET',
      url: `/api/v1/findings?targetId=${targetId}`,
    });
    expect(findingsRes.statusCode).toBe(200);
    const findings = findingsRes.json().data;
    expect(findings.length).toBeGreaterThan(0);
    findingId = findings[0].id;
  });

  it('2. GET /api/v1/test-runs/:id/stream serves SSE headers and initial run state snapshot', async () => {
    const streamRes = await app.inject({
      method: 'GET',
      url: `/api/v1/test-runs/${testRunId}/stream`,
    });

    expect(streamRes.statusCode).toBe(200);
    expect(streamRes.headers['content-type']).toContain('text/event-stream');
    expect(streamRes.headers['cache-control']).toContain('no-cache');
    expect(streamRes.headers['connection']).toBe('keep-alive');

    const body = streamRes.body;
    expect(body).toContain('event: run');
    expect(body).toContain(testRunId);
  });

  it('3. PATCH /api/v1/findings/:id triage finding as false_positive with audit notes', async () => {
    const updateRes = await app.inject({
      method: 'PATCH',
      url: `/api/v1/findings/${findingId}`,
      payload: {
        status: 'false_positive',
        notes: 'Verified via manual AppSec review: header is stripped by edge proxy.',
      },
    });

    expect(updateRes.statusCode).toBe(200);
    const updated = updateRes.json().data;
    expect(updated.id).toBe(findingId);
    expect(updated.status).toBe('false_positive');

    // Verify finding persistence
    const fetchRes = await app.inject({
      method: 'GET',
      url: `/api/v1/findings/${findingId}`,
    });
    expect(fetchRes.statusCode).toBe(200);
    expect(fetchRes.json().data.status).toBe('false_positive');
  });

  it('4. PATCH /api/v1/findings/:id resolves finding and triggers automated re-test', async () => {
    const resolveRes = await app.inject({
      method: 'PATCH',
      url: `/api/v1/findings/${findingId}`,
      payload: {
        status: 'resolved',
        notes: 'Patch deployed to staging server.',
        triggerRetest: true,
      },
    });

    expect(resolveRes.statusCode).toBe(200);
    const body = resolveRes.json();
    expect(body.data.status).toBe('resolved');
    expect(body.retestRunId).toBeDefined();

    // Verify the retest run exists in controller
    const retestRes = await app.inject({
      method: 'GET',
      url: `/api/v1/test-runs/${body.retestRunId}`,
    });
    expect(retestRes.statusCode).toBe(200);
    expect(retestRes.json().data.targetId).toBe(targetId);
  });

  it('5. POST /api/v1/policies/:id/waivers adds temporary waiver rule to policy', async () => {
    const waiverPayload = {
      fingerprint: 'test-fingerprint-sha256-abc12345',
      reason: 'WAF virtual patching active until Q4 sprint release',
      approvedBy: 'Lead Security Architect',
      expiresAt: new Date(Date.now() + 30 * 86400000).toISOString(),
    };

    const waiverRes = await app.inject({
      method: 'POST',
      url: `/api/v1/policies/${policyId}/waivers`,
      payload: waiverPayload,
    });

    expect(waiverRes.statusCode).toBe(200);
    const polData = waiverRes.json().data;
    expect(polData.waivers).toBeDefined();
    expect(polData.waivers.length).toBeGreaterThan(0);

    const match = polData.waivers.find(
      (w: { fingerprint: string }) => w.fingerprint === waiverPayload.fingerprint
    );
    expect(match).toBeDefined();
    expect(match.reason).toBe(waiverPayload.reason);
    expect(match.approvedBy).toBe(waiverPayload.approvedBy);
  });
});
