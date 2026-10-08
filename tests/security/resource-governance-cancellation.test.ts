import http from 'node:http';
import net from 'node:net';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { getDatabase, closeDatabase, checkDatabaseHealth } from '../../apps/controller/src/services/db.js';
import {
  AgentClient,
  AgentWorker,
  JobCancelledError,
  JobTimeoutError,
} from '../../apps/agent/src/index.js';
import { engineRegistry, TestEngine, ExecutionContext, TestInput, TestOutput } from '@security-lab/test-sdk';

describe('Phase 16.6: Agent Resource Governance, Timeouts & Bidirectional Cancellation', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;
  let controllerUrl: string;

  let mockTargetServer: http.Server;
  let mockTargetPort: number;
  let mockTargetUrl: string;

  let tenant: { id: string; name: string; slug: string };
  let projectId: string;
  let targetId: string;
  let tekToken: string;

  let agentId: string;
  let agentToken: string;
  let agentClient: AgentClient;

  async function createTestRun(customTargetId?: string): Promise<string> {
    const runRes = await app.inject({
      method: 'POST',
      url: '/api/v1/test-runs',
      headers: { 'x-tenant-id': tenant.id },
      payload: {
        projectId,
        targetId: customTargetId || targetId,
        profileId: 'native-class-a',
        triggeredBy: 'manual',
      },
    });
    expect(runRes.statusCode).toBe(201);
    return runRes.json().data.id;
  }

  async function dispatchJob(testRunId: string, engineIds: string[] = ['engine-native-headers']): Promise<string> {
    const dispatchRes = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/dispatch',
      headers: { 'x-tenant-id': tenant.id },
      payload: { testRunId, engineIds },
    });
    expect(dispatchRes.statusCode).toBe(202);
    return dispatchRes.json().data.jobId;
  }

  beforeAll(async () => {
    app = buildApp({ disableLogging: true });
    await app.listen({ port: 0, host: '127.0.0.1' });
    const addr = app.server.address() as net.AddressInfo;
    controllerUrl = `http://127.0.0.1:${addr.port}`;

    const health = await checkDatabaseHealth();
    isDbAvailable = health === 'up';

    if (!isDbAvailable) {
      throw new Error('Database is not available for Phase 16.6 testing');
    }

    // Mock Target Server
    mockTargetServer = http.createServer((req, res) => {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        Server: 'VPC-Target/1.0',
      });
      res.end(JSON.stringify({ status: 'ok' }));
    });

    await new Promise<void>((resolve) => {
      mockTargetServer.listen(0, '127.0.0.1', () => {
        mockTargetPort = (mockTargetServer.address() as net.AddressInfo).port;
        mockTargetUrl = `http://127.0.0.1:${mockTargetPort}`;
        resolve();
      });
    });

    const suffix = `${Date.now()}-${Math.floor(Math.random() * 10000)}`;

    // 1. Provision Tenant
    const tenantRes = await app.inject({
      method: 'POST',
      url: '/api/v1/tenants',
      payload: { name: `Cancellation Org ${suffix}`, slug: `cancel-org-${suffix}` },
    });
    expect(tenantRes.statusCode).toBe(201);
    tenant = tenantRes.json().data;

    // 2. Generate Master TEK
    const tekRes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenant.id}/enrollment-keys`,
      payload: { name: `CI/CD Key ${suffix}`, expiresInDays: 30 },
    });
    expect(tekRes.statusCode).toBe(201);
    tekToken = tekRes.json().data.key;

    // 3. Provision Project & Target
    const projRes = await app.inject({
      method: 'POST',
      url: '/api/v1/projects',
      headers: { 'x-tenant-id': tenant.id },
      payload: { name: `Cancellation Target Project ${suffix}` },
    });
    expect(projRes.statusCode).toBe(201);
    projectId = projRes.json().data.id;

    const targetRes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectId}/targets`,
      headers: { 'x-tenant-id': tenant.id },
      payload: {
        name: 'Internal Target Service',
        baseUrl: mockTargetUrl,
        environment: 'staging',
        criticality: 'high',
        allowedHosts: ['127.0.0.1'],
        allowedPorts: [mockTargetPort],
        excludedPaths: [],
        testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
        limits: { maxRps: 50, maxConcurrency: 5, maxDuration: '10m' },
      },
    });
    expect(targetRes.statusCode).toBe(201);
    targetId = targetRes.json().data.id;

    // 4. Enroll Agent
    agentClient = new AgentClient(controllerUrl);
    const reg = await agentClient.register(
      {
        name: 'cancellation-agent-1',
        capabilities: ['engine-native-headers', 'engine-slow-cancellation', 'engine-infinite-timeout'],
        tags: ['vpc-test'],
      },
      tekToken,
      tenant.id,
    );
    agentId = reg.agentId;
    agentToken = reg.token;
    agentClient.setToken(agentToken);
  });

  afterAll(async () => {
    if (mockTargetServer) {
      await new Promise<void>((resolve) => mockTargetServer.close(() => resolve()));
    }
    await app.close();
    await closeDatabase();
  });

  it('1. Heartbeat response carries cancelledJobIds when user cancels test run', async () => {
    const testRunId = await createTestRun();
    const jobId = await dispatchJob(testRunId, ['engine-native-headers']);

    // Agent polls and claims the job
    const jobs = await agentClient.poll(agentId, ['engine-native-headers'], ['vpc-test'], 1);
    expect(jobs.length).toBe(1);
    expect(jobs[0].jobId).toBe(jobId);

    // Initial heartbeat before cancellation: no cancelled jobs
    const hb1 = await agentClient.heartbeat(agentId, 'busy', { activeJobsCount: 1 }, jobs[0].leaseId);
    expect(hb1.cancelledJobIds).toEqual([]);

    // User cancels the in-flight test run
    const cancelRes = await app.inject({
      method: 'POST',
      url: `/api/v1/test-runs/${testRunId}/cancel`,
      headers: { 'x-tenant-id': tenant.id },
    });
    expect(cancelRes.statusCode).toBe(200);
    expect(cancelRes.json().data.status).toBe('cancelled');

    // Next agent heartbeat check-in receives the cancellation signal
    const hb2 = await agentClient.heartbeat(agentId, 'busy', { activeJobsCount: 1 }, jobs[0].leaseId);
    expect(hb2.cancelledJobIds).toContain(jobId);
  });

  it('2. Agent acknowledges cancellation via POST /cancel-ack and cleans up backchannel', async () => {
    const testRunId = await createTestRun();
    const jobId = await dispatchJob(testRunId, ['engine-native-headers']);

    const jobs = await agentClient.poll(agentId, ['engine-native-headers'], ['vpc-test'], 1);
    expect(jobs.length).toBe(1);

    // Cancel test run
    await app.inject({
      method: 'POST',
      url: `/api/v1/test-runs/${testRunId}/cancel`,
      headers: { 'x-tenant-id': tenant.id },
    });

    // Verify heartbeat returns the cancelled jobId
    const hb = await agentClient.heartbeat(agentId, 'busy', {}, jobs[0].leaseId);
    expect(hb.cancelledJobIds).toContain(jobId);

    // Agent transmits cancellation acknowledgment to controller
    await agentClient.acknowledgeCancellation(jobId);

    // Confirm that the job cancellation ack is recorded in agent_jobs
    const { sql } = getDatabase();
    const rows = await sql`SELECT result FROM agent_jobs WHERE id = ${jobId} LIMIT 1`;
    expect(rows[0]?.result?.cancelledAck).toBe(true);

    // Subsequent heartbeat check-in no longer includes the acknowledged cancelled jobId
    const hbAfterAck = await agentClient.heartbeat(agentId, 'online', {});
    expect(hbAfterAck.cancelledJobIds).not.toContain(jobId);
  });

  it('3. In-flight execution is halted and aborted within 2 seconds when AbortController triggers', async () => {
    let engineStarted = false;
    let engineCleanedUp = false;

    // Register a mock long-running engine that listens to context.abortSignal
    const slowEngine: TestEngine = {
      id: 'engine-slow-cancellation',
      name: 'Slow Cancellation Test Engine',
      version: '1.0.0',
      type: 'custom',
      async execute(_input: TestInput, context: ExecutionContext): Promise<TestOutput> {
        engineStarted = true;
        const startTime = Date.now();

        return new Promise<TestOutput>((resolve, reject) => {
          const timeout = setTimeout(() => {
            resolve({
              success: true,
              durationMs: Date.now() - startTime,
              findings: [],
            });
          }, 5000); // 5 seconds if not aborted

          context.abortSignal.addEventListener(
            'abort',
            () => {
              clearTimeout(timeout);
              engineCleanedUp = true;
              reject(new Error('Slow engine aborted by execution signal'));
            },
            { once: true },
          );
        });
      },
    };

    engineRegistry.register(slowEngine);

    const testRunId = await createTestRun();
    const _jobId = await dispatchJob(testRunId, ['engine-slow-cancellation']);
    const jobs = await agentClient.poll(agentId, ['engine-slow-cancellation'], ['vpc-test'], 1);
    expect(jobs.length).toBe(1);

    const worker = new AgentWorker(agentClient, { allowLocalTesting: true });
    const abortController = new AbortController();

    const startExecution = Date.now();
    const executionPromise = worker.executeJob(jobs[0], abortController.signal);

    // Wait until engine has started
    while (!engineStarted && Date.now() - startExecution < 1000) {
      await new Promise((r) => setTimeout(r, 20));
    }
    expect(engineStarted).toBe(true);

    // Trigger immediate cancellation
    const cancelTime = Date.now();
    abortController.abort(new Error('User emergency cancel'));

    // Assert that execution stops immediately with JobCancelledError
    await expect(executionPromise).rejects.toThrow(JobCancelledError);
    const totalCancellationDuration = Date.now() - cancelTime;

    // Architecture Constraint: Must terminate within 2 seconds (< 2000ms)
    expect(totalCancellationDuration).toBeLessThan(2000);
    expect(engineCleanedUp).toBe(true);
  });

  it('4. Late completion shielding: completed report on cancelled job returns 200 with ignored: true without database mutation', async () => {
    const testRunId = await createTestRun();
    const jobId = await dispatchJob(testRunId, ['engine-native-headers']);
    const [claimedJob] = await agentClient.poll(agentId, ['engine-native-headers'], ['vpc-test'], 1);
    expect(claimedJob).toBeDefined();

    // Cancel test run
    await app.inject({
      method: 'POST',
      url: `/api/v1/test-runs/${testRunId}/cancel`,
      headers: { 'x-tenant-id': tenant.id },
    });

    // Agent attempts to submit a late completion report with findings and metrics
    const lateCompleteRes = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${jobId}/complete`,
      headers: { authorization: `Bearer ${agentToken}`, 'x-protocol-version': '1.0.0' },
      payload: {
        jobId,
        testRunId,
        status: 'completed',
        findings: [
          {
            sourceEngine: 'engine-native-headers',
            title: 'Late Unauthorized Finding',
            description: 'Should never be inserted into database',
            rawSeverity: 'high',
          },
        ],
        metrics: [
          {
            name: 'late_metric',
            value: 999,
            unit: 'ms',
          },
        ],
        executions: [
          {
            engineId: 'engine-native-headers',
            status: 'completed',
          },
        ],
      },
    });

    // Late completion is safely discarded and acknowledged
    expect(lateCompleteRes.statusCode).toBe(200);
    const body = lateCompleteRes.json();
    expect(body.ignored).toBe(true);
    expect(body.status).toBe('cancelled');

    // Verify test run in database remains cancelled
    const { sql } = getDatabase();
    const runRows = await sql`SELECT status FROM test_runs WHERE id = ${testRunId} LIMIT 1`;
    expect(runRows[0]?.status).toBe('cancelled');

    // Verify no findings were inserted
    const findingRows = await sql`SELECT id FROM findings WHERE test_run_id = ${testRunId}`;
    expect(findingRows.length).toBe(0);

    // Verify no metrics were inserted
    const metricRows = await sql`SELECT id FROM metrics WHERE test_run_id = ${testRunId}`;
    expect(metricRows.length).toBe(0);
  });

  it('5. Hard execution timeout: worker self-aborts when execution exceeds maxDuration', async () => {
    // Register an engine that runs forever unless aborted
    const infiniteEngine: TestEngine = {
      id: 'engine-infinite-timeout',
      name: 'Infinite Timeout Test Engine',
      version: '1.0.0',
      type: 'custom',
      async execute(_input: TestInput, context: ExecutionContext): Promise<TestOutput> {
        return new Promise<TestOutput>((_resolve, reject) => {
          context.abortSignal.addEventListener(
            'abort',
            () => reject(new Error('Infinite engine aborted by timeout')),
            { once: true },
          );
        });
      },
    };

    engineRegistry.register(infiniteEngine);

    // Create target with a strict 250ms maxDuration
    const timeoutTargetRes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectId}/targets`,
      headers: { 'x-tenant-id': tenant.id },
      payload: {
        name: 'Timeout Target Service',
        baseUrl: mockTargetUrl,
        environment: 'staging',
        criticality: 'high',
        allowedHosts: ['127.0.0.1'],
        allowedPorts: [mockTargetPort],
        excludedPaths: [],
        testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
        limits: { maxRps: 50, maxConcurrency: 5, maxDuration: '250ms' },
      },
    });
    expect(timeoutTargetRes.statusCode).toBe(201);
    const timeoutTargetId = timeoutTargetRes.json().data.id;

    const testRunId = await createTestRun(timeoutTargetId);
    const jobId = await dispatchJob(testRunId, ['engine-infinite-timeout']);
    const [claimedJob] = await agentClient.poll(agentId, ['engine-infinite-timeout'], ['vpc-test'], 1);
    expect(claimedJob).toBeDefined();

    const worker = new AgentWorker(agentClient, { allowLocalTesting: true });
    const start = Date.now();

    // Worker must self-abort after 250ms and throw JobTimeoutError
    await expect(worker.executeJob(claimedJob)).rejects.toThrow(JobTimeoutError);
    const duration = Date.now() - start;

    expect(duration).toBeGreaterThanOrEqual(240);
    expect(duration).toBeLessThan(1500);

    // Verify job in database is marked failed by reportFailure
    const { sql } = getDatabase();
    const failedRows = await sql`SELECT status, error FROM agent_jobs WHERE id = ${jobId} LIMIT 1`;
    expect(failedRows[0]?.status).toBe('failed');
    expect(failedRows[0]?.error).toContain('Job execution timed out after exceeding maximum duration of 250ms');
  });

  it('6. Rate limiting on /heartbeat enforces 120 requests/minute per agent', async () => {
    // Register a dedicated agent for rate limit testing
    const rateLimitClient = new AgentClient(controllerUrl);
    const reg = await rateLimitClient.register(
      { name: 'rate-limit-agent-1', capabilities: ['engine-native-headers'], tags: [] },
      tekToken,
      tenant.id,
    );
    rateLimitClient.setToken(reg.token);

    // Send 120 valid heartbeats (allowed within 1 minute window)
    for (let i = 0; i < 120; i++) {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/agents/heartbeat',
        headers: { authorization: `Bearer ${reg.token}`, 'x-protocol-version': '1.0.0' },
        payload: { agentId: reg.agentId, status: 'online' },
      });
      expect(res.statusCode).toBe(200);
    }

    // 121st heartbeat must be rate-limited with HTTP 429
    const blockedRes = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/heartbeat',
      headers: { authorization: `Bearer ${reg.token}`, 'x-protocol-version': '1.0.0' },
      payload: { agentId: reg.agentId, status: 'online' },
    });
    expect(blockedRes.statusCode).toBe(429);
    expect(blockedRes.json().message || blockedRes.json().error).toBeDefined();
  });

  it('7. Rate limiting on /poll enforces 60 requests/minute per agent', async () => {
    // Register a second dedicated agent for poll rate limiting
    const pollRateClient = new AgentClient(controllerUrl);
    const reg = await pollRateClient.register(
      { name: 'poll-rate-agent-2', capabilities: ['engine-native-headers'], tags: [] },
      tekToken,
      tenant.id,
    );
    pollRateClient.setToken(reg.token);

    // Send 60 polls (allowed within 1 minute window)
    for (let i = 0; i < 60; i++) {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/agents/poll',
        headers: { authorization: `Bearer ${reg.token}`, 'x-protocol-version': '1.0.0' },
        payload: { agentId: reg.agentId, maxJobs: 1 },
      });
      expect(res.statusCode).toBe(200);
    }

    // 61st poll must be rate-limited with HTTP 429
    const blockedPoll = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/poll',
      headers: { authorization: `Bearer ${reg.token}`, 'x-protocol-version': '1.0.0' },
      payload: { agentId: reg.agentId, maxJobs: 1 },
    });
    expect(blockedPoll.statusCode).toBe(429);
  });

  it('8. Body limit: /complete rejects payloads exceeding 5MB with HTTP 413', async () => {
    const testRunId = await createTestRun();
    const jobId = await dispatchJob(testRunId, ['engine-native-headers']);

    // Generate a payload exceeding 5MB (e.g. 5.5MB of padding)
    const largePadding = 'X'.repeat(5.5 * 1024 * 1024);

    const oversizedRes = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${jobId}/complete`,
      headers: { authorization: `Bearer ${agentToken}`, 'x-protocol-version': '1.0.0' },
      payload: {
        jobId,
        testRunId,
        status: 'completed',
        findings: [
          {
            sourceEngine: 'engine-native-headers',
            title: 'Oversized Finding',
            description: largePadding,
            rawSeverity: 'info',
          },
        ],
        metrics: [],
        executions: [],
      },
    });

    // Fastify rejects payloads exceeding bodyLimit with 413
    expect(oversizedRes.statusCode).toBe(413);
  });
});
