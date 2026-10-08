import http from 'node:http';
import net from 'node:net';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth, getDatabase } from '../../apps/controller/src/services/db.js';
import { AgentClient, AgentWorker } from '../../apps/agent/src/index.js';
import {
  computeFindingsHash,
  computeResultSignature,
} from '@security-lab/evidence';

describe('Phase 16.4: Result Authenticity, Evidence HMAC & Idempotent Ingestion', () => {
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

  async function createTestRun(): Promise<string> {
    const runRes = await app.inject({
      method: 'POST',
      url: '/api/v1/test-runs',
      headers: { 'x-tenant-id': tenant.id },
      payload: {
        projectId,
        targetId,
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
      throw new Error('Database is not available for Phase 16.4 testing');
    }

    mockTargetServer = http.createServer((req, res) => {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        Server: 'Attestation-Target/1.0',
      });
      res.end(JSON.stringify({ status: 'ok' }));
    });

    await new Promise<void>((resolve) => {
      mockTargetServer.listen(0, '127.0.0.1', () => {
        const targetAddr = mockTargetServer.address() as net.AddressInfo;
        mockTargetPort = targetAddr.port;
        mockTargetUrl = `http://127.0.0.1:${mockTargetPort}`;
        resolve();
      });
    });

    const suffix = `${Date.now()}-${Math.floor(Math.random() * 10000)}`;

    // 1. Create dedicated testing tenant
    const tenantRes = await app.inject({
      method: 'POST',
      url: '/api/v1/tenants',
      payload: {
        name: `Attestation Corp ${suffix}`,
        slug: `attest-corp-${suffix}`,
        plan: 'enterprise',
      },
    });
    expect(tenantRes.statusCode).toBe(201);
    tenant = tenantRes.json().data;

    // 2. Create Project and Target
    const projectRes = await app.inject({
      method: 'POST',
      url: '/api/v1/projects',
      headers: { 'x-tenant-id': tenant.id },
      payload: { name: `Attestation Project ${suffix}`, description: 'Phase 16.4' },
    });
    expect(projectRes.statusCode).toBe(201);
    projectId = projectRes.json().data.id;

    const targetRes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectId}/targets`,
      headers: { 'x-tenant-id': tenant.id },
      payload: {
        name: `Attestation Target ${suffix}`,
        baseUrl: mockTargetUrl,
        environment: 'staging',
        criticality: 'high',
        allowedHosts: ['127.0.0.1'],
        allowedPorts: [mockTargetPort],
        excludedPaths: [],
        testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
        limits: { maxRps: 50, maxConcurrency: 5, maxDuration: '2m' },
      },
    });
    expect(targetRes.statusCode).toBe(201);
    targetId = targetRes.json().data.id;

    // 3. Create TEK
    const tekRes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenant.id}/enrollment-keys`,
      payload: { name: `Attestation TEK ${suffix}`, expiresInDays: 30 },
    });
    expect(tekRes.statusCode).toBe(201);
    tekToken = tekRes.json().data.key;

    // 4. Enroll Agent
    agentClient = new AgentClient(controllerUrl);
    const regData = await agentClient.register(
      {
        name: `attest-agent-${suffix}`,
        capabilities: ['engine-native-headers', 'engine-port-scanner'],
        tags: ['vpc-secure'],
        systemInfo: { os: 'linux', arch: 'x64', nodeVersion: 'v20.0.0', cpuCount: 8, totalMemoryMb: 16384 },
      },
      tekToken,
    );
    agentId = regData.agentId;
    agentToken = regData.token;
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
    if (mockTargetServer) {
      await new Promise<void>((resolve, reject) => {
        mockTargetServer.close((err) => (err ? reject(err) : resolve()));
      });
    }
    await closeDatabase();
  });

  it('1. Ephemeral Job Dispatch Secret is provided upon atomic lease acquisition', async () => {
    const testRunId = await createTestRun();
    const jobId = await dispatchJob(testRunId);

    const polled = await agentClient.poll(agentId, ['engine-native-headers'], [], 1);
    expect(polled.length).toBe(1);
    const job = polled[0];

    expect(job.jobId).toBe(jobId);
    expect(job.leaseId).toBeDefined();
    expect(typeof job.leaseId).toBe('string');
    expect(job.jobDispatchSecret).toBeDefined();
    expect(typeof job.jobDispatchSecret).toBe('string');
    expect(job.jobDispatchSecret!.length).toBe(64); // SHA-256 hex string
  });

  it('2. Valid signed report completes successfully and atomically ingests findings and metrics', async () => {
    const testRunId = await createTestRun();
    await dispatchJob(testRunId);

    const [job] = await agentClient.poll(agentId, ['engine-native-headers'], [], 1);
    expect(job).toBeDefined();

    const findings = [
      {
        sourceEngine: 'engine-native-headers',
        title: 'Missing Content-Security-Policy',
        description: 'No Content-Security-Policy header present on response',
        rawSeverity: 'medium',
        location: 'https://staging.internal.corp',
      },
      {
        sourceEngine: 'engine-native-headers',
        title: 'X-Frame-Options Header Missing',
        description: 'Clickjacking protection header is absent',
        rawSeverity: 'low',
        location: 'https://staging.internal.corp/login',
      },
    ];

    const executions = [
      {
        engineId: 'engine-native-headers',
        status: 'completed',
        durationMs: 145,
      },
    ];

    const metrics = [
      {
        name: 'header_check_latency_ms',
        value: 145,
        unit: 'ms',
        tags: { engine: 'engine-native-headers' },
      },
    ];

    const findingsHash = computeFindingsHash(findings, executions);
    const resultSignature = computeResultSignature(job.jobDispatchSecret!, job.jobId, findingsHash);

    const completeRes = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${job.jobId}/complete`,
      headers: { authorization: `Bearer ${agentToken}`, 'x-protocol-version': '1.0.0' },
      payload: {
        jobId: job.jobId,
        testRunId,
        leaseId: job.leaseId,
        status: 'completed',
        findings,
        executions,
        metrics,
        resultSignature,
      },
    });

    expect(completeRes.statusCode).toBe(200);
    expect(completeRes.json().success).toBe(true);

    // Verify DB state
    const { sql } = getDatabase();
    const [jobRow] = await sql`SELECT status, lease_id FROM agent_jobs WHERE id = ${job.jobId}`;
    expect(jobRow.status).toBe('completed');

    const [testRunRow] = await sql`SELECT status FROM test_runs WHERE id = ${testRunId}`;
    expect(testRunRow.status).toBe('completed');

    const findingsRows = await sql`SELECT id, title, severity FROM findings WHERE test_run_id = ${testRunId}`;
    expect(findingsRows.length).toBe(2);

    const execRows = await sql`SELECT id, engine_id, status FROM test_executions WHERE test_run_id = ${testRunId}`;
    expect(execRows.length).toBe(1);

    const metricRows = await sql`SELECT id, name, value FROM metrics WHERE test_run_id = ${testRunId}`;
    expect(metricRows.length).toBe(1);
  });

  it('3. Rule 7 & SEC-04: Submitting the exact same report a second time returns deduplicated: true without database mutation', async () => {
    const testRunId = await createTestRun();
    await dispatchJob(testRunId);

    const [job] = await agentClient.poll(agentId, ['engine-native-headers'], [], 1);
    expect(job).toBeDefined();

    const findings = [
      {
        sourceEngine: 'engine-native-headers',
        title: 'Strict-Transport-Security Missing',
        description: 'HSTS header not enforced',
        rawSeverity: 'medium',
        location: 'https://staging.internal.corp',
      },
    ];
    const executions = [
      {
        engineId: 'engine-native-headers',
        status: 'completed',
        durationMs: 80,
      },
    ];

    const findingsHash = computeFindingsHash(findings, executions);
    const resultSignature = computeResultSignature(job.jobDispatchSecret!, job.jobId, findingsHash);

    const payload = {
      jobId: job.jobId,
      testRunId,
      leaseId: job.leaseId,
      status: 'completed',
      findings,
      executions,
      metrics: [],
      resultSignature,
    };

    // First completion submission
    const firstRes = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${job.jobId}/complete`,
      headers: { authorization: `Bearer ${agentToken}`, 'x-protocol-version': '1.0.0' },
      payload,
    });
    expect(firstRes.statusCode).toBe(200);
    expect(firstRes.json().success).toBe(true);

    const { sql } = getDatabase();
    const [findingsCount1] = await sql`SELECT COUNT(*)::int as count FROM findings WHERE test_run_id = ${testRunId}`;
    const [execCount1] = await sql`SELECT COUNT(*)::int as count FROM test_executions WHERE test_run_id = ${testRunId}`;
    expect(findingsCount1.count).toBe(1);
    expect(execCount1.count).toBe(1);

    // Duplicate submission (replayed by agent due to network retry)
    const duplicateRes = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${job.jobId}/complete`,
      headers: { authorization: `Bearer ${agentToken}`, 'x-protocol-version': '1.0.0' },
      payload,
    });
    expect(duplicateRes.statusCode).toBe(200);
    expect(duplicateRes.json().success).toBe(true);
    expect(duplicateRes.json().deduplicated).toBe(true);

    // Verify database counts remain strictly unchanged
    const [findingsCount2] = await sql`SELECT COUNT(*)::int as count FROM findings WHERE test_run_id = ${testRunId}`;
    const [execCount2] = await sql`SELECT COUNT(*)::int as count FROM test_executions WHERE test_run_id = ${testRunId}`;
    expect(findingsCount2.count).toBe(1);
    expect(execCount2.count).toBe(1);
  });

  it('4. Rule 4 & SEC-04: Tampering with 1 byte of finding description causes signature verification failure (403 SIGNATURE_INVALID)', async () => {
    const testRunId = await createTestRun();
    await dispatchJob(testRunId);

    const [job] = await agentClient.poll(agentId, ['engine-native-headers'], [], 1);
    expect(job).toBeDefined();

    const legitimateFindings = [
      {
        sourceEngine: 'engine-native-headers',
        title: 'Genuine Finding A',
        description: 'Authentic findings description signed by agent',
        rawSeverity: 'medium',
        location: '/api/v1/resource',
      },
    ];
    const executions = [
      {
        engineId: 'engine-native-headers',
        status: 'completed',
        durationMs: 50,
      },
    ];

    // Compute signature on genuine findings
    const findingsHash = computeFindingsHash(legitimateFindings, executions);
    const legitimateSignature = computeResultSignature(job.jobDispatchSecret!, job.jobId, findingsHash);

    // Adversary modifies 1 byte in description in transit: 'Authentic' -> 'Xuthentic'
    const tamperedFindings = [
      {
        sourceEngine: 'engine-native-headers',
        title: 'Genuine Finding A',
        description: 'Xuthentic findings description signed by agent', // 1 byte tampered
        rawSeverity: 'medium',
        location: '/api/v1/resource',
      },
    ];

    const tamperedRes = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${job.jobId}/complete`,
      headers: { authorization: `Bearer ${agentToken}`, 'x-protocol-version': '1.0.0' },
      payload: {
        jobId: job.jobId,
        testRunId,
        leaseId: job.leaseId,
        status: 'completed',
        findings: tamperedFindings,
        executions,
        metrics: [],
        resultSignature: legitimateSignature,
      },
    });

    expect(tamperedRes.statusCode).toBe(403);
    expect(tamperedRes.json().error.code).toBe('SIGNATURE_INVALID');

    // Confirm that no findings were ingested into database
    const { sql } = getDatabase();
    const findingsInDb = await sql`SELECT id FROM findings WHERE test_run_id = ${testRunId}`;
    expect(findingsInDb.length).toBe(0);

    const [jobInDb] = await sql`SELECT status FROM agent_jobs WHERE id = ${job.jobId}`;
    expect(jobInDb.status).not.toBe('completed');
  });

  it('5. Tampering with execution details causes signature verification failure (403 SIGNATURE_INVALID)', async () => {
    const testRunId = await createTestRun();
    await dispatchJob(testRunId);

    const [job] = await agentClient.poll(agentId, ['engine-native-headers'], [], 1);
    expect(job).toBeDefined();

    const findings = [
      {
        sourceEngine: 'engine-native-headers',
        title: 'Genuine Finding B',
        description: 'Authentic findings description',
        rawSeverity: 'info',
        location: '/api/v1/info',
      },
    ];
    const executions = [
      {
        engineId: 'engine-native-headers',
        status: 'completed',
        durationMs: 100,
      },
    ];

    const findingsHash = computeFindingsHash(findings, executions);
    const signature = computeResultSignature(job.jobDispatchSecret!, job.jobId, findingsHash);

    // Tamper with execution status: completed -> failed
    const tamperedExecutions = [
      {
        engineId: 'engine-native-headers',
        status: 'failed',
        durationMs: 100,
      },
    ];

    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${job.jobId}/complete`,
      headers: { authorization: `Bearer ${agentToken}`, 'x-protocol-version': '1.0.0' },
      payload: {
        jobId: job.jobId,
        testRunId,
        leaseId: job.leaseId,
        status: 'completed',
        findings,
        executions: tamperedExecutions,
        metrics: [],
        resultSignature: signature,
      },
    });

    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('SIGNATURE_INVALID');
  });

  it('6. Forged or random hex signature is rejected (403 SIGNATURE_INVALID)', async () => {
    const testRunId = await createTestRun();
    await dispatchJob(testRunId);

    const [job] = await agentClient.poll(agentId, ['engine-native-headers'], [], 1);
    expect(job).toBeDefined();

    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${job.jobId}/complete`,
      headers: { authorization: `Bearer ${agentToken}`, 'x-protocol-version': '1.0.0' },
      payload: {
        jobId: job.jobId,
        testRunId,
        leaseId: job.leaseId,
        status: 'completed',
        findings: [],
        executions: [],
        metrics: [],
        resultSignature: 'deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef',
      },
    });

    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('SIGNATURE_INVALID');
  });

  it('7. Rule 21: Submitting a report with a mismatched leaseId fails with 409 Conflict (LEASE_MISMATCH)', async () => {
    const testRunId = await createTestRun();
    await dispatchJob(testRunId);

    const [job] = await agentClient.poll(agentId, ['engine-native-headers'], [], 1);
    expect(job).toBeDefined();

    const findingsHash = computeFindingsHash([], []);
    const signature = computeResultSignature(job.jobDispatchSecret!, job.jobId, findingsHash);

    const mismatchRes = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${job.jobId}/complete`,
      headers: { authorization: `Bearer ${agentToken}`, 'x-protocol-version': '1.0.0' },
      payload: {
        jobId: job.jobId,
        testRunId,
        leaseId: '11111111-2222-3333-4444-555555555555', // Mismatched lease ID
        status: 'completed',
        findings: [],
        executions: [],
        metrics: [],
        resultSignature: signature,
      },
    });

    expect(mismatchRes.statusCode).toBe(409);
    expect(mismatchRes.json().error.code).toBe('LEASE_MISMATCH');
  });

  it('8. Rule 8: Submitting a report with an expired lease fails with 409 Conflict (LEASE_EXPIRED)', async () => {
    const testRunId = await createTestRun();
    await dispatchJob(testRunId);

    const [job] = await agentClient.poll(agentId, ['engine-native-headers'], [], 1);
    expect(job).toBeDefined();

    // Artificially expire the lease in the database
    const { sql } = getDatabase();
    await sql`
      UPDATE agent_jobs
      SET lease_expires_at = NOW() - INTERVAL '10 seconds'
      WHERE id = ${job.jobId}
    `;

    const findingsHash = computeFindingsHash([], []);
    const signature = computeResultSignature(job.jobDispatchSecret!, job.jobId, findingsHash);

    const expiredRes = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${job.jobId}/complete`,
      headers: { authorization: `Bearer ${agentToken}`, 'x-protocol-version': '1.0.0' },
      payload: {
        jobId: job.jobId,
        testRunId,
        leaseId: job.leaseId,
        status: 'completed',
        findings: [],
        executions: [],
        metrics: [],
        resultSignature: signature,
      },
    });

    expect(expiredRes.statusCode).toBe(409);
    expect(expiredRes.json().error.code).toBe('LEASE_EXPIRED');

    // Prevent background watchdog reaper from recycling test 8's expired job
    await sql`UPDATE agent_jobs SET status = 'failed' WHERE id = ${job.jobId}`;
  });

  it('9. End-to-end: AgentWorker automatically signs results and completes job idempotently', async () => {
    const { sql } = getDatabase();
    await sql`UPDATE agent_jobs SET status = 'failed' WHERE tenant_id = ${tenant.id} AND status IN ('queued', 'leased')`;

    const testRunId = await createTestRun();
    await dispatchJob(testRunId);

    const [dispatchedJob] = await agentClient.poll(agentId, ['engine-native-headers'], [], 1);
    expect(dispatchedJob).toBeDefined();
    expect(dispatchedJob.testRunId).toBe(testRunId);
    expect(dispatchedJob.jobDispatchSecret).toBeDefined();

    const worker = new AgentWorker(agentClient);

    // Initial worker execution
    await worker.executeJob(dispatchedJob);

    // Verify test run in controller is now completed
    const runRes = await app.inject({
      method: 'GET',
      url: `/api/v1/test-runs/${testRunId}`,
    });
    expect(runRes.statusCode).toBe(200);
    expect(runRes.json().data.status).toBe('completed');

    // Executing the same job a second time triggers idempotent deduplication
    await expect(worker.executeJob(dispatchedJob)).resolves.not.toThrow();

    // Verify database job is still marked completed
    const [jobRow] = await sql`SELECT status FROM agent_jobs WHERE id = ${dispatchedJob.jobId}`;
    expect(jobRow.status).toBe('completed');
  });
});
