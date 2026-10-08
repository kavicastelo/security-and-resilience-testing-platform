import net from 'node:net';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth, getDatabase } from '../../apps/controller/src/services/db.js';
import { AgentClient } from '../../apps/agent/src/index.js';

describe('Phase 16.2: Tenant Isolation, Contextual Binding & Route Authorization', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;
  let controllerUrl: string;

  // Tenants
  let tenantA: { id: string; name: string; slug: string };
  let tenantB: { id: string; name: string; slug: string };

  // Targets & Projects
  let projectAId: string;
  let targetAId: string;

  // Agents
  let agentA1Data: { agentId: string; token: string; tenantId: string };
  let agentA2Data: { agentId: string; token: string; tenantId: string };
  let agentBData: { agentId: string; token: string; tenantId: string };
  let agentA1Client: AgentClient;
  let agentA2Client: AgentClient;
  let agentBClient: AgentClient;

  // Jobs
  let jobA1Id: string;
  let testRunA1Id: string;

  beforeAll(async () => {
    // 1. Initialize Fastify app
    app = buildApp({ disableLogging: true });
    await app.listen({ port: 0, host: '127.0.0.1' });
    const addr = app.server.address() as net.AddressInfo;
    controllerUrl = `http://127.0.0.1:${addr.port}`;

    // 2. Health check
    const health = await checkDatabaseHealth();
    isDbAvailable = health === 'up';

    // 3. Create Tenant Alpha and Tenant Beta
    const suffix = `${Date.now()}-${Math.floor(Math.random() * 10000)}`;
    const tenantARes = await app.inject({
      method: 'POST',
      url: '/api/v1/tenants',
      payload: { name: `Isolation Alpha Corp ${suffix}`, slug: `iso-alpha-${suffix}`, plan: 'enterprise' },
    });
    expect(tenantARes.statusCode).toBe(201);
    tenantA = tenantARes.json().data;

    const tenantBRes = await app.inject({
      method: 'POST',
      url: '/api/v1/tenants',
      payload: { name: `Isolation Beta Corp ${suffix}`, slug: `iso-beta-${suffix}`, plan: 'enterprise' },
    });
    expect(tenantBRes.statusCode).toBe(201);
    tenantB = tenantBRes.json().data;

    // 4. Create Project & Target in Tenant Alpha
    const projectRes = await app.inject({
      method: 'POST',
      url: '/api/v1/projects',
      headers: { 'x-tenant-id': tenantA.id },
      payload: { name: `Alpha Secret Microservices ${suffix}`, description: 'Tenant Alpha' },
    });
    expect(projectRes.statusCode).toBe(201);
    projectAId = projectRes.json().data.id;

    const targetRes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectAId}/targets`,
      headers: { 'x-tenant-id': tenantA.id },
      payload: {
        name: 'Alpha Target',
        baseUrl: 'http://127.0.0.1:9099',
        environment: 'staging',
        criticality: 'high',
        allowedHosts: ['127.0.0.1'],
        allowedPorts: [9099],
        excludedPaths: [],
        testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
        limits: { maxRps: 50, maxConcurrency: 5, maxDuration: '2m' },
      },
    });
    targetAId = targetRes.json().data.id;

    // 5. Provision TEK for Tenant Alpha and Tenant Beta
    const tekARes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenantA.id}/enrollment-keys`,
      payload: { name: 'Alpha Isolation TEK' },
    });
    const tekA = tekARes.json().data.key;

    const tekBRes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenantB.id}/enrollment-keys`,
      payload: { name: 'Beta Isolation TEK' },
    });
    const tekB = tekBRes.json().data.key;

    // 6. Register Agent A1 (Tenant Alpha), Agent A2 (Tenant Alpha), and Agent B (Tenant Beta)
    agentA1Client = new AgentClient(controllerUrl);
    agentA1Data = await agentA1Client.register(
      { name: 'agent-a1-worker', tags: ['vpc-a'], capabilities: ['engine-native-headers'] },
      tekA,
    );

    agentA2Client = new AgentClient(controllerUrl);
    agentA2Data = await agentA2Client.register(
      { name: 'agent-a2-worker', tags: ['vpc-a'], capabilities: ['engine-native-headers'] },
      tekA,
    );

    agentBClient = new AgentClient(controllerUrl);
    agentBData = await agentBClient.register(
      { name: 'agent-b-worker', tags: ['vpc-b'], capabilities: ['engine-native-headers'] },
      tekB,
    );

    // 7. Create Test Run & Dispatch Job for Tenant Alpha
    const runRes = await app.inject({
      method: 'POST',
      url: '/api/v1/test-runs',
      headers: { 'x-tenant-id': tenantA.id },
      payload: {
        projectId: projectAId,
        targetId: targetAId,
        profileId: 'native-class-a',
        triggeredBy: 'manual',
      },
    });
    testRunA1Id = runRes.json().data.id;

    const dispatchRes = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/dispatch',
      headers: { 'x-tenant-id': tenantA.id },
      payload: {
        testRunId: testRunA1Id,
        engineIds: ['engine-native-headers'],
      },
    });
    jobA1Id = dispatchRes.json().data.jobId;

    // Agent A1 claims/leases Job A1
    const polled = await agentA1Client.poll(agentA1Data.agentId, ['engine-native-headers'], ['vpc-a'], 1);
    expect(polled.length).toBe(1);
    expect(polled[0].jobId).toBe(jobA1Id);
  });

  afterAll(async () => {
    await app.close();
    if (isDbAvailable) {
      await closeDatabase();
    }
  });

  it('1. Verifies setup preconditions and agent tenant bindings', () => {
    expect(isDbAvailable).toBe(true);
    expect(agentA1Data.tenantId).toBe(tenantA.id);
    expect(agentA2Data.tenantId).toBe(tenantA.id);
    expect(agentBData.tenantId).toBe(tenantB.id);
    expect(agentBData.tenantId).not.toBe(tenantA.id);
  });

  it('2. Blocks cross-tenant job progress update with 403 TENANT_MISMATCH', async () => {
    // Attack Path: Agent B (Tenant Beta) attempts to report progress for Job A1 (Tenant Alpha)
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${jobA1Id}/progress`,
      headers: { authorization: `Bearer ${agentBData.token}`, 'x-protocol-version': '1.0.0' },
      payload: {
        jobId: jobA1Id,
        testRunId: testRunA1Id,
        percent: 50,
        message: 'Malicious cross-tenant progress update',
      },
    });

    expect(res.statusCode).toBe(403);
    const body = res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('TENANT_MISMATCH');
    expect(body.error.message).toContain('Tenant mismatch');
  });

  it('3. Blocks cross-tenant job completion with 403 TENANT_MISMATCH', async () => {
    // Attack Path: Agent B (Tenant Beta) attempts to complete Job A1 (Tenant Alpha)
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${jobA1Id}/complete`,
      headers: { authorization: `Bearer ${agentBData.token}`, 'x-protocol-version': '1.0.0' },
      payload: {
        jobId: jobA1Id,
        testRunId: testRunA1Id,
        status: 'completed',
        findings: [
          {
            sourceEngine: 'attacker-engine',
            title: 'Injected Cross-Tenant Finding',
            description: 'Malicious payload from Tenant Beta',
            rawSeverity: 'critical',
          },
        ],
        metrics: [],
        executions: [],
      },
    });

    expect(res.statusCode).toBe(403);
    const body = res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('TENANT_MISMATCH');
    expect(body.error.message).toContain('Tenant mismatch');

    // Confirm no finding was persisted
    const findingsRes = await app.inject({
      method: 'GET',
      url: `/api/v1/findings?testRunId=${testRunA1Id}`,
      headers: { 'x-tenant-id': tenantA.id },
    });
    expect(findingsRes.statusCode).toBe(200);
    const findings = findingsRes.json().data;
    expect(findings.some((f: { title: string }) => f.title === 'Injected Cross-Tenant Finding')).toBe(false);
  });

  it('4. Blocks cross-tenant job failure report with 403 TENANT_MISMATCH', async () => {
    // Attack Path: Agent B (Tenant Beta) attempts to fail Job A1 (Tenant Alpha)
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${jobA1Id}/fail`,
      headers: { authorization: `Bearer ${agentBData.token}`, 'x-protocol-version': '1.0.0' },
      payload: { error: 'Malicious cross-tenant failure injection' },
    });

    expect(res.statusCode).toBe(403);
    const body = res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('TENANT_MISMATCH');
    expect(body.error.message).toContain('Tenant mismatch');
  });

  it('5. Blocks cross-agent job progress update within the same tenant with 403 AGENT_MISMATCH', async () => {
    // Attack Path: Agent A2 belongs to Tenant Alpha, but Job A1 is leased to Agent A1
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${jobA1Id}/progress`,
      headers: { authorization: `Bearer ${agentA2Data.token}`, 'x-protocol-version': '1.0.0' },
      payload: {
        jobId: jobA1Id,
        testRunId: testRunA1Id,
        percent: 75,
        message: 'Non-assigned worker progress attempt',
      },
    });

    expect(res.statusCode).toBe(403);
    const body = res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('AGENT_MISMATCH');
    expect(body.error.message).toContain('Agent mismatch');
  });

  it('6. Blocks cross-agent job completion within the same tenant with 403 AGENT_MISMATCH', async () => {
    // Attack Path: Agent A2 belongs to Tenant Alpha, but Job A1 is leased to Agent A1
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${jobA1Id}/complete`,
      headers: { authorization: `Bearer ${agentA2Data.token}`, 'x-protocol-version': '1.0.0' },
      payload: {
        jobId: jobA1Id,
        testRunId: testRunA1Id,
        status: 'completed',
        findings: [],
        metrics: [],
        executions: [],
      },
    });

    expect(res.statusCode).toBe(403);
    const body = res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('AGENT_MISMATCH');
    expect(body.error.message).toContain('Agent mismatch');
  });

  it('7. Blocks cross-agent job failure within the same tenant with 403 AGENT_MISMATCH', async () => {
    // Attack Path: Agent A2 belongs to Tenant Alpha, but Job A1 is leased to Agent A1
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${jobA1Id}/fail`,
      headers: { authorization: `Bearer ${agentA2Data.token}`, 'x-protocol-version': '1.0.0' },
      payload: { error: 'Non-assigned worker trying to fail job' },
    });

    expect(res.statusCode).toBe(403);
    const body = res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('AGENT_MISMATCH');
    expect(body.error.message).toContain('Agent mismatch');
  });

  it('8. Blocks header-based tenant spoofing when x-tenant-id conflicts with agent token (Rule 5)', async () => {
    // Attack Path: Agent A1 provides its valid token, but includes x-tenant-id header for Tenant Beta
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${jobA1Id}/progress`,
      headers: {
        authorization: `Bearer ${agentA1Data.token}`,
        'x-tenant-id': tenantB.id, // Conflict with Agent A1's token tenant!
        'x-protocol-version': '1.0.0',
      },
      payload: {
        jobId: jobA1Id,
        testRunId: testRunA1Id,
        percent: 25,
        message: 'Spoofed tenant header attempt',
      },
    });

    expect(res.statusCode).toBe(403);
    const body = res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('TENANT_MISMATCH');
  });

  it('9. Blocks header-based tenant spoofing on GET /api/v1/agents listing (Rule 5)', async () => {
    // Attack Path: Agent A1 queries /api/v1/agents but specifies x-tenant-id: tenantB
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/agents',
      headers: {
        authorization: `Bearer ${agentA1Data.token}`,
        'x-tenant-id': tenantB.id,
      },
    });

    expect(res.statusCode).toBe(403);
    const body = res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('TENANT_MISMATCH');
  });

  it('10. Allows legitimate agent leaseholder (Agent A1) to report progress and complete job', async () => {
    // 1. Report progress
    const progRes = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${jobA1Id}/progress`,
      headers: { authorization: `Bearer ${agentA1Data.token}`, 'x-protocol-version': '1.0.0' },
      payload: {
        jobId: jobA1Id,
        testRunId: testRunA1Id,
        percent: 90,
        message: 'Legitimate execution nearly done',
      },
    });
    expect(progRes.statusCode).toBe(200);
    expect(progRes.json().success).toBe(true);

    // 2. Complete job
    const compRes = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${jobA1Id}/complete`,
      headers: { authorization: `Bearer ${agentA1Data.token}`, 'x-protocol-version': '1.0.0' },
      payload: {
        jobId: jobA1Id,
        testRunId: testRunA1Id,
        status: 'completed',
        findings: [
          {
            sourceEngine: 'engine-native-headers',
            title: 'Legitimate Alpha Finding',
            description: 'Header analysis reported missing security headers',
            rawSeverity: 'medium',
            location: '/api/v1/secure',
          },
        ],
        metrics: [],
        executions: [
          {
            engineId: 'engine-native-headers',
            status: 'completed',
            durationMs: 120,
          },
        ],
      },
    });
    expect(compRes.statusCode).toBe(200);
    expect(compRes.json().success).toBe(true);

    // Confirm job state in DB
    const { sql } = getDatabase();
    const [job] = await sql`SELECT status, agent_id, tenant_id FROM agent_jobs WHERE id = ${jobA1Id}`;
    expect(job.status).toBe('completed');
    expect(job.agent_id).toBe(agentA1Data.agentId);
    expect(job.tenant_id).toBe(tenantA.id);
  });

  it('11. Allows legitimate agent leaseholder to report job failure', async () => {
    // Dispatch second job for Tenant Alpha
    const runRes = await app.inject({
      method: 'POST',
      url: '/api/v1/test-runs',
      headers: { 'x-tenant-id': tenantA.id },
      payload: {
        projectId: projectAId,
        targetId: targetAId,
        profileId: 'native-class-a',
        triggeredBy: 'manual',
      },
    });
    const runId = runRes.json().data.id;

    const dispatchRes = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/dispatch',
      headers: { 'x-tenant-id': tenantA.id },
      payload: {
        testRunId: runId,
        engineIds: ['engine-native-headers'],
      },
    });
    const jobFailId = dispatchRes.json().data.jobId;

    // Agent A2 claims this second job
    const polled = await agentA2Client.poll(agentA2Data.agentId, ['engine-native-headers'], ['vpc-a'], 1);
    expect(polled.length).toBe(1);
    expect(polled[0].jobId).toBe(jobFailId);

    // Agent A2 fails its own leased job
    const failRes = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${jobFailId}/fail`,
      headers: { authorization: `Bearer ${agentA2Data.token}`, 'x-protocol-version': '1.0.0' },
      payload: { error: 'Network timeout to target VPC endpoint' },
    });

    expect(failRes.statusCode).toBe(200);
    expect(failRes.json().success).toBe(true);

    const { sql } = getDatabase();
    const [job] = await sql`SELECT status, error, agent_id FROM agent_jobs WHERE id = ${jobFailId}`;
    expect(job.status).toBe('failed');
    expect(job.error).toBe('Network timeout to target VPC endpoint');
    expect(job.agent_id).toBe(agentA2Data.agentId);
  });
});
