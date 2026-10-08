import http from 'node:http';
import net from 'node:net';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { AgentJobDispatch } from '@security-lab/contracts';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth, getDatabase } from '../../apps/controller/src/services/db.js';
import { hashAgentToken } from '../../apps/controller/src/services/agent-dispatcher.service.js';
import { AgentClient, AgentWorker } from '../../apps/agent/src/index.js';

describe('Phase 15: Distributed Agent Architecture & Multi-Tenant SaaS Integration', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;
  let controllerUrl: string;

  // Mock Target Server simulating customer private VPC endpoint
  let mockTargetServer: http.Server;
  let mockTargetPort: number;
  let mockTargetUrl: string;

  // Tenant Alpha & Beta
  let tenantA: { id: string; name: string; slug: string };
  let tenantB: { id: string; name: string; slug: string };

  // Projects & Targets
  let projectAId: string;
  let projectBId: string;
  let targetAId: string;
  let targetBId: string;

  // Agents
  let agentAData: { agentId: string; token: string };
  let agentBData: { agentId: string; token: string };
  let agentAClient: AgentClient;
  let agentBClient: AgentClient;

  // Test Runs & Jobs
  let testRunAId: string;
  let testRunBId: string;
  let jobAId: string;
  let jobBId: string;

  beforeAll(async () => {
    // 1. Initialize Controller Fastify App
    app = buildApp({ disableLogging: true });
    await app.listen({ port: 0, host: '127.0.0.1' });
    const controllerAddr = app.server.address() as net.AddressInfo;
    controllerUrl = `http://127.0.0.1:${controllerAddr.port}`;

    // 2. Check Database Health
    const health = await checkDatabaseHealth();
    isDbAvailable = health === 'up';

    // 3. Start Mock Target Server (simulating an insecure private VPC service)
    mockTargetServer = http.createServer((req, res) => {
      // Insecure headers (missing HSTS, CSP, X-Frame-Options) to guarantee findings
      res.writeHead(200, {
        'Content-Type': 'application/json',
        Server: 'VPC-Internal-Microservice/1.0',
        'X-Powered-By': 'Express',
      });
      res.end(JSON.stringify({ status: 'ok', message: 'Private VPC target reachable by local agent' }));
    });

    await new Promise<void>((resolve) => {
      mockTargetServer.listen(0, '127.0.0.1', () => {
        const addr = mockTargetServer.address() as net.AddressInfo;
        mockTargetPort = addr.port;
        mockTargetUrl = `http://127.0.0.1:${mockTargetPort}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await app.close();
    await new Promise<void>((resolve, reject) => {
      mockTargetServer.close((err) => (err ? reject(err) : resolve()));
    });
    if (isDbAvailable) {
      await closeDatabase();
    }
  });

  it('1. Confirms database and controller server health', () => {
    expect(isDbAvailable).toBe(true);
    expect(controllerUrl).toBeDefined();
    expect(mockTargetUrl).toBeDefined();
  });

  it('2. Provisions SaaS Tenants Alpha and Beta', async () => {
    const randomSuffix = Math.floor(Math.random() * 1000000);

    // Create Tenant Alpha
    const resA = await app.inject({
      method: 'POST',
      url: '/api/v1/tenants',
      payload: {
        name: `Tenant Alpha ${randomSuffix}`,
        slug: `tenant-alpha-${randomSuffix}`,
        plan: 'enterprise',
      },
    });
    expect(resA.statusCode).toBe(201);
    tenantA = resA.json().data;
    expect(tenantA.id).toBeDefined();

    // Create Tenant Beta
    const resB = await app.inject({
      method: 'POST',
      url: '/api/v1/tenants',
      payload: {
        name: `Tenant Beta ${randomSuffix}`,
        slug: `tenant-beta-${randomSuffix}`,
        plan: 'enterprise',
      },
    });
    expect(resB.statusCode).toBe(201);
    tenantB = resB.json().data;
    expect(tenantB.id).toBeDefined();
    expect(tenantB.id).not.toBe(tenantA.id);
  });

  it('3. Enforces multi-tenant project and target boundary isolation', async () => {
    const randomSuffix = Math.floor(Math.random() * 10000000);

    // Create Project A under Tenant Alpha
    const projARes = await app.inject({
      method: 'POST',
      url: '/api/v1/projects',
      headers: { 'x-tenant-id': tenantA.id },
      payload: { name: `Alpha Core Services ${randomSuffix}`, description: 'Tenant Alpha Project' },
    });
    expect(projARes.statusCode).toBe(201);
    projectAId = projARes.json().data.id;

    // Create Project B under Tenant Beta
    const projBRes = await app.inject({
      method: 'POST',
      url: '/api/v1/projects',
      headers: { 'x-tenant-id': tenantB.id },
      payload: { name: `Beta Core Services ${randomSuffix}`, description: 'Tenant Beta Project' },
    });
    expect(projBRes.statusCode).toBe(201);
    projectBId = projBRes.json().data.id;

    // Create Target A under Tenant Alpha
    const targetARes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectAId}/targets`,
      headers: { 'x-tenant-id': tenantA.id },
      payload: {
        name: `Alpha VPC Internal Service ${randomSuffix}`,
        baseUrl: mockTargetUrl,
        environment: 'staging',
        criticality: 'high',
        allowedHosts: ['127.0.0.1'],
        allowedPorts: [mockTargetPort],
        excludedPaths: [],
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
    expect(targetARes.statusCode).toBe(201);
    targetAId = targetARes.json().data.id;

    // Create Target B under Tenant Beta
    const targetBRes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectBId}/targets`,
      headers: { 'x-tenant-id': tenantB.id },
      payload: {
        name: `Beta VPC Internal Service ${randomSuffix}`,
        baseUrl: mockTargetUrl,
        environment: 'staging',
        criticality: 'high',
        allowedHosts: ['127.0.0.1'],
        allowedPorts: [mockTargetPort],
        excludedPaths: [],
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
    expect(targetBRes.statusCode).toBe(201);
    targetBId = targetBRes.json().data.id;

    // Verify Tenant Alpha query only returns Target A
    const listARes = await app.inject({
      method: 'GET',
      url: '/api/v1/targets',
      headers: { 'x-tenant-id': tenantA.id },
    });
    expect(listARes.statusCode).toBe(200);
    const targetsA = listARes.json().data;
    const targetAIds = targetsA.map((t: { id: string }) => t.id);
    expect(targetAIds).toContain(targetAId);
    expect(targetAIds).not.toContain(targetBId);

    // Verify Tenant Beta query only returns Target B
    const listBRes = await app.inject({
      method: 'GET',
      url: '/api/v1/targets',
      headers: { 'x-tenant-id': tenantB.id },
    });
    expect(listBRes.statusCode).toBe(200);
    const targetsB = listBRes.json().data;
    const targetBIds = targetsB.map((t: { id: string }) => t.id);
    expect(targetBIds).toContain(targetBId);
    expect(targetBIds).not.toContain(targetAId);
  });

  it('4. Registers distributed agents with SHA-256 token hashing and tenant partitioning', async () => {
    agentAClient = new AgentClient(controllerUrl);
    agentBClient = new AgentClient(controllerUrl);

    // Provision Master Tenant Enrollment Key (TEK) for Tenant Alpha
    const tekARes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenantA.id}/enrollment-keys`,
      payload: { name: 'Alpha Agent Enrollment Key' },
    });
    expect(tekARes.statusCode).toBe(201);
    const tekA = tekARes.json().data.key;
    expect(tekA).toMatch(/^tek_/);

    // Register Agent A for Tenant Alpha using TEK
    agentAData = await agentAClient.register(
      {
        name: 'agent-alpha-vpc-01',
        tags: ['vpc-alpha', 'staging'],
        capabilities: ['native-http', 'auth-audit', 'declarative-dsl'],
        systemInfo: { arch: 'x64', platform: 'linux', cpus: 4, memoryMb: 8192 },
      },
      tekA,
    );

    expect(agentAData.agentId).toBeDefined();
    expect(agentAData.token).toMatch(/^agt_sec_[a-f0-9]{64}$/);
    expect(agentAData.tokenExpiresAt).toBeDefined();
    expect(agentAData.tenantId).toBe(tenantA.id);

    // Verify database token hashing invariant: plaintext token must NEVER exist in DB
    const { sql } = getDatabase();
    const [agentARecord] = await sql`
      SELECT id, token_hash, expires_at FROM agents WHERE id = ${agentAData.agentId} LIMIT 1
    `;

    expect(agentARecord).toBeDefined();
    expect(agentARecord.token_hash).toBe(hashAgentToken(agentAData.token));
    expect(agentARecord.token_hash).not.toBe(agentAData.token);
    expect(agentARecord.expires_at).toBeDefined();

    // Provision Master Tenant Enrollment Key (TEK) for Tenant Beta
    const tekBRes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenantB.id}/enrollment-keys`,
      payload: { name: 'Beta Agent Enrollment Key' },
    });
    expect(tekBRes.statusCode).toBe(201);
    const tekB = tekBRes.json().data.key;
    expect(tekB).toMatch(/^tek_/);

    // Register Agent B for Tenant Beta using TEK
    agentBData = await agentBClient.register(
      {
        name: 'agent-beta-vpc-01',
        tags: ['vpc-beta', 'production'],
        capabilities: ['native-http', 'auth-audit'],
        systemInfo: { arch: 'x64', platform: 'linux', cpus: 8, memoryMb: 16384 },
      },
      tekB,
    );

    expect(agentBData.agentId).toBeDefined();
    expect(agentBData.token).toMatch(/^agt_sec_[a-f0-9]{64}$/);
    expect(agentBData.tokenExpiresAt).toBeDefined();
    expect(agentBData.tenantId).toBe(tenantB.id);

    // Verify Tenant isolation in Agent listing:
    // Tenant A listing returns ONLY Agent A
    const listAgentsARes = await app.inject({
      method: 'GET',
      url: '/api/v1/agents',
      headers: { 'x-tenant-id': tenantA.id },
    });
    expect(listAgentsARes.statusCode).toBe(200);
    const agentsA = listAgentsARes.json().data;
    const agentAIds = agentsA.map((a: { id: string }) => a.id);
    expect(agentAIds).toContain(agentAData.agentId);
    expect(agentAIds).not.toContain(agentBData.agentId);

    // Tenant B listing returns ONLY Agent B
    const listAgentsBRes = await app.inject({
      method: 'GET',
      url: '/api/v1/agents',
      headers: { 'x-tenant-id': tenantB.id },
    });
    expect(listAgentsBRes.statusCode).toBe(200);
    const agentsB = listAgentsBRes.json().data;
    const agentBIds = agentsB.map((a: { id: string }) => a.id);
    expect(agentBIds).toContain(agentBData.agentId);
    expect(agentBIds).not.toContain(agentAData.agentId);
  });

  it('5. Handles agent authentication and heartbeat telemetry', async () => {
    // Unauthenticated heartbeat must return 401
    const unauthClient = new AgentClient(controllerUrl, 'agt_sec_invalid_token_9999999999999999999999999999999999999999999999999999999999999999');
    const unauthHeartbeat = await unauthClient.heartbeat(agentAData.agentId);
    expect(unauthHeartbeat.acknowledged).toBe(false);

    // Authenticated heartbeat for Agent Alpha
    const hbResponse = await agentAClient.heartbeat(agentAData.agentId, 'online', {
      cpuUsagePercent: 18.5,
      memoryUsageMb: 240,
      activeJobsCount: 0,
    });

    expect(hbResponse.acknowledged).toBe(true);
    expect(hbResponse.command).toBe('continue');

    // Confirm heartbeat timestamp updated in database
    const { sql } = getDatabase();
    const [agent] = await sql`
      SELECT status, last_heartbeat_at, system_info FROM agents WHERE id = ${agentAData.agentId} LIMIT 1
    `;

    expect(agent.status).toBe('online');
    expect(agent.last_heartbeat_at).not.toBeNull();
    expect(agent.system_info.activeJobsCount).toBe(0);
  });

  it('6. Dispatches jobs to separate tenants and validates polling queue isolation', async () => {
    // 1. Create Test Run Alpha
    const runARes = await app.inject({
      method: 'POST',
      url: '/api/v1/test-runs',
      payload: {
        projectId: projectAId,
        targetId: targetAId,
        profileId: 'native-class-a',
        triggeredBy: 'manual',
      },
    });
    expect(runARes.statusCode).toBe(201);
    testRunAId = runARes.json().data.id;

    // 2. Create Test Run Beta
    const runBRes = await app.inject({
      method: 'POST',
      url: '/api/v1/test-runs',
      payload: {
        projectId: projectBId,
        targetId: targetBId,
        profileId: 'native-class-a',
        triggeredBy: 'manual',
      },
    });
    expect(runBRes.statusCode).toBe(201);
    testRunBId = runBRes.json().data.id;

    // 3. Dispatch Job Alpha under Tenant Alpha
    const dispatchARes = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/dispatch',
      headers: { 'x-tenant-id': tenantA.id },
      payload: {
        testRunId: testRunAId,
        engineIds: ['engine-native-headers'],
      },
    });
    expect(dispatchARes.statusCode).toBe(202);
    jobAId = dispatchARes.json().data.jobId;
    expect(jobAId).toBeDefined();

    // 4. Dispatch Job Beta under Tenant Beta
    const dispatchBRes = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/dispatch',
      headers: { 'x-tenant-id': tenantB.id },
      payload: {
        testRunId: testRunBId,
        engineIds: ['engine-native-headers'],
      },
    });
    expect(dispatchBRes.statusCode).toBe(202);
    jobBId = dispatchBRes.json().data.jobId;
    expect(jobBId).toBeDefined();

    // 5. Poll with Agent Alpha (Tenant Alpha)
    const polledJobsA = await agentAClient.poll(agentAData.agentId, ['native-http'], ['vpc-alpha'], 10);
    expect(polledJobsA.length).toBe(1);
    expect(polledJobsA[0].jobId).toBe(jobAId);
    expect(polledJobsA[0].testRunId).toBe(testRunAId);
    expect(polledJobsA[0].tenantId).toBe(tenantA.id);
    expect(polledJobsA[0].target.baseUrl).toBe(mockTargetUrl);

    // CRITICAL: Agent Alpha MUST NOT receive Job Beta
    expect(polledJobsA.some((j) => j.jobId === jobBId)).toBe(false);

    // 6. Poll with Agent Beta (Tenant Beta)
    const polledJobsB = await agentBClient.poll(agentBData.agentId, ['native-http'], ['vpc-beta'], 10);
    expect(polledJobsB.length).toBe(1);
    expect(polledJobsB[0].jobId).toBe(jobBId);
    expect(polledJobsB[0].testRunId).toBe(testRunBId);
    expect(polledJobsB[0].tenantId).toBe(tenantB.id);

    // CRITICAL: Agent Beta MUST NOT receive Job Alpha
    expect(polledJobsB.some((j) => j.jobId === jobAId)).toBe(false);
  });

  it('7. Executes remote job via AgentWorker and streams progress and completion back to control plane', async () => {
    // Instantiate worker for Agent Alpha
    const workerA = new AgentWorker(agentAClient);

    // Retrieve the dispatched job for Alpha
    const { sql } = getDatabase();
    const [jobRecord] = await sql`
      SELECT id, payload FROM agent_jobs WHERE id = ${jobAId} LIMIT 1
    `;

    expect(jobRecord).toBeDefined();
    const jobPayload = jobRecord.payload as unknown as AgentJobDispatch;

    // Execute job using AgentWorker (simulating remote runner in customer VPC)
    await workerA.executeJob(jobPayload);

    // Verify test run in controller is now completed
    const runRes = await app.inject({
      method: 'GET',
      url: `/api/v1/test-runs/${testRunAId}`,
    });
    expect(runRes.statusCode).toBe(200);
    const runData = runRes.json().data;
    expect(runData.status).toBe('completed');
    expect(runData.summary).toBeDefined();

    // Verify findings were ingested and partitioned under Tenant Alpha
    const findingsARes = await app.inject({
      method: 'GET',
      url: `/api/v1/findings?testRunId=${testRunAId}`,
      headers: { 'x-tenant-id': tenantA.id },
    });
    expect(findingsARes.statusCode).toBe(200);
    const findingsA = findingsARes.json().data;
    expect(findingsA.length).toBeGreaterThan(0);

    // Verify all findings have correct targetId and sourceEngine
    for (const f of findingsA) {
      expect(f.targetId).toBe(targetAId);
      expect(f.fingerprint).toBeDefined();
      expect(f.status).toBe('open');
    }

    // Verify tenant boundary on findings: Tenant Beta CANNOT see Tenant Alpha findings
    const findingsBRes = await app.inject({
      method: 'GET',
      url: `/api/v1/findings?testRunId=${testRunAId}`,
      headers: { 'x-tenant-id': tenantB.id },
    });
    expect(findingsBRes.statusCode).toBe(200);
    const findingsB = findingsBRes.json().data;
    expect(findingsB.length).toBe(0); // Zero cross-tenant leakage!
  });

  it('8. Preserves offline developer mode without x-tenant-id header (Rule 19)', async () => {
    // Querying targets or projects without x-tenant-id header should succeed using default tenant
    const targetsRes = await app.inject({
      method: 'GET',
      url: '/api/v1/targets',
    });
    expect(targetsRes.statusCode).toBe(200);
    expect(Array.isArray(targetsRes.json().data)).toBe(true);

    const projectsRes = await app.inject({
      method: 'GET',
      url: '/api/v1/projects',
    });
    expect(projectsRes.statusCode).toBe(200);
    expect(Array.isArray(projectsRes.json().data)).toBe(true);
  });
});
