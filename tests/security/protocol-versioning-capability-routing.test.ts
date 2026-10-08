import http from 'node:http';
import net from 'node:net';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import {
  CURRENT_PROTOCOL_VERSION,
  MIN_SUPPORTED_PROTOCOL_VERSION,
  CONTROLLER_VERSION,
  HEADER_PROTOCOL_VERSION,
  HEADER_CONTROLLER_VERSION,
  HEADER_AGENT_VERSION,
} from '@security-lab/contracts';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth, getDatabase } from '../../apps/controller/src/services/db.js';
import { AgentClient, IncompatibleProtocolError, AgentDaemon } from '../../apps/agent/src/index.js';

describe('Phase 16.8: Protocol Handshake, Semantic Versioning & Capability Negotiation', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;
  let controllerUrl: string;

  // Mock Target
  let mockTargetServer: http.Server;
  let mockTargetPort: number;
  let mockTargetUrl: string;

  // Tenant & TEK
  let tenantId: string;
  let tekKey: string;
  let projectId: string;
  let targetId: string;

  beforeAll(async () => {
    app = buildApp({ disableLogging: true });
    await app.listen({ port: 0, host: '127.0.0.1' });
    const controllerAddr = app.server.address() as net.AddressInfo;
    controllerUrl = `http://127.0.0.1:${controllerAddr.port}`;

    const health = await checkDatabaseHealth();
    isDbAvailable = health === 'up';

    mockTargetServer = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok' }));
    });

    await new Promise<void>((resolve) => {
      mockTargetServer.listen(0, '127.0.0.1', () => {
        const addr = mockTargetServer.address() as net.AddressInfo;
        mockTargetPort = addr.port;
        mockTargetUrl = `http://127.0.0.1:${mockTargetPort}`;
        resolve();
      });
    });

    // Create Tenant
    const suffix = `${Date.now()}-${Math.floor(Math.random() * 10000)}`;
    const tenantRes = await app.inject({
      method: 'POST',
      url: '/api/v1/tenants',
      payload: { name: `Protocol Corp ${suffix}`, slug: `proto-${suffix}`, plan: 'enterprise' },
    });
    if (tenantRes.statusCode !== 201) {
      console.error('tenantRes failed:', tenantRes.statusCode, tenantRes.json());
    }
    expect(tenantRes.statusCode).toBe(201);
    tenantId = tenantRes.json().data.id;

    // Create TEK
    const tekRes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenantId}/enrollment-keys`,
      payload: { name: 'Protocol TEK' },
    });
    if (tekRes.statusCode !== 201) {
      console.error('tekRes failed:', tekRes.statusCode, tekRes.json());
    }
    expect(tekRes.statusCode).toBe(201);
    tekKey = tekRes.json().data.key;

    // Create Project & Target
    const projRes = await app.inject({
      method: 'POST',
      url: '/api/v1/projects',
      headers: { 'x-tenant-id': tenantId },
      payload: { name: `Protocol Project ${suffix}`, description: 'Protocol Test' },
    });
    if (projRes.statusCode !== 201) {
      console.error('projRes failed:', projRes.statusCode, projRes.json());
    }
    expect(projRes.statusCode).toBe(201);
    projectId = projRes.json().data.id;

    const targetRes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectId}/targets`,
      headers: { 'x-tenant-id': tenantId },
      payload: {
        name: 'Protocol Target',
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

  it('1. Confirms database health and protocol constants', () => {
    expect(isDbAvailable).toBe(true);
    expect(CURRENT_PROTOCOL_VERSION).toBe('1.0.0');
    expect(MIN_SUPPORTED_PROTOCOL_VERSION).toBe('1.0.0');
    expect(CONTROLLER_VERSION).toBe('0.2.0');
  });

  it('2. Protocol Handshake: Agent sending valid 1.0.0 header receives 200/201 and controller version headers', async () => {
    const client = new AgentClient(controllerUrl);
    const reg = await client.register(
      {
        name: 'valid-proto-agent',
        capabilities: ['engine-native-headers'],
        tags: ['vpc-prod'],
      },
      tekKey,
    );

    expect(reg.agentId).toBeDefined();

    // Verify raw response headers on controller
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/heartbeat',
      headers: {
        authorization: `Bearer ${reg.token}`,
        [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        [HEADER_AGENT_VERSION]: '0.2.0',
      },
      payload: { agentId: reg.agentId, status: 'online' },
    });

    expect(res.statusCode).toBe(200);
    expect(res.headers[HEADER_PROTOCOL_VERSION]).toBe('1.0.0');
    expect(res.headers[HEADER_CONTROLLER_VERSION]).toBe('0.2.0');
  });

  it('3. Rejects agent request missing X-Protocol-Version with 426 Upgrade Required (PROTOCOL_INCOMPATIBLE)', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/register',
      headers: {
        authorization: `Bearer ${tekKey}`,
        // Omitting X-Protocol-Version completely
      },
      payload: {
        name: 'unversioned-agent',
        capabilities: [],
        tags: [],
      },
    });

    expect(res.statusCode).toBe(426);
    const body = res.json();
    expect(body.success).toBe(false);
    expect(body.code).toBe('PROTOCOL_INCOMPATIBLE');
    expect(body.error.code).toBe('PROTOCOL_INCOMPATIBLE');
    expect(body.minSupportedVersion).toBe(MIN_SUPPORTED_PROTOCOL_VERSION);
    expect(res.headers[HEADER_PROTOCOL_VERSION]).toBe('1.0.0');
    expect(res.headers[HEADER_CONTROLLER_VERSION]).toBe('0.2.0');
  });

  it('4. Rejects agent request with outdated version (0.8.0) with 426 Upgrade Required (PROTOCOL_INCOMPATIBLE)', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/register',
      headers: {
        authorization: `Bearer ${tekKey}`,
        [HEADER_PROTOCOL_VERSION]: '0.8.0',
      },
      payload: {
        name: 'legacy-agent',
        capabilities: [],
        tags: [],
      },
    });

    expect(res.statusCode).toBe(426);
    const body = res.json();
    expect(body.success).toBe(false);
    expect(body.code).toBe('PROTOCOL_INCOMPATIBLE');
    expect(body.error.code).toBe('PROTOCOL_INCOMPATIBLE');
    expect(body.error.message).toContain('outdated');
  });

  it('5. Rejects major version mismatch (2.0.0 vs 1.0.0) with 400 Bad Request (INCOMPATIBLE_MAJOR)', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/register',
      headers: {
        authorization: `Bearer ${tekKey}`,
        [HEADER_PROTOCOL_VERSION]: '2.0.0',
      },
      payload: {
        name: 'future-major-agent',
        capabilities: [],
        tags: [],
      },
    });

    expect(res.statusCode).toBe(400);
    const body = res.json();
    expect(body.success).toBe(false);
    expect(body.code).toBe('INCOMPATIBLE_MAJOR');
    expect(body.error.code).toBe('INCOMPATIBLE_MAJOR');
    expect(body.error.message).toContain('major version mismatch');
  });

  it('6. AgentClient throws IncompatibleProtocolError on 426 response', async () => {
    const client = new AgentClient(controllerUrl);
    // Explicitly configure client to simulate legacy agent protocol
    client.setProtocolVersion('0.7.0');

    await expect(
      client.register({ name: 'test-legacy-client', capabilities: [], tags: [] }, tekKey),
    ).rejects.toThrow(IncompatibleProtocolError);

    try {
      await client.register({ name: 'test-legacy-client', capabilities: [], tags: [] }, tekKey);
    } catch (err: unknown) {
      expect(err).toBeInstanceOf(IncompatibleProtocolError);
      const protoErr = err as IncompatibleProtocolError;
      expect(protoErr.statusCode).toBe(426);
      expect(protoErr.code).toBe('PROTOCOL_INCOMPATIBLE');
    }
  });

  it('7. AgentDaemon shuts down cleanly when receiving 426 IncompatibleProtocolError during startup', async () => {
    const daemon = new AgentDaemon({
      controllerUrl,
      enrollmentKey: tekKey,
      tenantId,
      name: 'daemon-protocol-test',
      heartbeatIntervalMs: 500,
      pollIntervalMs: 500,
    });

    // Set daemon client to outdated protocol version
    (daemon as unknown as { client: AgentClient }).client.setProtocolVersion('0.6.0');

    // Start daemon: should encounter 426 on registration, catch IncompatibleProtocolError, and stop cleanly without throwing
    await daemon.start();

    // Verify daemon did not register or stay running
    expect(daemon.getAgentId()).toBeUndefined();
    await daemon.stop();
  });

  it('8. Capability Routing: Agent lacking "engine-zap" is never leased a job requiring "engine-zap"', async () => {
    // 1. Register Agent A with native-headers only
    const clientA = new AgentClient(controllerUrl);
    const agentA = await clientA.register(
      {
        name: 'agent-native-only',
        capabilities: ['engine-native-headers'],
        tags: ['vpc-prod'],
      },
      tekKey,
    );

    // 2. Dispatch a job that strictly requires "engine-zap"
    const runRes = await app.inject({
      method: 'POST',
      url: '/api/v1/test-runs',
      headers: { 'x-tenant-id': tenantId },
      payload: {
        projectId,
        targetId,
        profileId: 'native-class-a',
        triggeredBy: 'manual',
      },
    });
    const runId = runRes.json().data.id;

    const dispatchRes = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/dispatch',
      headers: { 'x-tenant-id': tenantId },
      payload: {
        testRunId: runId,
        engineIds: ['engine-zap'],
        requiredCapabilities: ['engine-zap'],
        requiredTags: ['vpc-prod'],
      },
    });
    expect(dispatchRes.statusCode).toBe(202);
    const zapJobId = dispatchRes.json().data.jobId;

    // 3. Agent A polls for jobs
    const polledA = await clientA.poll(agentA.agentId, ['engine-native-headers'], ['vpc-prod'], 1);
    // Agent A must NOT receive this job because it lacks engine-zap!
    expect(polledA.length).toBe(0);

    // 4. Verify job is still queued in database
    const { sql } = getDatabase();
    const [jobInDb] = await sql`SELECT status, agent_id FROM agent_jobs WHERE id = ${zapJobId}`;
    expect(jobInDb.status).toBe('queued');
    expect(jobInDb.agent_id).toBeNull();
  });

  it('9. Capability Routing: Agent possessing "engine-zap" is leased the job', async () => {
    // 1. Register Agent B with both native-headers AND engine-zap
    const clientB = new AgentClient(controllerUrl);
    const agentB = await clientB.register(
      {
        name: 'agent-zap-capable',
        capabilities: ['engine-native-headers', 'engine-zap'],
        tags: ['vpc-prod'],
      },
      tekKey,
    );

    // 2. Agent B polls for jobs with its capabilities
    const polledB = await clientB.poll(
      agentB.agentId,
      ['engine-native-headers', 'engine-zap'],
      ['vpc-prod'],
      1,
    );

    // Agent B MUST receive the ZAP job!
    expect(polledB.length).toBe(1);
    expect(polledB[0].engineIds).toContain('engine-zap');
    expect(polledB[0].requiredCapabilities).toContain('engine-zap');
    expect(polledB[0].leaseId).toBeDefined();

    // 3. Verify job in DB is now leased to Agent B
    const { sql } = getDatabase();
    const [jobInDb] = await sql`SELECT status, agent_id, lease_id FROM agent_jobs WHERE id = ${polledB[0].jobId}`;
    expect(jobInDb.status).toBe('leased');
    expect(jobInDb.agent_id).toBe(agentB.agentId);
  });

  it('10. Tag Routing: Agent with vpc-dev does NOT receive job targeted to vpc-prod; Agent with vpc-prod DOES', async () => {
    // 1. Create a job targeted to tag "vpc-prod"
    const runRes = await app.inject({
      method: 'POST',
      url: '/api/v1/test-runs',
      headers: { 'x-tenant-id': tenantId },
      payload: {
        projectId,
        targetId,
        profileId: 'native-class-a',
        triggeredBy: 'manual',
      },
    });
    const runId = runRes.json().data.id;

    const dispatchRes = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/dispatch',
      headers: { 'x-tenant-id': tenantId },
      payload: {
        testRunId: runId,
        engineIds: ['engine-native-headers'],
        requiredCapabilities: ['engine-native-headers'],
        requiredTags: ['vpc-prod'],
      },
    });
    const tagJobId = dispatchRes.json().data.jobId;

    // 2. Register Agent in Dev VPC
    const clientDev = new AgentClient(controllerUrl);
    const agentDev = await clientDev.register(
      {
        name: 'agent-dev-vpc',
        capabilities: ['engine-native-headers'],
        tags: ['vpc-dev'],
      },
      tekKey,
    );

    // 3. Dev Agent polls: must NOT receive the vpc-prod job
    const devPolled = await clientDev.poll(agentDev.agentId, ['engine-native-headers'], ['vpc-dev'], 1);
    expect(devPolled.length).toBe(0);

    // 4. Register Agent in Prod VPC
    const clientProd = new AgentClient(controllerUrl);
    const agentProd = await clientProd.register(
      {
        name: 'agent-prod-vpc',
        capabilities: ['engine-native-headers'],
        tags: ['vpc-prod'],
      },
      tekKey,
    );

    // 5. Prod Agent polls: MUST receive the vpc-prod job
    const prodPolled = await clientProd.poll(agentProd.agentId, ['engine-native-headers'], ['vpc-prod'], 1);
    expect(prodPolled.length).toBe(1);
    expect(prodPolled[0].jobId).toBe(tagJobId);
    expect(prodPolled[0].requiredTags).toContain('vpc-prod');
  });

  it('11. Backward Compatibility: Unconstrained jobs (empty capabilities and tags) are claimable by any agent', async () => {
    // Dispatch unconstrained job
    const runRes = await app.inject({
      method: 'POST',
      url: '/api/v1/test-runs',
      headers: { 'x-tenant-id': tenantId },
      payload: {
        projectId,
        targetId,
        profileId: 'native-class-a',
        triggeredBy: 'manual',
      },
    });
    const runId = runRes.json().data.id;

    const dispatchRes = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/dispatch',
      headers: { 'x-tenant-id': tenantId },
      payload: {
        testRunId: runId,
        engineIds: ['engine-native-headers'],
        // No requiredCapabilities or requiredTags passed
      },
    });
    const unconstrainedJobId = dispatchRes.json().data.jobId;

    const client = new AgentClient(controllerUrl);
    const agent = await client.register(
      {
        name: 'agent-general-worker',
        capabilities: ['any-capability'],
        tags: ['any-tag'],
      },
      tekKey,
    );

    const polled = await client.poll(agent.agentId, ['any-capability'], ['any-tag'], 1);
    expect(polled.length).toBe(1);
    expect(polled[0].jobId).toBe(unconstrainedJobId);
  });
});
