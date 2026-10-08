import fs from 'node:fs';
import os from 'node:os';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'yaml';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import {
  CURRENT_PROTOCOL_VERSION,
  HEADER_PROTOCOL_VERSION,
} from '@security-lab/contracts';
import {
  computeFindingsHash,
  computeResultSignature,
  computeScopeSignature,
} from '@security-lab/evidence';
import {
  DockerRunner,
  ContainerSecurityError,
  validateVolumePath,
  isApprovedImage,
  engineRegistry,
  TestEngine,
  ExecutionContext,
  TestInput,
  TestOutput,
} from '@security-lab/test-sdk';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth, getDatabase } from '../../apps/controller/src/services/db.js';
import {
  agentDispatcherService,
  agentJobReaper,
} from '../../apps/controller/src/services/agent-dispatcher.service.js';
import {
  agentAuditService,
  scrubSecrets,
  REDACTED_PLACEHOLDER,
} from '../../apps/controller/src/services/agent-audit.service.js';
import {
  AgentClient,
  AgentWorker,
  ScopeTamperingError,
  SecurityBoundaryError,
  JobCancelledError,
} from '../../apps/agent/src/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

type PolledJob = Awaited<ReturnType<AgentClient['poll']>>[number];

describe('Phase 16.10: End-to-End Adversarial Security & Penetration Verification (T1–T18 Mitigations)', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;
  let controllerUrl: string;

  // Mock Target HTTP Server for realistic scan probing
  let mockTargetServer: http.Server;
  let mockTargetPort: number;
  let mockTargetUrl: string;

  // Tenants
  let tenantA: { id: string; name: string; slug: string };
  let tenantB: { id: string; name: string; slug: string };

  // TEKs
  let tekA: string;
  let tekB: string;

  // Projects & Targets
  let projectAId: string;
  let targetAId: string;
  let projectBId: string;
  let _targetBId: string;

  // Standard Agents
  let agentA1Data: { agentId: string; token: string; tenantId: string };
  let agentA1Client: AgentClient;
  let agentA2Data: { agentId: string; token: string; tenantId: string };
  let agentA2Client: AgentClient;
  let agentBData: { agentId: string; token: string; tenantId: string };
  let agentBClient: AgentClient;

  // Test Run & Job Helper
  async function createTestRun(tenantId: string, projectId: string, targetId: string): Promise<string> {
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
    expect(runRes.statusCode).toBe(201);
    return runRes.json().data.id;
  }

  async function dispatchJob(
    tenantId: string,
    testRunId: string,
    engineIds: string[] = ['engine-native-headers'],
    requiredCapabilities: string[] = [],
    requiredTags: string[] = [],
  ): Promise<string> {
    const dispatchRes = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/dispatch',
      headers: { 'x-tenant-id': tenantId },
      payload: {
        testRunId,
        engineIds,
        requiredCapabilities,
        requiredTags,
      },
    });
    expect(dispatchRes.statusCode).toBe(202);
    return dispatchRes.json().data.jobId;
  }

  beforeAll(async () => {
    // 1. Initialize Fastify Controller App
    app = buildApp({ disableLogging: true });
    await app.listen({ port: 0, host: '127.0.0.1' });
    const addr = app.server.address() as net.AddressInfo;
    controllerUrl = `http://127.0.0.1:${addr.port}`;

    // 2. Health check database
    const health = await checkDatabaseHealth();
    isDbAvailable = health === 'up';
    if (!isDbAvailable) {
      throw new Error('Database is not available for Phase 16.10 penetration testing');
    }

    // 3. Start Mock Target Server
    mockTargetServer = http.createServer((_req, res) => {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        Server: 'SecurityLab-Target/1.0',
      });
      res.end(JSON.stringify({ status: 'ok', service: 'penetration-testing-target' }));
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

    // 4. Provision Tenant Alpha & Tenant Beta
    const tenantARes = await app.inject({
      method: 'POST',
      url: '/api/v1/tenants',
      payload: { name: `PenTest Tenant Alpha ${suffix}`, slug: `pentest-alpha-${suffix}`, plan: 'enterprise' },
    });
    expect(tenantARes.statusCode).toBe(201);
    tenantA = tenantARes.json().data;

    const tenantBRes = await app.inject({
      method: 'POST',
      url: '/api/v1/tenants',
      payload: { name: `PenTest Tenant Beta ${suffix}`, slug: `pentest-beta-${suffix}`, plan: 'enterprise' },
    });
    expect(tenantBRes.statusCode).toBe(201);
    tenantB = tenantBRes.json().data;

    // 5. Provision TEK for Tenant Alpha and Tenant Beta
    const tekARes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenantA.id}/enrollment-keys`,
      payload: { name: 'Alpha PenTest TEK', maxUses: 20 },
    });
    expect(tekARes.statusCode).toBe(201);
    tekA = tekARes.json().data.key;

    const tekBRes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenantB.id}/enrollment-keys`,
      payload: { name: 'Beta PenTest TEK', maxUses: 20 },
    });
    expect(tekBRes.statusCode).toBe(201);
    tekB = tekBRes.json().data.key;

    // 6. Setup Projects & Targets for Tenant Alpha and Beta
    const projARes = await app.inject({
      method: 'POST',
      url: '/api/v1/projects',
      headers: { 'x-tenant-id': tenantA.id },
      payload: { name: `Alpha PenTest Project ${suffix}`, description: 'Tenant Alpha Scope' },
    });
    expect(projARes.statusCode).toBe(201);
    projectAId = projARes.json().data.id;

    const targetARes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectAId}/targets`,
      headers: { 'x-tenant-id': tenantA.id },
      payload: {
        name: 'Alpha Target Service',
        baseUrl: mockTargetUrl,
        environment: 'staging',
        criticality: 'high',
        allowedHosts: ['127.0.0.1', 'localhost'],
        allowedPorts: [mockTargetPort],
        excludedPaths: ['/internal/admin'],
        testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
        limits: { maxRps: 50, maxConcurrency: 5, maxDuration: '2m' },
      },
    });
    expect(targetARes.statusCode).toBe(201);
    targetAId = targetARes.json().data.id;

    const projBRes = await app.inject({
      method: 'POST',
      url: '/api/v1/projects',
      headers: { 'x-tenant-id': tenantB.id },
      payload: { name: `Beta PenTest Project ${suffix}`, description: 'Tenant Beta Scope' },
    });
    expect(projBRes.statusCode).toBe(201);
    projectBId = projBRes.json().data.id;

    const targetBRes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectBId}/targets`,
      headers: { 'x-tenant-id': tenantB.id },
      payload: {
        name: 'Beta Target Service',
        baseUrl: mockTargetUrl,
        environment: 'staging',
        criticality: 'medium',
        allowedHosts: ['127.0.0.1'],
        allowedPorts: [mockTargetPort],
        excludedPaths: [],
        testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
        limits: { maxRps: 20, maxConcurrency: 2, maxDuration: '2m' },
      },
    });
    expect(targetBRes.statusCode).toBe(201);
    _targetBId = targetBRes.json().data.id;

    // 7. Register Standard Agents
    agentA1Client = new AgentClient(controllerUrl);
    agentA1Data = await agentA1Client.register(
      { name: 'agent-alpha-primary', tags: ['vpc-alpha'], capabilities: ['engine-native-headers', 'engine-native-cors'] },
      tekA,
    );

    agentA2Client = new AgentClient(controllerUrl);
    agentA2Data = await agentA2Client.register(
      { name: 'agent-alpha-secondary', tags: ['vpc-alpha'], capabilities: ['engine-native-headers'] },
      tekA,
    );

    agentBClient = new AgentClient(controllerUrl);
    agentBData = await agentBClient.register(
      { name: 'agent-beta-primary', tags: ['vpc-beta'], capabilities: ['engine-native-headers'] },
      tekB,
    );
  });

  afterAll(async () => {
    agentJobReaper.stop();
    if (mockTargetServer) {
      await new Promise<void>((resolve) => mockTargetServer.close(() => resolve()));
    }
    await app.close();
    if (isDbAvailable) {
      await closeDatabase();
    }
  });

  // =========================================================================
  // Battery 1: T1 & T2 — Anonymous Enrollment & Tenant Header Spoofing Defense
  // =========================================================================
  describe('Battery 1: Threat T1 & T2 — Agent Authentication & Tenant Bound Identity', () => {
    it('T1: Blocks anonymous enrollment without credentials with HTTP 401 AGENT_UNAUTHORIZED', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/agents/register',
        headers: { [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION },
        payload: {
          name: 'anonymous-rogue-agent',
          tags: ['rogue'],
          capabilities: ['engine-native-headers'],
        },
      });

      expect(res.statusCode).toBe(401);
      const body = res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('AGENT_UNAUTHORIZED');
    });

    it('T1: Blocks enrollment with forged or non-existent TEK with HTTP 401 INVALID_ENROLLMENT_KEY', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/agents/register',
        headers: {
          authorization: 'Bearer tek_forged_deadbeef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
          [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        },
        payload: {
          name: 'forged-tek-agent',
          tags: ['rogue'],
          capabilities: ['engine-native-headers'],
        },
      });

      expect(res.statusCode).toBe(401);
      const body = res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('INVALID_ENROLLMENT_KEY');
    });

    it('T2: Tenant Header Spoofing — Registration strictly binds to TEK tenant, ignoring spoofed x-tenant-id', async () => {
      // Attacker uses Tenant A's TEK but tries to inject Tenant B's UUID in x-tenant-id header
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/agents/register',
        headers: {
          authorization: `Bearer ${tekA}`,
          'x-tenant-id': tenantB.id,
          [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        },
        payload: {
          name: 'spoofing-attempt-agent',
          tags: ['spoof-test'],
          capabilities: ['engine-native-headers'],
        },
      });

      expect(res.statusCode).toBe(201);
      const reg = res.json().data;
      // Must be bound strictly to Tenant A (owner of the TEK), never Tenant B
      expect(reg.tenantId).toBe(tenantA.id);
      expect(reg.tenantId).not.toBe(tenantB.id);

      // Verify database record independently
      const { sql } = getDatabase();
      const [dbAgent] = await sql`SELECT tenant_id FROM agents WHERE id = ${reg.agentId}`;
      expect(dbAgent.tenant_id).toBe(tenantA.id);
    });

    it('T1: Revoked agent token cannot poll or heartbeat and is rejected with HTTP 401/403', async () => {
      // Register a temporary agent to revoke
      const tempClient = new AgentClient(controllerUrl);
      const tempAgent = await tempClient.register(
        { name: 'temp-agent-to-revoke', tags: [], capabilities: ['engine-native-headers'] },
        tekA,
      );

      // Revoke agent through administrative route
      const revokeRes = await app.inject({
        method: 'POST',
        url: `/api/v1/agents/${tempAgent.agentId}/revoke`,
        headers: { 'x-tenant-id': tenantA.id },
      });
      expect(revokeRes.statusCode).toBe(200);

      // Subsequent heartbeat fails
      const hbRes = await app.inject({
        method: 'POST',
        url: '/api/v1/agents/heartbeat',
        headers: {
          authorization: `Bearer ${tempAgent.token}`,
          [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        },
        payload: { agentId: tempAgent.agentId, status: 'online' },
      });
      expect([401, 403]).toContain(hbRes.statusCode);

      // Subsequent polling fails
      const pollRes = await app.inject({
        method: 'POST',
        url: '/api/v1/agents/poll',
        headers: {
          authorization: `Bearer ${tempAgent.token}`,
          [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        },
        payload: { agentId: tempAgent.agentId, maxJobs: 1 },
      });
      expect([401, 403]).toContain(pollRes.statusCode);
    });
  });

  // =========================================================================
  // Battery 2: T3 — Cross-Tenant Job Theft & Boundary Enforcement
  // =========================================================================
  describe('Battery 2: Threat T3 — Cross-Tenant Job Claim and Completion Defense', () => {
    let jobAId: string;
    let testRunAId: string;

    beforeAll(async () => {
      testRunAId = await createTestRun(tenantA.id, projectAId, targetAId);
      jobAId = await dispatchJob(tenantA.id, testRunAId, ['engine-native-headers']);
    });

    it('T3: Tenant Beta agent polling receives 0 jobs from Tenant Alpha queue', async () => {
      const polled = await agentBClient.poll(agentBData.agentId, ['engine-native-headers'], ['vpc-beta'], 1);
      expect(polled.find((j) => j.jobId === jobAId)).toBeUndefined();
    });

    it('T3: Tenant Alpha Agent A1 claims Job A successfully', async () => {
      const polled = await agentA1Client.poll(agentA1Data.agentId, ['engine-native-headers'], ['vpc-alpha'], 1);
      expect(polled.length).toBe(1);
      expect(polled[0].jobId).toBe(jobAId);
      expect(polled[0].jobDispatchSecret).toBeDefined();
    });

    it('T3: Blocks cross-tenant job progress update with HTTP 403 TENANT_MISMATCH', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/agents/jobs/${jobAId}/progress`,
        headers: {
          authorization: `Bearer ${agentBData.token}`,
          [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        },
        payload: {
          jobId: jobAId,
          testRunId: testRunAId,
          percent: 50,
          message: 'Adversary cross-tenant progress spoof',
        },
      });

      expect(res.statusCode).toBe(403);
      const body = res.json();
      expect(body.error.code).toBe('TENANT_MISMATCH');
    });

    it('T3: Blocks cross-tenant job completion with HTTP 403 TENANT_MISMATCH', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/agents/jobs/${jobAId}/complete`,
        headers: {
          authorization: `Bearer ${agentBData.token}`,
          [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        },
        payload: {
          jobId: jobAId,
          testRunId: testRunAId,
          status: 'completed',
          findings: [
            {
              sourceEngine: 'engine-native-headers',
              title: 'Injected Cross-Tenant Vulnerability',
              description: 'Malicious finding from Tenant Beta',
              rawSeverity: 'critical',
            },
          ],
          executions: [],
          metrics: [],
        },
      });

      expect(res.statusCode).toBe(403);
      expect(res.json().error.code).toBe('TENANT_MISMATCH');

      // Verify no findings were inserted
      const { sql } = getDatabase();
      const findings = await sql`SELECT id FROM findings WHERE test_run_id = ${testRunAId}`;
      expect(findings.length).toBe(0);
    });

    it('T3: Blocks cross-agent completion within the same tenant with HTTP 403 AGENT_MISMATCH', async () => {
      // Agent A2 belongs to Tenant Alpha, but Job A is leased to Agent A1
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/agents/jobs/${jobAId}/complete`,
        headers: {
          authorization: `Bearer ${agentA2Data.token}`,
          [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        },
        payload: {
          jobId: jobAId,
          testRunId: testRunAId,
          status: 'completed',
          findings: [],
          executions: [],
          metrics: [],
        },
      });

      expect(res.statusCode).toBe(403);
      expect(res.json().error.code).toBe('AGENT_MISMATCH');
    });
  });

  // =========================================================================
  // Battery 3: T4 — Replay Attacks & Idempotent Result Ingestion
  // =========================================================================
  describe('Battery 3: Threat T4 — Replay Attacks & Idempotent Result Deduplication', () => {
    let replayJobId: string;
    let replayTestRunId: string;
    let leasedJob: PolledJob;

    beforeAll(async () => {
      replayTestRunId = await createTestRun(tenantA.id, projectAId, targetAId);
      replayJobId = await dispatchJob(tenantA.id, replayTestRunId, ['engine-native-headers']);
      const polled = await agentA1Client.poll(agentA1Data.agentId, ['engine-native-headers'], ['vpc-alpha'], 1);
      leasedJob = polled.find((j) => j.jobId === replayJobId);
      expect(leasedJob).toBeDefined();
    });

    it('T4: Processes first legitimate completion successfully and signs results', async () => {
      const findings = [
        {
          sourceEngine: 'engine-native-headers',
          title: 'Missing Content-Security-Policy',
          description: 'The endpoint does not emit a Content-Security-Policy header.',
          rawSeverity: 'medium',
          location: '/api/v1/resource',
        },
      ];
      const executions = [
        {
          engineId: 'engine-native-headers',
          status: 'completed',
          durationMs: 45,
        },
      ];

      const findingsHash = computeFindingsHash(findings, executions);
      const signature = computeResultSignature(leasedJob.jobDispatchSecret, leasedJob.jobId, findingsHash);

      const completeRes = await app.inject({
        method: 'POST',
        url: `/api/v1/agents/jobs/${leasedJob.jobId}/complete`,
        headers: {
          authorization: `Bearer ${agentA1Data.token}`,
          [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        },
        payload: {
          jobId: leasedJob.jobId,
          testRunId: replayTestRunId,
          leaseId: leasedJob.leaseId,
          status: 'completed',
          findings,
          executions,
          metrics: [],
          resultSignature: signature,
        },
      });

      expect(completeRes.statusCode).toBe(200);
      const body = completeRes.json();
      expect(body.success).toBe(true);

      // Verify status in DB
      const { sql } = getDatabase();
      const [dbJob] = await sql`SELECT status FROM agent_jobs WHERE id = ${leasedJob.jobId}`;
      expect(dbJob.status).toBe('completed');

      // Verify findings persisted
      const dbFindings = await sql`SELECT id FROM findings WHERE test_run_id = ${replayTestRunId}`;
      expect(dbFindings.length).toBe(1);
    });

    it('T4: Replaying identical completion payload is safely deduplicated without creating duplicate records', async () => {
      const findings = [
        {
          sourceEngine: 'engine-native-headers',
          title: 'Missing Content-Security-Policy',
          description: 'The endpoint does not emit a Content-Security-Policy header.',
          rawSeverity: 'medium',
          location: '/api/v1/resource',
        },
      ];
      const executions = [
        {
          engineId: 'engine-native-headers',
          status: 'completed',
          durationMs: 45,
        },
      ];

      const findingsHash = computeFindingsHash(findings, executions);
      const signature = computeResultSignature(leasedJob.jobDispatchSecret, leasedJob.jobId, findingsHash);

      // Replay attack: send identical request a second time
      const replayRes = await app.inject({
        method: 'POST',
        url: `/api/v1/agents/jobs/${leasedJob.jobId}/complete`,
        headers: {
          authorization: `Bearer ${agentA1Data.token}`,
          [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        },
        payload: {
          jobId: leasedJob.jobId,
          testRunId: replayTestRunId,
          leaseId: leasedJob.leaseId,
          status: 'completed',
          findings,
          executions,
          metrics: [],
          resultSignature: signature,
        },
      });

      expect(replayRes.statusCode).toBe(200);
      const body = replayRes.json();
      expect(body.success).toBe(true);
      expect(body.deduplicated).toBe(true);

      // Verify that database STILL has exactly 1 finding (zero duplicate rows)
      const { sql } = getDatabase();
      const dbFindings = await sql`SELECT id FROM findings WHERE test_run_id = ${replayTestRunId}`;
      expect(dbFindings.length).toBe(1);
    });
  });

  // =========================================================================
  // Battery 4: T5 — Result Forgery & 1-Byte Finding Modification Defense
  // =========================================================================
  describe('Battery 4: Threat T5 — Result Integrity & Cryptographic Signature Verification', () => {
    let forgeJobId: string;
    let forgeTestRunId: string;
    let leasedForgeJob: PolledJob;

    beforeAll(async () => {
      forgeTestRunId = await createTestRun(tenantA.id, projectAId, targetAId);
      forgeJobId = await dispatchJob(tenantA.id, forgeTestRunId, ['engine-native-headers']);
      const polled = await agentA1Client.poll(agentA1Data.agentId, ['engine-native-headers'], ['vpc-alpha'], 1);
      leasedForgeJob = polled.find((j) => j.jobId === forgeJobId);
      expect(leasedForgeJob).toBeDefined();
    });

    it('T5: Modifying 1 byte of finding description causes signature mismatch and HTTP 403 SIGNATURE_INVALID', async () => {
      const authenticFindings = [
        {
          sourceEngine: 'engine-native-headers',
          title: 'Strict-Transport-Security Missing',
          description: 'HSTS header missing on target endpoint.',
          rawSeverity: 'high',
          location: '/api/v1/secure',
        },
      ];
      const executions = [
        {
          engineId: 'engine-native-headers',
          status: 'completed',
          durationMs: 30,
        },
      ];

      // Legitimate signature computed on authentic findings
      const findingsHash = computeFindingsHash(authenticFindings, executions);
      const authenticSignature = computeResultSignature(
        leasedForgeJob.jobDispatchSecret,
        leasedForgeJob.jobId,
        findingsHash,
      );

      // Adversary modifies 1 byte in description: 'HSTS' -> 'XSTS'
      const tamperedFindings = [
        {
          sourceEngine: 'engine-native-headers',
          title: 'Strict-Transport-Security Missing',
          description: 'XSTS header missing on target endpoint.', // 1 byte altered
          rawSeverity: 'high',
          location: '/api/v1/secure',
        },
      ];

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/agents/jobs/${leasedForgeJob.jobId}/complete`,
        headers: {
          authorization: `Bearer ${agentA1Data.token}`,
          [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        },
        payload: {
          jobId: leasedForgeJob.jobId,
          testRunId: forgeTestRunId,
          leaseId: leasedForgeJob.leaseId,
          status: 'completed',
          findings: tamperedFindings,
          executions,
          metrics: [],
          resultSignature: authenticSignature,
        },
      });

      expect(res.statusCode).toBe(403);
      const body = res.json();
      expect(body.error.code).toBe('SIGNATURE_INVALID');

      // Verify zero findings persisted in DB
      const { sql } = getDatabase();
      const dbFindings = await sql`SELECT id FROM findings WHERE test_run_id = ${forgeTestRunId}`;
      expect(dbFindings.length).toBe(0);
    });

    it('T5: Forged or invalid signature on completed results is rejected with HTTP 403 SIGNATURE_INVALID', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/agents/jobs/${leasedForgeJob.jobId}/complete`,
        headers: {
          authorization: `Bearer ${agentA1Data.token}`,
          [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        },
        payload: {
          jobId: leasedForgeJob.jobId,
          testRunId: forgeTestRunId,
          leaseId: leasedForgeJob.leaseId,
          status: 'completed',
          findings: [
            {
              sourceEngine: 'engine-native-headers',
              title: 'Forged Finding',
              description: 'Attacker provides an invalid forged signature',
              rawSeverity: 'low',
            },
          ],
          executions: [],
          metrics: [],
          resultSignature: 'badc0ffee0000000000000000000000000000000000000000000000000000000',
        },
      });

      expect(res.statusCode).toBe(403);
      expect(res.json().error.code).toBe('SIGNATURE_INVALID');
    });
  });

  // =========================================================================
  // Battery 5: T6, T7 & T13 — Target Scope, Base URL Tampering & Metadata SSRF Defense
  // =========================================================================
  describe('Battery 5: Threats T6, T7 & T13 — Scope Cryptographic Attestation & Distributed SSRF Defense', () => {
    let scopeJob: PolledJob;

    beforeAll(async () => {
      const testRunId = await createTestRun(tenantA.id, projectAId, targetAId);
      const jobId = await dispatchJob(tenantA.id, testRunId, ['engine-native-headers']);
      const polled = await agentA1Client.poll(agentA1Data.agentId, ['engine-native-headers'], ['vpc-alpha'], 1);
      scopeJob = polled.find((j) => j.jobId === jobId);
      expect(scopeJob).toBeDefined();
      expect(scopeJob.target.scopeSignature).toBeDefined();
    });

    it('T6: Tampering with allowedHosts in target scope triggers ScopeTamperingError locally before socket open', async () => {
      // Adversary attempts scope expansion by injecting unauthorized subnet into allowedHosts
      const tamperedJob = {
        ...scopeJob,
        target: {
          ...scopeJob.target,
          scope: {
            ...scopeJob.target.scope,
            allowedHosts: ['127.0.0.1', '10.0.0.0/8', 'attacker-external.net'],
          },
        },
      };

      const worker = new AgentWorker(agentA1Client, { allowLocalTesting: true });
      await expect(worker.executeJob(tamperedJob)).rejects.toThrow(ScopeTamperingError);
    });

    it('T7: Tampering with target baseUrl triggers ScopeTamperingError locally', async () => {
      // Adversary changes baseUrl to private internal service while preserving scopeSignature
      const tamperedJob = {
        ...scopeJob,
        target: {
          ...scopeJob.target,
          baseUrl: 'http://consul-internal.corp:8500',
        },
      };

      const worker = new AgentWorker(agentA1Client, { allowLocalTesting: true });
      await expect(worker.executeJob(tamperedJob)).rejects.toThrow(ScopeTamperingError);
    });

    it('T13: In-agent defense-in-depth blocks cloud metadata IP (169.254.169.254) with SecurityBoundaryError even if signed by controller', async () => {
      const metadataBaseUrl = 'http://169.254.169.254/latest/meta-data/';
      const metadataScope = {
        allowedHosts: ['169.254.169.254'],
        allowedPorts: [80],
        excludedPaths: [],
        testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
        limits: { maxRps: 10, maxConcurrency: 1, maxDuration: '1m' },
      };

      const scopeSignature = computeScopeSignature(scopeJob.target.id, metadataBaseUrl, metadataScope);

      const maliciousJob = {
        ...scopeJob,
        target: {
          ...scopeJob.target,
          baseUrl: metadataBaseUrl,
          scope: metadataScope,
          scopeSignature,
        },
      };

      const worker = new AgentWorker(agentA1Client, { allowLocalTesting: true });
      await expect(worker.executeJob(maliciousJob)).rejects.toThrow(SecurityBoundaryError);
    });

    it('T6: Legitimate job with untampered scope executes cleanly without scope error', async () => {
      const worker = new AgentWorker(agentA1Client, { allowLocalTesting: true });
      await expect(worker.executeJob(scopeJob)).resolves.not.toThrow();
    });
  });

  // =========================================================================
  // Battery 6: T8 — Capability & Tag Containment
  // =========================================================================
  describe('Battery 6: Threat T8 — Capability & Tag Containment in Job Dispatch', () => {
    let zapJobId: string;
    let zapTestRunId: string;

    beforeAll(async () => {
      zapTestRunId = await createTestRun(tenantA.id, projectAId, targetAId);
      // Dispatch job strictly requiring 'engine-zap' and tag 'zone-isolated'
      zapJobId = await dispatchJob(
        tenantA.id,
        zapTestRunId,
        ['engine-zap'],
        ['engine-zap'],
        ['zone-isolated'],
      );
    });

    it('T8: Incapable agent lacking engine-zap capability NEVER receives specialized container job', async () => {
      // Agent A1 only has ['engine-native-headers', 'engine-native-cors'] and tag ['vpc-alpha']
      const polled = await agentA1Client.poll(agentA1Data.agentId, ['engine-native-headers'], ['vpc-alpha'], 1);
      expect(polled.find((j) => j.jobId === zapJobId)).toBeUndefined();
    });

    it('T8: Agent possessing required engine-zap capability and zone-isolated tag successfully leases job', async () => {
      // Register dedicated specialized container agent
      const zapAgentClient = new AgentClient(controllerUrl);
      const zapAgent = await zapAgentClient.register(
        {
          name: 'specialized-zap-worker',
          capabilities: ['engine-zap', 'engine-native-headers'],
          tags: ['zone-isolated', 'vpc-alpha'],
        },
        tekA,
      );

      const polled = await zapAgentClient.poll(zapAgent.agentId, ['engine-zap'], ['zone-isolated'], 1);
      expect(polled.length).toBe(1);
      expect(polled[0].jobId).toBe(zapJobId);
      expect(polled[0].requiredCapabilities).toContain('engine-zap');
      expect(polled[0].requiredTags).toContain('zone-isolated');
    });
  });

  // =========================================================================
  // Battery 7: T9 — Secret Masking & Audit Trail Hygiene
  // =========================================================================
  describe('Battery 7: Threat T9 — Zero Credential Leakage in Audit Logs & Telemetry', () => {
    it('T9: scrubSecrets recursively sanitizes sensitive keys and token formats to ***REDACTED***', () => {
      const sensitivePayload = {
        agentName: 'production-runner-01',
        authorization: 'Bearer agt_sec_0123456789abcdef0123456789abcdef',
        tekKey: 'tek_alpha_secret_token_1234567890',
        token: 'raw_secret_token_value',
        credentials: {
          apiKey: 'sec_key_xyz987654321',
          dbPassword: 'super_secret_master_password',
        },
        headers: {
          'x-api-key': 'live_key_999999',
          authHeader: 'Bearer my_secret_token',
        },
        safeField: 'normal-metric-value',
      };

      const sanitized = scrubSecrets(sensitivePayload) as Record<string, unknown>;
      const credentials = sanitized.credentials as Record<string, unknown>;
      const headers = sanitized.headers as Record<string, unknown>;

      expect(sanitized.agentName).toBe('production-runner-01');
      expect(sanitized.safeField).toBe('normal-metric-value');

      expect(sanitized.authorization).toBe(REDACTED_PLACEHOLDER);
      expect(sanitized.tekKey).toBe(REDACTED_PLACEHOLDER);
      expect(sanitized.token).toBe(REDACTED_PLACEHOLDER);
      expect(credentials.apiKey).toBe(REDACTED_PLACEHOLDER);
      expect(credentials.dbPassword).toBe(REDACTED_PLACEHOLDER);
      expect(headers['x-api-key']).toBe(REDACTED_PLACEHOLDER);
      expect(headers.authHeader).toBe(REDACTED_PLACEHOLDER);
    });

    it('T9: Database audit log queries reveal ZERO plaintext tokens or secrets across recorded events', async () => {
      const audit = await agentAuditService.getAuditEvents({
        tenantId: tenantA.id,
        limit: 50,
      });

      expect(audit.total).toBeGreaterThan(0);
      for (const event of audit.events) {
        const metadataStr = JSON.stringify(event.metadata);
        expect(metadataStr).not.toContain(tekA);
        expect(metadataStr).not.toContain(agentA1Data.token);
        expect(metadataStr).not.toContain('agt_sec_');
      }
    });
  });

  // =========================================================================
  // Battery 8: T10 & T11 — Kubernetes & Docker Runner Hardening
  // =========================================================================
  describe('Battery 8: Threats T10 & T11 — Kubernetes Manifest and Docker Runner Hardening', () => {
    it('T10: Kubernetes agent manifest (infrastructure/k8s/agent.yaml) strictly enforces rootless, read-only rootfs, and no docker.sock mount', () => {
      const manifestPath = path.resolve(__dirname, '../../infrastructure/k8s/agent.yaml');
      expect(fs.existsSync(manifestPath)).toBe(true);

      const rawYaml = fs.readFileSync(manifestPath, 'utf8');
      const docs = yaml.parseAllDocuments(rawYaml).map((d) => d.toJSON());

      const deployment = docs.find((d) => d?.kind === 'Deployment' && d?.metadata?.name === 'security-lab-agent');
      expect(deployment).toBeDefined();

      const spec = deployment.spec.template.spec;

      // 1. Pod security context
      expect(spec.securityContext.runAsNonRoot).toBe(true);
      expect(spec.securityContext.runAsUser).toBe(10001);

      // 2. Container security context
      const agentContainer = spec.containers.find((c: { name: string }) => c.name === 'agent');
      expect(agentContainer).toBeDefined();
      expect(agentContainer.securityContext.privileged).toBe(false);
      expect(agentContainer.securityContext.readOnlyRootFilesystem).toBe(true);
      expect(agentContainer.securityContext.allowPrivilegeEscalation).toBe(false);
      expect(agentContainer.securityContext.capabilities.drop).toContain('ALL');

      // 3. Prohibit Docker daemon socket mounts
      const mounts = agentContainer.volumeMounts || [];
      const hasDockerSockMount = mounts.some((m: { mountPath: string }) => m.mountPath.includes('docker.sock'));
      expect(hasDockerSockMount).toBe(false);

      const volumes = spec.volumes || [];
      const hasHostDockerSock = volumes.some((v: { hostPath?: { path?: string } }) => v.hostPath?.path?.includes('docker.sock'));
      expect(hasHostDockerSock).toBe(false);
    });

    it('T11: Docker policy allows approved scanner images and rejects arbitrary/unapproved images', () => {
      expect(isApprovedImage('zaproxy/zaproxy:latest')).toBe(true);
      expect(isApprovedImage('ghcr.io/zaproxy/zaproxy:stable')).toBe(true);
      expect(isApprovedImage('aquasec/trivy:latest')).toBe(true);
      expect(isApprovedImage('grafana/k6:latest')).toBe(true);

      // Arbitrary/malicious images rejected
      expect(isApprovedImage('ubuntu:latest')).toBe(false);
      expect(isApprovedImage('alpine:latest')).toBe(false);
      expect(isApprovedImage('busybox:latest')).toBe(false);
      expect(isApprovedImage('malicious-registry.io/evil:v1')).toBe(false);
    });

    it('T11: Docker volume validation strictly forbids docker.sock, host root /, and system directories', () => {
      expect(validateVolumePath('/var/run/docker.sock').valid).toBe(false);
      expect(validateVolumePath('//./pipe/docker_engine').valid).toBe(false);
      expect(validateVolumePath('/etc').valid).toBe(false);
      expect(validateVolumePath('/root').valid).toBe(false);
      expect(validateVolumePath('/').valid).toBe(false);

      // Ephemeral scratch directories inside os.tmpdir are allowed
      expect(validateVolumePath(path.join(os.tmpdir(), 'scratch-test')).valid).toBe(true);
    });

    it('T11: DockerRunner throws ContainerSecurityError when attempting to run unapproved image or illegal volume', async () => {
      const runner = new DockerRunner();

      // Unapproved image rejected
      await expect(
        runner.execute({
          image: 'unapproved-attacker-image:latest',
          simulated: true,
        }),
      ).rejects.toThrow(ContainerSecurityError);

      // Prohibited volume rejected
      await expect(
        runner.execute({
          image: 'zaproxy/zaproxy:latest',
          volumes: [{ hostPath: '/var/run/docker.sock', containerPath: '/var/run/docker.sock', readonly: false }],
          simulated: true,
        }),
      ).rejects.toThrow(ContainerSecurityError);
    });
  });

  // =========================================================================
  // Battery 9: T12 — Sliding-Window Rate Limiting & DoS Defense
  // =========================================================================
  describe('Battery 9: Threat T12 — Sliding-Window Rate Limiting & Resource Exhaustion Defense', () => {
    it('T12: Exceeding sliding-window poll rate limit (60 req/min) returns HTTP 429 Too Many Requests', async () => {
      // Register dedicated agent for rate limit test
      const rateLimitClient = new AgentClient(controllerUrl);
      const rlAgent = await rateLimitClient.register(
        { name: 'dos-pen-test-agent', capabilities: ['engine-native-headers'], tags: [] },
        tekA,
      );

      // Send 60 polls within window (permitted)
      for (let i = 0; i < 60; i++) {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/agents/poll',
          headers: {
            authorization: `Bearer ${rlAgent.token}`,
            [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
          },
          payload: { agentId: rlAgent.agentId, maxJobs: 1 },
        });
        expect(res.statusCode).toBe(200);
      }

      // 61st poll triggers rate limiter with HTTP 429
      const blockedRes = await app.inject({
        method: 'POST',
        url: '/api/v1/agents/poll',
        headers: {
          authorization: `Bearer ${rlAgent.token}`,
          [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        },
        payload: { agentId: rlAgent.agentId, maxJobs: 1 },
      });

      expect(blockedRes.statusCode).toBe(429);
      expect(blockedRes.json().message || blockedRes.json().error).toBeDefined();
    });
  });

  // =========================================================================
  // Battery 10: T17 — Lease Expiration & Stalled Job Watchdog Reaping
  // =========================================================================
  describe('Battery 10: Threat T17 — Stale Agent Execution & Watchdog Reaper', () => {
    it('T17: Completion attempt with expired lease is rejected with HTTP 403 or 409 LEASE_EXPIRED', async () => {
      const testRunId = await createTestRun(tenantA.id, projectAId, targetAId);
      const jobId = await dispatchJob(tenantA.id, testRunId, ['engine-native-headers']);

      const [claimedJob] = await agentA1Client.poll(agentA1Data.agentId, ['engine-native-headers'], ['vpc-alpha'], 1);
      expect(claimedJob).toBeDefined();
      expect(claimedJob.jobId).toBe(jobId);

      const { sql } = getDatabase();
      // Artificially expire the lease in database
      await sql`
        UPDATE agent_jobs
        SET lease_expires_at = NOW() - INTERVAL '10 seconds'
        WHERE id = ${jobId};
      `;

      // Agent attempts completion after lease expiration
      const completeRes = await app.inject({
        method: 'POST',
        url: `/api/v1/agents/jobs/${jobId}/complete`,
        headers: {
          authorization: `Bearer ${agentA1Data.token}`,
          [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        },
        payload: {
          jobId,
          testRunId,
          leaseId: claimedJob.leaseId,
          status: 'completed',
          findings: [],
          executions: [],
          metrics: [],
        },
      });

      expect([403, 409]).toContain(completeRes.statusCode);
      expect(completeRes.json().error.code).toBe('LEASE_EXPIRED');

      // Clean up job to avoid background timer interference
      await sql`UPDATE agent_jobs SET status = 'failed', error = 'PenTest expired lease test cleanup' WHERE id = ${jobId}`;
    });

    it('T17: Watchdog reaper automatically transitions stalled jobs to failed when retry attempts are exhausted', async () => {
      const testRunId = await createTestRun(tenantA.id, projectAId, targetAId);
      const jobId = await dispatchJob(tenantA.id, testRunId, ['engine-native-headers']);

      const { sql } = getDatabase();
      // Set status = 'leased', attempts = 3, max_attempts = 3, expired lease
      await sql`
        UPDATE agent_jobs
        SET status = 'leased',
            attempts = 3,
            max_attempts = 3,
            agent_id = ${agentA1Data.agentId},
            lease_id = gen_random_uuid(),
            lease_expires_at = NOW() - INTERVAL '15 seconds'
        WHERE id = ${jobId};
      `;

      // Trigger reaper
      const reapResult = await agentDispatcherService.reapExpiredJobLeases();
      expect(reapResult.exhausted).toBeGreaterThanOrEqual(1);

      // Verify job marked failed and completed
      const [failedJob] = await sql`
        SELECT status, error, lease_expires_at FROM agent_jobs WHERE id = ${jobId};
      `;
      expect(failedJob.status).toBe('failed');
      expect(failedJob.error).toContain('exceeded maximum retries (3)');
      expect(failedJob.lease_expires_at).toBeNull();

      // Verify associated test run is failed
      const [tr] = await sql`SELECT status FROM test_runs WHERE id = ${testRunId};`;
      expect(tr.status).toBe('failed');
    });
  });

  // =========================================================================
  // Battery 11: T18 — Concurrency Race Condition Defense (FOR UPDATE SKIP LOCKED)
  // =========================================================================
  describe('Battery 11: Threat T18 — High Concurrency Race Condition Defense', () => {
    it('T18: 10 concurrent agents polling 1 single job simultaneously produce exactly 1 lease and 0 duplicates', async () => {
      // 1. Register 10 test agents for concurrency blast
      const concurrentAgents: Array<{ agentId: string; client: AgentClient }> = [];
      for (let i = 0; i < 10; i++) {
        const client = new AgentClient(controllerUrl);
        const data = await client.register(
          {
            name: `concurrent-pen-worker-${i}`,
            capabilities: ['engine-native-headers'],
            tags: ['concurrency-pen'],
          },
          tekA,
        );
        concurrentAgents.push({ agentId: data.agentId, client });
      }

      // 2. Dispatch exactly 1 job
      const testRunId = await createTestRun(tenantA.id, projectAId, targetAId);
      const singleJobId = await dispatchJob(
        tenantA.id,
        testRunId,
        ['engine-native-headers'],
        ['engine-native-headers'],
        ['concurrency-pen'],
      );

      // 3. Concurrency Blast: All 10 agents poll simultaneously
      const pollPromises = concurrentAgents.map((a) =>
        a.client.poll(a.agentId, ['engine-native-headers'], ['concurrency-pen'], 1),
      );
      const results = await Promise.all(pollPromises);

      // 4. Distribution verification
      const claimsWithJobs = results.filter((res) => res.length > 0);
      const emptyClaims = results.filter((res) => res.length === 0);

      // Exactly 1 agent gets the job; exactly 9 receive empty arrays
      expect(claimsWithJobs.length).toBe(1);
      expect(emptyClaims.length).toBe(9);
      expect(claimsWithJobs[0][0].jobId).toBe(singleJobId);

      // 5. Database state verification: 1 lease record, status = 'leased', attempts = 1
      const { sql } = getDatabase();
      const [dbJob] = await sql`
        SELECT status, agent_id, attempts FROM agent_jobs WHERE id = ${singleJobId};
      `;
      expect(dbJob.status).toBe('leased');
      expect(dbJob.attempts).toBe(1);
      expect(dbJob.agent_id).toBeDefined();

      // Clean up job to keep test DB clean
      await sql`UPDATE agent_jobs SET status = 'completed' WHERE id = ${singleJobId}`;
    });
  });

  // =========================================================================
  // Battery 12: Emergency Bidirectional Cancellation
  // =========================================================================
  describe('Battery 12: Emergency Bidirectional Cancellation & In-Flight Interruption', () => {
    it('Emergency user cancellation stops in-flight agent within 2 seconds and acknowledges cancellation', async () => {
      let engineStarted = false;
      let engineAborted = false;

      // Register mock long-running engine
      const cancellableEngine: TestEngine = {
        id: 'engine-cancellable-pentest',
        name: 'Cancellable PenTest Engine',
        version: '1.0.0',
        type: 'custom',
        async execute(_input: TestInput, context: ExecutionContext): Promise<TestOutput> {
          engineStarted = true;
          return new Promise<TestOutput>((_resolve, reject) => {
            const timer = setTimeout(() => {
              reject(new Error('Engine timed out without cancellation'));
            }, 6000);

            context.abortSignal.addEventListener(
              'abort',
              () => {
                clearTimeout(timer);
                engineAborted = true;
                reject(new Error('In-flight engine cancelled by abort signal'));
              },
              { once: true },
            );
          });
        },
      };

      engineRegistry.register(cancellableEngine);

      const testRunId = await createTestRun(tenantA.id, projectAId, targetAId);
      const jobId = await dispatchJob(tenantA.id, testRunId, ['engine-cancellable-pentest']);

      const [claimedJob] = await agentA1Client.poll(
        agentA1Data.agentId,
        ['engine-cancellable-pentest'],
        ['vpc-alpha'],
        1,
      );
      expect(claimedJob).toBeDefined();

      const worker = new AgentWorker(agentA1Client, { allowLocalTesting: true });
      const abortController = new AbortController();

      // Start execution in background
      const executionPromise = worker.executeJob(claimedJob, abortController.signal);

      // Wait for engine to start
      while (!engineStarted) {
        await new Promise((r) => setTimeout(r, 20));
      }
      expect(engineStarted).toBe(true);

      // Trigger immediate cancellation
      const cancelStart = Date.now();
      abortController.abort(new Error('User Emergency Cancellation'));

      // Execution halts immediately with JobCancelledError
      await expect(executionPromise).rejects.toThrow(JobCancelledError);
      const durationMs = Date.now() - cancelStart;

      // Architectural requirement: must terminate within 2000ms
      expect(durationMs).toBeLessThan(2000);
      expect(engineAborted).toBe(true);

      // Controller cancellation propagation & ack test
      await app.inject({
        method: 'POST',
        url: `/api/v1/test-runs/${testRunId}/cancel`,
        headers: { 'x-tenant-id': tenantA.id },
      });

      // Heartbeat delivers cancelled job ID
      const hb = await agentA1Client.heartbeat(agentA1Data.agentId, 'busy', {}, claimedJob.leaseId);
      expect(hb.cancelledJobIds).toContain(jobId);

      // Agent transmits cancellation acknowledgment
      await agentA1Client.acknowledgeCancellation(jobId);

      // Confirm acknowledgment recorded in database
      const { sql } = getDatabase();
      const [dbJob] = await sql`SELECT result FROM agent_jobs WHERE id = ${jobId};`;
      expect(dbJob?.result?.cancelledAck).toBe(true);
    });
  });

  // =========================================================================
  // Battery 13: Local-First Compatibility Verification (Rule 1)
  // =========================================================================
  describe('Battery 13: Local-First Standalone Execution Compatibility (Architecture Rule 1)', () => {
    it('Executes native Class A engines in-process via test-run execute endpoint without any agent dependency', async () => {
      // 1. Create a TestRun
      const testRunId = await createTestRun(tenantA.id, projectAId, targetAId);

      // 2. Trigger synchronous in-process execution (CLI / standalone mode)
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/test-runs/${testRunId}/execute?wait=true`,
        headers: { 'x-tenant-id': tenantA.id },
        payload: {
          engineIds: ['engine-native-headers', 'engine-native-cors'],
        },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.success).toBe(true);

      const { testRun, executions, findings } = body.data;
      expect(testRun.id).toBe(testRunId);
      expect(testRun.status).toBe('completed');

      // Verify native executions were created and executed in-process
      expect(executions.length).toBe(2);
      const engineIds = executions.map((e: { engineId: string }) => e.engineId);
      expect(engineIds).toContain('engine-native-headers');
      expect(engineIds).toContain('engine-native-cors');

      // Verify findings were identified and persisted
      expect(findings.length).toBeGreaterThan(0);
      for (const finding of findings) {
        expect(finding.testRunId).toBe(testRunId);
        expect(finding.fingerprint).toBeDefined();
        expect(finding.severity).toBeDefined();
      }

      // Verify database state matches
      const { sql } = getDatabase();
      const [finalRun] = await sql`SELECT status FROM test_runs WHERE id = ${testRunId};`;
      expect(finalRun.status).toBe('completed');
    });
  });
});
