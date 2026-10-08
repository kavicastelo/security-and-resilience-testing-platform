import fs from 'node:fs';
import path from 'node:path';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth, getDatabase } from '../../apps/controller/src/services/db.js';
import { AgentClient } from '../../apps/agent/src/client.js';

describe('Phase 16.0: Distributed Agent Trust Boundary & Security Baseline Audit', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;
  let controllerUrl: string;

  // Tenants
  let tenantA: { id: string; name: string; slug: string };
  let tenantB: { id: string; name: string; slug: string };

  // Project & Target under Tenant Alpha
  let projectAId: string;
  let targetAId: string;
  let testRunAId: string;
  let jobAId: string;

  // Agents
  let agentAClient: AgentClient;
  let agentBClient: AgentClient;
  let agentAData: { agentId: string; token: string; tenantId: string };
  let agentBData: { agentId: string; token: string; tenantId: string };

  beforeAll(async () => {
    app = buildApp({ disableLogging: true });
    await app.listen({ port: 0, host: '127.0.0.1' });
    const addr = app.server.address();
    if (addr && typeof addr === 'object') {
      controllerUrl = `http://127.0.0.1:${addr.port}`;
    }

    const health = await checkDatabaseHealth();
    isDbAvailable = health === 'up';

    // Provision Tenant Alpha & Tenant Beta
    const suffix = Math.floor(Math.random() * 1000000);
    const resA = await app.inject({
      method: 'POST',
      url: '/api/v1/tenants',
      payload: { name: `Audit Tenant Alpha ${suffix}`, slug: `audit-alpha-${suffix}`, plan: 'enterprise' },
    });
    tenantA = resA.json().data;

    const resB = await app.inject({
      method: 'POST',
      url: '/api/v1/tenants',
      payload: { name: `Audit Tenant Beta ${suffix}`, slug: `audit-beta-${suffix}`, plan: 'enterprise' },
    });
    tenantB = resB.json().data;

    // Create Project A & Target A under Tenant Alpha
    const projRes = await app.inject({
      method: 'POST',
      url: '/api/v1/projects',
      headers: { 'x-tenant-id': tenantA.id },
      payload: { name: `Alpha Audit Project ${suffix}`, description: 'Tenant Alpha' },
    });
    projectAId = projRes.json().data.id;

    const targetRes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectAId}/targets`,
      headers: { 'x-tenant-id': tenantA.id },
      payload: {
        name: `Alpha VPC Target ${suffix}`,
        baseUrl: 'http://127.0.0.1:8080',
        environment: 'staging',
        criticality: 'high',
        allowedHosts: ['127.0.0.1'],
        allowedPorts: [8080],
        excludedPaths: [],
        testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
        limits: { maxRps: 50, maxConcurrency: 5, maxDuration: '2m' },
      },
    });
    targetAId = targetRes.json().data.id;

    // Create Test Run A under Tenant Alpha
    const runRes = await app.inject({
      method: 'POST',
      url: '/api/v1/test-runs',
      payload: {
        projectId: projectAId,
        targetId: targetAId,
        profileId: 'native-class-a',
        triggeredBy: 'manual',
      },
    });
    testRunAId = runRes.json().data.id;

    // Dispatch Job A under Tenant Alpha
    const dispatchRes = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/dispatch',
      headers: { 'x-tenant-id': tenantA.id },
      payload: {
        testRunId: testRunAId,
        engineIds: ['engine-native-headers'],
      },
    });
    jobAId = dispatchRes.json().data.jobId;

    // Provision TEK for Tenant Alpha and register legitimate Agent Alpha
    const tekARes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenantA.id}/enrollment-keys`,
      payload: { name: 'Audit Alpha TEK' },
    });
    const tekA = tekARes.json().data.key;

    agentAClient = new AgentClient(controllerUrl);
    agentAData = await agentAClient.register(
      {
        name: 'legit-agent-alpha',
        tags: ['vpc-alpha'],
        capabilities: ['engine-native-headers'],
      },
      tekA,
    );

    // Provision TEK for Tenant Beta and register legitimate Agent Beta
    const tekBRes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenantB.id}/enrollment-keys`,
      payload: { name: 'Audit Beta TEK' },
    });
    const tekB = tekBRes.json().data.key;

    agentBClient = new AgentClient(controllerUrl);
    agentBData = await agentBClient.register(
      {
        name: 'legit-agent-beta',
        tags: ['vpc-beta'],
        capabilities: ['engine-native-headers'],
      },
      tekB,
    );

    // Agent Alpha leases Job A
    await agentAClient.poll(agentAData.agentId, ['engine-native-headers'], ['vpc-alpha'], 1);
  });

  afterAll(async () => {
    await app.close();
    if (isDbAvailable) {
      await closeDatabase();
    }
  });

  it('1. Confirms database health and controller connectivity', () => {
    expect(isDbAvailable).toBe(true);
    expect(controllerUrl).toBeDefined();
    expect(jobAId).toBeDefined();
  });

  it('2. [SEC-01 Verified] Blocks anonymous agent enrollment and arbitrary tenant hijacking', async () => {
    // Attack Path: An anonymous, unauthenticated client attempts to enroll without a TEK.
    // In Phase 16.1, this is rejected with 401 Unauthorized / AGENT_UNAUTHORIZED.
    const rogueClient = new AgentClient(controllerUrl);
    const hijackedTenantId = tenantA.id;

    await expect(
      rogueClient.register(
        {
          name: 'rogue-unauthorized-agent',
          tags: ['hijacked'],
          capabilities: ['engine-native-headers'],
        },
        undefined, // No enrollment key
        hijackedTenantId,
      ),
    ).rejects.toThrow();

    // Verify raw controller response envelope
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/register',
      headers: { 'x-tenant-id': hijackedTenantId },
      payload: {
        name: 'rogue-unauthorized-agent',
        tags: ['hijacked'],
        capabilities: ['engine-native-headers'],
      },
    });

    expect(res.statusCode).toBe(401);
    const body = res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('AGENT_UNAUTHORIZED');
  });

  it('3. [SEC-02 Verified] Blocks cross-tenant job completion and enforces agent lease ownership', async () => {
    // Attack Path: Job A belongs to Tenant Alpha and is assigned to Agent Alpha.
    // Agent Beta belongs to Tenant Beta.
    // In Phase 16.2, cross-tenant or unassigned agent completion is strictly blocked with 403 TENANT_MISMATCH.
    expect(agentBData.tenantId).toBe(tenantB.id);
    expect(agentBData.tenantId).not.toBe(tenantA.id);

    // Agent Beta (Tenant Beta) attempts to submit a completion report for Job A (Tenant Alpha)
    const forgedFinding = {
      sourceEngine: 'forged-attacker-engine',
      title: 'Fabricated Critical RCE Vulnerability',
      description: 'Attacker injected this finding from Tenant B into Tenant A',
      rawSeverity: 'critical',
      location: '/api/v1/vulnerable-endpoint',
    };

    const completeRes = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${jobAId}/complete`,
      headers: {
        authorization: `Bearer ${agentBData.token}`, // Agent Beta credentials!
      },
      payload: {
        jobId: jobAId,
        testRunId: testRunAId,
        status: 'completed',
        findings: [forgedFinding],
        metrics: [],
        executions: [
          {
            engineId: 'forged-attacker-engine',
            status: 'completed',
            durationMs: 50,
          },
        ],
      },
    });

    // Tenant Isolation Invariant: Rejected with 403 Forbidden and TENANT_MISMATCH
    expect(completeRes.statusCode).toBe(403);
    const body = completeRes.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('TENANT_MISMATCH');

    // Verify the forged finding was NOT persisted into Tenant Alpha's test run
    const findingsRes = await app.inject({
      method: 'GET',
      url: `/api/v1/findings?testRunId=${testRunAId}`,
      headers: { 'x-tenant-id': tenantA.id },
    });
    expect(findingsRes.statusCode).toBe(200);
    const findings = findingsRes.json().data;
    const forgedMatch = findings.find((f: { title: string }) => f.title?.includes('Fabricated Critical RCE'));
    expect(forgedMatch).toBeUndefined();
  });

  it('4. [SEC-04 Verified] Enforces idempotent job completion and prevents duplicate data generation', async () => {
    // Attack Path Mitigation: If network instability causes an agent to retry /complete,
    // the controller recognizes the completed job and returns deduplicated: true without database mutation.
    const { sql } = getDatabase();

    // Legitimate Agent Alpha completes Job A initially
    const firstRes = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${jobAId}/complete`,
      headers: {
        authorization: `Bearer ${agentAData.token}`,
      },
      payload: {
        jobId: jobAId,
        testRunId: testRunAId,
        status: 'completed',
        findings: [],
        metrics: [],
        executions: [
          {
            engineId: 'duplicate-test-engine',
            status: 'completed',
            durationMs: 50,
          },
        ],
      },
    });
    expect(firstRes.statusCode).toBe(200);

    const [beforeCountRecord] = await sql`
      SELECT COUNT(*)::int as count FROM test_executions WHERE test_run_id = ${testRunAId}
    `;
    const initialExecutionCount = beforeCountRecord.count;

    // Resubmit the exact same completion request
    const duplicateRes = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${jobAId}/complete`,
      headers: {
        authorization: `Bearer ${agentAData.token}`,
      },
      payload: {
        jobId: jobAId,
        testRunId: testRunAId,
        status: 'completed',
        findings: [],
        metrics: [],
        executions: [
          {
            engineId: 'duplicate-test-engine',
            status: 'completed',
            durationMs: 50,
          },
        ],
      },
    });
    expect(duplicateRes.statusCode).toBe(200);
    expect(duplicateRes.json().deduplicated).toBe(true);

    const [afterCountRecord] = await sql`
      SELECT COUNT(*)::int as count FROM test_executions WHERE test_run_id = ${testRunAId}
    `;
    const finalExecutionCount = afterCountRecord.count;

    // Idempotency verified: Test execution count unchanged, duplicate rows rejected!
    expect(finalExecutionCount).toBe(initialExecutionCount);
  });

  it('5. [GAP SEC-07 Proof] Proves late agent completion overwrites user cancellations', async () => {
    // Step 1: Create a new test run and dispatch a job
    const runRes = await app.inject({
      method: 'POST',
      url: '/api/v1/test-runs',
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
    const jobId = dispatchRes.json().data.jobId;

    // Agent Alpha leases the job
    await agentAClient.poll(agentAData.agentId, ['engine-native-headers'], ['vpc-alpha'], 1);

    // Step 2: User issues an emergency cancellation
    const cancelRes = await app.inject({
      method: 'POST',
      url: `/api/v1/test-runs/${runId}/cancel`,
    });
    expect(cancelRes.statusCode).toBe(200);

    // Verify test run is cancelled in DB
    const checkRun1 = await app.inject({
      method: 'GET',
      url: `/api/v1/test-runs/${runId}`,
    });
    expect(checkRun1.json().data.status).toBe('cancelled');

    // Step 3: Agent completes execution later and posts /complete
    const completeRes = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${jobId}/complete`,
      headers: { authorization: `Bearer ${agentAData.token}` },
      payload: {
        jobId,
        testRunId: runId,
        status: 'completed',
        findings: [],
        metrics: [],
        executions: [],
      },
    });
    expect(completeRes.statusCode).toBe(200);

    // Step 4: Verify test run state
    const checkRun2 = await app.inject({
      method: 'GET',
      url: `/api/v1/test-runs/${runId}`,
    });

    // Vulnerability confirmed: Test run was silently overwritten from 'cancelled' back to 'completed'!
    expect(checkRun2.json().data.status).toBe('completed');
  });

  it('6. [GAP SEC-06 Proof] Verifies Docker socket exposure in Kubernetes deployment manifest', () => {
    // Audit of infrastructure/k8s/agent.yaml
    const manifestPath = path.resolve(__dirname, '../../infrastructure/k8s/agent.yaml');
    expect(fs.existsSync(manifestPath)).toBe(true);

    const manifestContent = fs.readFileSync(manifestPath, 'utf8');

    // Rule 13 Violation check: Manifest contains hostPath /var/run/docker.sock
    const hasDockerSocketMount = manifestContent.includes('/var/run/docker.sock');
    const hasHostPathSocket = manifestContent.includes('path: /var/run/docker.sock');

    // Vulnerability confirmed: Kubernetes manifest mounts host Docker daemon socket into agent container!
    expect(hasDockerSocketMount).toBe(true);
    expect(hasHostPathSocket).toBe(true);
  });
});
