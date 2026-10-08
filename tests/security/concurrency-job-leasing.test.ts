import net from 'node:net';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth, getDatabase } from '../../apps/controller/src/services/db.js';
import { AgentClient } from '../../apps/agent/src/index.js';
import { agentDispatcherService, agentJobReaper, agentStateMetrics } from '../../apps/controller/src/services/agent-dispatcher.service.js';

describe('Phase 16.3: Atomic Job Leasing, Watchdog Reaper & State Machine', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;
  let controllerUrl: string;

  let tenant: { id: string; name: string; slug: string };
  let projectId: string;
  let targetId: string;
  let tekToken: string;

  // 10 concurrent test agents
  const agents: Array<{
    agentId: string;
    token: string;
    client: AgentClient;
  }> = [];

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
      throw new Error('Database is not available for Phase 16.3 testing');
    }

    const suffix = `${Date.now()}-${Math.floor(Math.random() * 10000)}`;

    // 1. Create dedicated testing tenant
    const tenantRes = await app.inject({
      method: 'POST',
      url: '/api/v1/tenants',
      payload: {
        name: `Concurrency Corp ${suffix}`,
        slug: `conc-corp-${suffix}`,
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
      payload: { name: `Concurrency Project ${suffix}`, description: 'Phase 16.3' },
    });
    expect(projectRes.statusCode).toBe(201);
    projectId = projectRes.json().data.id;

    const targetRes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectId}/targets`,
      headers: { 'x-tenant-id': tenant.id },
      payload: {
        name: 'Concurrent Target',
        baseUrl: 'http://127.0.0.1:8088',
        environment: 'staging',
        criticality: 'high',
        allowedHosts: ['127.0.0.1'],
        allowedPorts: [8088],
        excludedPaths: [],
        testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
        limits: { maxRps: 50, maxConcurrency: 5, maxDuration: '2m' },
      },
    });
    expect(targetRes.statusCode).toBe(201);
    targetId = targetRes.json().data.id;

    // 3. Create Tenant Enrollment Key (TEK)
    const tekRes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenant.id}/enrollment-keys`,
      payload: { name: 'Concurrency Cluster TEK', maxUses: 50 },
    });
    expect(tekRes.statusCode).toBe(201);
    tekToken = tekRes.json().data.key;

    // 4. Enroll 10 distinct agents using TEK
    for (let i = 1; i <= 10; i++) {
      const client = new AgentClient(controllerUrl);
      const data = await client.register(
        {
          name: `Concurrent Agent ${i}-${suffix}`,
          tags: ['concurrency-test', 'edge'],
          capabilities: ['engine-native-headers', 'engine-native-cors'],
          systemInfo: { os: 'linux', arch: 'x64', nodeVersion: 'v20.0.0', cpuCount: 8, totalMemoryMb: 16384 },
        },
        tekToken,
      );
      agents.push({
        agentId: data.agentId,
        token: data.token,
        client,
      });
    }

    expect(agents.length).toBe(10);
  });

  afterAll(async () => {
    agentJobReaper.stop();
    await app.close();
    await closeDatabase();
  });

  it('SEC-03: 10 parallel agents competing for 2 jobs results in zero double-claims via FOR UPDATE SKIP LOCKED', async () => {
    // 1. Create 2 test runs and dispatch 2 jobs
    const testRun1Id = await createTestRun();
    const testRun2Id = await createTestRun();

    const job1Id = await dispatchJob(testRun1Id);
    const job2Id = await dispatchJob(testRun2Id);

    const { sql } = getDatabase();
    // Verify initially queued
    const initialJobs = await sql`
      SELECT id, status, attempts, lease_id, lease_expires_at
      FROM agent_jobs
      WHERE id IN (${job1Id}, ${job2Id});
    `;
    expect(initialJobs.length).toBe(2);
    for (const j of initialJobs) {
      expect(['queued', 'pending']).toContain(j.status);
      expect(j.attempts).toBe(0);
      expect(j.lease_id).toBeNull();
      expect(j.lease_expires_at).toBeNull();
    }

    const baselineLeasedTotal = agentStateMetrics.jobs_leased_total;

    // 2. Concurrency Blast: All 10 agents poll simultaneously
    const pollPromises = agents.map((agent) =>
      agent.client.poll(agent.agentId, ['engine-native-headers'], ['concurrency-test'], 1),
    );

    const pollResults = await Promise.all(pollPromises);

    // 3. Verify distribution
    const claimedByAgents = pollResults.map((jobs, idx) => ({
      agent: agents[idx],
      jobs,
    }));

    const successfulClaims = claimedByAgents.filter((c) => c.jobs.length > 0);
    const emptyClaims = claimedByAgents.filter((c) => c.jobs.length === 0);

    // Exactly 2 agents claimed a job; exactly 8 agents got empty arrays
    expect(successfulClaims.length).toBe(2);
    expect(emptyClaims.length).toBe(8);

    const claimedJobIds = successfulClaims.map((c) => c.jobs[0].jobId);
    expect(new Set(claimedJobIds).size).toBe(2);
    expect(claimedJobIds).toContain(job1Id);
    expect(claimedJobIds).toContain(job2Id);

    // Verify lease metadata on dispatched jobs
    for (const c of successfulClaims) {
      const dispatched = c.jobs[0];
      expect(dispatched.leaseId).toBeDefined();
      expect(dispatched.leaseExpiresAt).toBeDefined();
      expect(new Date(dispatched.leaseExpiresAt!).getTime()).toBeGreaterThan(Date.now());
    }

    // Verify database state: status = 'leased', attempts = 1, distinct lease_id
    const dbJobs = await sql`
      SELECT id, status, agent_id, lease_id, lease_expires_at, attempts
      FROM agent_jobs
      WHERE id IN (${job1Id}, ${job2Id});
    `;
    expect(dbJobs.length).toBe(2);

    const leasedAgents = new Set<string>();
    const leasedIds = new Set<string>();
    for (const dj of dbJobs) {
      expect(dj.status).toBe('leased');
      expect(dj.attempts).toBe(1);
      expect(dj.lease_id).not.toBeNull();
      expect(dj.agent_id).not.toBeNull();
      expect(new Date(dj.lease_expires_at).getTime()).toBeGreaterThan(Date.now());
      leasedAgents.add(dj.agent_id);
      leasedIds.add(dj.lease_id);
    }
    expect(leasedAgents.size).toBe(2);
    expect(leasedIds.size).toBe(2);

    // Verify metrics counter incremented by 2
    expect(agentStateMetrics.jobs_leased_total).toBe(baselineLeasedTotal + 2);
  });

  it('heartbeat renews active job lease and extends lease_expires_at', async () => {
    // 1. Create a job and claim it with Agent 0
    const testRunId = await createTestRun();
    const jobId = await dispatchJob(testRunId);

    const [dispatched] = await agents[0].client.poll(agents[0].agentId, ['engine-native-headers'], [], 1);
    expect(dispatched).toBeDefined();
    expect(dispatched.jobId).toBe(jobId);
    expect(dispatched.leaseId).toBeDefined();

    const { sql } = getDatabase();
    // Artificially wind down the lease_expires_at to 30 seconds from now
    await sql`
      UPDATE agent_jobs
      SET lease_expires_at = NOW() + INTERVAL '30 seconds'
      WHERE id = ${jobId};
    `;

    const [beforeHeartbeat] = await sql`
      SELECT lease_expires_at FROM agent_jobs WHERE id = ${jobId};
    `;
    const beforeExpiry = new Date(beforeHeartbeat.lease_expires_at).getTime();

    // 2. Agent sends heartbeat renewing active lease
    const hbResponse = await agents[0].client.heartbeat(
      agents[0].agentId,
      'busy',
      { memoryUsageMb: 128, activeJobsCount: 1 },
      dispatched.leaseId,
      [dispatched.leaseId!],
    );

    expect(hbResponse.acknowledged).toBe(true);
    expect(hbResponse.renewedLeases).toContain(dispatched.leaseId);

    // 3. Verify in database: lease_expires_at was extended by approximately 3 minutes
    const [afterHeartbeat] = await sql`
      SELECT lease_expires_at FROM agent_jobs WHERE id = ${jobId};
    `;
    const afterExpiry = new Date(afterHeartbeat.lease_expires_at).getTime();

    // Should be extended by ~2.5 to 3 minutes beyond beforeExpiry
    expect(afterExpiry - beforeExpiry).toBeGreaterThan(120 * 1000);
  });

  it('SEC-05: Watchdog reaper resets expired job to queued when attempts < max_attempts', async () => {
    // 1. Create a job and claim it with Agent 1
    const testRunId = await createTestRun();
    const jobId = await dispatchJob(testRunId);

    const [dispatched] = await agents[1].client.poll(agents[1].agentId, ['engine-native-headers'], [], 1);
    expect(dispatched).toBeDefined();
    expect(dispatched.jobId).toBe(jobId);

    const { sql } = getDatabase();
    // 2. Simulate agent crash: lease expired 10 seconds ago
    await sql`
      UPDATE agent_jobs
      SET lease_expires_at = NOW() - INTERVAL '10 seconds'
      WHERE id = ${jobId};
    `;

    const baselineReapedTotal = agentStateMetrics.jobs_reaped_total;

    // 3. Trigger watchdog reaper
    const result = await agentDispatcherService.reapExpiredJobLeases();
    expect(result.reaped).toBeGreaterThanOrEqual(1);
    expect(agentStateMetrics.jobs_reaped_total).toBeGreaterThanOrEqual(baselineReapedTotal + 1);

    // 4. Verify job was requeued with agent_id and lease_id cleared
    const [requeued] = await sql`
      SELECT status, agent_id, lease_id, lease_expires_at, attempts, max_attempts
      FROM agent_jobs
      WHERE id = ${jobId};
    `;
    expect(requeued.status).toBe('queued');
    expect(requeued.agent_id).toBeNull();
    expect(requeued.lease_id).toBeNull();
    expect(requeued.lease_expires_at).toBeNull();
    expect(requeued.attempts).toBe(1); // 1 previous attempt recorded
    expect(requeued.max_attempts).toBe(3);

    // 5. Verify another agent (Agent 2) can now claim the requeued job
    const [reclaimed] = await agents[2].client.poll(agents[2].agentId, ['engine-native-headers'], [], 1);
    expect(reclaimed).toBeDefined();
    expect(reclaimed.jobId).toBe(jobId);
    expect(reclaimed.leaseId).toBeDefined();

    // Verify attempts incremented to 2 upon second claim
    const [secondClaim] = await sql`
      SELECT status, agent_id, lease_id, attempts
      FROM agent_jobs
      WHERE id = ${jobId};
    `;
    expect(secondClaim.status).toBe('leased');
    expect(secondClaim.agent_id).toBe(agents[2].agentId);
    expect(secondClaim.attempts).toBe(2);
  });

  it('Watchdog reaper permanently fails job when attempts reach max_attempts', async () => {
    // 1. Create a job and test run
    const testRunId = await createTestRun();
    const jobId = await dispatchJob(testRunId);

    const { sql } = getDatabase();
    // 2. Set attempts = 3, max_attempts = 3, status = 'leased', expired lease
    await sql`
      UPDATE agent_jobs
      SET status = 'leased',
          attempts = 3,
          max_attempts = 3,
          agent_id = ${agents[3].agentId},
          lease_id = gen_random_uuid(),
          lease_expires_at = NOW() - INTERVAL '10 seconds'
      WHERE id = ${jobId};
    `;

    const baselineExhaustedTotal = agentStateMetrics.jobs_exhausted_total;

    // 3. Run reaper
    const result = await agentDispatcherService.reapExpiredJobLeases();
    expect(result.exhausted).toBeGreaterThanOrEqual(1);
    expect(agentStateMetrics.jobs_exhausted_total).toBeGreaterThanOrEqual(baselineExhaustedTotal + 1);

    // 4. Verify job transitioned to 'failed' and test run marked failed
    const [failedJob] = await sql`
      SELECT status, error, lease_expires_at, completed_at
      FROM agent_jobs
      WHERE id = ${jobId};
    `;
    expect(failedJob.status).toBe('failed');
    expect(failedJob.error).toContain('exceeded maximum retries (3)');
    expect(failedJob.lease_expires_at).toBeNull();
    expect(failedJob.completed_at).not.toBeNull();

    const [testRun] = await sql`
      SELECT status FROM test_runs WHERE id = ${testRunId};
    `;
    expect(testRun.status).toBe('failed');

    // 5. Subsequent polling by any agent returns empty array
    const polled = await agents[4].client.poll(agents[4].agentId, ['engine-native-headers'], [], 1);
    expect(polled.find((j) => j.jobId === jobId)).toBeUndefined();
  });

  it('Rule 8: Expired lease rejects progress, completion, and failure reports (403 LEASE_EXPIRED)', async () => {
    // 1. Create a job and claim it with Agent 5
    const testRunId = await createTestRun();
    const jobId = await dispatchJob(testRunId);

    const [dispatched] = await agents[5].client.poll(agents[5].agentId, ['engine-native-headers'], [], 1);
    expect(dispatched).toBeDefined();

    const { sql } = getDatabase();
    // 2. Expire the lease
    await sql`
      UPDATE agent_jobs
      SET lease_expires_at = NOW() - INTERVAL '5 seconds'
      WHERE id = ${jobId};
    `;

    // 3. Try to report progress
    const progressRes = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${jobId}/progress`,
      headers: { authorization: `Bearer ${agents[5].token}` },
      payload: { jobId, testRunId, percent: 50, message: 'Executing...' },
    });
    expect([403, 409]).toContain(progressRes.statusCode);
    expect(progressRes.json().error.code).toBe('LEASE_EXPIRED');

    // 4. Try to complete job
    const completeRes = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${jobId}/complete`,
      headers: { authorization: `Bearer ${agents[5].token}` },
      payload: {
        jobId,
        leaseId: dispatched.leaseId,
        testRunId,
        status: 'completed',
        findings: [],
        metrics: [],
        executions: [],
      },
    });
    expect([403, 409]).toContain(completeRes.statusCode);
    expect(completeRes.json().error.code).toBe('LEASE_EXPIRED');

    // 5. Try to fail job
    const failRes = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${jobId}/fail`,
      headers: { authorization: `Bearer ${agents[5].token}` },
      payload: { error: 'Should be rejected due to expired lease' },
    });
    expect([403, 409]).toContain(failRes.statusCode);
    expect(failRes.json().error.code).toBe('LEASE_EXPIRED');
  });

  it('Rule 21: Job completion is rejected if submitted leaseId does not match active lease (403 LEASE_MISMATCH)', async () => {
    // 1. Create a job and claim it with Agent 6
    const testRunId = await createTestRun();
    const jobId = await dispatchJob(testRunId);

    const [dispatched] = await agents[6].client.poll(agents[6].agentId, ['engine-native-headers'], [], 1);
    expect(dispatched).toBeDefined();

    // 2. Submit completion with a fabricated / mismatched leaseId
    const mismatchRes = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${jobId}/complete`,
      headers: { authorization: `Bearer ${agents[6].token}` },
      payload: {
        jobId,
        leaseId: '00000000-0000-0000-0000-000000000000', // Stale or wrong lease ID
        testRunId,
        status: 'completed',
        findings: [],
        metrics: [],
        executions: [],
      },
    });
    expect([403, 409]).toContain(mismatchRes.statusCode);
    expect(mismatchRes.json().error.code).toBe('LEASE_MISMATCH');

    // 3. Submit completion with the correct leaseId succeeds
    const validRes = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/jobs/${jobId}/complete`,
      headers: { authorization: `Bearer ${agents[6].token}` },
      payload: {
        jobId,
        leaseId: dispatched.leaseId,
        testRunId,
        status: 'completed',
        findings: [],
        metrics: [],
        executions: [],
      },
    });
    expect(validRes.statusCode).toBe(200);
    expect(validRes.json().success).toBe(true);

    const { sql } = getDatabase();
    const [completedJob] = await sql`SELECT status, lease_expires_at FROM agent_jobs WHERE id = ${jobId};`;
    expect(completedJob.status).toBe('completed');
    expect(completedJob.lease_expires_at).toBeNull();
  });

  it('AgentJobReaper service starts and stops cleanly without dangling resources', () => {
    expect(typeof agentJobReaper.start).toBe('function');
    expect(typeof agentJobReaper.stop).toBe('function');

    agentJobReaper.start();
    expect(agentJobReaper.isRunningState()).toBe(true);

    // Calling start again when already running is idempotent
    agentJobReaper.start();
    expect(agentJobReaper.isRunningState()).toBe(true);

    agentJobReaper.stop();
    expect(agentJobReaper.isRunningState()).toBe(false);
  });
});
