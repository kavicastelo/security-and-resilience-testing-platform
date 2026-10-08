import crypto from 'node:crypto';
import { eq, desc, and, inArray } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { agents, agentJobs, targets, testExecutions } from './db/schema.js';
import {
  AgentRegistrationRequest,
  AgentRegistrationResponse,
  AgentJobDispatch,
  AgentJobCompletionReport,
  AgentSummary,
} from '@security-lab/contracts';
import { FindingSeverity, TestRunSummary } from '@security-lab/domain';
import {
  computeJobDispatchSecret,
  computeScopeSignature,
  verifyResultSignature,
} from '@security-lab/evidence';
import { findingsService, computeHardenedFindingFingerprint } from './findings.service.js';
import { metricsService } from './metrics.service.js';
import { testRunsService } from './test-runs.service.js';
import { reportsService } from './reports.service.js';
import { executionManager } from './execution-manager.js';
import { logger } from '@security-lab/logger';
import { DEFAULT_TENANT_ID } from './tenants.service.js';
import { agentAuditService } from './agent-audit.service.js';

export const agentStateMetrics = {
  jobs_leased_total: 0,
  jobs_reaped_total: 0,
  jobs_exhausted_total: 0,
};

export function hashAgentToken(token: string): string {
  return crypto.createHash('sha256').update(token.trim()).digest('hex');
}

export class AuthorizationError extends Error {
  statusCode: number;
  code: string;

  constructor(message: string, code: string = 'FORBIDDEN', statusCode: number = 403) {
    super(message);
    this.name = 'AuthorizationError';
    this.statusCode = statusCode;
    this.code = code;
  }
}

export class NotFoundError extends Error {
  statusCode: number;
  code: string;

  constructor(message: string, code: string = 'NOT_FOUND') {
    super(message);
    this.name = 'NotFoundError';
    this.statusCode = 404;
    this.code = code;
  }
}

export interface AgentAuthResult {
  agent: typeof agents.$inferSelect | null;
  error?: string;
  code?: 'UNAUTHORIZED' | 'AGENT_REVOKED' | 'AGENT_TOKEN_EXPIRED';
}

export class AgentDispatcherService {
  /**
   * Registers a new distributed execution agent under a tenant.
   * Generates a single-use plaintext token and persists only its SHA-256 hash.
   * Sets a default 90-day token expiration.
   */
  async registerAgent(
    input: AgentRegistrationRequest,
    tenantId: string = DEFAULT_TENANT_ID,
    tokenExpiresInDays: number = 90,
  ): Promise<AgentRegistrationResponse> {
    const { db } = getDatabase();
    if (!db) throw new Error('Database unavailable');

    const rawToken = `agt_sec_${crypto.randomBytes(32).toString('hex')}`;
    const tokenHash = hashAgentToken(rawToken);
    const tokenExpiresAt = new Date(Date.now() + tokenExpiresInDays * 86400000);

    const [inserted] = await db
      .insert(agents)
      .values({
        tenantId,
        name: input.name.trim(),
        tokenHash,
        status: 'offline',
        capabilities: input.capabilities || [],
        tags: input.tags || [],
        systemInfo: input.systemInfo || {},
        expiresAt: tokenExpiresAt,
      })
      .returning();

    if (!inserted) {
      throw new Error('Failed to register agent in database');
    }

    logger.info(
      { agentId: inserted.id, tenantId, name: inserted.name, expiresAt: tokenExpiresAt.toISOString() },
      'Registered new distributed execution agent',
    );

    await agentAuditService.recordAuditEvent({
      tenantId: inserted.tenantId,
      agentId: inserted.id,
      eventType: 'agent.enrolled',
      actorType: 'admin',
      actorId: 'tek_enrollment',
      metadata: {
        agentName: inserted.name,
        tags: inserted.tags,
        capabilities: inserted.capabilities,
        tokenExpiresAt: inserted.expiresAt?.toISOString(),
      },
    });

    return {
      agentId: inserted.id,
      tenantId: inserted.tenantId,
      name: inserted.name,
      token: rawToken,
      tokenExpiresAt: inserted.expiresAt?.toISOString(),
      status: inserted.status as 'online' | 'busy' | 'draining' | 'offline',
      tags: inserted.tags as string[],
      capabilities: inserted.capabilities as string[],
      createdAt: inserted.createdAt.toISOString(),
    };
  }

  /**
   * Authenticates an agent via its raw Bearer token by computing its SHA-256 hash.
   * Asserts token validity, absence of revocation, and unexpired lifespan.
   */
  async authenticateAgent(token: string): Promise<AgentAuthResult> {
    const { db } = getDatabase();
    if (!db || !token) {
      return { agent: null, error: 'Missing or empty token', code: 'UNAUTHORIZED' };
    }

    const tokenHash = hashAgentToken(token);
    const [agent] = await db
      .select()
      .from(agents)
      .where(eq(agents.tokenHash, tokenHash))
      .limit(1);

    if (!agent) {
      return { agent: null, error: 'Invalid agent token', code: 'UNAUTHORIZED' };
    }

    if (agent.revokedAt) {
      return {
        agent: null,
        error: `Agent token has been revoked: ${agent.revocationReason || 'administrative action'}`,
        code: 'AGENT_REVOKED',
      };
    }

    if (agent.expiresAt && new Date(agent.expiresAt) <= new Date()) {
      return {
        agent: null,
        error: 'Agent token has expired. Rotation or re-enrollment required.',
        code: 'AGENT_TOKEN_EXPIRED',
      };
    }

    return { agent };
  }

  /**
   * Administratively revokes an agent token.
   */
  async revokeAgent(agentId: string, reason: string = 'Administrative revocation') {
    const { db } = getDatabase();
    if (!db) throw new Error('Database unavailable');

    const [updated] = await db
      .update(agents)
      .set({
        revokedAt: new Date(),
        revocationReason: reason,
        status: 'offline',
        updatedAt: new Date(),
      })
      .where(eq(agents.id, agentId))
      .returning();

    if (!updated) {
      throw new Error(`Agent "${agentId}" not found`);
    }

    logger.warn({ agentId, reason }, 'Agent revoked by administrator');

    await agentAuditService.recordAuditEvent({
      tenantId: updated.tenantId,
      agentId: updated.id,
      eventType: 'agent.revoked',
      actorType: 'admin',
      actorId: 'admin',
      metadata: {
        reason,
        revokedAt: updated.revokedAt!.toISOString(),
      },
    });
    return {
      agentId: updated.id,
      revokedAt: updated.revokedAt!.toISOString(),
      reason: updated.revocationReason || reason,
    };
  }

  /**
   * Rotates an agent's instance token, issuing a new token and setting a new expiration.
   */
  async rotateAgentToken(agentId: string, tokenExpiresInDays: number = 90) {
    const { db } = getDatabase();
    if (!db) throw new Error('Database unavailable');

    const newToken = `agt_sec_${crypto.randomBytes(32).toString('hex')}`;
    const newTokenHash = hashAgentToken(newToken);
    const tokenExpiresAt = new Date(Date.now() + tokenExpiresInDays * 86400000);

    const [updated] = await db
      .update(agents)
      .set({
        tokenHash: newTokenHash,
        expiresAt: tokenExpiresAt,
        updatedAt: new Date(),
      })
      .where(eq(agents.id, agentId))
      .returning();

    if (!updated) {
      throw new Error(`Agent "${agentId}" not found`);
    }

    logger.info({ agentId }, 'Agent token rotated successfully');

    await agentAuditService.recordAuditEvent({
      tenantId: updated.tenantId,
      agentId: updated.id,
      eventType: 'agent.token_rotated',
      actorType: 'agent',
      actorId: updated.id,
      metadata: {
        tokenExpiresAt: tokenExpiresAt.toISOString(),
      },
    });
    return {
      agentId: updated.id,
      token: newToken,
      tokenExpiresAt: tokenExpiresAt.toISOString(),
      rotatedAt: new Date().toISOString(),
    };
  }

  /**
   * Updates an agent's heartbeat and health status, renewing active job leases.
   */
  async recordHeartbeat(
    agentId: string,
    status: 'online' | 'busy' | 'draining' | 'offline' = 'online',
    metrics?: Record<string, unknown>,
    leaseId?: string,
    activeLeaseIds?: string[],
  ): Promise<{ acknowledged: boolean; renewedLeases: string[]; cancelledJobIds: string[] }> {
    const { db, sql } = getDatabase();
    if (!db) return { acknowledged: false, renewedLeases: [], cancelledJobIds: [] };

    const updateData: Record<string, unknown> = {
      status,
      lastHeartbeatAt: new Date(),
      updatedAt: new Date(),
    };

    if (metrics) {
      updateData.systemInfo = metrics;
    }

    const [updated] = await db
      .update(agents)
      .set(updateData)
      .where(eq(agents.id, agentId))
      .returning();

    const renewedLeases: string[] = [];
    const targetLeaseIds = [
      ...(leaseId ? [leaseId] : []),
      ...(activeLeaseIds || []),
    ].filter(Boolean);

    if (sql && targetLeaseIds.length > 0) {
      const renewed = await sql`
        UPDATE agent_jobs
        SET lease_expires_at = NOW() + INTERVAL '3 minutes',
            updated_at = NOW()
        WHERE agent_id = ${agentId}
          AND lease_id = ANY(${targetLeaseIds})
          AND status IN ('leased', 'running')
        RETURNING lease_id;
      `;
      for (const row of renewed) {
        renewedLeases.push(row.lease_id);
      }
      if (renewedLeases.length > 0) {
        logger.info(
          { agentId, renewedCount: renewedLeases.length, renewedLeases },
          'Agent heartbeat renewed active job leases',
        );
      }
    }

    const cancelledJobIds: string[] = [];
    if (sql) {
      const cancelledRows = await sql`
        SELECT id
        FROM agent_jobs
        WHERE agent_id = ${agentId}
          AND status = 'cancelled'
          AND (result IS NULL OR result->>'cancelledAck' IS NULL)
        ORDER BY updated_at DESC
        LIMIT 50;
      `;
      for (const row of cancelledRows) {
        cancelledJobIds.push(row.id);
      }
    }

    return { acknowledged: !!updated, renewedLeases, cancelledJobIds };
  }

  /**
   * Lists registered agents for a tenant.
   */
  async listAgents(tenantId?: string): Promise<AgentSummary[]> {
    const { db } = getDatabase();
    if (!db) return [];

    const query = db.select().from(agents);
    const rows = tenantId
      ? await query.where(eq(agents.tenantId, tenantId)).orderBy(desc(agents.createdAt))
      : await query.orderBy(desc(agents.createdAt));

    return rows.map((r: typeof agents.$inferSelect) => ({
      id: r.id,
      tenantId: r.tenantId,
      name: r.name,
      status: r.status as 'online' | 'busy' | 'draining' | 'offline',
      tags: (r.tags as string[]) || [],
      capabilities: (r.capabilities as string[]) || [],
      systemInfo: (r.systemInfo as Record<string, unknown>) || {},
      lastHeartbeatAt: r.lastHeartbeatAt ? r.lastHeartbeatAt.toISOString() : null,
      expiresAt: r.expiresAt ? r.expiresAt.toISOString() : null,
      revokedAt: r.revokedAt ? r.revokedAt.toISOString() : null,
      revocationReason: r.revocationReason || null,
      createdAt: r.createdAt.toISOString(),
      updatedAt: r.updatedAt.toISOString(),
    }));
  }

  /**
   * Retrieves a single agent by ID.
   */
  async getAgentById(agentId: string): Promise<AgentSummary | null> {
    const { db } = getDatabase();
    if (!db || !agentId) return null;

    const [r] = await db
      .select()
      .from(agents)
      .where(eq(agents.id, agentId))
      .limit(1);

    if (!r) return null;

    return {
      id: r.id,
      tenantId: r.tenantId,
      name: r.name,
      status: r.status as 'online' | 'busy' | 'draining' | 'offline',
      tags: (r.tags as string[]) || [],
      capabilities: (r.capabilities as string[]) || [],
      systemInfo: (r.systemInfo as Record<string, unknown>) || {},
      lastHeartbeatAt: r.lastHeartbeatAt ? r.lastHeartbeatAt.toISOString() : null,
      expiresAt: r.expiresAt ? r.expiresAt.toISOString() : null,
      revokedAt: r.revokedAt ? r.revokedAt.toISOString() : null,
      revocationReason: r.revocationReason || null,
      createdAt: r.createdAt.toISOString(),
      updatedAt: r.updatedAt.toISOString(),
    };
  }

  /**
   * Enqueues an execution task into the agent dispatch queue.
   */
  async enqueueAgentJob(
    testRunId: string,
    tenantId: string = DEFAULT_TENANT_ID,
    engineIds: string[] = [],
    options?: Record<string, unknown>,
    requiredCapabilities: string[] = [],
    requiredTags: string[] = [],
  ): Promise<string> {
    const { db } = getDatabase();
    if (!db) throw new Error('Database unavailable');

    const run = await testRunsService.getTestRunById(testRunId);
    if (!run) throw new Error(`Test run "${testRunId}" not found`);

    const target = await db
      .select()
      .from(targets)
      .where(eq(targets.id, run.targetId))
      .limit(1);

    const targetRow = target[0];
    if (!targetRow) {
      throw new Error(`Target "${run.targetId}" not found`);
    }

    const scopeSignature = computeScopeSignature(
      targetRow.id,
      targetRow.baseUrl,
      targetRow.scope,
    );

    const payload: AgentJobDispatch = {
      jobId: crypto.randomUUID(),
      testRunId,
      tenantId,
      target: {
        id: targetRow.id,
        name: targetRow.name,
        baseUrl: targetRow.baseUrl,
        scope: targetRow.scope as Record<string, unknown>,
        scopeSignature,
      },
      engineIds,
      options,
      requiredCapabilities,
      requiredTags,
    };

    const [job] = await db
      .insert(agentJobs)
      .values({
        id: payload.jobId,
        tenantId,
        testRunId,
        status: 'queued',
        attempts: 0,
        maxAttempts: 3,
        requiredCapabilities,
        requiredTags,
        payload: payload as unknown as Record<string, unknown>,
      })
      .returning();

    if (!job) {
      throw new Error('Failed to enqueue agent job');
    }

    logger.info(
      { jobId: job.id, testRunId, tenantId, requiredCapabilities, requiredTags },
      'Enqueued distributed agent execution task',
    );

    return job.id;
  }

  /**
   * Polls for pending/queued jobs matching agent tenant atomically.
   * Employs PostgreSQL row-level locking (SELECT ... FOR UPDATE SKIP LOCKED)
   * with JSONB array containment filtering on capabilities and tags.
   */
  async pollJobs(
    agentId: string,
    tenantId: string,
    capabilities: string[] = [],
    tags: string[] = [],
    maxJobs = 1,
  ): Promise<AgentJobDispatch[]> {
    const { sql } = getDatabase();
    if (!sql) return [];

    const capsJson = JSON.stringify(capabilities || []);
    const tagsJson = JSON.stringify(tags || []);

    const claimedRows = await sql`
      WITH claimable AS (
        SELECT id
        FROM agent_jobs
        WHERE tenant_id = ${tenantId}
          AND status IN ('queued', 'pending')
          AND attempts < max_attempts
          AND (required_capabilities <@ ${capsJson}::jsonb OR required_capabilities = '[]'::jsonb)
          AND (required_tags <@ ${tagsJson}::jsonb OR required_tags = '[]'::jsonb)
        ORDER BY created_at ASC
        LIMIT ${maxJobs}
        FOR UPDATE SKIP LOCKED
      )
      UPDATE agent_jobs
      SET status = 'leased',
          agent_id = ${agentId},
          lease_id = gen_random_uuid(),
          lease_expires_at = NOW() + INTERVAL '5 minutes',
          dispatched_at = NOW(),
          attempts = attempts + 1,
          updated_at = NOW()
      FROM claimable
      WHERE agent_jobs.id = claimable.id
      RETURNING
        agent_jobs.id,
        agent_jobs.tenant_id,
        agent_jobs.test_run_id,
        agent_jobs.agent_id,
        agent_jobs.status,
        agent_jobs.lease_id,
        agent_jobs.lease_expires_at,
        agent_jobs.attempts,
        agent_jobs.max_attempts,
        agent_jobs.required_capabilities,
        agent_jobs.required_tags,
        agent_jobs.payload,
        agent_jobs.created_at,
        agent_jobs.updated_at;
    `;

    if (!claimedRows || claimedRows.length === 0) return [];

    agentStateMetrics.jobs_leased_total += claimedRows.length;

    for (const row of claimedRows) {
      await agentAuditService.recordAuditEvent({
        tenantId: row.tenant_id,
        agentId,
        eventType: 'job.leased',
        actorType: 'agent',
        actorId: agentId,
        metadata: {
          jobId: row.id,
          testRunId: row.test_run_id,
          leaseId: row.lease_id,
          leaseExpiresAt: row.lease_expires_at,
          attempts: row.attempts,
          requiredCapabilities: row.required_capabilities,
          requiredTags: row.required_tags,
        },
      });
    }

    const dispatched: AgentJobDispatch[] = [];
    for (const row of claimedRows) {
      const payload = row.payload as unknown as AgentJobDispatch;
      const jobDispatchSecret = computeJobDispatchSecret(row.id, row.lease_id, agentId);

      let targetPayload = payload.target;
      if (!targetPayload.scopeSignature) {
        targetPayload = {
          ...targetPayload,
          scopeSignature: computeScopeSignature(
            targetPayload.id,
            targetPayload.baseUrl,
            targetPayload.scope,
          ),
        };
      }

      dispatched.push({
        ...payload,
        target: targetPayload,
        requiredCapabilities: (row.required_capabilities as string[]) || payload.requiredCapabilities || [],
        requiredTags: (row.required_tags as string[]) || payload.requiredTags || [],
        leaseId: row.lease_id,
        leaseExpiresAt: row.lease_expires_at ? new Date(row.lease_expires_at).toISOString() : undefined,
        jobDispatchSecret,
      });

      logger.info(
        {
          jobId: row.id,
          agentId,
          tenantId,
          leaseId: row.lease_id,
          attempt: row.attempts,
        },
        'Atomic job lease acquired by agent',
      );
    }

    return dispatched;
  }

  /**
   * Handles in-flight execution progress reports from agents.
   * Asserts that requesting agent belongs to the job's tenant and holds the active lease.
   */
  async reportJobProgress(
    jobId: string,
    agent: { id: string; tenantId: string },
    percent: number,
    message: string,
    engineId?: string,
  ) {
    const { db } = getDatabase();
    if (!db) return;

    const [job] = await db
      .select()
      .from(agentJobs)
      .where(eq(agentJobs.id, jobId))
      .limit(1);

    if (!job) {
      throw new NotFoundError(`Agent job "${jobId}" not found`);
    }

    // 1. Tenant boundary assertion (Rule 5 & Rule 6)
    if (job.tenantId !== agent.tenantId) {
      logger.warn(
        {
          event: 'security.cross_tenant_attempt',
          attemptedJobId: jobId,
          callerAgentId: agent.id,
          callerTenantId: agent.tenantId,
          targetTenantId: job.tenantId,
          action: 'progress',
        },
        'Blocked unauthorized cross-tenant job progress update',
      );
      await agentAuditService.recordAuditEvent({
        tenantId: job.tenantId,
        agentId: agent.id,
        eventType: 'security.tenant_mismatch',
        actorType: 'agent',
        actorId: agent.id,
        metadata: {
          action: 'progress',
          jobId,
          callerTenantId: agent.tenantId,
          targetTenantId: job.tenantId,
        },
      });
      throw new AuthorizationError(
        `Tenant mismatch: agent "${agent.id}" cannot update job belonging to tenant "${job.tenantId}"`,
        'TENANT_MISMATCH',
      );
    }

    // 2. Agent lease ownership assertion (Rule 6)
    if (job.agentId !== agent.id) {
      logger.warn(
        {
          event: 'security.cross_agent_attempt',
          attemptedJobId: jobId,
          callerAgentId: agent.id,
          assignedAgentId: job.agentId,
          action: 'progress',
        },
        'Blocked unauthorized job progress update by non-assigned agent',
      );
      throw new AuthorizationError(
        `Agent mismatch: job "${jobId}" is not assigned to agent "${agent.id}"`,
        'AGENT_MISMATCH',
      );
    }

    // 3. Lease expiration check (Rule 8)
    if (job.leaseExpiresAt && new Date() > new Date(job.leaseExpiresAt)) {
      logger.warn(
        {
          event: 'security.lease_expired',
          attemptedJobId: jobId,
          callerAgentId: agent.id,
          leaseExpiresAt: job.leaseExpiresAt,
          action: 'progress',
        },
        'Blocked progress update on expired job lease',
      );
      throw new AuthorizationError(
        `Lease expired: lease for job "${jobId}" expired at ${job.leaseExpiresAt.toISOString()}`,
        'LEASE_EXPIRED',
        409,
      );
    }

    await db
      .update(agentJobs)
      .set({
        status: 'running',
        updatedAt: new Date(),
      })
      .where(eq(agentJobs.id, jobId));

    executionManager.emit('progress', {
      testRunId: job.testRunId,
      engineId: engineId || 'agent-remote-worker',
      executionId: jobId,
      percent,
      message,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Ingests completed job results from an agent, storing findings, metrics,
   * updating test run status, and generating reports.
   * Asserts that requesting agent belongs to the job's tenant and holds the active lease.
   */
  async completeJob(
    jobId: string,
    agent: { id: string; tenantId: string },
    report: AgentJobCompletionReport,
  ) {
    const { db } = getDatabase();
    if (!db) throw new Error('Database unavailable');

    const [job] = await db
      .select()
      .from(agentJobs)
      .where(eq(agentJobs.id, jobId))
      .limit(1);

    if (!job) {
      throw new NotFoundError(`Agent job "${jobId}" not found`);
    }

    // 1. Tenant boundary assertion (Rule 5 & Rule 6)
    if (job.tenantId !== agent.tenantId) {
      logger.warn(
        {
          event: 'security.cross_tenant_attempt',
          attemptedJobId: jobId,
          callerAgentId: agent.id,
          callerTenantId: agent.tenantId,
          targetTenantId: job.tenantId,
          action: 'complete',
        },
        'Blocked unauthorized cross-tenant job completion attempt',
      );
      await agentAuditService.recordAuditEvent({
        tenantId: job.tenantId,
        agentId: agent.id,
        eventType: 'security.tenant_mismatch',
        actorType: 'agent',
        actorId: agent.id,
        metadata: {
          action: 'complete',
          jobId,
          callerTenantId: agent.tenantId,
          targetTenantId: job.tenantId,
        },
      });
      throw new AuthorizationError(
        `Tenant mismatch: agent "${agent.id}" cannot complete job belonging to tenant "${job.tenantId}"`,
        'TENANT_MISMATCH',
      );
    }

    // 2. Agent lease ownership assertion (Rule 6)
    if (job.agentId !== agent.id) {
      logger.warn(
        {
          event: 'security.cross_agent_attempt',
          attemptedJobId: jobId,
          callerAgentId: agent.id,
          assignedAgentId: job.agentId,
          action: 'complete',
        },
        'Blocked unauthorized job completion by non-assigned agent',
      );
      throw new AuthorizationError(
        `Agent mismatch: job "${jobId}" is not assigned to agent "${agent.id}"`,
        'AGENT_MISMATCH',
      );
    }

    // 3. Idempotency pre-check (Finding SEC-04 & Rule 7)
    if (job.status === 'completed') {
      logger.info(
        {
          event: 'result.deduplicated',
          jobId,
          testRunId: job.testRunId,
          tenantId: job.tenantId,
          agentId: agent.id,
        },
        'Duplicate job completion report deduplicated; returning cached completed status without database mutation',
      );
      return { status: 'completed', deduplicated: true };
    }

    // 3b. Late Completion Shielding (Rule 8 & Phase 16.6)
    if (job.status === 'cancelled') {
      logger.info(
        {
          event: 'result.ignored_cancelled',
          jobId,
          testRunId: job.testRunId,
          tenantId: job.tenantId,
          agentId: agent.id,
        },
        'Rejecting completion report: job was cancelled by user; returning status: cancelled with ignored: true without database mutation',
      );
      return { status: 'cancelled', ignored: true, success: true };
    }

    // 4. Lease ID validation (Finding SEC-05 & Rule 21)
    if (job.leaseId && report.leaseId && report.leaseId !== job.leaseId) {
      logger.warn(
        {
          event: 'security.lease_mismatch',
          attemptedJobId: jobId,
          callerAgentId: agent.id,
          reportLeaseId: report.leaseId,
          activeLeaseId: job.leaseId,
        },
        'Blocked job completion with mismatched lease ID',
      );
      throw new AuthorizationError(
        `Lease mismatch: report leaseId "${report.leaseId}" does not match active job leaseId "${job.leaseId}"`,
        'LEASE_MISMATCH',
        409,
      );
    }

    // 5. Lease expiration validation (Rule 8)
    if (job.leaseExpiresAt && new Date() > new Date(job.leaseExpiresAt)) {
      logger.warn(
        {
          event: 'security.lease_expired',
          attemptedJobId: jobId,
          callerAgentId: agent.id,
          leaseExpiresAt: job.leaseExpiresAt,
          action: 'complete',
        },
        'Blocked job completion on expired lease',
      );
      throw new AuthorizationError(
        `Cannot accept completion: lease for job "${jobId}" expired at ${job.leaseExpiresAt.toISOString()}`,
        'LEASE_EXPIRED',
        409,
      );
    }

    // 6. Cryptographic Result Attestation Verification (Rule 4, Finding SEC-04)
    if (report.resultSignature) {
      const jobDispatchSecret = computeJobDispatchSecret(job.id, job.leaseId || '', agent.id);
      const isValid = verifyResultSignature({
        jobDispatchSecret,
        jobId: job.id,
        findings: report.findings || [],
        executions: report.executions || [],
        signature: report.resultSignature,
      });

      if (!isValid) {
        logger.warn(
          {
            event: 'result.rejected_tampered',
            jobId,
            testRunId: job.testRunId,
            tenantId: job.tenantId,
            agentId: agent.id,
            action: 'complete',
            reason: 'SIGNATURE_MISMATCH',
          },
          'Agent result signature verification failed; potential finding tampering detected',
        );
        await agentAuditService.recordAuditEvent({
          tenantId: job.tenantId,
          agentId: agent.id,
          eventType: 'security.scope_tampering',
          actorType: 'agent',
          actorId: agent.id,
          metadata: {
            action: 'complete',
            jobId,
            testRunId: job.testRunId,
            leaseId: job.leaseId,
            reason: 'SIGNATURE_MISMATCH',
          },
        });
        throw new AuthorizationError(
          'Cryptographic signature verification failed for job findings',
          'SIGNATURE_INVALID',
          403,
        );
      }
    }

    const run = await testRunsService.getTestRunById(job.testRunId);
    if (!run) throw new Error(`Test run "${job.testRunId}" not found`);

    const executionMap = new Map<string, string>();
    let defaultExecutionId: string | null = null;
    const severityCounts: Record<FindingSeverity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    const finalStatus = report.status === 'completed' ? 'completed' : 'failed';
    const summary: TestRunSummary = {
      totalTests: report.executions.length || 1,
      passedTests: report.executions.filter((e) => e.status === 'completed').length || (report.status === 'completed' ? 1 : 0),
      failedTests: report.executions.filter((e) => e.status === 'failed').length || (report.status === 'failed' ? 1 : 0),
      errorTests: report.error ? 1 : 0,
      findingsCount: severityCounts,
    };

    // Atomic database transaction for executions, findings, metrics, and completion
    await db.transaction(async (tx) => {
      // 1. Create test_executions records
      if (report.executions && report.executions.length > 0) {
        for (const exec of report.executions) {
          const [insertedExec] = await tx
            .insert(testExecutions)
            .values({
              testRunId: job.testRunId,
              engineId: exec.engineId,
              executionClass: 'class_a_native',
              status: exec.status as 'pending' | 'running' | 'completed' | 'failed' | 'cancelled',
              durationMs: exec.durationMs || 0,
              errorMessage: exec.error,
              startedAt: new Date(Date.now() - (exec.durationMs || 0)),
              completedAt: new Date(),
            })
            .returning();
          if (insertedExec) {
            executionMap.set(exec.engineId, insertedExec.id);
            if (!defaultExecutionId) defaultExecutionId = insertedExec.id;
          }
        }
      }

      if (!defaultExecutionId) {
        const [fallbackExec] = await tx
          .insert(testExecutions)
          .values({
            testRunId: job.testRunId,
            engineId: 'agent-remote-worker',
            executionClass: 'class_a_native',
            status: report.status === 'completed' ? 'completed' : 'failed',
            startedAt: new Date(),
            completedAt: new Date(),
          })
          .returning();
        if (fallbackExec) {
          defaultExecutionId = fallbackExec.id;
        }
      }

      if (!defaultExecutionId) {
        throw new Error('Failed to create test execution record for agent job');
      }

      // 2. Ingest findings
      for (const raw of report.findings) {
        const severity = (raw.rawSeverity?.toLowerCase() || 'medium') as FindingSeverity;
        severityCounts[severity] = (severityCounts[severity] || 0) + 1;

        const fingerprint = computeHardenedFindingFingerprint({
          targetId: run.targetId,
          engineId: raw.sourceEngine || 'agent',
          category: raw.sourceEngine || 'agent',
          ruleOrCweId: raw.title,
          endpointPath: raw.location,
        });

        const execId = (raw.sourceEngine && executionMap.get(raw.sourceEngine)) || defaultExecutionId;

        await findingsService.saveFinding({
          tenantId: job.tenantId,
          fingerprint,
          title: raw.title,
          category: raw.sourceEngine || 'agent',
          severity,
          confidence: 'firm',
          status: 'open',
          description: raw.description,
          testDefinitionId: raw.sourceEngine || 'agent-worker',
          testRunId: job.testRunId,
          executionId: execId!,
          targetId: run.targetId,
          metadata: (raw.evidenceData as Record<string, unknown>) || {},
        }, tx);
      }

      // 3. Ingest metrics
      for (const m of report.metrics) {
        const metricExecId = (m.tags?.engineId && executionMap.get(m.tags.engineId)) || defaultExecutionId;
        await metricsService.saveMetric({
          testRunId: job.testRunId,
          executionId: metricExecId!,
          name: m.name,
          value: m.value,
          unit: m.unit,
          tags: m.tags || {},
        }, tx);
      }

      // 4. Update test run status
      await testRunsService.updateTestRunStatus(job.testRunId, finalStatus, summary, tx);

      // 5. Mark agent job as completed
      await tx
        .update(agentJobs)
        .set({
          status: 'completed',
          result: report as unknown as Record<string, unknown>,
          leaseExpiresAt: null,
          completedAt: new Date(),
          updatedAt: new Date(),
        })
        .where(eq(agentJobs.id, jobId));
    });

    // Persist reports outside the transaction
    try {
      await reportsService.persistTestRunReports(job.testRunId);
    } catch (err: unknown) {
      logger.warn({ err }, 'Failed to persist test run reports from agent job');
    }

    executionManager.emit('run', {
      testRunId: job.testRunId,
      status: finalStatus,
      summary,
      timestamp: new Date().toISOString(),
    });

    logger.info(
      {
        event: 'result.accepted',
        jobId,
        testRunId: job.testRunId,
        tenantId: job.tenantId,
        agentId: agent.id,
        findingsCount: report.findings.length,
        executionsCount: report.executions.length,
      },
      'Agent execution job completed and ingested into control plane',
    );

    await agentAuditService.recordAuditEvent({
      tenantId: job.tenantId,
      agentId: agent.id,
      eventType: 'job.completed',
      actorType: 'agent',
      actorId: agent.id,
      metadata: {
        jobId,
        testRunId: job.testRunId,
        leaseId: job.leaseId,
        findingsCount: report.findings.length,
        executionsCount: report.executions.length,
      },
    });

    return { status: 'completed', deduplicated: false };
  }

  /**
   * Marks an agent job as failed.
   * Asserts that requesting agent belongs to the job's tenant and holds the active lease.
   */
  async failJob(
    jobId: string,
    agent: { id: string; tenantId: string },
    error: string,
  ) {
    const { db } = getDatabase();
    if (!db) throw new Error('Database unavailable');

    const [job] = await db
      .select()
      .from(agentJobs)
      .where(eq(agentJobs.id, jobId))
      .limit(1);

    if (!job) {
      throw new NotFoundError(`Agent job "${jobId}" not found`);
    }

    // 1. Tenant boundary assertion (Rule 5 & Rule 6)
    if (job.tenantId !== agent.tenantId) {
      logger.warn(
        {
          event: 'security.cross_tenant_attempt',
          attemptedJobId: jobId,
          callerAgentId: agent.id,
          callerTenantId: agent.tenantId,
          targetTenantId: job.tenantId,
          action: 'fail',
        },
        'Blocked unauthorized cross-tenant job failure attempt',
      );
      await agentAuditService.recordAuditEvent({
        tenantId: job.tenantId,
        agentId: agent.id,
        eventType: 'security.tenant_mismatch',
        actorType: 'agent',
        actorId: agent.id,
        metadata: {
          action: 'fail',
          jobId,
          callerTenantId: agent.tenantId,
          targetTenantId: job.tenantId,
        },
      });
      throw new AuthorizationError(
        `Tenant mismatch: agent "${agent.id}" cannot fail job belonging to tenant "${job.tenantId}"`,
        'TENANT_MISMATCH',
      );
    }

    // 2. Agent lease ownership assertion (Rule 6)
    if (job.agentId !== agent.id) {
      logger.warn(
        {
          event: 'security.cross_agent_attempt',
          attemptedJobId: jobId,
          callerAgentId: agent.id,
          assignedAgentId: job.agentId,
          action: 'fail',
        },
        'Blocked unauthorized job failure report by non-assigned agent',
      );
      throw new AuthorizationError(
        `Agent mismatch: job "${jobId}" is not assigned to agent "${agent.id}"`,
        'AGENT_MISMATCH',
      );
    }

    // 3. Lease expiration validation (Rule 8)
    if (job.leaseExpiresAt && new Date() > new Date(job.leaseExpiresAt)) {
      logger.warn(
        {
          event: 'security.lease_expired',
          attemptedJobId: jobId,
          callerAgentId: agent.id,
          leaseExpiresAt: job.leaseExpiresAt,
          action: 'fail',
        },
        'Blocked failure report on expired lease',
      );
      throw new AuthorizationError(
        `Cannot accept failure report: lease for job "${jobId}" expired at ${job.leaseExpiresAt.toISOString()}`,
        'LEASE_EXPIRED',
        409,
      );
    }

    // 3b. Ignore failure report if job was already cancelled (Rule 8)
    if (job.status === 'cancelled') {
      logger.info(
        {
          event: 'result.ignored_cancelled',
          jobId,
          testRunId: job.testRunId,
          tenantId: job.tenantId,
          agentId: agent.id,
        },
        'Ignoring failure report: job was already cancelled by user',
      );
      return { status: 'cancelled', ignored: true, success: true };
    }

    await db
      .update(agentJobs)
      .set({
        status: 'failed',
        error,
        leaseExpiresAt: null,
        completedAt: new Date(),
        updatedAt: new Date(),
      })
      .where(eq(agentJobs.id, jobId));

    await testRunsService.updateTestRunStatus(job.testRunId, 'failed');

    executionManager.emit('run', {
      testRunId: job.testRunId,
      status: 'failed',
      timestamp: new Date().toISOString(),
    });

    await agentAuditService.recordAuditEvent({
      tenantId: job.tenantId,
      agentId: agent.id,
      eventType: 'job.failed',
      actorType: 'agent',
      actorId: agent.id,
      metadata: {
        jobId,
        testRunId: job.testRunId,
        leaseId: job.leaseId,
        error,
      },
    });

    return { status: 'failed', success: true };
  }

  /**
   * Identifies expired job leases and automatically recovers or fails them.
   * - If attempts < max_attempts: resets status = 'queued', agent_id = null, lease_id = null, lease_expires_at = null
   * - If attempts >= max_attempts: marks status = 'failed', records timeout error, marks test run as 'failed'
   */
  async reapExpiredJobLeases(): Promise<{ reaped: number; exhausted: number }> {
    const { sql } = getDatabase();
    if (!sql) return { reaped: 0, exhausted: 0 };

    // 1. Identify jobs whose lease expired while in 'leased' or 'running'
    const expiredJobs = await sql`
      SELECT id, test_run_id, tenant_id, agent_id, status, lease_id, lease_expires_at, attempts, max_attempts
      FROM agent_jobs
      WHERE status IN ('leased', 'running')
        AND lease_expires_at IS NOT NULL
        AND lease_expires_at < NOW()
      FOR UPDATE SKIP LOCKED;
    `;

    if (!expiredJobs || expiredJobs.length === 0) {
      return { reaped: 0, exhausted: 0 };
    }

    let reapedCount = 0;
    let exhaustedCount = 0;

    for (const job of expiredJobs) {
      if (job.attempts < job.max_attempts) {
        // Requeue for another attempt
        await sql`
          UPDATE agent_jobs
          SET status = 'queued',
              agent_id = NULL,
              lease_id = NULL,
              lease_expires_at = NULL,
              updated_at = NOW()
          WHERE id = ${job.id};
        `;

        logger.warn(
          {
            event: 'job_reaped',
            jobId: job.id,
            attempt: job.attempts,
            maxAttempts: job.max_attempts,
            tenantId: job.tenant_id,
            lastAgentId: job.agent_id,
          },
          'Expired job lease reaped and requeued for next available agent',
        );
        reapedCount++;
        agentStateMetrics.jobs_reaped_total++;
      } else {
        // Max attempts exhausted: mark permanently failed
        const timeoutError = `Execution timed out and exceeded maximum retries (${job.max_attempts})`;
        await sql`
          UPDATE agent_jobs
          SET status = 'failed',
              error = ${timeoutError},
              lease_expires_at = NULL,
              completed_at = NOW(),
              updated_at = NOW()
          WHERE id = ${job.id};
        `;

        await testRunsService.updateTestRunStatus(job.test_run_id, 'failed');

        executionManager.emit('run', {
          testRunId: job.test_run_id,
          status: 'failed',
          timestamp: new Date().toISOString(),
        });

        logger.error(
          {
            event: 'job_exhausted',
            jobId: job.id,
            testRunId: job.test_run_id,
            attempts: job.attempts,
            maxAttempts: job.max_attempts,
          },
          'Expired job exceeded maximum retry attempts; permanently failed',
        );
        exhaustedCount++;
        agentStateMetrics.jobs_exhausted_total++;
      }
    }

    return { reaped: reapedCount, exhausted: exhaustedCount };
  }

  /**
   * Acknowledges that an agent has received and executed cancellation for a job.
   */
  async acknowledgeJobCancellation(
    jobId: string,
    agent: { id: string; tenantId: string },
  ): Promise<{ success: boolean; jobId: string; acknowledgedAt: string }> {
    const { db } = getDatabase();
    if (!db) throw new Error('Database unavailable');

    const [job] = await db
      .select()
      .from(agentJobs)
      .where(eq(agentJobs.id, jobId))
      .limit(1);

    if (!job) {
      throw new NotFoundError(`Agent job "${jobId}" not found`);
    }

    if (job.tenantId !== agent.tenantId) {
      logger.warn(
        {
          event: 'security.cross_tenant_attempt',
          attemptedJobId: jobId,
          callerAgentId: agent.id,
          action: 'cancel-ack',
        },
        'Blocked unauthorized cross-tenant job cancel acknowledgement',
      );
      await agentAuditService.recordAuditEvent({
        tenantId: job.tenantId,
        agentId: agent.id,
        eventType: 'security.tenant_mismatch',
        actorType: 'agent',
        actorId: agent.id,
        metadata: {
          action: 'cancel-ack',
          jobId,
          callerTenantId: agent.tenantId,
          targetTenantId: job.tenantId,
        },
      });
      throw new AuthorizationError(
        `Tenant mismatch: agent "${agent.id}" cannot acknowledge job belonging to tenant "${job.tenantId}"`,
        'TENANT_MISMATCH',
      );
    }

    if (job.agentId !== agent.id) {
      logger.warn(
        {
          event: 'security.cross_agent_attempt',
          attemptedJobId: jobId,
          callerAgentId: agent.id,
          assignedAgentId: job.agentId,
          action: 'cancel-ack',
        },
        'Blocked unauthorized job cancel acknowledgement by non-assigned agent',
      );
      throw new AuthorizationError(
        `Agent mismatch: job "${jobId}" is not assigned to agent "${agent.id}"`,
        'AGENT_MISMATCH',
      );
    }

    const currentResult = (job.result as Record<string, unknown>) || {};
    const now = new Date();
    await db
      .update(agentJobs)
      .set({
        result: { ...currentResult, cancelledAck: true, acknowledgedAt: now.toISOString() },
        updatedAt: now,
      })
      .where(eq(agentJobs.id, jobId));

    logger.info(
      { event: 'job.cancelled_propagated', jobId, agentId: agent.id, testRunId: job.testRunId },
      'Agent successfully acknowledged job cancellation',
    );

    await agentAuditService.recordAuditEvent({
      tenantId: job.tenantId,
      agentId: agent.id,
      eventType: 'job.cancelled',
      actorType: 'agent',
      actorId: agent.id,
      metadata: {
        jobId,
        testRunId: job.testRunId,
        acknowledged: true,
      },
    });

    return {
      success: true,
      jobId,
      acknowledgedAt: now.toISOString(),
    };
  }

  /**
   * Cancels all pending, leased, or running jobs for a test run.
   */
  async cancelJobsForTestRun(testRunId: string, reason = 'Execution cancelled by user'): Promise<number> {
    const { db } = getDatabase();
    if (!db) return 0;

    const now = new Date();
    const updated = await db
      .update(agentJobs)
      .set({
        status: 'cancelled',
        error: reason,
        leaseExpiresAt: null,
        completedAt: now,
        updatedAt: now,
      })
      .where(
        and(
          eq(agentJobs.testRunId, testRunId),
          inArray(agentJobs.status, ['queued', 'leased', 'running']),
        ),
      )
      .returning();

    for (const job of updated) {
      await agentAuditService.recordAuditEvent({
        tenantId: job.tenantId,
        agentId: job.agentId,
        eventType: 'job.cancelled',
        actorType: 'admin',
        actorId: 'admin',
        metadata: {
          jobId: job.id,
          testRunId: job.testRunId,
          reason,
        },
      });
    }

    return updated.length;
  }
}

export class AgentJobReaper {
  private timer?: NodeJS.Timeout;
  private isRunning = false;
  private readonly intervalMs: number;

  constructor(intervalMs = 30000) {
    this.intervalMs = intervalMs;
  }

  start(): void {
    if (this.isRunning) return;
    this.isRunning = true;
    this.timer = setInterval(async () => {
      try {
        await agentDispatcherService.reapExpiredJobLeases();
      } catch (err: unknown) {
        logger.error({ err }, 'Error in agent job watchdog reaper loop');
      }
    }, this.intervalMs);
    this.timer.unref();
  }

  stop(): void {
    this.isRunning = false;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }

  isRunningState(): boolean {
    return this.isRunning;
  }
}

export const agentJobReaper = new AgentJobReaper();
export const agentDispatcherService = new AgentDispatcherService();
