import crypto from 'node:crypto';
import { eq, and, desc } from 'drizzle-orm';
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
import { findingsService, computeHardenedFindingFingerprint } from './findings.service.js';
import { metricsService } from './metrics.service.js';
import { testRunsService } from './test-runs.service.js';
import { reportsService } from './reports.service.js';
import { executionManager } from './execution-manager.js';
import { logger } from '@security-lab/logger';
import { DEFAULT_TENANT_ID } from './tenants.service.js';

export function hashAgentToken(token: string): string {
  return crypto.createHash('sha256').update(token.trim()).digest('hex');
}

export class AgentDispatcherService {
  /**
   * Registers a new distributed execution agent under a tenant.
   * Generates a single-use plaintext token and persists only its SHA-256 hash.
   */
  async registerAgent(
    input: AgentRegistrationRequest,
    tenantId: string = DEFAULT_TENANT_ID,
  ): Promise<AgentRegistrationResponse> {
    const { db } = getDatabase();
    if (!db) throw new Error('Database unavailable');

    const rawToken = `agt_sec_${crypto.randomBytes(32).toString('hex')}`;
    const tokenHash = hashAgentToken(rawToken);

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
      })
      .returning();

    if (!inserted) {
      throw new Error('Failed to register agent in database');
    }

    logger.info(
      { agentId: inserted.id, tenantId, name: inserted.name },
      'Registered new distributed execution agent',
    );

    return {
      agentId: inserted.id,
      tenantId: inserted.tenantId,
      name: inserted.name,
      token: rawToken,
      status: inserted.status as 'online' | 'busy' | 'draining' | 'offline',
      tags: inserted.tags as string[],
      capabilities: inserted.capabilities as string[],
      createdAt: inserted.createdAt.toISOString(),
    };
  }

  /**
   * Authenticates an agent via its raw Bearer token by computing its SHA-256 hash.
   */
  async authenticateAgent(token: string) {
    const { db } = getDatabase();
    if (!db || !token) return null;

    const tokenHash = hashAgentToken(token);
    const [agent] = await db
      .select()
      .from(agents)
      .where(eq(agents.tokenHash, tokenHash))
      .limit(1);

    return agent || null;
  }

  /**
   * Updates an agent's heartbeat and health status.
   */
  async recordHeartbeat(
    agentId: string,
    status: 'online' | 'busy' | 'draining' | 'offline' = 'online',
    metrics?: Record<string, unknown>,
  ) {
    const { db } = getDatabase();
    if (!db) return false;

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

    return !!updated;
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
      createdAt: r.createdAt.toISOString(),
      updatedAt: r.updatedAt.toISOString(),
    }));
  }

  /**
   * Enqueues an execution task into the agent dispatch queue.
   */
  async enqueueAgentJob(
    testRunId: string,
    tenantId: string = DEFAULT_TENANT_ID,
    engineIds: string[] = [],
    options?: Record<string, unknown>,
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

    const payload: AgentJobDispatch = {
      jobId: crypto.randomUUID(),
      testRunId,
      tenantId,
      target: {
        id: targetRow.id,
        name: targetRow.name,
        baseUrl: targetRow.baseUrl,
        scope: targetRow.scope as Record<string, unknown>,
      },
      engineIds,
      options,
    };

    const [job] = await db
      .insert(agentJobs)
      .values({
        id: payload.jobId,
        tenantId,
        testRunId,
        status: 'pending',
        payload: payload as unknown as Record<string, unknown>,
      })
      .returning();

    if (!job) {
      throw new Error('Failed to enqueue agent job');
    }

    logger.info(
      { jobId: job.id, testRunId, tenantId },
      'Enqueued distributed agent execution task',
    );

    return job.id;
  }

  /**
   * Polls for pending jobs matching agent tenant, tags, or capabilities.
   */
  async pollJobs(
    agentId: string,
    tenantId: string,
    _capabilities: string[] = [],
    _tags: string[] = [],
    maxJobs = 1,
  ): Promise<AgentJobDispatch[]> {
    const { db } = getDatabase();
    if (!db) return [];

    const pending = await db
      .select()
      .from(agentJobs)
      .where(and(eq(agentJobs.tenantId, tenantId), eq(agentJobs.status, 'pending')))
      .limit(maxJobs);

    if (pending.length === 0) return [];

    const dispatched: AgentJobDispatch[] = [];
    for (const job of pending) {
      await db
        .update(agentJobs)
        .set({
          agentId,
          status: 'dispatched',
          dispatchedAt: new Date(),
          updatedAt: new Date(),
        })
        .where(eq(agentJobs.id, job.id));

      const payload = job.payload as unknown as AgentJobDispatch;
      dispatched.push(payload);
    }

    return dispatched;
  }

  /**
   * Handles in-flight execution progress reports from agents.
   */
  async reportJobProgress(
    jobId: string,
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

    if (!job) return;

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
   */
  async completeJob(jobId: string, report: AgentJobCompletionReport) {
    const { db } = getDatabase();
    if (!db) throw new Error('Database unavailable');

    const [job] = await db
      .select()
      .from(agentJobs)
      .where(eq(agentJobs.id, jobId))
      .limit(1);

    if (!job) throw new Error(`Agent job "${jobId}" not found`);

    const run = await testRunsService.getTestRunById(job.testRunId);
    if (!run) throw new Error(`Test run "${job.testRunId}" not found`);

    // 1. Create test_executions records for each reported engine execution
    const executionMap = new Map<string, string>();
    let defaultExecutionId: string | null = null;

    if (report.executions && report.executions.length > 0) {
      for (const exec of report.executions) {
        const [insertedExec] = await db
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
      const [fallbackExec] = await db
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
    const severityCounts: Record<FindingSeverity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

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
        executionId: execId,
        targetId: run.targetId,
        metadata: (raw.evidenceData as Record<string, unknown>) || {},
      });
    }

    // 3. Ingest metrics
    for (const m of report.metrics) {
      const metricExecId = (m.tags?.engineId && executionMap.get(m.tags.engineId)) || defaultExecutionId;
      await metricsService.saveMetric({
        testRunId: job.testRunId,
        executionId: metricExecId,
        name: m.name,
        value: m.value,
        unit: m.unit,
        tags: m.tags || {},
      });
    }

    const finalStatus = report.status === 'completed' ? 'completed' : 'failed';
    const summary: TestRunSummary = {
      totalTests: report.executions.length || 1,
      passedTests: report.executions.filter((e) => e.status === 'completed').length || (report.status === 'completed' ? 1 : 0),
      failedTests: report.executions.filter((e) => e.status === 'failed').length || (report.status === 'failed' ? 1 : 0),
      errorTests: report.error ? 1 : 0,
      findingsCount: severityCounts,
    };

    await testRunsService.updateTestRunStatus(job.testRunId, finalStatus, summary);

    // Persist reports
    try {
      await reportsService.persistTestRunReports(job.testRunId);
    } catch (err: unknown) {
      logger.warn({ err }, 'Failed to persist test run reports from agent job');
    }

    // Mark agent job as completed
    await db
      .update(agentJobs)
      .set({
        status: 'completed',
        result: report as unknown as Record<string, unknown>,
        completedAt: new Date(),
        updatedAt: new Date(),
      })
      .where(eq(agentJobs.id, jobId));

    executionManager.emit('run', {
      testRunId: job.testRunId,
      status: finalStatus,
      summary,
      timestamp: new Date().toISOString(),
    });

    logger.info(
      { jobId, testRunId: job.testRunId, status: finalStatus, findingsCount: report.findings.length },
      'Agent execution job completed and ingested into control plane',
    );
  }

  /**
   * Marks an agent job as failed.
   */
  async failJob(jobId: string, error: string) {
    const { db } = getDatabase();
    if (!db) return;

    const [job] = await db
      .select()
      .from(agentJobs)
      .where(eq(agentJobs.id, jobId))
      .limit(1);

    if (!job) return;

    await db
      .update(agentJobs)
      .set({
        status: 'failed',
        error,
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
  }
}

export const agentDispatcherService = new AgentDispatcherService();
