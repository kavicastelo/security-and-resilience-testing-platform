import { eq, and } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { testRuns, projects } from './db/schema.js';
import { targetsService } from './targets.service.js';
import { projectsService } from './projects.service.js';
import { isLocalHost } from './target-verification.js';
import {
  CreateTestRunInput,
  TestRun,
  TestRunStatus,
  TestRunSummary,
} from '@security-lab/domain';
import { billingService } from './billing/billing.service.js';

export class TestRunsService {
  async createTestRun(input: CreateTestRunInput, tenantId?: string, workspaceId?: string): Promise<TestRun> {
    const { db } = getDatabase();

    // 0. Verify Project workspace boundary if workspaceId is provided
    if (workspaceId) {
      const project = await projectsService.getProjectById(input.projectId, tenantId, workspaceId);
      if (!project) {
        throw new Error(`Cannot start test run: Project "${input.projectId}" not found or access denied in workspace`);
      }
    }

    // 1. Verify Target exists and is accessible within tenant boundary
    const target = await targetsService.getTargetById(input.targetId, tenantId);
    if (!target) {
      throw new Error(`Cannot start test run: Target "${input.targetId}" not found or access denied`);
    }

    if (target.projectId !== input.projectId) {
      throw new Error(`Target "${input.targetId}" does not belong to project "${input.projectId}"`);
    }

    // 1.1 Target Ownership Verification Gate:
    // If target is external and verificationStatus !== 'VERIFIED', reject active scanning plans.
    let isLocal = false;
    try {
      const targetHost = new URL(target.baseUrl).hostname;
      isLocal = isLocalHost(targetHost);
    } catch {
      isLocal = false;
    }

    const profile = (input.profileId || '').toLowerCase();
    const isActiveProfile =
      profile === 'active' ||
      profile === 'active-scan' ||
      profile === 'active-scanning' ||
      profile === 'dast' ||
      profile === 'fuzzing' ||
      profile === 'active_scan';
    const isExplicitActive =
      (input.metadata as Record<string, unknown> | undefined)?.activeScanning === true ||
      (input as any).activeScanning === true;
    const hasActiveEngines =
      Array.isArray((input as any).engines) &&
      (input as any).engines.some((e: string) =>
        e.includes('zap') || e.includes('active') || e.includes('fuzz'),
      );

    const isActiveScanPlan = isActiveProfile || isExplicitActive || hasActiveEngines;

    if (!isLocal && target.verificationStatus !== 'VERIFIED' && isActiveScanPlan) {
      throw new Error(
        `TARGET_UNVERIFIED: External target "${target.baseUrl}" requires verified ownership before active scanning plans can be executed. Current verification status is "${target.verificationStatus || 'PENDING'}". Please complete the DNS TXT or HTTP .well-known ownership challenge.`,
      );
    }

    // 2. Persist TestRun session
    const [inserted] = await db
      .insert(testRuns)
      .values({
        projectId: input.projectId,
        targetId: input.targetId,
        environmentId: input.environmentId,
        profileId: input.profileId,
        status: 'queued',
        triggeredBy: input.triggeredBy || 'manual',
        metadata: input.metadata || {},
        summary: {
          totalTests: 0,
          passedTests: 0,
          failedTests: 0,
          errorTests: 0,
          findingsCount: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        },
      })
      .returning();

    if (!inserted) {
      throw new Error('Failed to create TestRun record');
    }

    return this.mapToDomainTestRun(inserted);
  }

  async getTestRunById(id: string, tenantId?: string): Promise<TestRun | null> {
    const { db } = getDatabase();
    if (tenantId) {
      const [row] = await db
        .select({ testRun: testRuns })
        .from(testRuns)
        .innerJoin(projects, eq(testRuns.projectId, projects.id))
        .where(and(eq(testRuns.id, id), eq(projects.tenantId, tenantId)))
        .limit(1);

      if (!row) return null;
      return this.mapToDomainTestRun(row.testRun);
    }

    const [row] = await db.select().from(testRuns).where(eq(testRuns.id, id)).limit(1);
    if (!row) return null;

    return this.mapToDomainTestRun(row);
  }

  async listTestRuns(
    filters?: { projectId?: string; targetId?: string },
    tenantId?: string,
  ): Promise<TestRun[]> {
    const { db } = getDatabase();
    const conditions = [];

    if (filters?.projectId) {
      conditions.push(eq(testRuns.projectId, filters.projectId));
    }
    if (filters?.targetId) {
      conditions.push(eq(testRuns.targetId, filters.targetId));
    }

    if (tenantId) {
      conditions.push(eq(projects.tenantId, tenantId));
      const rows = await db
        .select({ testRun: testRuns })
        .from(testRuns)
        .innerJoin(projects, eq(testRuns.projectId, projects.id))
        .where(and(...conditions))
        .orderBy(testRuns.createdAt);

      return rows.map((r) => this.mapToDomainTestRun(r.testRun));
    }

    const query = db.select().from(testRuns);
    const rows = conditions.length > 0
      ? await query.where(and(...conditions)).orderBy(testRuns.createdAt)
      : await query.orderBy(testRuns.createdAt);

    return rows.map((r) => this.mapToDomainTestRun(r));
  }

  async updateTestRunStatus(
    id: string,
    status: TestRunStatus,
    summary?: TestRunSummary,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    dbClient?: any,
  ): Promise<TestRun> {
    const db = dbClient || getDatabase().db;
    const updateValues: Record<string, unknown> = { status };

    if (status === 'running') {
      updateValues.startedAt = new Date();
    } else if (['completed', 'failed', 'cancelled'].includes(status)) {
      updateValues.completedAt = new Date();
    }

    if (summary) {
      updateValues.summary = summary;
    }

    const [updated] = await db
      .update(testRuns)
      .set(updateValues)
      .where(eq(testRuns.id, id))
      .returning();

    if (!updated) {
      throw new Error(`TestRun "${id}" not found`);
    }

    if (['completed', 'failed', 'cancelled'].includes(status) && updated.startedAt && updated.completedAt) {
      try {
        const durationSec = Math.max(1, (updated.completedAt.getTime() - updated.startedAt.getTime()) / 1000);
        const [proj] = await db
          .select({ workspaceId: projects.workspaceId })
          .from(projects)
          .where(eq(projects.id, updated.projectId));
        if (proj?.workspaceId) {
          await billingService.recordRunUsage(proj.workspaceId, durationSec);
        }
      } catch {
        // Safe fallback if billing tracking encounters non-fatal DB issue
      }
    }

    return this.mapToDomainTestRun(updated);
  }

  async deleteTestRun(id: string, tenantId?: string): Promise<boolean> {
    const { db } = getDatabase();
    if (tenantId) {
      const existing = await this.getTestRunById(id, tenantId);
      if (!existing) return false;
    }

    const deleted = await db.delete(testRuns).where(eq(testRuns.id, id)).returning();
    return deleted.length > 0;
  }

  private mapToDomainTestRun(row: typeof testRuns.$inferSelect): TestRun {
    return {
      id: row.id,
      projectId: row.projectId,
      targetId: row.targetId,
      environmentId: row.environmentId ?? undefined,
      profileId: row.profileId ?? undefined,
      status: row.status as TestRunStatus,
      triggeredBy: row.triggeredBy as TestRun['triggeredBy'],
      startedAt: row.startedAt ?? undefined,
      completedAt: row.completedAt ?? undefined,
      summary: row.summary as TestRunSummary,
      metadata: (row.metadata as Record<string, unknown>) || {},
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  }
}

export const testRunsService = new TestRunsService();
