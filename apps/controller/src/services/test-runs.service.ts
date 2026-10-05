import { eq, and } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { testRuns } from './db/schema.js';
import { targetsService } from './targets.service.js';
import {
  CreateTestRunInput,
  TestRun,
  TestRunStatus,
  TestRunSummary,
} from '@security-lab/domain';

export class TestRunsService {
  async createTestRun(input: CreateTestRunInput): Promise<TestRun> {
    const { db } = getDatabase();

    // 1. Verify Target exists and is valid
    const target = await targetsService.getTargetById(input.targetId);
    if (!target) {
      throw new Error(`Cannot start test run: Target "${input.targetId}" not found`);
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

    return {
      id: inserted.id,
      projectId: inserted.projectId,
      targetId: inserted.targetId,
      environmentId: inserted.environmentId ?? undefined,
      profileId: inserted.profileId ?? undefined,
      status: inserted.status as TestRunStatus,
      triggeredBy: inserted.triggeredBy as TestRun['triggeredBy'],
      startedAt: inserted.startedAt ?? undefined,
      completedAt: inserted.completedAt ?? undefined,
      summary: inserted.summary as TestRunSummary,
      metadata: (inserted.metadata as Record<string, unknown>) || {},
      createdAt: inserted.createdAt,
      updatedAt: inserted.updatedAt,
    };
  }

  async getTestRunById(id: string): Promise<TestRun | null> {
    const { db } = getDatabase();
    const [row] = await db.select().from(testRuns).where(eq(testRuns.id, id));
    if (!row) return null;

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

  async listTestRuns(filters?: { projectId?: string; targetId?: string }): Promise<TestRun[]> {
    const { db } = getDatabase();
    const conditions = [];

    if (filters?.projectId) {
      conditions.push(eq(testRuns.projectId, filters.projectId));
    }
    if (filters?.targetId) {
      conditions.push(eq(testRuns.targetId, filters.targetId));
    }

    const query = db.select().from(testRuns);
    const rows = conditions.length > 0
      ? await query.where(and(...conditions)).orderBy(testRuns.createdAt)
      : await query.orderBy(testRuns.createdAt);

    return rows.map((r) => ({
      id: r.id,
      projectId: r.projectId,
      targetId: r.targetId,
      environmentId: r.environmentId ?? undefined,
      profileId: r.profileId ?? undefined,
      status: r.status as TestRunStatus,
      triggeredBy: r.triggeredBy as TestRun['triggeredBy'],
      startedAt: r.startedAt ?? undefined,
      completedAt: r.completedAt ?? undefined,
      summary: r.summary as TestRunSummary,
      metadata: (r.metadata as Record<string, unknown>) || {},
      createdAt: r.createdAt,
      updatedAt: r.updatedAt,
    }));
  }

  async updateTestRunStatus(
    id: string,
    status: TestRunStatus,
    summary?: TestRunSummary,
  ): Promise<TestRun> {
    const { db } = getDatabase();
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

    return {
      id: updated.id,
      projectId: updated.projectId,
      targetId: updated.targetId,
      environmentId: updated.environmentId ?? undefined,
      profileId: updated.profileId ?? undefined,
      status: updated.status as TestRunStatus,
      triggeredBy: updated.triggeredBy as TestRun['triggeredBy'],
      startedAt: updated.startedAt ?? undefined,
      completedAt: updated.completedAt ?? undefined,
      summary: updated.summary as TestRunSummary,
      metadata: (updated.metadata as Record<string, unknown>) || {},
      createdAt: updated.createdAt,
      updatedAt: updated.updatedAt,
    };
  }

  async deleteTestRun(id: string): Promise<boolean> {
    const { db } = getDatabase();
    const deleted = await db.delete(testRuns).where(eq(testRuns.id, id)).returning();
    return deleted.length > 0;
  }
}

export const testRunsService = new TestRunsService();
