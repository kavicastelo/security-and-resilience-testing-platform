import { eq } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { metrics } from './db/schema.js';
import { Metric } from '@security-lab/domain';

export interface CreateMetricInput {
  id?: string;
  testRunId: string;
  executionId: string;
  name: string;
  value: number;
  unit?: string;
  tags?: Record<string, string>;
  threshold?: {
    max?: number;
    min?: number;
    passed: boolean;
  };
}

export class MetricsService {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async saveMetric(input: CreateMetricInput, dbClient?: any): Promise<Metric> {
    const db = dbClient || getDatabase().db;

    const [inserted] = await db
      .insert(metrics)
      .values({
        id: input.id,
        testRunId: input.testRunId,
        executionId: input.executionId,
        name: input.name,
        value: input.value,
        unit: input.unit || 'ms',
        tags: input.tags || {},
        threshold: input.threshold || null,
      })
      .returning();

    if (!inserted) {
      throw new Error('Failed to persist metric record');
    }

    return {
      id: inserted.id,
      testRunId: inserted.testRunId,
      executionId: inserted.executionId,
      name: inserted.name,
      value: inserted.value,
      unit: inserted.unit,
      tags: (inserted.tags as Record<string, string>) || {},
      threshold: inserted.threshold as Metric['threshold'],
      timestamp: inserted.createdAt,
    };
  }

  async listMetricsByTestRunId(testRunId: string): Promise<Metric[]> {
    const { db } = getDatabase();
    const rows = await db
      .select()
      .from(metrics)
      .where(eq(metrics.testRunId, testRunId))
      .orderBy(metrics.createdAt);

    return rows.map((r) => ({
      id: r.id,
      testRunId: r.testRunId,
      executionId: r.executionId,
      name: r.name,
      value: r.value,
      unit: r.unit,
      tags: (r.tags as Record<string, string>) || {},
      threshold: r.threshold as Metric['threshold'],
      timestamp: r.createdAt,
    }));
  }
}

export const metricsService = new MetricsService();
