import { eq } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { evidenceRecords } from './db/schema.js';
import { Evidence } from '@security-lab/domain';

export class EvidenceService {
  async saveEvidence(evidence: Evidence): Promise<void> {
    const { db } = getDatabase();

    await db.insert(evidenceRecords).values({
      id: evidence.id,
      testRunId: evidence.testRunId,
      executionId: evidence.executionId,
      request: evidence.request || null,
      response: evidence.response || null,
      expected: (evidence.expected as Record<string, unknown>) || null,
      actual: (evidence.actual as Record<string, unknown>) || null,
      metadata: (evidence.metadata as Record<string, unknown>) || {},
      timestamp: evidence.timestamp,
      environment: evidence.environment,
      applicationVersion: evidence.applicationVersion,
      gitCommit: evidence.gitCommit,
      immutableHash: evidence.immutableHash || '',
    });
  }

  async getEvidenceById(id: string): Promise<Evidence | null> {
    const { db } = getDatabase();
    const [row] = await db.select().from(evidenceRecords).where(eq(evidenceRecords.id, id));
    if (!row) return null;

    return {
      id: row.id,
      testRunId: row.testRunId,
      executionId: row.executionId,
      request: (row.request as Evidence['request']) ?? undefined,
      response: (row.response as Evidence['response']) ?? undefined,
      expected: row.expected,
      actual: row.actual,
      metadata: (row.metadata as Record<string, unknown>) || {},
      timestamp: row.timestamp,
      environment: row.environment,
      applicationVersion: row.applicationVersion ?? undefined,
      gitCommit: row.gitCommit ?? undefined,
      immutableHash: row.immutableHash,
    };
  }

  async listEvidenceByTestRunId(testRunId: string): Promise<Evidence[]> {
    const { db } = getDatabase();
    const rows = await db
      .select()
      .from(evidenceRecords)
      .where(eq(evidenceRecords.testRunId, testRunId));

    return rows.map((row) => ({
      id: row.id,
      testRunId: row.testRunId,
      executionId: row.executionId,
      request: (row.request as Evidence['request']) ?? undefined,
      response: (row.response as Evidence['response']) ?? undefined,
      expected: row.expected,
      actual: row.actual,
      metadata: (row.metadata as Record<string, unknown>) || {},
      timestamp: row.timestamp,
      environment: row.environment,
      applicationVersion: row.applicationVersion ?? undefined,
      gitCommit: row.gitCommit ?? undefined,
      immutableHash: row.immutableHash,
    }));
  }
}

export const evidenceService = new EvidenceService();
