import { eq, and } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { findings } from './db/schema.js';
import { Finding, FindingSeverity, FindingConfidence, FindingStatus } from '@security-lab/domain';

export interface CreateFindingInput {
  id?: string;
  fingerprint: string;
  title: string;
  category: string;
  severity: FindingSeverity;
  confidence?: FindingConfidence;
  status?: FindingStatus;
  description: string;
  risk?: string;
  recommendation?: string;
  testDefinitionId: string;
  testRunId: string;
  executionId: string;
  targetId: string;
  releaseId?: string;
  evidenceId?: string;
  metadata?: Record<string, unknown>;
}

export class FindingsService {
  async saveFinding(input: CreateFindingInput): Promise<Finding> {
    const { db } = getDatabase();

    const [inserted] = await db
      .insert(findings)
      .values({
        id: input.id,
        fingerprint: input.fingerprint,
        title: input.title,
        category: input.category,
        severity: input.severity,
        confidence: input.confidence || 'firm',
        status: input.status || 'open',
        description: input.description,
        risk: input.risk,
        recommendation: input.recommendation,
        testDefinitionId: input.testDefinitionId,
        testRunId: input.testRunId,
        executionId: input.executionId,
        targetId: input.targetId,
        releaseId: input.releaseId,
        evidenceId: input.evidenceId,
        metadata: input.metadata || {},
      })
      .returning();

    if (!inserted) {
      throw new Error('Failed to persist finding');
    }

    return {
      id: inserted.id,
      fingerprint: inserted.fingerprint,
      title: inserted.title,
      category: inserted.category,
      severity: inserted.severity,
      confidence: inserted.confidence,
      status: inserted.status,
      description: inserted.description,
      risk: inserted.risk ?? undefined,
      recommendation: inserted.recommendation ?? undefined,
      testDefinitionId: inserted.testDefinitionId,
      testRunId: inserted.testRunId,
      executionId: inserted.executionId,
      targetId: inserted.targetId,
      releaseId: inserted.releaseId ?? undefined,
      evidenceId: inserted.evidenceId ?? undefined,
      firstDetectedAt: inserted.firstDetectedAt,
      lastDetectedAt: inserted.lastDetectedAt,
      fixedAt: inserted.fixedAt ?? undefined,
      metadata: (inserted.metadata as Record<string, unknown>) || {},
    };
  }

  async getFindingById(id: string): Promise<Finding | null> {
    const { db } = getDatabase();
    const [row] = await db.select().from(findings).where(eq(findings.id, id));
    if (!row) return null;

    return {
      id: row.id,
      fingerprint: row.fingerprint,
      title: row.title,
      category: row.category,
      severity: row.severity,
      confidence: row.confidence,
      status: row.status,
      description: row.description,
      risk: row.risk ?? undefined,
      recommendation: row.recommendation ?? undefined,
      testDefinitionId: row.testDefinitionId,
      testRunId: row.testRunId,
      executionId: row.executionId,
      targetId: row.targetId,
      releaseId: row.releaseId ?? undefined,
      evidenceId: row.evidenceId ?? undefined,
      firstDetectedAt: row.firstDetectedAt,
      lastDetectedAt: row.lastDetectedAt,
      fixedAt: row.fixedAt ?? undefined,
      metadata: (row.metadata as Record<string, unknown>) || {},
    };
  }

  async listFindings(filters?: {
    testRunId?: string;
    targetId?: string;
    severity?: FindingSeverity;
  }): Promise<Finding[]> {
    const { db } = getDatabase();
    const conditions = [];

    if (filters?.testRunId) {
      conditions.push(eq(findings.testRunId, filters.testRunId));
    }
    if (filters?.targetId) {
      conditions.push(eq(findings.targetId, filters.targetId));
    }
    if (filters?.severity) {
      conditions.push(eq(findings.severity, filters.severity));
    }

    const query = db.select().from(findings);
    const rows = conditions.length > 0
      ? await query.where(and(...conditions)).orderBy(findings.firstDetectedAt)
      : await query.orderBy(findings.firstDetectedAt);

    return rows.map((row) => ({
      id: row.id,
      fingerprint: row.fingerprint,
      title: row.title,
      category: row.category,
      severity: row.severity,
      confidence: row.confidence,
      status: row.status,
      description: row.description,
      risk: row.risk ?? undefined,
      recommendation: row.recommendation ?? undefined,
      testDefinitionId: row.testDefinitionId,
      testRunId: row.testRunId,
      executionId: row.executionId,
      targetId: row.targetId,
      releaseId: row.releaseId ?? undefined,
      evidenceId: row.evidenceId ?? undefined,
      firstDetectedAt: row.firstDetectedAt,
      lastDetectedAt: row.lastDetectedAt,
      fixedAt: row.fixedAt ?? undefined,
      metadata: (row.metadata as Record<string, unknown>) || {},
    }));
  }
}

export const findingsService = new FindingsService();
