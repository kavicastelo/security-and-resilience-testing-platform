import crypto from 'node:crypto';
import { eq, and, or, inArray } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { findings } from './db/schema.js';
import { Finding, FindingSeverity, FindingConfidence, FindingStatus } from '@security-lab/domain';
import { logger } from '@security-lab/logger';

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

export interface HardenedFingerprintParams {
  targetId: string;
  engineId: string;
  category: string;
  ruleOrCweId: string;
  endpointPath?: string;
  parameterName?: string;
}

/**
 * Computes a collision-resistant finding fingerprint according to the platform standard:
 * SHA-256(targetId : engineId : category : ruleOrCweId : endpointPath : (parameterName || ''))
 */
export function computeHardenedFindingFingerprint(params: HardenedFingerprintParams): string {
  const targetId = params.targetId.trim();
  const engineId = params.engineId.trim();
  const category = params.category.trim();
  const ruleOrCweId = params.ruleOrCweId.trim();
  const endpointPath = (params.endpointPath || '').trim();
  const parameterName = (params.parameterName || '').trim();

  const rawFingerprint = `${targetId}:${engineId}:${category}:${ruleOrCweId}:${endpointPath}:${parameterName}`;
  return crypto.createHash('sha256').update(rawFingerprint).digest('hex');
}

export function extractFindingComponents(rawFinding: {
  category: string;
  title: string;
  location?: string;
  evidence?: { request?: { url?: string } };
  metadata?: Record<string, unknown>;
}): { ruleOrCweId: string; endpointPath: string; parameterName: string } {
  // 1. Extract rule or CWE ID
  let ruleOrCweId = rawFinding.title;
  if (rawFinding.metadata) {
    if (typeof rawFinding.metadata.ruleId === 'string' && rawFinding.metadata.ruleId.trim()) {
      ruleOrCweId = rawFinding.metadata.ruleId.trim();
    } else if (typeof rawFinding.metadata.cwe === 'string' && rawFinding.metadata.cwe.trim()) {
      ruleOrCweId = rawFinding.metadata.cwe.trim();
    } else if (typeof rawFinding.metadata.cve === 'string' && rawFinding.metadata.cve.trim()) {
      ruleOrCweId = rawFinding.metadata.cve.trim();
    }
  }

  // 2. Extract endpoint path
  let endpointPath = '';
  if (rawFinding.metadata?.endpoint) {
    if (typeof rawFinding.metadata.endpoint === 'object') {
      const epObj = rawFinding.metadata.endpoint as { path?: string };
      if (typeof epObj.path === 'string') {
        endpointPath = epObj.path;
      }
    } else if (typeof rawFinding.metadata.endpoint === 'string') {
      const parts = rawFinding.metadata.endpoint.trim().split(' ');
      endpointPath = parts.length > 1 ? parts[1]! : parts[0]!;
    }
  } else if (typeof rawFinding.metadata?.path === 'string') {
    endpointPath = rawFinding.metadata.path;
  } else if (rawFinding.location) {
    const parts = rawFinding.location.trim().split(' ');
    endpointPath = parts.length > 1 ? parts[1]! : parts[0]!;
  } else if (rawFinding.evidence?.request?.url) {
    try {
      endpointPath = new URL(rawFinding.evidence.request.url).pathname;
    } catch {
      endpointPath = rawFinding.evidence.request.url;
    }
  }

  // 3. Extract parameter name
  let parameterName = '';
  if (rawFinding.metadata) {
    if (typeof rawFinding.metadata.parameter === 'string') {
      parameterName = rawFinding.metadata.parameter;
    } else if (typeof rawFinding.metadata.param === 'string') {
      parameterName = rawFinding.metadata.param;
    } else if (typeof rawFinding.metadata.targetField === 'string') {
      parameterName = rawFinding.metadata.targetField;
    }
  }

  return { ruleOrCweId, endpointPath, parameterName };
}

export class FindingsService {
  /**
   * Persists or updates a finding according to the vulnerability lifecycle state machine:
   * - New finding: inserted with status 'open' and occurrenceCount = 1.
   * - Existing 'open' / 'acknowledged' / 'in_progress': increments occurrenceCount and updates lastDetectedAt.
   * - Existing 'resolved': transitions status to 'regressed', updates lastDetectedAt, logs regression event.
   * - Existing 'false_positive' / 'accepted_risk' / 'ignored': preserves triaged status while updating timestamps.
   */
  async saveFinding(input: CreateFindingInput): Promise<Finding> {
    const { db } = getDatabase();

    // Query existing finding with identical fingerprint for this specific target
    const [existing] = await db
      .select()
      .from(findings)
      .where(and(eq(findings.targetId, input.targetId), eq(findings.fingerprint, input.fingerprint)))
      .limit(1);

    if (existing) {
      const previousStatus = existing.status;
      const occurrenceCount = (existing.occurrenceCount || 1) + 1;
      const now = new Date();
      const existingMetadata = (existing.metadata as Record<string, unknown>) || {};

      // Case A: Regression transition (was resolved, now re-detected)
      if (previousStatus === 'resolved') {
        const regressionEvents = Array.isArray(existingMetadata.regressionEvents)
          ? [...existingMetadata.regressionEvents]
          : [];
        regressionEvents.push({
          regressedAt: now.toISOString(),
          testRunId: input.testRunId,
          executionId: input.executionId,
        });

        const mergedMetadata = {
          ...existingMetadata,
          ...(input.metadata || {}),
          regressionEvents,
        };

        const [updated] = await db
          .update(findings)
          .set({
            status: 'regressed',
            occurrenceCount,
            lastDetectedAt: now,
            fixedAt: null,
            fixedInRunId: null,
            testRunId: input.testRunId,
            executionId: input.executionId,
            evidenceId: input.evidenceId || existing.evidenceId,
            description: input.description,
            recommendation: input.recommendation || existing.recommendation,
            metadata: mergedMetadata,
          })
          .where(eq(findings.id, existing.id))
          .returning();

        logger.warn(
          {
            findingId: existing.id,
            targetId: input.targetId,
            fingerprint: input.fingerprint,
            title: input.title,
            occurrenceCount,
          },
          'Finding lifecycle transition: regression detected for previously resolved finding',
        );

        return this.mapToDomainFinding(updated!);
      }

      // Case B: Preserving analyst triage decisions (false_positive, accepted_risk, ignored)
      if (
        previousStatus === 'false_positive' ||
        previousStatus === 'accepted_risk' ||
        previousStatus === 'ignored'
      ) {
        const [updated] = await db
          .update(findings)
          .set({
            occurrenceCount,
            lastDetectedAt: now,
            testRunId: input.testRunId,
            executionId: input.executionId,
            evidenceId: input.evidenceId || existing.evidenceId,
            metadata: { ...existingMetadata, ...(input.metadata || {}) },
          })
          .where(eq(findings.id, existing.id))
          .returning();

        logger.info(
          {
            findingId: existing.id,
            targetId: input.targetId,
            status: previousStatus,
            occurrenceCount,
          },
          'Finding lifecycle transition: recurring finding detected (triaged status preserved)',
        );

        return this.mapToDomainFinding(updated!);
      }

      // Case C: Standard recurring finding (was open, in_progress, acknowledged, or already regressed)
      const [updated] = await db
        .update(findings)
        .set({
          occurrenceCount,
          lastDetectedAt: now,
          testRunId: input.testRunId,
          executionId: input.executionId,
          evidenceId: input.evidenceId || existing.evidenceId,
          description: input.description,
          recommendation: input.recommendation || existing.recommendation,
          metadata: { ...existingMetadata, ...(input.metadata || {}) },
        })
        .where(eq(findings.id, existing.id))
        .returning();

      logger.info(
        {
          findingId: existing.id,
          targetId: input.targetId,
          status: previousStatus,
          occurrenceCount,
        },
        'Finding lifecycle transition: recurring finding detected',
      );

      return this.mapToDomainFinding(updated!);
    }

    // Case D: New Finding
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
        occurrenceCount: 1,
        metadata: input.metadata || {},
      })
      .returning();

    if (!inserted) {
      throw new Error('Failed to persist finding');
    }

    logger.info(
      {
        findingId: inserted.id,
        targetId: input.targetId,
        fingerprint: input.fingerprint,
        title: input.title,
        severity: input.severity,
      },
      'Finding lifecycle transition: new finding detected',
    );

    return this.mapToDomainFinding(inserted);
  }

  /**
   * Reconciles findings after a test run:
   * Any previously 'open' or 'regressed' findings for this target that were NOT
   * detected in the newly completed test run are automatically transitioned to 'resolved'.
   */
  async reconcileTestRunFindings(
    testRunId: string,
    targetId: string,
    engineIds?: string[],
  ): Promise<{ resolvedCount: number; resolvedFindingIds: string[] }> {
    const { db } = getDatabase();

    // 1. Get all fingerprints detected in this test run
    const detectedRows = await db
      .select({ fingerprint: findings.fingerprint })
      .from(findings)
      .where(and(eq(findings.testRunId, testRunId), eq(findings.targetId, targetId)));

    const detectedFingerprints = new Set(detectedRows.map((r) => r.fingerprint));

    // 2. Query previously open or regressed findings for this target
    const conditions = [
      eq(findings.targetId, targetId),
      or(eq(findings.status, 'open'), eq(findings.status, 'regressed')),
    ];

    if (engineIds && engineIds.length > 0) {
      conditions.push(inArray(findings.testDefinitionId, engineIds));
    }

    const candidateFindings = await db
      .select()
      .from(findings)
      .where(and(...conditions));

    const resolvedFindingIds: string[] = [];
    const now = new Date();

    for (const f of candidateFindings) {
      // If the finding was not re-detected in this run, it has been resolved
      if (!detectedFingerprints.has(f.fingerprint)) {
        const metadata = (f.metadata as Record<string, unknown>) || {};
        const [updated] = await db
          .update(findings)
          .set({
            status: 'resolved',
            fixedAt: now,
            fixedInRunId: testRunId,
            metadata: {
              ...metadata,
              resolvedInTestRunId: testRunId,
              resolvedAt: now.toISOString(),
            },
          })
          .where(eq(findings.id, f.id))
          .returning();

        if (updated) {
          resolvedFindingIds.push(updated.id);
          logger.info(
            {
              findingId: f.id,
              targetId,
              fixedInRunId: testRunId,
              title: f.title,
              previousStatus: f.status,
            },
            'Finding lifecycle transition: previously detected finding has been resolved',
          );
        }
      }
    }

    return {
      resolvedCount: resolvedFindingIds.length,
      resolvedFindingIds,
    };
  }

  async getFindingById(id: string): Promise<Finding | null> {
    const { db } = getDatabase();
    const [row] = await db.select().from(findings).where(eq(findings.id, id));
    if (!row) return null;
    return this.mapToDomainFinding(row);
  }

  async listFindings(filters?: {
    testRunId?: string;
    targetId?: string;
    severity?: FindingSeverity;
    status?: FindingStatus;
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
    if (filters?.status) {
      conditions.push(eq(findings.status, filters.status));
    }

    const query = db.select().from(findings);
    const rows = conditions.length > 0
      ? await query.where(and(...conditions)).orderBy(findings.firstDetectedAt)
      : await query.orderBy(findings.firstDetectedAt);

    return rows.map((row) => this.mapToDomainFinding(row));
  }

  async updateFindingStatus(
    id: string,
    status: FindingStatus,
    notes?: string,
  ): Promise<Finding | null> {
    const { db } = getDatabase();
    const existing = await this.getFindingById(id);
    if (!existing) return null;

    const metadata = {
      ...existing.metadata,
      statusUpdatedNotes: notes,
      statusUpdatedAt: new Date().toISOString(),
    };

    const updateValues: Record<string, unknown> = {
      status,
      metadata,
    };

    if (status === 'resolved') {
      updateValues.fixedAt = new Date();
    }

    const [updated] = await db
      .update(findings)
      .set(updateValues)
      .where(eq(findings.id, id))
      .returning();

    if (!updated) return null;

    logger.info(
      { findingId: id, previousStatus: existing.status, newStatus: status, notes },
      'Finding lifecycle transition: manual triage status update',
    );

    return this.mapToDomainFinding(updated);
  }

  async deleteFinding(id: string): Promise<boolean> {
    const { db } = getDatabase();
    const deleted = await db.delete(findings).where(eq(findings.id, id)).returning();
    return deleted.length > 0;
  }

  private mapToDomainFinding(row: typeof findings.$inferSelect): Finding {
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
      occurrenceCount: row.occurrenceCount,
      fixedInRunId: row.fixedInRunId ?? undefined,
      firstDetectedAt: row.firstDetectedAt,
      lastDetectedAt: row.lastDetectedAt,
      fixedAt: row.fixedAt ?? undefined,
      metadata: (row.metadata as Record<string, unknown>) || {},
    };
  }
}

export const findingsService = new FindingsService();
