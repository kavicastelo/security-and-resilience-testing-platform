import crypto from 'node:crypto';
import { eq, and, or, inArray } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { findings, targets, projects } from './db/schema.js';
import { Finding, FindingSeverity, FindingConfidence, FindingStatus } from '@security-lab/domain';
import { logger } from '@security-lab/logger';
import { DEFAULT_TENANT_ID } from './tenants.service.js';
import { webhookQueueService } from './webhook-queue.js';

export interface CreateFindingInput {
  id?: string;
  tenantId?: string;
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
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async saveFinding(input: CreateFindingInput, dbClient?: any): Promise<Finding> {
    const db = dbClient || getDatabase().db;

    // Query existing finding with identical fingerprint for this specific target and tenant
    const findConditions = [eq(findings.targetId, input.targetId), eq(findings.fingerprint, input.fingerprint)];
    if (input.tenantId) {
      findConditions.push(eq(findings.tenantId, input.tenantId));
    }
    const [existing] = await db
      .select()
      .from(findings)
      .where(and(...findConditions))
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
        tenantId: input.tenantId || DEFAULT_TENANT_ID,
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

    // Asynchronously dispatch finding.created webhook
    try {
      const targetRow = await db
        .select({ projectId: targets.projectId })
        .from(targets)
        .where(eq(targets.id, input.targetId))
        .limit(1);

      if (targetRow[0]?.projectId) {
        const projectRow = await db
          .select({ workspaceId: projects.workspaceId })
          .from(projects)
          .where(eq(projects.id, targetRow[0].projectId))
          .limit(1);

        const workspaceId = projectRow[0]?.workspaceId || '00000000-0000-0000-0000-000000000000';
        await webhookQueueService.dispatchEvent(workspaceId, 'finding.created', {
          findingId: inserted.id,
          targetId: inserted.targetId,
          fingerprint: inserted.fingerprint,
          title: inserted.title,
          category: inserted.category,
          severity: inserted.severity,
          testDefinitionId: inserted.testDefinitionId,
          testRunId: inserted.testRunId,
          description: inserted.description,
        });
      }
    } catch (whErr) {
      logger.warn({ whErr }, 'Failed to dispatch finding.created webhook');
    }

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

  async getFindingById(id: string, tenantId?: string): Promise<Finding | null> {
    const { db } = getDatabase();
    const conditions = [eq(findings.id, id)];
    if (tenantId) {
      conditions.push(eq(findings.tenantId, tenantId));
    }
    const [row] = await db.select().from(findings).where(and(...conditions)).limit(1);
    if (!row) return null;
    return this.mapToDomainFinding(row);
  }

  async listFindings(filters?: {
    testRunId?: string;
    targetId?: string;
    severity?: FindingSeverity;
    status?: FindingStatus;
    tenantId?: string;
    isFlapping?: boolean;
  }): Promise<Finding[]> {
    const { db } = getDatabase();
    const conditions = [];

    if (filters?.tenantId) {
      conditions.push(eq(findings.tenantId, filters.tenantId));
    }
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
    if (filters?.isFlapping !== undefined) {
      conditions.push(eq(findings.isFlapping, filters.isFlapping));
    }

    const query = db.select().from(findings);
    const rows = conditions.length > 0
      ? await query.where(and(...conditions)).orderBy(findings.firstDetectedAt)
      : await query.orderBy(findings.firstDetectedAt);

    return rows.map((row) => this.mapToDomainFinding(row));
  }

  /**
   * Enhanced Triage State Machine enforcing transition integrity and audit history.
   * Enforces valid transitions:
   * OPEN -> CONFIRMED -> RESOLVED / FALSE_POSITIVE / ACCEPTED_RISK.
   */
  async triageFinding(
    id: string,
    request: {
      status: FindingStatus | string;
      comment?: string;
      notes?: string;
      expiresAt?: string;
      actorId?: string;
    },
    actorId?: string,
    tenantId?: string,
  ): Promise<Finding | null> {
    const { db } = getDatabase();
    const existing = await this.getFindingById(id, tenantId);
    if (!existing) return null;

    const normalizedStatus = (request.status.toLowerCase() === 'risk_accepted'
      ? 'accepted_risk'
      : request.status.toLowerCase()) as FindingStatus;

    const currentStatus = existing.status.toLowerCase();
    const comment = request.comment || request.notes || '';
    const effectiveActor = request.actorId || actorId || 'system';

    // 1. Validate status transitions
    const validTransitions: Record<string, string[]> = {
      open: ['confirmed', 'resolved', 'false_positive', 'accepted_risk', 'ignored'],
      confirmed: ['open', 'resolved', 'false_positive', 'accepted_risk', 'ignored'],
      regressed: ['open', 'confirmed', 'resolved', 'false_positive', 'accepted_risk', 'ignored'],
      false_positive: ['open', 'confirmed', 'resolved'],
      accepted_risk: ['open', 'confirmed', 'resolved'],
      resolved: ['open', 'confirmed', 'regressed'],
      ignored: ['open', 'confirmed', 'resolved'],
      acknowledged: ['open', 'confirmed', 'in_progress', 'resolved', 'false_positive', 'accepted_risk', 'ignored'],
      in_progress: ['open', 'confirmed', 'resolved', 'false_positive', 'accepted_risk', 'ignored'],
    };

    if (currentStatus !== normalizedStatus) {
      const allowed = validTransitions[currentStatus] || ['open', 'confirmed', 'resolved'];
      if (!allowed.includes(normalizedStatus)) {
        throw new Error(
          `Invalid state transition: Cannot transition finding from "${currentStatus}" to "${normalizedStatus}". Allowed transitions: ${allowed.join(', ')}`,
        );
      }
    }

    // 2. Validate rationale constraints
    if (normalizedStatus === 'false_positive' && (!comment || comment.trim().length === 0)) {
      throw new Error('Rationale comment is required when marking a finding as false_positive');
    }

    if (normalizedStatus === 'accepted_risk') {
      if (!comment || comment.trim().length === 0) {
        throw new Error('Rationale comment is required when accepting risk for a finding');
      }
      if (!request.expiresAt) {
        throw new Error('Expiration date (expiresAt) is strictly required for accepted_risk status');
      }
      const expDate = new Date(request.expiresAt);
      if (Number.isNaN(expDate.getTime()) || expDate.getTime() <= Date.now()) {
        throw new Error('Expiration date (expiresAt) must be a valid future ISO timestamp');
      }
    }

    // 3. Build triage history entry
    const historyEntry = {
      id: crypto.randomUUID(),
      fromStatus: currentStatus,
      toStatus: normalizedStatus,
      timestamp: new Date().toISOString(),
      actorId: effectiveActor,
      comment,
      expiresAt: request.expiresAt || null,
    };

    const existingHistory = Array.isArray(existing.triageHistory) ? [...existing.triageHistory] : [];
    existingHistory.push(historyEntry);

    const metadata = {
      ...existing.metadata,
      statusUpdatedNotes: comment,
      statusUpdatedAt: new Date().toISOString(),
      lastTriagedBy: effectiveActor,
      lastTriageComment: comment,
      ...(request.expiresAt ? { riskAcceptedExpiresAt: request.expiresAt } : {}),
    };

    const updateValues: Record<string, unknown> = {
      status: normalizedStatus,
      metadata,
      triageHistory: existingHistory,
    };

    if (normalizedStatus === 'resolved') {
      updateValues.fixedAt = new Date();
    }

    const updateConditions = [eq(findings.id, id)];
    if (tenantId) {
      updateConditions.push(eq(findings.tenantId, tenantId));
    }

    const [updated] = await db
      .update(findings)
      .set(updateValues)
      .where(and(...updateConditions))
      .returning();

    if (!updated) return null;

    // 4. Record audit event in auditEvents table
    try {
      const { auditEvents } = await import('./db/schema.js');
      await db.insert(auditEvents).values({
        actorId: effectiveActor,
        eventType: 'finding.triaged',
        details: {
          findingId: id,
          targetId: existing.targetId,
          fromStatus: currentStatus,
          toStatus: normalizedStatus,
          comment,
          expiresAt: request.expiresAt || null,
        },
      });
    } catch (auditErr) {
      logger.warn({ err: auditErr, findingId: id }, 'Failed to record triage audit event');
    }

    logger.info(
      {
        findingId: id,
        previousStatus: currentStatus,
        newStatus: normalizedStatus,
        actorId: effectiveActor,
        comment,
      },
      'Finding lifecycle transition: triage state updated with audit log',
    );

    // Asynchronously dispatch finding.triaged webhook
    try {
      const targetRow = await db
        .select({ projectId: targets.projectId })
        .from(targets)
        .where(eq(targets.id, existing.targetId))
        .limit(1);

      if (targetRow[0]?.projectId) {
        const projectRow = await db
          .select({ workspaceId: projects.workspaceId })
          .from(projects)
          .where(eq(projects.id, targetRow[0].projectId))
          .limit(1);

        const workspaceId = projectRow[0]?.workspaceId || '00000000-0000-0000-0000-000000000000';
        await webhookQueueService.dispatchEvent(workspaceId, 'finding.triaged', {
          findingId: id,
          targetId: existing.targetId,
          fromStatus: currentStatus,
          toStatus: normalizedStatus,
          actorId: effectiveActor,
          comment,
          expiresAt: request.expiresAt || null,
        });
      }
    } catch (whErr) {
      logger.warn({ whErr }, 'Failed to dispatch finding.triaged webhook');
    }

    return this.mapToDomainFinding(updated);
  }

  async updateFindingStatus(
    id: string,
    status: FindingStatus | string,
    notes?: string,
    tenantId?: string,
    actorId?: string,
    expiresAt?: string,
  ): Promise<Finding | null> {
    return this.triageFinding(
      id,
      {
        status,
        comment: notes,
        notes,
        expiresAt,
        actorId,
      },
      actorId,
      tenantId,
    );
  }

  async deleteFinding(id: string, tenantId?: string): Promise<boolean> {
    const { db } = getDatabase();
    const existing = await this.getFindingById(id, tenantId);
    if (!existing) return false;

    const deleteConditions = [eq(findings.id, id)];
    if (tenantId) {
      deleteConditions.push(eq(findings.tenantId, tenantId));
    }
    const deleted = await db.delete(findings).where(and(...deleteConditions)).returning();
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
      flappingScore: row.flappingScore ?? 0.0,
      isFlapping: row.isFlapping ?? false,
      triageHistory: (row.triageHistory as Record<string, unknown>[]) || [],
    };
  }
}

export const findingsService = new FindingsService();
