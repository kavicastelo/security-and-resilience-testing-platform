import crypto from 'node:crypto';
import { eq } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { releases, testExecutions } from './db/schema.js';
import { Release, ReleaseGateDecision, Policy } from '@security-lab/domain';
import { testRunsService } from './test-runs.service.js';
import { findingsService } from './findings.service.js';
import { metricsService } from './metrics.service.js';
import { policiesService } from './policies.service.js';
import { evaluatePolicy, PolicyEvaluationResult } from '@security-lab/policy-engine';
import { calculatePostureScore, PostureScoreResult } from '@security-lab/scoring';
import { logger } from '@security-lab/logger';

export interface CreateReleaseInput {
  id?: string;
  projectId: string;
  name: string;
  version: string;
  gitCommit?: string;
  gitBranch?: string;
  testRunId?: string;
  policyId?: string;
  decision?: ReleaseGateDecision;
  reason?: string;
  evaluatorHash?: string;
  metadata?: Record<string, unknown>;
}

export interface EvaluateReleaseGateInput {
  testRunId: string;
  policyId?: string;
  projectId?: string;
  name?: string;
  version?: string;
  gitCommit?: string;
  gitBranch?: string;
  executedProfiles?: string[];
  executedEngines?: string[];
  policyOverride?: Partial<Policy>;
}

export interface ReleaseGateEvaluationSummary {
  decision: ReleaseGateDecision;
  passed: boolean;
  score: PostureScoreResult;
  gateResult: PolicyEvaluationResult;
  policy: Policy;
  release?: Release;
  evaluatorHash: string;
}

export class ReleasesService {
  async createRelease(input: CreateReleaseInput): Promise<Release> {
    const { db } = getDatabase();

    const [row] = await db
      .insert(releases)
      .values({
        id: input.id,
        projectId: input.projectId,
        name: input.name,
        version: input.version,
        gitCommit: input.gitCommit,
        gitBranch: input.gitBranch,
        testRunId: input.testRunId,
        policyId: input.policyId,
        decision: input.decision ?? 'warning',
        reason: input.reason,
        evaluatorHash: input.evaluatorHash,
        metadata: input.metadata || {},
      })
      .returning();

    if (!row) {
      throw new Error('Failed to persist release record');
    }

    return {
      id: row.id,
      projectId: row.projectId,
      name: row.name,
      version: row.version,
      gitCommit: row.gitCommit || undefined,
      gitBranch: row.gitBranch || undefined,
      testRunId: row.testRunId || undefined,
      policyId: row.policyId || undefined,
      decision: row.decision as ReleaseGateDecision,
      reason: row.reason || undefined,
      evaluatorHash: row.evaluatorHash || undefined,
      metadata: (row.metadata as Record<string, unknown>) || {},
      evaluatedAt: row.evaluatedAt || undefined,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  }

  async listReleases(projectId?: string): Promise<Release[]> {
    const { db } = getDatabase();
    const query = projectId
      ? db.select().from(releases).where(eq(releases.projectId, projectId)).orderBy(releases.createdAt)
      : db.select().from(releases).orderBy(releases.createdAt);

    const rows = await query;
    return rows.map((r) => ({
      id: r.id,
      projectId: r.projectId,
      name: r.name,
      version: r.version,
      gitCommit: r.gitCommit || undefined,
      gitBranch: r.gitBranch || undefined,
      testRunId: r.testRunId || undefined,
      policyId: r.policyId || undefined,
      decision: r.decision as ReleaseGateDecision,
      reason: r.reason || undefined,
      evaluatorHash: r.evaluatorHash || undefined,
      metadata: (r.metadata as Record<string, unknown>) || {},
      evaluatedAt: r.evaluatedAt || undefined,
      createdAt: r.createdAt,
      updatedAt: r.updatedAt,
    }));
  }

  async getReleaseById(id: string): Promise<Release | null> {
    const { db } = getDatabase();
    const [row] = await db.select().from(releases).where(eq(releases.id, id)).limit(1);

    if (!row) {
      return null;
    }

    return {
      id: row.id,
      projectId: row.projectId,
      name: row.name,
      version: row.version,
      gitCommit: row.gitCommit || undefined,
      gitBranch: row.gitBranch || undefined,
      testRunId: row.testRunId || undefined,
      policyId: row.policyId || undefined,
      decision: row.decision as ReleaseGateDecision,
      reason: row.reason || undefined,
      evaluatorHash: row.evaluatorHash || undefined,
      metadata: (row.metadata as Record<string, unknown>) || {},
      evaluatedAt: row.evaluatedAt || undefined,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  }

  async evaluateReleaseGate(input: EvaluateReleaseGateInput): Promise<ReleaseGateEvaluationSummary> {
    const { db } = getDatabase();
    const testRun = await testRunsService.getTestRunById(input.testRunId);
    if (!testRun) {
      throw new Error(`TestRun "${input.testRunId}" not found`);
    }

    const findings = await findingsService.listFindings({ testRunId: input.testRunId });
    const metrics = await metricsService.listMetricsByTestRunId(input.testRunId);

    // Collect executed profiles and engines
    const executedExecutions = await db
      .select({ engineId: testExecutions.engineId })
      .from(testExecutions)
      .where(eq(testExecutions.testRunId, input.testRunId));

    const executedEngines = new Set<string>([
      ...executedExecutions.map((e) => e.engineId),
      ...(input.executedEngines || []),
    ]);

    const executedProfiles = new Set<string>();
    if (testRun.profileId) {
      executedProfiles.add(testRun.profileId);
    }
    const runMeta = (testRun.metadata as Record<string, unknown>) || {};
    if (Array.isArray(runMeta.executedProfiles)) {
      for (const p of runMeta.executedProfiles) {
        if (typeof p === 'string') executedProfiles.add(p);
      }
    }
    if (input.executedProfiles) {
      for (const p of input.executedProfiles) executedProfiles.add(p);
    }

    // Resolve base policy
    const basePolicy = input.policyId
      ? (await policiesService.getPolicyById(input.policyId)) || (await policiesService.getDefaultPolicy())
      : await policiesService.getDefaultPolicy();

    // Apply policy override if supplied
    const effectivePolicy: Policy = input.policyOverride
      ? {
          ...basePolicy,
          ...input.policyOverride,
          rules: input.policyOverride.rules || basePolicy.rules,
          waivers: input.policyOverride.waivers || basePolicy.waivers || [],
          requiredProfiles: input.policyOverride.requiredProfiles || basePolicy.requiredProfiles,
        }
      : basePolicy;

    // 1. Evaluate policy violations and decision
    const gateResult = evaluatePolicy(effectivePolicy, findings, metrics, {
      executedProfiles: Array.from(executedProfiles),
      executedEngines: Array.from(executedEngines),
    });

    // 2. Compute posture score (based on active/unwaived findings)
    const waivedIds = new Set(gateResult.waivedFindings.map((w) => w.findingId));
    const activeFindings = findings.filter((f) => !waivedIds.has(f.id));
    const score = calculatePostureScore(activeFindings);

    // 3. Cryptographically seal release evaluation record
    const evaluatorHash = crypto
      .createHash('sha256')
      .update(
        `${effectivePolicy.id}:${testRun.id}:${gateResult.decision}:${gateResult.timestamp.toISOString()}`,
      )
      .digest('hex');

    // 4. Observability: Log release evaluation outcome
    logger.info(
      {
        testRunId: testRun.id,
        policyId: effectivePolicy.id,
        decision: gateResult.decision,
        passed: gateResult.passed,
        evaluatedRulesCount: gateResult.evaluatedRulesCount,
        violationsCount: gateResult.violations.length,
        waivedFindingsCount: gateResult.waivedFindings.length,
        expiredWaiversCount: gateResult.expiredWaivers.length,
        evaluatorHash,
      },
      'Release governance: policy evaluation completed and cryptographically sealed',
    );

    let createdRelease: Release | undefined;
    if (input.name && input.version) {
      const reasons = gateResult.violations.map((v) => `${v.ruleName}: ${v.reason}`).join('; ');

      const releaseMetadata: Record<string, unknown> = {
        evaluatorHash,
        waivedCount: gateResult.waivedFindings.length,
        waivedFindings: gateResult.waivedFindings,
        expiredWaiversCount: gateResult.expiredWaivers.length,
        expiredWaivers: gateResult.expiredWaivers,
        violationsCount: gateResult.violations.length,
        executedProfiles: Array.from(executedProfiles),
        executedEngines: Array.from(executedEngines),
        score: score.score,
        grade: score.grade,
      };

      const [row] = await db
        .insert(releases)
        .values({
          projectId: input.projectId || testRun.projectId,
          name: input.name,
          version: input.version,
          gitCommit: input.gitCommit,
          gitBranch: input.gitBranch,
          testRunId: testRun.id,
          policyId: effectivePolicy.id,
          decision: gateResult.decision,
          reason: reasons || 'Compliant with security baseline',
          evaluatorHash,
          metadata: releaseMetadata,
          evaluatedAt: gateResult.timestamp,
        })
        .returning();

      if (row) {
        createdRelease = {
          id: row.id,
          projectId: row.projectId,
          name: row.name,
          version: row.version,
          gitCommit: row.gitCommit || undefined,
          gitBranch: row.gitBranch || undefined,
          testRunId: row.testRunId || undefined,
          policyId: row.policyId || undefined,
          decision: row.decision as ReleaseGateDecision,
          reason: row.reason || undefined,
          evaluatorHash: row.evaluatorHash || undefined,
          metadata: (row.metadata as Record<string, unknown>) || {},
          evaluatedAt: row.evaluatedAt || undefined,
          createdAt: row.createdAt,
          updatedAt: row.updatedAt,
        };
      }
    }

    return {
      decision: gateResult.decision,
      passed: gateResult.passed,
      score,
      gateResult,
      policy: effectivePolicy,
      release: createdRelease,
      evaluatorHash,
    };
  }

  async deleteRelease(id: string): Promise<boolean> {
    const { db } = getDatabase();
    const deleted = await db.delete(releases).where(eq(releases.id, id)).returning();
    return deleted.length > 0;
  }
}

export const releasesService = new ReleasesService();

