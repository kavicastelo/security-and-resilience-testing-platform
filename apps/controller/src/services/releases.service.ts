import { eq } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { releases } from './db/schema.js';
import { Release, ReleaseGateDecision, Policy } from '@security-lab/domain';
import { testRunsService } from './test-runs.service.js';
import { findingsService } from './findings.service.js';
import { metricsService } from './metrics.service.js';
import { policiesService } from './policies.service.js';
import { evaluatePolicy, PolicyEvaluationResult } from '@security-lab/policy-engine';
import { calculatePostureScore, PostureScoreResult } from '@security-lab/scoring';

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
}

export interface EvaluateReleaseGateInput {
  testRunId: string;
  policyId?: string;
  projectId?: string;
  name?: string;
  version?: string;
  gitCommit?: string;
  gitBranch?: string;
}

export interface ReleaseGateEvaluationSummary {
  decision: ReleaseGateDecision;
  passed: boolean;
  score: PostureScoreResult;
  gateResult: PolicyEvaluationResult;
  policy: Policy;
  release?: Release;
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
      evaluatedAt: row.evaluatedAt || undefined,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  }

  async evaluateReleaseGate(input: EvaluateReleaseGateInput): Promise<ReleaseGateEvaluationSummary> {
    const testRun = await testRunsService.getTestRunById(input.testRunId);
    if (!testRun) {
      throw new Error(`TestRun "${input.testRunId}" not found`);
    }

    const findings = await findingsService.listFindings({ testRunId: input.testRunId });
    const metrics = await metricsService.listMetricsByTestRunId(input.testRunId);

    const policy = input.policyId
      ? (await policiesService.getPolicyById(input.policyId)) || (await policiesService.getDefaultPolicy())
      : await policiesService.getDefaultPolicy();

    // 1. Evaluate policy violations and decision
    const gateResult = evaluatePolicy(policy, findings, metrics);

    // 2. Compute posture score
    const score = calculatePostureScore(findings);

    let createdRelease: Release | undefined;
    if (input.name && input.version) {
      const { db } = getDatabase();
      const reasons = gateResult.violations.map((v) => `${v.ruleName}: ${v.reason}`).join('; ');

      const [row] = await db
        .insert(releases)
        .values({
          projectId: input.projectId || testRun.projectId,
          name: input.name,
          version: input.version,
          gitCommit: input.gitCommit,
          gitBranch: input.gitBranch,
          testRunId: testRun.id,
          policyId: policy.id,
          decision: gateResult.decision,
          reason: reasons || 'Compliant with security baseline',
          evaluatedAt: new Date(),
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
      policy,
      release: createdRelease,
    };
  }
}

export const releasesService = new ReleasesService();
