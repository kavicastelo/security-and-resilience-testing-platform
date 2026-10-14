import { eq, and, desc, inArray } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { findings, testRuns } from './db/schema.js';
import { findingsService } from './findings.service.js';
import {
  FlappingAnalysisResponse,
  FlappingRunSnapshot,
} from '@security-lab/contracts';
import { logger } from '@security-lab/logger';

export class FlappingService {
  /**
   * Calculates the historical flapping score for a specific finding across the last N test runs.
   * FlappingScore = (State Transitions) / (Total Runs)
   * If FlappingScore > 0.4, the finding is tagged as UNSTABLE_FLAPPING.
   */
  async calculateFlappingScore(
    findingId: string,
    tenantId?: string,
    maxRuns = 10,
  ): Promise<FlappingAnalysisResponse | null> {
    const { db } = getDatabase();
    const finding = await findingsService.getFindingById(findingId, tenantId);
    if (!finding) return null;

    // 1. Query the last N test runs for this target
    const recentRuns = await db
      .select({
        id: testRuns.id,
        createdAt: testRuns.createdAt,
        status: testRuns.status,
      })
      .from(testRuns)
      .where(eq(testRuns.targetId, finding.targetId))
      .orderBy(desc(testRuns.createdAt))
      .limit(maxRuns);

    const chronologicalRuns = [...recentRuns].reverse();
    const totalRuns = chronologicalRuns.length;

    // 2. Build history and count transitions
    const history: FlappingRunSnapshot[] = [];
    let transitionsCount = 0;

    if (totalRuns > 0) {
      // Find all finding records with this fingerprint associated with these runs
      const runIds = chronologicalRuns.map((r) => r.id);
      const matchingFindings = await db
        .select({
          testRunId: findings.testRunId,
          status: findings.status,
          fixedInRunId: findings.fixedInRunId,
        })
        .from(findings)
        .where(
          and(
            eq(findings.fingerprint, finding.fingerprint),
            eq(findings.targetId, finding.targetId),
            inArray(findings.testRunId, runIds),
          ),
        );

      const findingsByRunId = new Map<string, string>();
      for (const mf of matchingFindings) {
        findingsByRunId.set(mf.testRunId, mf.status);
      }

      // Check if finding metadata contains explicit runHistory
      const explicitHistory = (
        finding.metadata?.runHistory as Array<{ runId: string; status: string; timestamp?: string }> | undefined
      );

      let previousState: string | null = null;

      for (const run of chronologicalRuns) {
        let runStatus = 'ABSENT';

        if (explicitHistory) {
          const matchedExplicit = explicitHistory.find((h) => h.runId === run.id);
          if (matchedExplicit) {
            runStatus = matchedExplicit.status;
          }
        } else if (findingsByRunId.has(run.id)) {
          const fStatus = findingsByRunId.get(run.id)!;
          runStatus = fStatus === 'resolved' ? 'ABSENT' : 'PRESENT';
        }

        history.push({
          runId: run.id,
          status: runStatus,
          timestamp: run.createdAt.toISOString(),
        });

        if (previousState !== null && previousState !== runStatus) {
          transitionsCount++;
        }
        previousState = runStatus;
      }
    }

    // 3. Compute FlappingScore = Transitions / Total Runs
    const flappingScore = totalRuns > 0 ? transitionsCount / totalRuns : 0.0;
    const isFlapping = totalRuns >= 2 && flappingScore > 0.4;
    const roundedScore = Math.round(flappingScore * 1000) / 1000;

    // 4. Update finding record in database
    const existingMetadata = (finding.metadata as Record<string, unknown>) || {};
    const existingTags = Array.isArray(existingMetadata.tags)
      ? [...(existingMetadata.tags as string[])]
      : [];

    let updatedTags = existingTags;
    if (isFlapping) {
      if (!updatedTags.includes('UNSTABLE_FLAPPING')) {
        updatedTags.push('UNSTABLE_FLAPPING');
      }
    } else {
      updatedTags = updatedTags.filter((t) => t !== 'UNSTABLE_FLAPPING');
    }

    const updatedMetadata = {
      ...existingMetadata,
      unstableFlapping: isFlapping,
      flappingScore: roundedScore,
      tags: updatedTags,
    };

    await db
      .update(findings)
      .set({
        flappingScore: roundedScore,
        isFlapping,
        metadata: updatedMetadata,
      })
      .where(eq(findings.id, finding.id));

    if (isFlapping) {
      logger.warn(
        {
          findingId: finding.id,
          fingerprint: finding.fingerprint,
          flappingScore: roundedScore,
          transitionsCount,
          totalRuns,
        },
        'Finding tagged as UNSTABLE_FLAPPING: release gate failure suppressed',
      );
    }

    return {
      findingId: finding.id,
      fingerprint: finding.fingerprint,
      targetId: finding.targetId,
      totalRunsAnalyzed: totalRuns,
      transitionsCount,
      flappingScore: roundedScore,
      isFlapping,
      suppressReleaseGate: isFlapping,
      history,
    };
  }

  /**
   * Analyzes all active findings for a target to update flapping scores after test run completion.
   */
  async analyzeTargetFindings(targetId: string, tenantId?: string, maxRuns = 10): Promise<FlappingAnalysisResponse[]> {
    const activeFindings = await findingsService.listFindings({ targetId, tenantId });
    const results: FlappingAnalysisResponse[] = [];
    for (const f of activeFindings) {
      const res = await this.calculateFlappingScore(f.id, tenantId, maxRuns);
      if (res) {
        results.push(res);
      }
    }
    return results;
  }
}

export const flappingService = new FlappingService();
