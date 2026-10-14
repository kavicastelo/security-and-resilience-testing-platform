import crypto from 'node:crypto';
import { getDatabase } from '../db.js';
import { aiRemediations } from '../db/schema.js';
import { eq, desc } from 'drizzle-orm';
import { findingsService } from '../findings.service.js';
import { targetsService } from '../targets.service.js';
import { remediationPromptBuilder } from './prompt-builder.js';
import { llmClient } from './client.js';
import { remediationVerifier } from './remediation-verifier.js';
import {
  RemediationProposal,
  RemediateFindingRequest,
  VerifyRemediationRequest,
  VerifyRemediationResponse,
} from '@security-lab/contracts';
import { logger } from '@security-lab/logger';
import { telemetryRegistry } from '../../telemetry.js';

export class RemediationService {
  /**
   * Generates a context-aware AI remediation proposal for a given finding.
   */
  async generateRemediation(
    findingId: string,
    request?: RemediateFindingRequest,
    workspaceId?: string,
  ): Promise<RemediationProposal> {
    const { db } = getDatabase();

    // 1. Fetch finding
    const finding = await findingsService.getFindingById(findingId);
    if (!finding) {
      throw new Error(`Finding "${findingId}" not found`);
    }

    // 2. Fetch associated target
    const target = await targetsService.getTargetById(finding.targetId);

    // 3. Build context-aware prompt with secret sanitization
    const prompt = remediationPromptBuilder.buildPrompt(finding, target, {
      sourceCodeSnippet: request?.sourceCodeSnippet,
      filePath: request?.filePath,
    });

    // 4. Generate explanation and unified diff via pluggable LLM provider
    const llmResult = await llmClient.generateRemediation(prompt, {
      provider: request?.provider,
      model: request?.model,
    });

    // 5. Persist remediation proposal
    const remediationId = crypto.randomUUID();
    const effectiveWorkspaceId = workspaceId || target?.projectId || undefined;

    const [inserted] = await db
      .insert(aiRemediations)
      .values({
        id: remediationId,
        findingId: finding.id,
        workspaceId: effectiveWorkspaceId,
        explanation: llmResult.explanation,
        gitDiff: llmResult.gitDiff,
        confidenceScore: llmResult.confidenceScore,
        verifiedStatus: 'UNVERIFIED',
        model: llmResult.model,
        promptTokens: llmResult.promptTokens,
        completionTokens: llmResult.completionTokens,
      })
      .returning();

    if (!inserted) {
      throw new Error('Failed to persist remediation proposal');
    }

    logger.info(
      {
        remediationId: inserted.id,
        findingId: finding.id,
        model: inserted.model,
      },
      'Created new AI remediation proposal',
    );

    telemetryRegistry.recordAiRemediation('generated');

    return {
      id: inserted.id,
      findingId: inserted.findingId,
      workspaceId: inserted.workspaceId || undefined,
      explanation: inserted.explanation,
      gitDiff: inserted.gitDiff,
      confidenceScore: inserted.confidenceScore,
      verifiedStatus: inserted.verifiedStatus as RemediationProposal['verifiedStatus'],
      model: inserted.model || undefined,
      promptTokens: inserted.promptTokens ?? 0,
      completionTokens: inserted.completionTokens ?? 0,
      verificationOutput: inserted.verificationOutput || undefined,
      createdAt: inserted.createdAt.toISOString(),
      updatedAt: inserted.updatedAt.toISOString(),
    };
  }

  /**
   * Retrieves all remediation proposals associated with a finding.
   */
  async getRemediationsForFinding(findingId: string): Promise<RemediationProposal[]> {
    const { db } = getDatabase();
    const rows = await db
      .select()
      .from(aiRemediations)
      .where(eq(aiRemediations.findingId, findingId))
      .orderBy(desc(aiRemediations.createdAt));

    return rows.map((row) => ({
      id: row.id,
      findingId: row.findingId,
      workspaceId: row.workspaceId || undefined,
      explanation: row.explanation,
      gitDiff: row.gitDiff,
      confidenceScore: row.confidenceScore,
      verifiedStatus: row.verifiedStatus as RemediationProposal['verifiedStatus'],
      model: row.model || undefined,
      promptTokens: row.promptTokens ?? 0,
      completionTokens: row.completionTokens ?? 0,
      verificationOutput: row.verificationOutput || undefined,
      createdAt: row.createdAt.toISOString(),
      updatedAt: row.updatedAt.toISOString(),
    }));
  }

  /**
   * Retrieves a single remediation proposal by ID.
   */
  async getRemediationById(id: string): Promise<RemediationProposal | null> {
    const { db } = getDatabase();
    const [row] = await db
      .select()
      .from(aiRemediations)
      .where(eq(aiRemediations.id, id))
      .limit(1);

    if (!row) return null;

    return {
      id: row.id,
      findingId: row.findingId,
      workspaceId: row.workspaceId || undefined,
      explanation: row.explanation,
      gitDiff: row.gitDiff,
      confidenceScore: row.confidenceScore,
      verifiedStatus: row.verifiedStatus as RemediationProposal['verifiedStatus'],
      model: row.model || undefined,
      promptTokens: row.promptTokens ?? 0,
      completionTokens: row.completionTokens ?? 0,
      verificationOutput: row.verificationOutput || undefined,
      createdAt: row.createdAt.toISOString(),
      updatedAt: row.updatedAt.toISOString(),
    };
  }

  /**
   * Triggers the automated patch verification loop.
   */
  async verifyRemediation(
    remediationId: string,
    options?: VerifyRemediationRequest,
  ): Promise<VerifyRemediationResponse> {
    return remediationVerifier.verifyPatch(remediationId, {
      timeoutMs: options?.timeoutMs,
    });
  }
}

export const remediationService = new RemediationService();
