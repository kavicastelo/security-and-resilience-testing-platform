import { z } from 'zod';

export const RemediationVerifiedStatusSchema = z.enum(['UNVERIFIED', 'PASSED', 'FAILED']);
export type RemediationVerifiedStatus = z.infer<typeof RemediationVerifiedStatusSchema>;

export const RemediationProposalSchema = z.object({
  id: z.string().uuid(),
  findingId: z.string().uuid(),
  workspaceId: z.string().uuid().optional(),
  explanation: z.string(),
  gitDiff: z.string(),
  confidenceScore: z.number().min(0).max(1).default(0.85),
  verifiedStatus: RemediationVerifiedStatusSchema.default('UNVERIFIED'),
  model: z.string().optional(),
  promptTokens: z.number().int().nonnegative().optional(),
  completionTokens: z.number().int().nonnegative().optional(),
  verificationOutput: z.string().optional(),
  createdAt: z.string(),
  updatedAt: z.string(),
});

export type RemediationProposal = z.infer<typeof RemediationProposalSchema>;

export const RemediateFindingRequestSchema = z.object({
  sourceCodeSnippet: z.string().optional(),
  filePath: z.string().optional(),
  model: z.string().optional(),
  provider: z.enum(['anthropic', 'openai', 'ollama', 'mock']).optional(),
  optInConfirmed: z.boolean().optional().default(true),
});

export type RemediateFindingRequest = z.infer<typeof RemediateFindingRequestSchema>;

export const VerifyRemediationRequestSchema = z.object({
  remediationId: z.string().uuid().optional(),
  targetUrl: z.string().url().optional(),
  timeoutMs: z.number().int().positive().optional().default(5000),
});

export type VerifyRemediationRequest = z.infer<typeof VerifyRemediationRequestSchema>;

export const VerifyRemediationResponseSchema = z.object({
  remediationId: z.string().uuid(),
  findingId: z.string().uuid(),
  verifiedStatus: RemediationVerifiedStatusSchema,
  retestSuccess: z.boolean(),
  verificationDetails: z.string(),
  durationMs: z.number().nonnegative(),
  verifiedAt: z.string(),
});

export type VerifyRemediationResponse = z.infer<typeof VerifyRemediationResponseSchema>;
