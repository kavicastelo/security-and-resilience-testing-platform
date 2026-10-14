import { z } from 'zod';
import { FindingSchema, FindingSeveritySchema } from '@security-lab/domain';

export const RawFindingPayloadSchema = z.object({
  sourceEngine: z.string(),
  externalId: z.string().optional(),
  title: z.string(),
  description: z.string(),
  rawSeverity: z.string(),
  evidenceData: z.record(z.string(), z.unknown()).optional(),
  location: z.string().optional(),
});

export type RawFindingPayload = z.infer<typeof RawFindingPayloadSchema>;

export const FindingIngestRequestSchema = z.object({
  testRunId: z.string().uuid(),
  executionId: z.string().uuid(),
  targetId: z.string().uuid(),
  findings: z.array(RawFindingPayloadSchema),
});

export type FindingIngestRequest = z.infer<typeof FindingIngestRequestSchema>;

export const NormalizedFindingListResponseSchema = z.object({
  testRunId: z.string().uuid(),
  totalCount: z.number().int().nonnegative(),
  countsBySeverity: z.record(FindingSeveritySchema, z.number().int().nonnegative()),
  findings: z.array(FindingSchema),
});

export type NormalizedFindingListResponse = z.infer<typeof NormalizedFindingListResponseSchema>;

// ==============================================================================
// Phase 16: Finding Lifecycle Intelligence, Retesting & Flapping Contracts
// ==============================================================================

export const FindingTriageStatusSchema = z.enum([
  'open',
  'confirmed',
  'resolved',
  'false_positive',
  'accepted_risk',
  'ignored',
  'regressed',
]);

export type FindingTriageStatus = z.infer<typeof FindingTriageStatusSchema>;

export const TriageHistoryEntrySchema = z.object({
  id: z.string().uuid().optional(),
  fromStatus: z.string(),
  toStatus: z.string(),
  timestamp: z.string(),
  actorId: z.string().optional(),
  comment: z.string().optional(),
  expiresAt: z.string().optional(),
});

export type TriageHistoryEntry = z.infer<typeof TriageHistoryEntrySchema>;

export const FindingTriageRequestSchema = z
  .object({
    status: z.preprocess((val) => {
      if (typeof val === 'string') {
        const lower = val.toLowerCase();
        if (lower === 'risk_accepted') return 'accepted_risk';
        return lower;
      }
      return val;
    }, FindingTriageStatusSchema),
    comment: z.string().optional(),
    notes: z.string().optional(),
    expiresAt: z.string().optional(),
    actorId: z.string().optional(),
  })
  .superRefine((data, ctx) => {
    const effectiveComment = data.comment || data.notes;
    if (data.status === 'false_positive' && (!effectiveComment || effectiveComment.trim().length === 0)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Rationale comment is required when marking a finding as false_positive',
        path: ['comment'],
      });
    }

    if (data.status === 'accepted_risk') {
      if (!effectiveComment || effectiveComment.trim().length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'Rationale comment is required when accepting risk for a finding',
          path: ['comment'],
        });
      }
      if (!data.expiresAt) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'Expiration date (expiresAt) is strictly required for accepted_risk status',
          path: ['expiresAt'],
        });
      } else {
        const expDate = new Date(data.expiresAt);
        if (Number.isNaN(expDate.getTime()) || expDate.getTime() <= Date.now()) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'Expiration date (expiresAt) must be a valid future ISO timestamp',
            path: ['expiresAt'],
          });
        }
      }
    }
  });

export type FindingTriageRequest = z.infer<typeof FindingTriageRequestSchema>;

export const RetestResultSchema = z.object({
  findingId: z.string().uuid(),
  status: z.enum(['RESOLVED', 'REOPENED', 'open', 'resolved', 'regressed']),
  stillDetected: z.boolean(),
  testedEndpoint: z.string().optional(),
  ruleId: z.string().optional(),
  durationMs: z.number().nonnegative(),
  retestRunId: z.string().uuid().optional(),
  message: z.string().optional(),
  timestamp: z.string(),
});

export type RetestResult = z.infer<typeof RetestResultSchema>;

export const FlappingRunSnapshotSchema = z.object({
  runId: z.string(),
  status: z.string(),
  timestamp: z.string(),
});

export type FlappingRunSnapshot = z.infer<typeof FlappingRunSnapshotSchema>;

export const FlappingAnalysisResponseSchema = z.object({
  findingId: z.string().uuid(),
  fingerprint: z.string(),
  targetId: z.string().uuid(),
  totalRunsAnalyzed: z.number().int().nonnegative(),
  transitionsCount: z.number().int().nonnegative(),
  flappingScore: z.number().min(0).max(1),
  isFlapping: z.boolean(),
  suppressReleaseGate: z.boolean(),
  history: z.array(FlappingRunSnapshotSchema),
});

export type FlappingAnalysisResponse = z.infer<typeof FlappingAnalysisResponseSchema>;
