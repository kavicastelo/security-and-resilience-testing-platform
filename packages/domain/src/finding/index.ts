import { z } from 'zod';

export const FindingSeveritySchema = z.enum([
  'critical',
  'high',
  'medium',
  'low',
  'info',
]);

export type FindingSeverity = z.infer<typeof FindingSeveritySchema>;

export const FindingConfidenceSchema = z.enum([
  'certain',
  'firm',
  'tentative',
]);

export type FindingConfidence = z.infer<typeof FindingConfidenceSchema>;

export const FindingStatusSchema = z.enum([
  'open',
  'acknowledged',
  'in_progress',
  'resolved',
  'false_positive',
  'accepted_risk',
]);

export type FindingStatus = z.infer<typeof FindingStatusSchema>;

export const FindingSchema = z.object({
  id: z.string().uuid(),
  fingerprint: z.string().min(1),
  title: z.string().min(1).max(200),
  category: z.string().min(1),
  severity: FindingSeveritySchema,
  confidence: FindingConfidenceSchema.default('firm'),
  status: FindingStatusSchema.default('open'),
  description: z.string(),
  risk: z.string().optional(),
  recommendation: z.string().optional(),
  testDefinitionId: z.string(),
  testRunId: z.string().uuid(),
  executionId: z.string().uuid(),
  targetId: z.string().uuid(),
  releaseId: z.string().uuid().optional(),
  evidenceId: z.string().uuid().optional(),
  firstDetectedAt: z.date(),
  lastDetectedAt: z.date(),
  fixedAt: z.date().optional(),
  metadata: z.record(z.string(), z.any()).default({}),
});

export type Finding = z.infer<typeof FindingSchema>;
