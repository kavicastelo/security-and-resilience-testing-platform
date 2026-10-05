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
