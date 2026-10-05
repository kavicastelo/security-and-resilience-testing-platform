import { z } from 'zod';
import { TargetScopeSchema } from '@security-lab/domain';

export const ExecutionJobMessageSchema = z.object({
  jobId: z.string().uuid(),
  testRunId: z.string().uuid(),
  engineId: z.string(),
  target: z.object({
    id: z.string().uuid(),
    baseUrl: z.string().url(),
    scope: TargetScopeSchema,
  }),
  inputs: z.record(z.string(), z.unknown()).default({}),
  timeoutMs: z.number().int().positive().default(300000),
  correlationId: z.string().uuid(),
});

export type ExecutionJobMessage = z.infer<typeof ExecutionJobMessageSchema>;

export const ExecutionProgressMessageSchema = z.object({
  jobId: z.string().uuid(),
  testRunId: z.string().uuid(),
  percentage: z.number().min(0).max(100),
  currentStep: z.string(),
  timestamp: z.string().datetime(),
});

export type ExecutionProgressMessage = z.infer<typeof ExecutionProgressMessageSchema>;

export const ExecutionCompletedMessageSchema = z.object({
  jobId: z.string().uuid(),
  testRunId: z.string().uuid(),
  status: z.enum(['succeeded', 'failed', 'timed_out', 'cancelled']),
  durationMs: z.number().nonnegative(),
  rawResultsUri: z.string().optional(),
  error: z.string().optional(),
  timestamp: z.string().datetime(),
});

export type ExecutionCompletedMessage = z.infer<typeof ExecutionCompletedMessageSchema>;
