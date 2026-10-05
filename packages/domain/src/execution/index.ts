import { z } from 'zod';

export const ExecutionClassSchema = z.enum([
  'class_a_native',
  'class_b_container',
  'class_c_worker',
]);

export type ExecutionClass = z.infer<typeof ExecutionClassSchema>;

export const ExecutionStatusSchema = z.enum([
  'pending',
  'running',
  'completed',
  'failed',
  'timed_out',
  'skipped',
]);

export type ExecutionStatus = z.infer<typeof ExecutionStatusSchema>;

export const TestExecutionSchema = z.object({
  id: z.string().uuid(),
  testRunId: z.string().uuid(),
  engineId: z.string(),
  executionClass: ExecutionClassSchema,
  status: ExecutionStatusSchema.default('pending'),
  startedAt: z.date().optional(),
  completedAt: z.date().optional(),
  durationMs: z.number().int().nonnegative().optional(),
  exitCode: z.number().int().optional(),
  errorMessage: z.string().optional(),
  rawResult: z.unknown().optional(),
  metadata: z.record(z.string(), z.any()).default({}),
  createdAt: z.date(),
  updatedAt: z.date(),
});

export type TestExecution = z.infer<typeof TestExecutionSchema>;
