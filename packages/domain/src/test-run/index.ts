import { z } from 'zod';

export const TestRunStatusSchema = z.enum([
  'pending',
  'queued',
  'running',
  'completed',
  'failed',
  'cancelled',
]);

export type TestRunStatus = z.infer<typeof TestRunStatusSchema>;

export const TestRunTriggerSchema = z.enum(['manual', 'cli', 'ci', 'schedule', 'api']);

export type TestRunTrigger = z.infer<typeof TestRunTriggerSchema>;

export const TestRunSummarySchema = z.object({
  totalTests: z.number().int().nonnegative().default(0),
  passedTests: z.number().int().nonnegative().default(0),
  failedTests: z.number().int().nonnegative().default(0),
  errorTests: z.number().int().nonnegative().default(0),
  findingsCount: z.record(z.enum(['critical', 'high', 'medium', 'low', 'info']), z.number().int().nonnegative()).default({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  }),
});

export type TestRunSummary = z.infer<typeof TestRunSummarySchema>;

export const TestRunSchema = z.object({
  id: z.string().uuid(),
  projectId: z.string().uuid(),
  targetId: z.string().uuid(),
  environmentId: z.string().uuid().optional(),
  profileId: z.string().optional(),
  status: TestRunStatusSchema.default('pending'),
  triggeredBy: TestRunTriggerSchema.default('manual'),
  startedAt: z.date().optional(),
  completedAt: z.date().optional(),
  summary: TestRunSummarySchema.default({
    totalTests: 0,
    passedTests: 0,
    failedTests: 0,
    errorTests: 0,
    findingsCount: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  }),
  metadata: z.record(z.string(), z.any()).default({}),
  createdAt: z.date(),
  updatedAt: z.date(),
});

export type TestRun = z.infer<typeof TestRunSchema>;

export const CreateTestRunInputSchema = z.object({
  projectId: z.string().uuid(),
  targetId: z.string().uuid(),
  environmentId: z.string().uuid().optional(),
  profileId: z.string().optional(),
  testDefinitionIds: z.array(z.string()).optional(),
  triggeredBy: TestRunTriggerSchema.default('manual'),
  metadata: z.record(z.string(), z.any()).optional(),
});

export type CreateTestRunInput = z.infer<typeof CreateTestRunInputSchema>;
