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

export const FORBIDDEN_SIMULATION_KEYS = ['simulated', 'mockReport', 'skipVerification'] as const;

export function checkForbiddenSimulationOptions(
  data: unknown,
  ctx: z.RefinementCtx,
  pathPrefix: (string | number)[] = [],
): void {
  if (!data || typeof data !== 'object') return;
  const record = data as Record<string, unknown>;

  for (const key of FORBIDDEN_SIMULATION_KEYS) {
    if (key in record && record[key] !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Simulation options are not permitted via the public API',
        path: [...pathPrefix, key],
      });
    }
  }

  if (record.options && typeof record.options === 'object') {
    const opts = record.options as Record<string, unknown>;
    for (const key of FORBIDDEN_SIMULATION_KEYS) {
      if (key in opts && opts[key] !== undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'Simulation options are not permitted via the public API',
          path: [...pathPrefix, 'options', key],
        });
      }
    }
  }
}

export const CreateTestRunInputSchema = z
  .object({
    projectId: z.string().uuid(),
    targetId: z.string().uuid(),
    environmentId: z.string().uuid().optional(),
    profileId: z.string().optional(),
    testDefinitionIds: z.array(z.string()).optional(),
    triggeredBy: TestRunTriggerSchema.default('manual'),
    options: z.record(z.string(), z.unknown()).optional(),
    metadata: z.record(z.string(), z.any()).optional(),
  })
  .passthrough()
  .superRefine((data, ctx) => {
    checkForbiddenSimulationOptions(data, ctx);
  });

export type CreateTestRunInput = z.infer<typeof CreateTestRunInputSchema>;
export type CreateTestRunDto = CreateTestRunInput;

export const ExecuteTestRunInputSchema = z
  .object({
    engineIds: z.array(z.string()).optional(),
    definitionYaml: z.string().optional(),
    customHeaders: z.record(z.string(), z.string()).optional(),
    options: z.record(z.string(), z.unknown()).optional(),
    wait: z.boolean().optional(),
  })
  .passthrough()
  .superRefine((data, ctx) => {
    checkForbiddenSimulationOptions(data, ctx);
  });

export type ExecuteTestRunDto = z.infer<typeof ExecuteTestRunInputSchema>;

