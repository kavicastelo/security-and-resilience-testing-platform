import { z } from 'zod';

export const MetricSchema = z.object({
  id: z.string().uuid(),
  testRunId: z.string().uuid(),
  executionId: z.string().uuid(),
  name: z.string().min(1),
  value: z.number(),
  unit: z.string().default('ms'),
  timestamp: z.date(),
  tags: z.record(z.string(), z.string()).default({}),
  threshold: z
    .object({
      max: z.number().optional(),
      min: z.number().optional(),
      passed: z.boolean(),
    })
    .optional(),
});

export type Metric = z.infer<typeof MetricSchema>;
