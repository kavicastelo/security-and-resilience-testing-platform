import { z } from 'zod';
import { FindingSeveritySchema } from '../finding/index.js';

export const PolicyRuleSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  description: z.string().optional(),
  condition: z.object({
    maxAllowedSeverity: FindingSeveritySchema.optional(),
    maxCountBySeverity: z.record(FindingSeveritySchema, z.number().int().nonnegative()).optional(),
    disallowCategories: z.array(z.string()).optional(),
    maxP95LatencyMs: z.number().positive().optional(),
    maxErrorRatePercent: z.number().min(0).max(100).optional(),
  }),
  action: z.enum(['block_release', 'warn', 'require_approval']).default('block_release'),
});

export type PolicyRule = z.infer<typeof PolicyRuleSchema>;

export const PolicySchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  description: z.string().optional(),
  rules: z.array(PolicyRuleSchema).min(1),
  createdAt: z.date(),
  updatedAt: z.date(),
});

export type Policy = z.infer<typeof PolicySchema>;
