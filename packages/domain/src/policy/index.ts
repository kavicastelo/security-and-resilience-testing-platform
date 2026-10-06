import { z } from 'zod';
import { FindingSeveritySchema } from '../finding/index.js';

export const PolicyWaiverSchema = z.object({
  fingerprint: z.string().min(1),
  reason: z.string().min(1),
  approvedBy: z.string().min(1),
  expiresAt: z.union([z.string().datetime(), z.date()]).transform((val) => (typeof val === 'string' ? new Date(val) : val)),
});

export type PolicyWaiver = z.infer<typeof PolicyWaiverSchema>;

export const EndpointSlaSchema = z.object({
  path: z.string().min(1),
  maxP95LatencyMs: z.number().positive(),
  maxErrorRatePercent: z.number().min(0).max(100).optional(),
});

export type EndpointSla = z.infer<typeof EndpointSlaSchema>;

export const PolicyRuleConditionSchema = z.object({
  maxAllowedSeverity: FindingSeveritySchema.optional(),
  maxCountBySeverity: z.record(FindingSeveritySchema, z.number().int().nonnegative()).optional(),
  disallowCategories: z.array(z.string()).optional(),
  maxP95LatencyMs: z.number().positive().optional(),
  maxErrorRatePercent: z.number().min(0).max(100).optional(),
  requiredProfiles: z.array(z.string()).optional(),
  endpointSlas: z.array(EndpointSlaSchema).optional(),
});

export type PolicyRuleCondition = z.infer<typeof PolicyRuleConditionSchema>;

export const PolicyRuleSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  description: z.string().optional(),
  condition: PolicyRuleConditionSchema,
  action: z.enum(['block_release', 'warn', 'require_approval']).default('block_release'),
});

export type PolicyRule = z.infer<typeof PolicyRuleSchema>;

export const PolicySchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  description: z.string().optional(),
  requiredProfiles: z.array(z.string()).optional(),
  waivers: z.array(PolicyWaiverSchema).optional(),
  rules: z.array(PolicyRuleSchema).min(1),
  createdAt: z.date(),
  updatedAt: z.date(),
});

export type Policy = z.infer<typeof PolicySchema>;

