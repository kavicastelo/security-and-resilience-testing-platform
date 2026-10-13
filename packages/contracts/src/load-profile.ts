import { z } from 'zod';

export const LoadProfileTypeSchema = z.enum(['constant', 'ramping', 'spike']);
export type LoadProfileType = z.infer<typeof LoadProfileTypeSchema>;

export const LoadThresholdsSchema = z.object({
  maxP50Ms: z.number().positive().optional(),
  maxP90Ms: z.number().positive().optional(),
  maxP95Ms: z.number().positive().optional(),
  maxP99Ms: z.number().positive().optional(),
  maxP999Ms: z.number().positive().optional(),
  minRps: z.number().positive().optional(),
  maxErrorRate: z.number().min(0).max(1).optional(), // e.g. 0.05 = 5%
});
export type LoadThresholds = z.infer<typeof LoadThresholdsSchema>;

export const LoadStageSchema = z.object({
  durationSec: z.number().positive(),
  targetConnections: z.number().int().positive(),
  targetRps: z.number().positive().optional(),
});
export type LoadStage = z.infer<typeof LoadStageSchema>;

export const LoadProfileSchema = z.object({
  id: z.string().optional(),
  name: z.string().optional(),
  type: LoadProfileTypeSchema.default('constant'),
  durationSec: z.number().positive().default(10),
  connections: z.number().int().min(1).max(200).default(10),
  pipelining: z.number().int().min(1).max(10).default(1),
  rateLimit: z.number().int().positive().optional(),
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']).default('GET'),
  path: z.string().default('/'),
  headers: z.record(z.string(), z.string()).optional(),
  body: z.union([z.string(), z.record(z.string(), z.unknown())]).optional(),
  stages: z.array(LoadStageSchema).optional(),
  thresholds: LoadThresholdsSchema.optional(),
  timeoutMs: z.number().int().positive().default(10000),
});
export type LoadProfile = z.infer<typeof LoadProfileSchema>;

export const LatencyPercentilesSchema = z.object({
  p50: z.number().nonnegative(),
  p90: z.number().nonnegative(),
  p95: z.number().nonnegative(),
  p99: z.number().nonnegative(),
  p999: z.number().nonnegative(),
  min: z.number().nonnegative(),
  max: z.number().nonnegative(),
  avg: z.number().nonnegative(),
  stdDev: z.number().nonnegative(),
});
export type LatencyPercentiles = z.infer<typeof LatencyPercentilesSchema>;

export const LoadExecutionSummarySchema = z.object({
  totalRequests: z.number().int().nonnegative(),
  successfulRequests: z.number().int().nonnegative(),
  failedRequests: z.number().int().nonnegative(),
  errorRate: z.number().min(0).max(1),
  durationSec: z.number().positive(),
  rps: z.number().nonnegative(),
  bytesTransferred: z.number().int().nonnegative(),
  statusCodes: z.record(z.string(), z.number().int()),
  latency: LatencyPercentilesSchema,
  sloPassed: z.boolean(),
  sloViolations: z.array(z.string()),
});
export type LoadExecutionSummary = z.infer<typeof LoadExecutionSummarySchema>;
