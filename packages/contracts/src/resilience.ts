import { z } from 'zod';

export const FaultActionSchema = z.enum(['LATENCY', 'STATUS_CODE', 'DROP', 'TRUNCATE']);
export type FaultAction = z.infer<typeof FaultActionSchema>;

export const FaultRuleMatchSchema = z.object({
  path: z.string(),
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', '*']).default('*'),
});
export type FaultRuleMatch = z.infer<typeof FaultRuleMatchSchema>;

export const FaultRuleSchema = z.object({
  id: z.string(),
  name: z.string(),
  match: FaultRuleMatchSchema,
  action: FaultActionSchema,
  percentage: z.number().min(0).max(100).default(100),
  latencyMs: z.number().nonnegative().optional(),
  jitterMs: z.number().nonnegative().optional(),
  statusCode: z.number().int().min(100).max(599).default(503).optional(),
  statusBody: z.string().optional(),
  truncateBytes: z.number().int().positive().optional(),
});
export type FaultRule = z.infer<typeof FaultRuleSchema>;

export const ClientScenarioStepSchema = z.object({
  name: z.string(),
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']).default('GET'),
  path: z.string(),
  headers: z.record(z.string(), z.string()).optional(),
  body: z.unknown().optional(),
  maxRetries: z.number().int().nonnegative().default(3),
  retryBackoffMs: z.number().nonnegative().default(50),
  expectedFinalStatus: z.number().int().default(200),
});
export type ClientScenarioStep = z.infer<typeof ClientScenarioStepSchema>;

export const ChaosPlanSchema = z.object({
  id: z.string().optional(),
  name: z.string().optional(),
  targetBaseUrl: z.string().optional(),
  faultRules: z.array(FaultRuleSchema).default([]),
  scenarioSteps: z.array(ClientScenarioStepSchema).optional(),
  proxyTimeoutMs: z.number().int().positive().default(15000),
});
export type ChaosPlan = z.infer<typeof ChaosPlanSchema>;

export const InjectedFaultRecordSchema = z.object({
  ruleId: z.string(),
  ruleName: z.string(),
  action: FaultActionSchema,
  path: z.string(),
  method: string(),
  details: z.string(),
  timestamp: z.number(),
});
export type InjectedFaultRecord = z.infer<typeof InjectedFaultRecordSchema>;

export const ResilienceExecutionSummarySchema = z.object({
  proxyPort: z.number().int().positive(),
  totalRequestsReceived: z.number().int().nonnegative(),
  faultsInjected: z.number().int().nonnegative(),
  faultsByType: z.record(z.string(), z.number().int()),
  recoveredRequests: z.number().int().nonnegative(),
  unrecoveredRequests: z.number().int().nonnegative(),
  avgRecoveryLatencyMs: z.number().nonnegative(),
  clientRetries: z.number().int().nonnegative(),
  passed: z.boolean(),
  failures: z.array(z.string()),
  faultLog: z.array(InjectedFaultRecordSchema).optional(),
});
export type ResilienceExecutionSummary = z.infer<typeof ResilienceExecutionSummarySchema>;

function string() {
  return z.string();
}
