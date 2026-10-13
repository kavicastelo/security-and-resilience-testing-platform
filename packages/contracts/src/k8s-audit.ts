import { z } from 'zod';

export const K8sAuditTargetTypeSchema = z.enum([
  'manifest_yaml',
  'helm_chart',
  'dockerfile',
  'mixed',
]);

export type K8sAuditTargetType = z.infer<typeof K8sAuditTargetTypeSchema>;

export const K8sSecurityRuleSeveritySchema = z.enum([
  'critical',
  'high',
  'medium',
  'low',
  'info',
]);

export type K8sSecurityRuleSeverity = z.infer<typeof K8sSecurityRuleSeveritySchema>;

export const K8sAuditEngineOptionsSchema = z.object({
  manifestYaml: z.string().optional(),
  dockerfileContent: z.string().optional(),
  filePaths: z.array(z.string()).optional(),
  policyLevel: z.enum(['privileged', 'baseline', 'restricted']).default('restricted').optional(),
  failFast: z.boolean().default(false).optional(),
  ignoredRuleIds: z.array(z.string()).default([]).optional(),
});

export type K8sAuditEngineOptions = z.infer<typeof K8sAuditEngineOptionsSchema>;

export const K8sAuditRuleFindingSchema = z.object({
  ruleId: z.string(),
  title: z.string(),
  description: z.string(),
  severity: K8sSecurityRuleSeveritySchema,
  category: z.string(),
  resourceKind: z.string().optional(),
  resourceName: z.string().optional(),
  containerName: z.string().optional(),
  filePath: z.string().optional(),
  lineNumber: z.number().int().positive().optional(),
  violatingSnippet: z.string().optional(),
  recommendation: z.string(),
});

export type K8sAuditRuleFinding = z.infer<typeof K8sAuditRuleFindingSchema>;

export const K8sAuditSummarySchema = z.object({
  totalFilesAnalyzed: z.number().int().nonnegative(),
  totalResourcesAudited: z.number().int().nonnegative(),
  totalRulesEvaluated: z.number().int().nonnegative(),
  findingsCount: z.number().int().nonnegative(),
  countsBySeverity: z.record(z.string(), z.number().int().nonnegative()),
  passedRuleCount: z.number().int().nonnegative(),
  failedRuleCount: z.number().int().nonnegative(),
  durationMs: z.number().nonnegative(),
});

export type K8sAuditSummary = z.infer<typeof K8sAuditSummarySchema>;
