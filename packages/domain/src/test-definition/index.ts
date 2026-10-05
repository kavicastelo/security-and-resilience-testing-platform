import { z } from 'zod';

export const TestCategorySchema = z.enum([
  'http_security',
  'headers',
  'tls_ssl',
  'cors',
  'cookies',
  'authentication',
  'authorization',
  'rate_limiting',
  'api_schema',
  'performance',
  'resilience',
]);

export type TestCategory = z.infer<typeof TestCategorySchema>;

export const TestAuthenticationConfigSchema = z.object({
  type: z.enum(['none', 'bearer', 'api_key', 'basic', 'oauth2']).default('none'),
  tokenEnvVar: z.string().optional(),
  headerName: z.string().optional(),
  headerValuePrefix: z.string().optional(),
});

export type TestAuthenticationConfig = z.infer<typeof TestAuthenticationConfigSchema>;

export const SingleTestSpecSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  description: z.string().optional(),
  path: z.string().default('/'),
  method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']).default('GET'),
  headers: z.record(z.string(), z.string()).optional(),
  expectedStatus: z.array(z.number().int()).optional(),
  assertions: z.array(
    z.object({
      field: z.string(),
      operator: z.enum([
        'equals',
        'not_equals',
        'contains',
        'not_contains',
        'exists',
        'does_not_exist',
        'matches_regex',
      ]),
      value: z.any().optional(),
      severity: z.enum(['info', 'low', 'medium', 'high', 'critical']).default('medium'),
      message: z.string().optional(),
    }),
  ).default([]),
});

export type SingleTestSpec = z.infer<typeof SingleTestSpecSchema>;

export const TestThresholdsSchema = z.object({
  maxAllowedFindings: z.record(z.enum(['critical', 'high', 'medium', 'low', 'info']), z.number().int().nonnegative()).default({
    critical: 0,
    high: 0,
    medium: 5,
    low: 10,
    info: 50,
  }),
  maxResponseTimeMs: z.number().int().positive().optional(),
  minAvailabilityRatio: z.number().min(0).max(1).optional(),
});

export type TestThresholds = z.infer<typeof TestThresholdsSchema>;

export const TestDefinitionSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  version: z.string().regex(/^\d+\.\d+\.\d+$/),
  category: TestCategorySchema,
  description: z.string().optional(),
  target: z.object({
    endpoint: z.string().optional(),
    requiredCapabilities: z.array(z.string()).default([]),
  }),
  inputs: z.record(z.string(), z.any()).default({}),
  authentication: TestAuthenticationConfigSchema.default({ type: 'none' }),
  tests: z.array(SingleTestSpecSchema).min(1),
  thresholds: TestThresholdsSchema.default({
    maxAllowedFindings: { critical: 0, high: 0, medium: 5, low: 10, info: 50 },
  }),
});

export type TestDefinition = z.infer<typeof TestDefinitionSchema>;

export * from './parser.js';
export * from './evaluator.js';
