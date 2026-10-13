import { z } from 'zod';

export const HttpMethodSchema = z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']);
export type HttpMethod = z.infer<typeof HttpMethodSchema>;

export const PersonaRoleSchema = z.enum([
  'admin',
  'user',
  'auditor',
  'manager',
  'guest',
  'anonymous',
]);
export type PersonaRole = z.infer<typeof PersonaRoleSchema>;

export const PersonaConfigSchema = z.object({
  /** Unique persona identifier (e.g. 'user_a', 'user_b', 'admin', 'anon') */
  id: z.string().min(1),
  /** Human-readable persona label */
  name: z.string().min(1),
  /** Role classification */
  role: z.string().default('user'),
  /** Optional static Bearer or API token */
  token: z.string().optional(),
  /** Optional custom headers (e.g. Authorization, Cookie) */
  headers: z.record(z.string()).default({}),
  /** Associated target profile ID or auth profile */
  authProfileId: z.string().optional(),
  /** Known owned resource IDs for this persona (e.g. { orderId: 'ord-101', docId: 'doc-A' }) */
  resourceIds: z.record(z.string()).default({}),
  /** Whether this persona represents an unauthenticated guest */
  isGuest: z.boolean().default(false),
  /** Optional metadata */
  metadata: z.record(z.unknown()).default({}),
});
export type PersonaConfig = z.infer<typeof PersonaConfigSchema>;

export const AuthzViolationTypeSchema = z.enum([
  'BOLA_HORIZONTAL_IDOR',
  'BFLA_VERTICAL_ESCALATION',
  'MISSING_AUTHENTICATION',
]);
export type AuthzViolationType = z.infer<typeof AuthzViolationTypeSchema>;

export const ExpectedPermissionSchema = z.object({
  path: z.string(),
  method: HttpMethodSchema.default('GET'),
  allowedRoles: z.array(z.string()).default([]),
  allowedPersonas: z.array(z.string()).default([]),
  allowOwnerOnly: z.boolean().default(true),
  allowAnonymous: z.boolean().default(false),
});
export type ExpectedPermission = z.infer<typeof ExpectedPermissionSchema>;

export const AuthzMatrixTestCaseSchema = z.object({
  id: z.string(),
  type: AuthzViolationTypeSchema,
  endpointPath: z.string(),
  method: HttpMethodSchema,
  url: z.string(),
  actorPersona: PersonaConfigSchema,
  targetResourceId: z.string().optional(),
  resourceParamName: z.string().optional(),
  ownerPersona: PersonaConfigSchema.optional(),
  expectedStatuses: z.array(z.number().int()).default([401, 403, 404]),
  description: z.string(),
});
export type AuthzMatrixTestCase = z.infer<typeof AuthzMatrixTestCaseSchema>;

export const AuthzMatrixEvaluationFindingSchema = z.object({
  ruleId: z.string(),
  type: AuthzViolationTypeSchema,
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
  title: z.string(),
  description: z.string(),
  endpoint: z.string(),
  method: HttpMethodSchema,
  testedUrl: z.string(),
  actorPersonaId: z.string(),
  actorPersonaRole: z.string(),
  ownerPersonaId: z.string().optional(),
  resourceId: z.string().optional(),
  statusCode: z.number(),
  expectedStatuses: z.array(z.number()),
  remediation: z.string(),
  requestHeaders: z.record(z.string()).optional(),
  responseHeaders: z.record(z.string()).optional(),
  responseBodySnippet: z.string().optional(),
  curlCommand: z.string(),
});
export type AuthzMatrixEvaluationFinding = z.infer<typeof AuthzMatrixEvaluationFindingSchema>;

export const AuthzMatrixReportCellSchema = z.object({
  endpoint: z.string(),
  method: HttpMethodSchema,
  personaId: z.string(),
  status: z.enum(['ALLOWED', 'DENIED', 'VIOLATION_BOLA', 'VIOLATION_BFLA', 'VIOLATION_MISSING_AUTH', 'ERROR']),
  httpStatus: z.number(),
});
export type AuthzMatrixReportCell = z.infer<typeof AuthzMatrixReportCellSchema>;

export const AuthzMatrixReportSchema = z.object({
  title: z.string(),
  endpointsCount: z.number(),
  personasCount: z.number(),
  totalTests: z.number(),
  passedCount: z.number(),
  violationCount: z.number(),
  cells: z.array(AuthzMatrixReportCellSchema),
  markdownTable: z.string(),
});
export type AuthzMatrixReport = z.infer<typeof AuthzMatrixReportSchema>;
