import { z } from 'zod';
import { RawFindingPayloadSchema } from '../findings/index.js';

export const AgentStatusSchema = z.enum(['online', 'offline', 'busy', 'draining']);
export type AgentStatus = z.infer<typeof AgentStatusSchema>;

export const AgentSystemInfoSchema = z.object({
  os: z.string().optional(),
  arch: z.string().optional(),
  nodeVersion: z.string().optional(),
  cpuCount: z.number().optional(),
  totalMemoryMb: z.number().optional(),
  hostname: z.string().optional(),
});
export type AgentSystemInfo = z.infer<typeof AgentSystemInfoSchema>;

export const AgentRegistrationRequestSchema = z.object({
  name: z.string().min(2).max(100),
  tags: z.array(z.string()).default([]),
  capabilities: z.array(z.string()).default([]),
  systemInfo: AgentSystemInfoSchema.optional(),
});
export type AgentRegistrationRequest = z.infer<typeof AgentRegistrationRequestSchema>;

export const CreateTenantEnrollmentKeySchema = z.object({
  name: z.string().min(2).max(100),
  maxUses: z.number().int().positive().optional(),
  expiresInDays: z.number().positive().optional().default(30),
});
export type CreateTenantEnrollmentKeyRequest = z.infer<typeof CreateTenantEnrollmentKeySchema>;

export const TenantEnrollmentKeyResponseSchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  name: z.string(),
  keyPrefix: z.string(),
  key: z.string().optional(), // Provided only once upon creation
  maxUses: z.number().nullable().optional(),
  usesCount: z.number(),
  expiresAt: z.string().nullable().optional(),
  revokedAt: z.string().nullable().optional(),
  createdAt: z.string(),
});
export type TenantEnrollmentKeyResponse = z.infer<typeof TenantEnrollmentKeyResponseSchema>;

export const AgentRegistrationResponseSchema = z.object({
  agentId: z.string().uuid(),
  tenantId: z.string().uuid(),
  name: z.string(),
  token: z.string(),
  tokenExpiresAt: z.string().optional(),
  status: AgentStatusSchema,
  tags: z.array(z.string()),
  capabilities: z.array(z.string()),
  createdAt: z.string(),
});
export type AgentRegistrationResponse = z.infer<typeof AgentRegistrationResponseSchema>;

export const AgentHeartbeatRequestSchema = z.object({
  agentId: z.string().uuid(),
  status: AgentStatusSchema.default('online'),
  metrics: z
    .object({
      cpuUsagePercent: z.number().optional(),
      memoryUsageMb: z.number().optional(),
      activeJobsCount: z.number().default(0),
    })
    .optional(),
  leaseId: z.string().uuid().optional(),
  activeLeaseIds: z.array(z.string().uuid()).optional(),
});
export type AgentHeartbeatRequest = z.infer<typeof AgentHeartbeatRequestSchema>;

export const AgentHeartbeatResponseSchema = z.object({
  acknowledged: z.boolean(),
  timestamp: z.string(),
  command: z.enum(['continue', 'drain', 'restart']).default('continue'),
  renewedLeases: z.array(z.string().uuid()).default([]),
  cancelledJobIds: z.array(z.string().uuid()).default([]),
});
export type AgentHeartbeatResponse = z.infer<typeof AgentHeartbeatResponseSchema>;

export const AgentPollRequestSchema = z.object({
  agentId: z.string().uuid(),
  capabilities: z.array(z.string()).default([]),
  tags: z.array(z.string()).default([]),
  maxJobs: z.number().int().min(1).max(10).default(1),
});
export type AgentPollRequest = z.infer<typeof AgentPollRequestSchema>;

export const CURRENT_PROTOCOL_VERSION = '1.0.0';
export const MIN_SUPPORTED_PROTOCOL_VERSION = '1.0.0';
export const CONTROLLER_VERSION = '0.2.0';
export const AGENT_VERSION = '0.2.0';

export const HEADER_PROTOCOL_VERSION = 'x-protocol-version';
export const HEADER_CONTROLLER_VERSION = 'x-controller-version';
export const HEADER_AGENT_VERSION = 'x-agent-version';

export const PROTOCOL_ERROR_CODES = {
  PROTOCOL_INCOMPATIBLE: 'PROTOCOL_INCOMPATIBLE',
  INCOMPATIBLE_MAJOR: 'INCOMPATIBLE_MAJOR',
} as const;

export interface ParsedSemver {
  major: number;
  minor: number;
  patch: number;
  prerelease?: string;
}

export function parseSemver(version: string): ParsedSemver | null {
  if (!version || typeof version !== 'string') return null;
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/.exec(version.trim());
  if (!match || !match[1] || !match[2] || !match[3]) return null;
  return {
    major: parseInt(match[1], 10),
    minor: parseInt(match[2], 10),
    patch: parseInt(match[3], 10),
    prerelease: match[4],
  };
}

export function compareSemver(v1: string, v2: string): number {
  const parsed1 = parseSemver(v1);
  const parsed2 = parseSemver(v2);
  if (!parsed1 || !parsed2) {
    throw new Error(`Invalid semver comparison between "${v1}" and "${v2}"`);
  }
  if (parsed1.major !== parsed2.major) {
    return parsed1.major > parsed2.major ? 1 : -1;
  }
  if (parsed1.minor !== parsed2.minor) {
    return parsed1.minor > parsed2.minor ? 1 : -1;
  }
  if (parsed1.patch !== parsed2.patch) {
    return parsed1.patch > parsed2.patch ? 1 : -1;
  }
  if (parsed1.prerelease && !parsed2.prerelease) return -1;
  if (!parsed1.prerelease && parsed2.prerelease) return 1;
  return 0;
}

export interface ProtocolEvaluationResult {
  compatible: boolean;
  statusCode?: 400 | 426;
  errorCode?: 'PROTOCOL_INCOMPATIBLE' | 'INCOMPATIBLE_MAJOR';
  message?: string;
}

export function evaluateProtocolCompatibility(clientVersion?: string | null): ProtocolEvaluationResult {
  if (!clientVersion || typeof clientVersion !== 'string' || clientVersion.trim() === '') {
    return {
      compatible: false,
      statusCode: 426,
      errorCode: 'PROTOCOL_INCOMPATIBLE',
      message: 'Missing X-Protocol-Version header. Upgrade required.',
    };
  }

  const parsed = parseSemver(clientVersion);
  if (!parsed) {
    return {
      compatible: false,
      statusCode: 426,
      errorCode: 'PROTOCOL_INCOMPATIBLE',
      message: `Malformed X-Protocol-Version "${clientVersion}". Must follow semantic versioning (MAJOR.MINOR.PATCH).`,
    };
  }

  if (compareSemver(clientVersion, MIN_SUPPORTED_PROTOCOL_VERSION) < 0) {
    return {
      compatible: false,
      statusCode: 426,
      errorCode: 'PROTOCOL_INCOMPATIBLE',
      message: `Protocol version ${clientVersion} is outdated. Minimum supported version is ${MIN_SUPPORTED_PROTOCOL_VERSION}.`,
    };
  }

  const serverParsed = parseSemver(CURRENT_PROTOCOL_VERSION)!;
  if (parsed.major !== serverParsed.major) {
    return {
      compatible: false,
      statusCode: 400,
      errorCode: 'INCOMPATIBLE_MAJOR',
      message: `Protocol major version mismatch: client is ${parsed.major}.x, controller requires ${serverParsed.major}.x.`,
    };
  }

  return { compatible: true };
}

export const AgentJobDispatchSchema = z.object({
  jobId: z.string().uuid(),
  testRunId: z.string().uuid(),
  tenantId: z.string().uuid(),
  target: z.object({
    id: z.string().uuid(),
    name: z.string(),
    baseUrl: z.string(),
    scope: z.record(z.string(), z.unknown()),
    scopeSignature: z.string().optional(),
  }),
  engineIds: z.array(z.string()).default([]),
  definitionYaml: z.string().optional(),
  customHeaders: z.record(z.string(), z.string()).optional(),
  options: z.record(z.string(), z.unknown()).optional(),
  requiredCapabilities: z.array(z.string()).default([]),
  requiredTags: z.array(z.string()).default([]),
  leaseId: z.string().uuid().optional(),
  leaseExpiresAt: z.string().optional(),
  jobDispatchSecret: z.string().optional(),
});
export type AgentJobDispatch = z.infer<typeof AgentJobDispatchSchema>;

export const AgentPollResponseSchema = z.object({
  jobs: z.array(AgentJobDispatchSchema),
});
export type AgentPollResponse = z.infer<typeof AgentPollResponseSchema>;

export const AgentJobProgressReportSchema = z.object({
  jobId: z.string().uuid(),
  testRunId: z.string().uuid(),
  percent: z.number().min(0).max(100),
  message: z.string(),
  engineId: z.string().optional(),
});
export type AgentJobProgressReport = z.infer<typeof AgentJobProgressReportSchema>;

export const AgentJobCompletionReportSchema = z.object({
  jobId: z.string().uuid(),
  testRunId: z.string().uuid(),
  leaseId: z.string().uuid().optional(),
  status: z.enum(['completed', 'failed']),
  findings: z.array(RawFindingPayloadSchema).default([]),
  metrics: z
    .array(
      z.object({
        name: z.string(),
        value: z.number(),
        unit: z.string(),
        tags: z.record(z.string(), z.string()).optional(),
      }),
    )
    .default([]),
  executions: z
    .array(
      z.object({
        engineId: z.string(),
        status: z.string(),
        durationMs: z.number().optional(),
        error: z.string().optional(),
      }),
    )
    .default([]),
  error: z.string().optional(),
  resultSignature: z.string().optional(),
});
export type AgentJobCompletionReport = z.infer<typeof AgentJobCompletionReportSchema>;

export const AgentSummarySchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  name: z.string(),
  status: AgentStatusSchema,
  tags: z.array(z.string()),
  capabilities: z.array(z.string()),
  systemInfo: AgentSystemInfoSchema.optional(),
  lastHeartbeatAt: z.string().nullable().optional(),
  expiresAt: z.string().nullable().optional(),
  revokedAt: z.string().nullable().optional(),
  revocationReason: z.string().nullable().optional(),
  createdAt: z.string(),
  updatedAt: z.string(),
});
export type AgentSummary = z.infer<typeof AgentSummarySchema>;

export const RevokeAgentRequestSchema = z.object({
  reason: z.string().max(100).optional().default('Administrative revocation'),
});
export type RevokeAgentRequest = z.infer<typeof RevokeAgentRequestSchema>;

export const RevokeAgentResponseSchema = z.object({
  success: z.boolean(),
  agentId: z.string().uuid(),
  revokedAt: z.string(),
  reason: z.string(),
});
export type RevokeAgentResponse = z.infer<typeof RevokeAgentResponseSchema>;

export const RotateAgentTokenResponseSchema = z.object({
  agentId: z.string().uuid(),
  token: z.string(),
  tokenExpiresAt: z.string(),
  rotatedAt: z.string(),
});
export type RotateAgentTokenResponse = z.infer<typeof RotateAgentTokenResponseSchema>;

export const AgentCancelAckResponseSchema = z.object({
  success: z.boolean(),
  jobId: z.string().uuid(),
  acknowledgedAt: z.string(),
});
export type AgentCancelAckResponse = z.infer<typeof AgentCancelAckResponseSchema>;
export const AgentAuditEventTypeSchema = z.enum([
  'agent.enrolled',
  'agent.authenticated',
  'agent.token_rotated',
  'agent.revoked',
  'job.leased',
  'job.progress',
  'job.completed',
  'job.failed',
  'job.cancelled',
  'security.scope_violation',
  'security.scope_tampering',
  'security.tenant_mismatch',
  'security.protocol_violation',
  'security.invalid_auth',
]);
export type AgentAuditEventType = z.infer<typeof AgentAuditEventTypeSchema> | (string & {});

export const AgentAuditEventSchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  agentId: z.string().uuid().nullable().optional(),
  eventType: z.string(),
  actorType: z.enum(['agent', 'admin', 'system']),
  actorId: z.string(),
  metadata: z.record(z.string(), z.unknown()),
  ipAddress: z.string().nullable().optional(),
  createdAt: z.string(),
});
export type AgentAuditEvent = z.infer<typeof AgentAuditEventSchema>;

export const AgentAuditEventsResponseSchema = z.object({
  success: z.boolean(),
  data: z.array(AgentAuditEventSchema),
  events: z.array(AgentAuditEventSchema).optional(),
  pagination: z.object({
    total: z.number().int().nonnegative(),
    page: z.number().int().positive(),
    limit: z.number().int().positive(),
    totalPages: z.number().int().nonnegative(),
  }),
});
export type AgentAuditEventsResponse = z.infer<typeof AgentAuditEventsResponseSchema>;
