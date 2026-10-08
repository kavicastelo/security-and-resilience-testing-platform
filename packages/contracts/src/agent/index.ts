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
});
export type AgentHeartbeatResponse = z.infer<typeof AgentHeartbeatResponseSchema>;

export const AgentPollRequestSchema = z.object({
  agentId: z.string().uuid(),
  capabilities: z.array(z.string()).default([]),
  tags: z.array(z.string()).default([]),
  maxJobs: z.number().int().min(1).max(10).default(1),
});
export type AgentPollRequest = z.infer<typeof AgentPollRequestSchema>;

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

