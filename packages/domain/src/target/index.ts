import { z } from 'zod';

export const TargetTestingCapabilitiesSchema = z.object({
  activeScanning: z.boolean().default(false),
  loadTesting: z.boolean().default(false),
  chaosTesting: z.boolean().default(false),
});

export type TargetTestingCapabilities = z.infer<typeof TargetTestingCapabilitiesSchema>;

export const TargetLimitsSchema = z.object({
  maxRps: z.number().int().positive().default(100),
  maxConcurrency: z.number().int().positive().default(20),
  maxDuration: z.string().default('10m'),
});

export type TargetLimits = z.infer<typeof TargetLimitsSchema>;

export const TargetScopeSchema = z.object({
  allowedHosts: z.array(z.string().min(1)).min(1),
  allowedPorts: z.array(z.number().int().min(1).max(65535)).default([80, 443]),
  excludedPaths: z.array(z.string()).default([]),
  testing: TargetTestingCapabilitiesSchema,
  limits: TargetLimitsSchema,
  allowPrivateIps: z.boolean().default(false).optional(),
});

export type TargetScope = z.infer<typeof TargetScopeSchema>;

export const VerificationStatusSchema = z.enum(['PENDING', 'VERIFIED', 'FAILED', 'REVOKED']);
export type VerificationStatus = z.infer<typeof VerificationStatusSchema>;

export const VerificationMethodSchema = z.enum(['DNS_TXT', 'HTTP_WELL_KNOWN', 'MANUAL', 'LOCAL_OVERRIDE']);
export type VerificationMethod = z.infer<typeof VerificationMethodSchema>;

export const TargetSchema = z.object({
  id: z.string().uuid(),
  projectId: z.string().uuid(),
  name: z.string().min(1).max(100),
  baseUrl: z.string().url(),
  scope: TargetScopeSchema,
  verificationToken: z.string().nullable().optional(),
  verificationStatus: VerificationStatusSchema.default('PENDING'),
  verifiedAt: z.date().nullable().optional(),
  verificationMethod: VerificationMethodSchema.nullable().optional(),
  authConfigured: z.boolean().default(false).optional(),
  authType: z.string().optional(),
  encryptedAuthData: z.unknown().optional(),
  createdAt: z.date(),
  updatedAt: z.date(),
});

export type Target = z.infer<typeof TargetSchema>;

export const CreateTargetInputSchema = z.object({
  projectId: z.string().uuid(),
  name: z.string().min(1).max(100),
  baseUrl: z.string().url(),
  allowedHosts: z.array(z.string().min(1)).min(1),
  allowedPorts: z.array(z.number().int().min(1).max(65535)).default([80, 443]),
  excludedPaths: z.array(z.string()).default([]),
  testing: TargetTestingCapabilitiesSchema.optional(),
  limits: TargetLimitsSchema.optional(),
  allowPrivateIps: z.boolean().default(false).optional(),
  authFlow: z.record(z.unknown()).optional(),
});

export type CreateTargetInput = z.infer<typeof CreateTargetInputSchema>;

export * from './ip-utils.js';
export * from './scope-validator.js';
