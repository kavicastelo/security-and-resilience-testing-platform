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
});

export type TargetScope = z.infer<typeof TargetScopeSchema>;

export const TargetSchema = z.object({
  id: z.string().uuid(),
  projectId: z.string().uuid(),
  name: z.string().min(1).max(100),
  baseUrl: z.string().url(),
  scope: TargetScopeSchema,
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
});

export type CreateTargetInput = z.infer<typeof CreateTargetInputSchema>;

export * from './scope-validator.js';
