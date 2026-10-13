import { z } from 'zod';

export const SmugglingTechniqueSchema = z.enum([
  'CL_TE',
  'TE_CL',
  'TE_TE',
  'HOST_POISONING',
  'HOP_BY_HOP',
]);
export type SmugglingTechnique = z.infer<typeof SmugglingTechniqueSchema>;

export const SmugglingSeveritySchema = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
export type SmugglingSeverity = z.infer<typeof SmugglingSeveritySchema>;

export const SmugglingMutationVariantSchema = z.object({
  id: z.string(),
  technique: SmugglingTechniqueSchema,
  name: z.string(),
  description: z.string(),
  headers: z.array(z.tuple([z.string(), z.string()])).optional(),
  obfuscationType: z.string().optional(),
});
export type SmugglingMutationVariant = z.infer<typeof SmugglingMutationVariantSchema>;

export const SmugglingEngineOptionsSchema = z.object({
  canaryPath: z.string().default('/robots.txt'),
  normalPath: z.string().default('/'),
  techniques: z.array(SmugglingTechniqueSchema).optional(),
  timeoutMs: z.number().int().positive().default(5000),
  timingDelayThresholdMs: z.number().int().positive().default(1500),
  concurrency: z.number().int().positive().default(2),
  poisonCanaryHost: z.string().default('canary.internal.testing'),
  allowSelfSignedTls: z.boolean().default(true),
});
export type SmugglingEngineOptions = z.infer<typeof SmugglingEngineOptionsSchema>;

export const RawSocketEvidenceSchema = z.object({
  technique: SmugglingTechniqueSchema,
  variantId: z.string(),
  requestSent: z.string(),
  requestHexDump: z.string(),
  responseReceived: z.string(),
  responseHexDump: z.string(),
  statusCode: z.number().int().optional(),
  latencyMs: z.number().nonnegative(),
  evidenceHash: z.string(),
  details: z.record(z.string(), z.unknown()).optional(),
});
export type RawSocketEvidence = z.infer<typeof RawSocketEvidenceSchema>;

export const SmugglingExecutionSummarySchema = z.object({
  targetHost: z.string(),
  targetPort: z.number().int().positive(),
  useTls: z.boolean(),
  probesDispatched: z.number().int().nonnegative(),
  vulnerabilitiesDetected: z.number().int().nonnegative(),
  variantsTested: z.array(z.string()),
  findings: z.array(RawSocketEvidenceSchema),
  durationMs: z.number().nonnegative(),
});
export type SmugglingExecutionSummary = z.infer<typeof SmugglingExecutionSummarySchema>;
