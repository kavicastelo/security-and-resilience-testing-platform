import { z } from 'zod';

export const HttpRequestEvidenceSchema = z.object({
  method: z.string(),
  url: z.string(),
  headers: z.record(z.string(), z.string()).default({}),
  body: z.string().optional(),
});

export type HttpRequestEvidence = z.infer<typeof HttpRequestEvidenceSchema>;

export const HttpResponseEvidenceSchema = z.object({
  statusCode: z.number().int(),
  headers: z.record(z.string(), z.string()).default({}),
  body: z.string().optional(),
  responseTimeMs: z.number().optional(),
});

export type HttpResponseEvidence = z.infer<typeof HttpResponseEvidenceSchema>;

export const EvidenceSchema = z.object({
  id: z.string().uuid(),
  testRunId: z.string().uuid(),
  executionId: z.string().uuid(),
  request: HttpRequestEvidenceSchema.optional(),
  response: HttpResponseEvidenceSchema.optional(),
  expected: z.unknown().optional(),
  actual: z.unknown().optional(),
  metadata: z.record(z.string(), z.any()).default({}),
  timestamp: z.date(),
  environment: z.string(),
  applicationVersion: z.string().optional(),
  gitCommit: z.string().optional(),
  immutableHash: z.string().optional(),
});

export type Evidence = Readonly<z.infer<typeof EvidenceSchema>>;
