import { z } from 'zod';

export const ReleaseGateDecisionSchema = z.enum([
  'passed',
  'failed',
  'warning',
  'manual_override',
]);

export type ReleaseGateDecision = z.infer<typeof ReleaseGateDecisionSchema>;

export const ReleaseSchema = z.object({
  id: z.string().uuid(),
  projectId: z.string().uuid(),
  name: z.string().min(1),
  version: z.string().min(1),
  gitCommit: z.string().optional(),
  gitBranch: z.string().optional(),
  testRunId: z.string().uuid().optional(),
  policyId: z.string().optional(),
  decision: ReleaseGateDecisionSchema.default('warning'),
  reason: z.string().optional(),
  evaluatedAt: z.date().optional(),
  createdAt: z.date(),
  updatedAt: z.date(),
});

export type Release = z.infer<typeof ReleaseSchema>;
