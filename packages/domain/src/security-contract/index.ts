import { z } from 'zod';

export const SecurityContractSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  version: z.string().regex(/^\d+\.\d+\.\d+$/),
  targetPattern: z.string(),
  requiredHeaders: z.array(
    z.object({
      name: z.string(),
      requiredValue: z.string().optional(),
      pattern: z.string().optional(),
    }),
  ).default([]),
  forbiddenHeaders: z.array(z.string()).default([]),
  enforceTlsVersion: z.enum(['TLSv1.2', 'TLSv1.3']).default('TLSv1.2'),
  requireAuthenticationForPaths: z.array(z.string()).default([]),
  maxSeverityAllowed: z.enum(['info', 'low', 'medium', 'high', 'critical']).default('low'),
  createdAt: z.date(),
  updatedAt: z.date(),
});

export type SecurityContract = z.infer<typeof SecurityContractSchema>;
