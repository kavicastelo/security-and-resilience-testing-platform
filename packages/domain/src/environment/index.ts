import { z } from 'zod';

export const EnvironmentTypeSchema = z.enum([
  'development',
  'staging',
  'qa',
  'production',
  'ephemeral',
]);

export type EnvironmentType = z.infer<typeof EnvironmentTypeSchema>;

export const EnvironmentSchema = z.object({
  id: z.string().uuid(),
  projectId: z.string().uuid(),
  name: z.string().min(1).max(100),
  type: EnvironmentTypeSchema,
  variables: z.record(z.string(), z.string()).default({}),
  headers: z.record(z.string(), z.string()).default({}),
  createdAt: z.date(),
  updatedAt: z.date(),
});

export type Environment = z.infer<typeof EnvironmentSchema>;

export const CreateEnvironmentInputSchema = EnvironmentSchema.omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type CreateEnvironmentInput = z.infer<typeof CreateEnvironmentInputSchema>;
