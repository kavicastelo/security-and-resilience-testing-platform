import { z } from 'zod';

export const TargetProtocolSchema = z.enum([
  'http:',
  'https:',
  'postgres:',
  'postgresql:',
  'mysql:',
  'redis:',
]);

export type TargetProtocol = z.infer<typeof TargetProtocolSchema>;

export const DatabaseTargetEndpointSchema = z.object({
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535),
  protocol: TargetProtocolSchema,
  databaseName: z.string().optional(),
  sslMode: z.enum(['disable', 'require', 'verify-full']).default('require').optional(),
});

export type DatabaseTargetEndpoint = z.infer<typeof DatabaseTargetEndpointSchema>;
