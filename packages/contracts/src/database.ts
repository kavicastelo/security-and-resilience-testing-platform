import { z } from 'zod';
import { TargetProtocolSchema } from './target.js';

export const DatabaseTypeSchema = z.enum(['POSTGRES', 'MYSQL', 'REDIS']);
export type DatabaseType = z.infer<typeof DatabaseTypeSchema>;

export const DatabaseEngineOptionsSchema = z.object({
  databaseType: DatabaseTypeSchema.optional(),
  checkTls: z.boolean().default(true),
  checkAuth: z.boolean().default(true),
  checkDefaultCredentials: z.boolean().default(true),
  testSaturation: z.boolean().default(false),
  saturationTargetConnections: z.number().int().min(1).max(200).default(25),
  timeoutMs: z.number().int().positive().default(5000),
  defaultAccounts: z
    .array(
      z.object({
        username: z.string(),
        password: z.string(),
      }),
    )
    .optional(),
});
export type DatabaseEngineOptions = z.infer<typeof DatabaseEngineOptionsSchema>;

export const DatabaseHandshakeResultSchema = z.object({
  databaseType: DatabaseTypeSchema,
  tlsSupported: z.boolean(),
  tlsMandated: z.boolean(),
  unauthenticatedAccessAllowed: z.boolean(),
  defaultCredentialsMatched: z.boolean(),
  matchedCredentialUser: z.string().optional(),
  serverVersion: z.string().optional(),
  authMethod: z.string().optional(),
  rawBannerHex: z.string().optional(),
  details: z.record(z.string(), z.unknown()).optional(),
});
export type DatabaseHandshakeResult = z.infer<typeof DatabaseHandshakeResultSchema>;

export const DatabaseSaturationSummarySchema = z.object({
  attemptedConnections: z.number().int().nonnegative(),
  successfulConnections: z.number().int().nonnegative(),
  rejectedConnections: z.number().int().nonnegative(),
  rejectionReason: z.string().optional(),
  avgConnectionTimeMs: z.number().nonnegative(),
  serverGraceful: z.boolean(),
});
export type DatabaseSaturationSummary = z.infer<typeof DatabaseSaturationSummarySchema>;

export const DatabaseExecutionSummarySchema = z.object({
  targetHost: z.string(),
  targetPort: z.number().int().positive(),
  protocol: TargetProtocolSchema,
  databaseType: DatabaseTypeSchema,
  handshake: DatabaseHandshakeResultSchema,
  saturation: DatabaseSaturationSummarySchema.optional(),
  findingsCount: z.number().int().nonnegative(),
  durationMs: z.number().nonnegative(),
});
export type DatabaseExecutionSummary = z.infer<typeof DatabaseExecutionSummarySchema>;
