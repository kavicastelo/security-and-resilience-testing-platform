import { z } from 'zod';

export const OutputFormatSchema = z.enum(['table', 'json', 'yaml', 'junit', 'sarif']);

export type OutputFormat = z.infer<typeof OutputFormatSchema>;

export const CliGlobalOptionsSchema = z.object({
  apiUrl: z.string().url().default('http://localhost:4000'),
  apiKey: z.string().optional(),
  format: OutputFormatSchema.default('table'),
  verbose: z.boolean().default(false),
  quiet: z.boolean().default(false),
});

export type CliGlobalOptions = z.infer<typeof CliGlobalOptionsSchema>;

export const CliRunTestOptionsSchema = CliGlobalOptionsSchema.extend({
  targetId: z.string().uuid().optional(),
  targetUrl: z.string().url().optional(),
  profile: z.string().optional(),
  testDefinition: z.string().optional(),
  failOnSeverity: z.enum(['low', 'medium', 'high', 'critical']).default('high'),
  timeout: z.string().default('10m'),
});

export type CliRunTestOptions = z.infer<typeof CliRunTestOptionsSchema>;
