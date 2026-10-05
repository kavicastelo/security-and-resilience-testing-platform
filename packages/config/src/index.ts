import { z } from 'zod';
import dotenv from 'dotenv';
import path from 'path';

// Load .env if present
dotenv.config({ path: path.resolve(process.cwd(), '.env') });

export const ConfigSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1024).max(65535).default(4000),
  HOST: z.string().default('0.0.0.0'),
  CORS_ORIGIN: z.string().default('http://localhost:3000'),
  DATABASE_URL: z.string().url().default('postgresql://postgres:postgres@localhost:5432/security_lab'),
  DB_MAX_CONNECTIONS: z.coerce.number().int().positive().default(10),
  DB_IDLE_TIMEOUT_MS: z.coerce.number().int().positive().default(30000),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  LOG_PRETTY: z
    .string()
    .transform((val) => val === 'true' || val === '1')
    .default('false'),
  DATA_DIR: z.string().default('./.data'),
  EVIDENCE_DIR: z.string().default('./.data/evidence'),
  REPORTS_DIR: z.string().default('./.data/reports'),
  MAX_CONCURRENT_RUNS: z.coerce.number().int().positive().default(5),
  DEFAULT_RUNNER_TIMEOUT_MS: z.coerce.number().int().positive().default(600000),
  ENFORCE_STRICT_SCOPES: z
    .string()
    .transform((val) => val !== 'false' && val !== '0')
    .default('true'),
});

export type Config = z.infer<typeof ConfigSchema>;

let cachedConfig: Config | null = null;

export function loadConfig(overrides?: Record<string, string | undefined>): Config {
  const envToValidate = overrides ? { ...process.env, ...overrides } : process.env;
  const result = ConfigSchema.safeParse(envToValidate);

  if (!result.success) {
    const errorDetails = result.error.errors
      .map((err) => `  - ${err.path.join('.')}: ${err.message}`)
      .join('\n');
    throw new Error(
      `[Security Lab Configuration Error] Failed to validate environment variables:\n${errorDetails}\n` +
        `Please ensure all required variables are set according to .env.example.`,
    );
  }

  cachedConfig = result.data;
  return cachedConfig;
}

export function getConfig(): Config {
  if (!cachedConfig) {
    return loadConfig();
  }
  return cachedConfig;
}
