import { z } from 'zod';
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';

// Load .env if present (check cwd and parent workspace directories)
const candidateEnvPaths = [
  path.resolve(process.cwd(), '.env'),
  path.resolve(process.cwd(), '../../.env'),
  path.resolve(process.cwd(), '../.env'),
];

for (const envPath of candidateEnvPaths) {
  if (fs.existsSync(envPath)) {
    dotenv.config({ path: envPath });
  }
}

export class ConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigurationError';
    Object.setPrototypeOf(this, ConfigurationError.prototype);
  }
}

export const DEFAULT_DEV_DATABASE_URL = 'postgresql://postgres:postgres@localhost:5431/security_lab';

export function validateDatabaseUrl(urlString: string): { valid: boolean; error?: string } {
  if (!urlString || typeof urlString !== 'string' || urlString.trim().length === 0) {
    return { valid: false, error: 'DATABASE_URL cannot be empty' };
  }

  // Pre-validate port if specified in the URI (as WHATWG URL throws generic TypeError on port > 65535)
  const portMatch = urlString.match(/:(\d+)(?:\/|\?|$)/);
  if (portMatch && portMatch[1]) {
    const port = Number(portMatch[1]);
    if (isNaN(port) || port < 1 || port > 65535) {
      return {
        valid: false,
        error: `DATABASE_URL specifies an invalid port '${portMatch[1]}'. Port must be between 1 and 65535`,
      };
    }
  }

  try {
    const parsed = new URL(urlString);
    if (parsed.protocol !== 'postgres:' && parsed.protocol !== 'postgresql:') {
      return {
        valid: false,
        error: `Invalid protocol '${parsed.protocol}'. DATABASE_URL must start with 'postgresql://' or 'postgres://'`,
      };
    }
    if (!parsed.hostname || parsed.hostname.trim().length === 0) {
      return {
        valid: false,
        error: 'DATABASE_URL must contain a valid hostname',
      };
    }
    if (parsed.port) {
      const port = Number(parsed.port);
      if (isNaN(port) || port < 1 || port > 65535) {
        return {
          valid: false,
          error: `DATABASE_URL specifies an invalid port '${parsed.port}'. Port must be between 1 and 65535`,
        };
      }
    }
    return { valid: true };
  } catch {
    return {
      valid: false,
      error: 'DATABASE_URL is not a valid URI',
    };
  }
}

export function maskDatabaseUrl(urlStr: string): string {
  if (!urlStr || typeof urlStr !== 'string') {
    return '';
  }
  try {
    const parsed = new URL(urlStr);
    if (parsed.password) {
      parsed.password = '***';
    }
    return parsed.toString();
  } catch {
    return urlStr.replace(/:\/\/([^:]+):([^@]+)@/, '://$1:***@');
  }
}

export function getDatabaseHostPort(urlStr: string): { host: string; port: number } {
  if (!urlStr || typeof urlStr !== 'string') {
    return { host: 'unknown', port: 5432 };
  }
  try {
    const parsed = new URL(urlStr);
    const port = parsed.port ? Number(parsed.port) : 5432;
    return {
      host: parsed.hostname || 'localhost',
      port: isNaN(port) ? 5432 : port,
    };
  } catch {
    return { host: 'unknown', port: 5432 };
  }
}

export const ConfigSchema = z.preprocess(
  (rawInput: unknown) => {
    if (typeof rawInput === 'object' && rawInput !== null) {
      const copy = { ...(rawInput as Record<string, unknown>) };
      const nodeEnv = copy.NODE_ENV ?? process.env.NODE_ENV ?? 'development';
      if (nodeEnv !== 'production') {
        if (!copy.DATABASE_URL || typeof copy.DATABASE_URL !== 'string' || copy.DATABASE_URL.trim() === '') {
          copy.DATABASE_URL = DEFAULT_DEV_DATABASE_URL;
        }
      }
      return copy;
    }
    return rawInput;
  },
  z
    .object({
      NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
      PORT: z.coerce.number().int().min(1024).max(65535).default(4000),
      HOST: z.string().default('0.0.0.0'),
      CORS_ORIGIN: z.string().default('http://localhost:3000'),
      DATABASE_URL: z
        .string({
          required_error: "DATABASE_URL must be explicitly configured when NODE_ENV is 'production'",
          invalid_type_error: 'DATABASE_URL must be a string',
        })
        .min(1, { message: "DATABASE_URL must be explicitly configured when NODE_ENV is 'production'" }),
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
      ARTIFACTS_DIR: z.string().default('./.data/artifacts'),
      BACKUPS_DIR: z.string().default('./.data/backups'),
      MAX_CONCURRENT_RUNS: z.coerce.number().int().positive().default(5),
      DEFAULT_RUNNER_TIMEOUT_MS: z.coerce.number().int().positive().default(600000),
      ENFORCE_STRICT_SCOPES: z
        .string()
        .transform((val) => val !== 'false' && val !== '0')
        .default('true'),
      SECURITY_LAB_API_KEY: z
        .string()
        .optional()
        .transform((val) => (val && val.trim().length > 0 ? val.trim() : 'security-lab-default-api-key-change-in-production'))
        .refine((val) => val.length >= 16, { message: 'SECURITY_LAB_API_KEY must be at least 16 characters' }),
      SECURITY_LAB_ADMIN_KEY: z
        .string()
        .optional()
        .transform((val) => (val && val.trim().length > 0 ? val.trim() : 'security-lab-default-admin-key-change-in-production'))
        .refine((val) => val.length >= 16, { message: 'SECURITY_LAB_ADMIN_KEY must be at least 16 characters' }),
      SECURITY_LAB_BYPASS_AUTH_IN_TESTS: z
        .string()
        .transform((val) => val === 'true' || val === '1')
        .default('false'),
      AGENT_MASTER_SECRET: z
        .string()
        .optional()
        .transform((val) => (val && val.trim().length > 0 ? val.trim() : 'security-lab-dev-agent-master-secret-32-chars'))
        .refine((val) => val.length >= 32, { message: 'AGENT_MASTER_SECRET must be at least 32 characters' }),
      AGENT_MASTER_SECRET_PREVIOUS: z
        .string()
        .optional()
        .transform((val) => (val && val.trim().length > 0 ? val.trim() : undefined))
        .refine((val) => !val || val.length >= 32, {
          message: 'AGENT_MASTER_SECRET_PREVIOUS must be at least 32 characters if set',
        }),
    })
    .superRefine((data, ctx) => {
      if (data.DATABASE_URL) {
        const urlValidation = validateDatabaseUrl(data.DATABASE_URL);
        if (!urlValidation.valid) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['DATABASE_URL'],
            message: urlValidation.error ?? 'Invalid DATABASE_URL',
          });
        }
      }

      if (data.NODE_ENV === 'production') {
        if (!data.DATABASE_URL || data.DATABASE_URL.trim().length === 0) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['DATABASE_URL'],
            message: "DATABASE_URL must be explicitly configured when NODE_ENV is 'production'",
          });
        } else if (data.DATABASE_URL === DEFAULT_DEV_DATABASE_URL) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['DATABASE_URL'],
            message: 'Default development DATABASE_URL is not permitted in production. Provide an explicit production database URI.',
          });
        }

        if (data.SECURITY_LAB_API_KEY === 'security-lab-default-api-key-change-in-production') {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['SECURITY_LAB_API_KEY'],
            message: 'Default SECURITY_LAB_API_KEY is not permitted in production. Provide a secure, high-entropy key.',
          });
        }
        if (data.SECURITY_LAB_ADMIN_KEY === 'security-lab-default-admin-key-change-in-production') {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['SECURITY_LAB_ADMIN_KEY'],
            message: 'Default SECURITY_LAB_ADMIN_KEY is not permitted in production. Provide a secure, high-entropy key.',
          });
        }
        if (data.AGENT_MASTER_SECRET === 'security-lab-dev-agent-master-secret-32-chars') {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['AGENT_MASTER_SECRET'],
            message: 'AGENT_MASTER_SECRET must be explicitly configured in production with at least 32 characters.',
          });
        }
      }
    }),
);

export type Config = z.infer<typeof ConfigSchema>;

let cachedConfig: Config | null = null;

export function resetConfig(): void {
  cachedConfig = null;
}

export function loadConfig(overrides?: Record<string, string | undefined>): Config {
  const envToValidate = overrides ? { ...process.env, ...overrides } : process.env;

  const nodeEnv = envToValidate.NODE_ENV ?? process.env.NODE_ENV ?? 'development';
  if (nodeEnv === 'production' && (!envToValidate.DATABASE_URL || envToValidate.DATABASE_URL.trim().length === 0)) {
    throw new ConfigurationError("DATABASE_URL must be explicitly configured when NODE_ENV is 'production'");
  }

  const result = ConfigSchema.safeParse(envToValidate);

  if (!result.success) {
    const errorDetails = result.error.errors
      .map((err) => `  - ${err.path.join('.')}: ${err.message}`)
      .join('\n');
    throw new ConfigurationError(
      `[Security Lab Configuration Error] Failed to validate environment variables:\n${errorDetails}\n` +
        `Please ensure all required variables are set according to .env.example.`,
    );
  }

  if (result.data.NODE_ENV === 'development' && (!envToValidate.DATABASE_URL || envToValidate.DATABASE_URL.trim() === '')) {
    console.info(
      `[Security Lab Notice] DATABASE_URL not specified; using default local development database: ${maskDatabaseUrl(DEFAULT_DEV_DATABASE_URL)}`,
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
