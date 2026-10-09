import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  ConfigSchema,
  loadConfig,
  resetConfig,
  ConfigurationError,
  DEFAULT_DEV_DATABASE_URL,
  maskDatabaseUrl,
  getDatabaseHostPort,
  validateDatabaseUrl,
} from '../src/index.js';

describe('Configuration & Attestation Secret Validation (REM-03)', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
    resetConfig();
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    resetConfig();
  });

  it('generates ephemeral runtime key if AGENT_MASTER_SECRET is missing in non-production', () => {
    delete process.env.AGENT_MASTER_SECRET;
    process.env.NODE_ENV = 'development';

    const parsed = ConfigSchema.parse({
      NODE_ENV: 'development',
    });

    expect(parsed.AGENT_MASTER_SECRET).toBeDefined();
    expect(typeof parsed.AGENT_MASTER_SECRET).toBe('string');
    expect(parsed.AGENT_MASTER_SECRET.length).toBeGreaterThanOrEqual(32);
  });

  it('fails validation in production if AGENT_MASTER_SECRET is missing', () => {
    delete process.env.AGENT_MASTER_SECRET;

    const result = ConfigSchema.safeParse({
      NODE_ENV: 'production',
      SECURITY_LAB_API_KEY: 'production-api-key-at-least-16-chars',
      SECURITY_LAB_ADMIN_KEY: 'production-admin-key-at-least-16-chars',
      DATABASE_URL: 'postgresql://prod-user:prod-pass@prod-db:5432/security_lab',
    });

    expect(result.success).toBe(false);
    if (!result.success) {
      const messages = result.error.errors.map((e) => e.message).join(' ');
      expect(messages).toMatch(/AGENT_MASTER_SECRET/);
    }
  });

  it('fails validation in production if AGENT_MASTER_SECRET is shorter than 32 characters', () => {
    const result = ConfigSchema.safeParse({
      NODE_ENV: 'production',
      SECURITY_LAB_API_KEY: 'production-api-key-at-least-16-chars',
      SECURITY_LAB_ADMIN_KEY: 'production-admin-key-at-least-16-chars',
      DATABASE_URL: 'postgresql://prod-user:prod-pass@prod-db:5432/security_lab',
      AGENT_MASTER_SECRET: 'short-secret-less-than-32-chars',
    });

    expect(result.success).toBe(false);
    if (!result.success) {
      const messages = result.error.errors.map((e) => e.message).join(' ');
      expect(messages).toMatch(/at least 32 characters/);
    }
  });

  it('passes validation in production when valid AGENT_MASTER_SECRET is provided', () => {
    const validSecret = 'production-agent-master-secret-at-least-32-chars-long';
    const result = ConfigSchema.safeParse({
      NODE_ENV: 'production',
      SECURITY_LAB_API_KEY: 'production-api-key-at-least-16-chars',
      SECURITY_LAB_ADMIN_KEY: 'production-admin-key-at-least-16-chars',
      DATABASE_URL: 'postgresql://prod-user:prod-pass@prod-db:5432/security_lab',
      AGENT_MASTER_SECRET: validSecret,
    });

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.AGENT_MASTER_SECRET).toBe(validSecret);
    }
  });

  it('validates optional AGENT_MASTER_SECRET_PREVIOUS length when provided', () => {
    const validSecret = 'production-agent-master-secret-at-least-32-chars-long';
    const validPrevious = 'previous-agent-master-secret-at-least-32-chars-long';

    const result = ConfigSchema.safeParse({
      NODE_ENV: 'production',
      SECURITY_LAB_API_KEY: 'production-api-key-at-least-16-chars',
      SECURITY_LAB_ADMIN_KEY: 'production-admin-key-at-least-16-chars',
      DATABASE_URL: 'postgresql://prod-user:prod-pass@prod-db:5432/security_lab',
      AGENT_MASTER_SECRET: validSecret,
      AGENT_MASTER_SECRET_PREVIOUS: validPrevious,
    });

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.AGENT_MASTER_SECRET_PREVIOUS).toBe(validPrevious);
    }

    const invalidResult = ConfigSchema.safeParse({
      NODE_ENV: 'production',
      SECURITY_LAB_API_KEY: 'production-api-key-at-least-16-chars',
      SECURITY_LAB_ADMIN_KEY: 'production-admin-key-at-least-16-chars',
      DATABASE_URL: 'postgresql://prod-user:prod-pass@prod-db:5432/security_lab',
      AGENT_MASTER_SECRET: validSecret,
      AGENT_MASTER_SECRET_PREVIOUS: 'too-short',
    });

    expect(invalidResult.success).toBe(false);
  });
});

describe('Database Configuration & Hardening (REM-09)', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
    resetConfig();
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    resetConfig();
  });

  describe('Production Fail-Closed Enforcement', () => {
    it('fails schema validation in production if DATABASE_URL is missing', () => {
      const result = ConfigSchema.safeParse({
        NODE_ENV: 'production',
        SECURITY_LAB_API_KEY: 'production-api-key-at-least-16-chars',
        SECURITY_LAB_ADMIN_KEY: 'production-admin-key-at-least-16-chars',
        AGENT_MASTER_SECRET: 'production-agent-master-secret-32-chars',
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        const errorMessages = result.error.errors.map((e) => e.message).join(' ');
        expect(errorMessages).toMatch(/DATABASE_URL must be explicitly configured when NODE_ENV is 'production'/);
      }
    });

    it('throws ConfigurationError on loadConfig when NODE_ENV is production and DATABASE_URL is omitted', () => {
      delete process.env.DATABASE_URL;

      expect(() => {
        loadConfig({
          NODE_ENV: 'production',
          DATABASE_URL: '',
          SECURITY_LAB_API_KEY: 'production-api-key-at-least-16-chars',
          SECURITY_LAB_ADMIN_KEY: 'production-admin-key-at-least-16-chars',
          AGENT_MASTER_SECRET: 'production-agent-master-secret-32-chars',
        });
      }).toThrowError(ConfigurationError);

      expect(() => {
        loadConfig({
          NODE_ENV: 'production',
          DATABASE_URL: '',
        });
      }).toThrowError(/DATABASE_URL must be explicitly configured when NODE_ENV is 'production'/);
    });

    it('rejects default dev credentials (localhost:5431) in production mode', () => {
      const result = ConfigSchema.safeParse({
        NODE_ENV: 'production',
        SECURITY_LAB_API_KEY: 'production-api-key-at-least-16-chars',
        SECURITY_LAB_ADMIN_KEY: 'production-admin-key-at-least-16-chars',
        AGENT_MASTER_SECRET: 'production-agent-master-secret-32-chars',
        DATABASE_URL: DEFAULT_DEV_DATABASE_URL,
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        const errorMessages = result.error.errors.map((e) => e.message).join(' ');
        expect(errorMessages).toMatch(/Default development DATABASE_URL is not permitted in production/);
      }
    });

    it('passes validation in production when an explicit valid DATABASE_URL is provided', () => {
      const prodDbUrl = 'postgresql://prod_app_user:StrongPassword123!@db-cluster.internal:5432/security_lab_prod';
      const result = ConfigSchema.safeParse({
        NODE_ENV: 'production',
        SECURITY_LAB_API_KEY: 'production-api-key-at-least-16-chars',
        SECURITY_LAB_ADMIN_KEY: 'production-admin-key-at-least-16-chars',
        AGENT_MASTER_SECRET: 'production-agent-master-secret-32-chars',
        DATABASE_URL: prodDbUrl,
      });

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.DATABASE_URL).toBe(prodDbUrl);
      }
    });

    it('loads configuration successfully in production via loadConfig with valid parameters', () => {
      const prodDbUrl = 'postgresql://prod_app_user:StrongPassword123!@db-cluster.internal:5432/security_lab_prod';
      const loaded = loadConfig({
        NODE_ENV: 'production',
        SECURITY_LAB_API_KEY: 'production-api-key-at-least-16-chars',
        SECURITY_LAB_ADMIN_KEY: 'production-admin-key-at-least-16-chars',
        AGENT_MASTER_SECRET: 'production-agent-master-secret-32-chars',
        DATABASE_URL: prodDbUrl,
      });

      expect(loaded.DATABASE_URL).toBe(prodDbUrl);
      expect(loaded.NODE_ENV).toBe('production');
    });
  });

  describe('Development & Test Fallback', () => {
    it('falls back to DEFAULT_DEV_DATABASE_URL in development when DATABASE_URL is omitted', () => {
      const parsed = ConfigSchema.parse({
        NODE_ENV: 'development',
      });

      expect(parsed.DATABASE_URL).toBe(DEFAULT_DEV_DATABASE_URL);
      expect(parsed.DATABASE_URL).toBe('postgresql://postgres:postgres@localhost:5431/security_lab');
    });

    it('falls back to DEFAULT_DEV_DATABASE_URL in test mode when DATABASE_URL is omitted', () => {
      const parsed = ConfigSchema.parse({
        NODE_ENV: 'test',
      });

      expect(parsed.DATABASE_URL).toBe(DEFAULT_DEV_DATABASE_URL);
    });

    it('allows overriding DATABASE_URL in development mode', () => {
      const customDevUrl = 'postgresql://custom:custom@127.0.0.1:5433/custom_dev_db';
      const parsed = ConfigSchema.parse({
        NODE_ENV: 'development',
        DATABASE_URL: customDevUrl,
      });

      expect(parsed.DATABASE_URL).toBe(customDevUrl);
    });
  });

  describe('PostgreSQL URI Format & Range Validation', () => {
    it('accepts valid postgresql:// and postgres:// protocols', () => {
      expect(validateDatabaseUrl('postgresql://usr:pass@localhost:5432/mydb').valid).toBe(true);
      expect(validateDatabaseUrl('postgres://usr:pass@localhost:5432/mydb').valid).toBe(true);
      expect(validateDatabaseUrl('postgresql://remote-host/mydb').valid).toBe(true);
    });

    it('rejects invalid schemes such as http://, mysql://, or file://', () => {
      const httpCheck = validateDatabaseUrl('http://localhost:5432/mydb');
      expect(httpCheck.valid).toBe(false);
      expect(httpCheck.error).toMatch(/DATABASE_URL must start with 'postgresql:\/\/' or 'postgres:\/\/'/);

      const mysqlCheck = validateDatabaseUrl('mysql://root:pass@localhost:3306/mydb');
      expect(mysqlCheck.valid).toBe(false);
      expect(mysqlCheck.error).toMatch(/DATABASE_URL must start with 'postgresql:\/\/' or 'postgres:\/\/'/);
    });

    it('rejects invalid port numbers (negative or > 65535)', () => {
      const portCheckHigh = validateDatabaseUrl('postgresql://usr:pass@localhost:70000/mydb');
      expect(portCheckHigh.valid).toBe(false);
      expect(portCheckHigh.error).toMatch(/invalid port/);

      const portCheckZero = validateDatabaseUrl('postgresql://usr:pass@localhost:0/mydb');
      expect(portCheckZero.valid).toBe(false);
      expect(portCheckZero.error).toMatch(/invalid port/);
    });

    it('rejects invalid URIs without hostname', () => {
      const noHostCheck = validateDatabaseUrl('postgresql:///mydb');
      expect(noHostCheck.valid).toBe(false);
      expect(noHostCheck.error).toMatch(/must contain a valid hostname/);
    });

    it('rejects completely malformed URI strings', () => {
      const malformedCheck = validateDatabaseUrl('not-a-valid-uri-at-all');
      expect(malformedCheck.valid).toBe(false);
      expect(malformedCheck.error).toMatch(/not a valid URI/);
    });
  });

  describe('URL Password Masking & Credential Redaction (maskDatabaseUrl)', () => {
    it('redacts plaintext passwords in connection URIs', () => {
      const masked = maskDatabaseUrl('postgresql://usr:secretpw@db:5432/db');
      expect(masked).toBe('postgresql://usr:***@db:5432/db');
      expect(masked).not.toContain('secretpw');
    });

    it('redacts password in default dev database URL', () => {
      const masked = maskDatabaseUrl(DEFAULT_DEV_DATABASE_URL);
      expect(masked).toBe('postgresql://postgres:***@localhost:5431/security_lab');
    });

    it('preserves URIs without credentials without modification', () => {
      expect(maskDatabaseUrl('postgresql://db:5432/db')).toBe('postgresql://db:5432/db');
      expect(maskDatabaseUrl('postgresql://localhost/db')).toBe('postgresql://localhost/db');
    });

    it('preserves username when no password is provided', () => {
      expect(maskDatabaseUrl('postgresql://appuser@db:5432/db')).toBe('postgresql://appuser@db:5432/db');
    });

    it('handles empty or non-string inputs safely', () => {
      expect(maskDatabaseUrl('')).toBe('');
      expect(maskDatabaseUrl(null as unknown as string)).toBe('');
    });
  });

  describe('Host & Port Extraction (getDatabaseHostPort)', () => {
    it('extracts host and explicit port correctly', () => {
      const { host, port } = getDatabaseHostPort('postgresql://usr:secretpw@db:5432/db');
      expect(host).toBe('db');
      expect(port).toBe(5432);
    });

    it('extracts host and non-standard port', () => {
      const { host, port } = getDatabaseHostPort('postgresql://usr:secretpw@127.0.0.1:5431/security_lab');
      expect(host).toBe('127.0.0.1');
      expect(port).toBe(5431);
    });

    it('defaults to port 5432 when port is omitted in postgres URI', () => {
      const { host, port } = getDatabaseHostPort('postgresql://appuser@db-host/mydb');
      expect(host).toBe('db-host');
      expect(port).toBe(5432);
    });

    it('returns fallback values on malformed inputs', () => {
      const { host, port } = getDatabaseHostPort('not-a-valid-uri');
      expect(host).toBe('unknown');
      expect(port).toBe(5432);
    });
  });
});

