import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase } from '../../apps/controller/src/services/db.js';
import { timingSafeCompare, extractAuthToken } from '../../apps/controller/src/plugins/auth.js';

describe('Controller Authentication & Role-Based Access Control (REM-01)', () => {
  let app: FastifyInstance;
  const testApiKey = 'test-operator-api-key-32chars-long';
  const testAdminKey = 'test-admin-secret-key-32chars-long';

  beforeAll(async () => {
    // Explicitly enforce authentication by setting bypassAuth: false
    app = buildApp({
      disableLogging: true,
      enableReaper: false,
      bypassAuth: false,
      apiKey: testApiKey,
      adminKey: testAdminKey,
    });
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
    await closeDatabase();
  });

  // ---------------------------------------------------------------------------
  // 1. Timing-Safe Comparison Utility Tests
  // ---------------------------------------------------------------------------
  describe('Constant-Time Comparison', () => {
    it('returns true for identical keys', () => {
      expect(timingSafeCompare('my-secret-key-1234567890', 'my-secret-key-1234567890')).toBe(true);
    });

    it('returns false for different keys of identical length', () => {
      expect(timingSafeCompare('my-secret-key-1234567890', 'my-secret-key-1234567891')).toBe(false);
    });

    it('returns false for keys of different lengths without timing bias', () => {
      expect(timingSafeCompare('short', 'longer-key-string-here')).toBe(false);
      expect(timingSafeCompare('longer-key-string-here', 'short')).toBe(false);
    });

    it('handles empty and invalid values safely', () => {
      expect(timingSafeCompare('', '')).toBe(true);
      expect(timingSafeCompare('', 'something')).toBe(false);
      expect(timingSafeCompare(null as unknown as string, 'something')).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Token Extraction Tests
  // ---------------------------------------------------------------------------
  describe('Credential Extraction', () => {
    it('extracts Bearer token with case-insensitive scheme', () => {
      const mockReq1 = { headers: { authorization: 'Bearer token-abc-123' } } as any;
      expect(extractAuthToken(mockReq1)).toBe('token-abc-123');

      const mockReq2 = { headers: { authorization: 'bearer token-xyz-789' } } as any;
      expect(extractAuthToken(mockReq2)).toBe('token-xyz-789');
    });

    it('extracts token from X-API-Key header', () => {
      const mockReq = { headers: { 'x-api-key': 'custom-api-key-val' } } as any;
      expect(extractAuthToken(mockReq)).toBe('custom-api-key-val');
    });

    it('returns null when headers are missing or malformed', () => {
      expect(extractAuthToken({ headers: {} } as any)).toBeNull();
      expect(extractAuthToken({ headers: { authorization: 'Basic dXNlcjpwYXNz' } } as any)).toBeNull();
      expect(extractAuthToken({ headers: { authorization: 'Bearer ' } } as any)).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Public Route Exceptions
  // ---------------------------------------------------------------------------
  describe('Allowlisted Public Endpoints', () => {
    it('GET /health succeeds unauthenticated without exposing secrets', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/health',
      });

      expect(res.statusCode).toBe(200);
      const data = res.json();
      expect(['ok', 'degraded']).toContain(data.status);
      expect(data).toHaveProperty('version');
      expect(data).not.toHaveProperty('env');
      expect(data).not.toHaveProperty('config');
      expect(data).not.toHaveProperty('apiKey');
    });

    it('GET /api/v1/health succeeds unauthenticated', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/health',
      });

      expect(res.statusCode).toBe(200);
      expect(['ok', 'degraded']).toContain(res.json().status);
    });
  });

  // ---------------------------------------------------------------------------
  // 4. Fail-Closed Authentication on Protected Endpoints
  // ---------------------------------------------------------------------------
  describe('Protected Route Authentication (Fail-Closed)', () => {
    it('rejects unauthenticated GET /api/v1/projects with 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/projects',
      });

      expect(res.statusCode).toBe(401);
      const body = res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('UNAUTHORIZED');
      expect(body.error.message).toContain('Valid API key or bearer token required');
    });

    it('rejects unauthenticated GET /api/v1/targets with 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/targets',
      });
      expect(res.statusCode).toBe(401);
    });

    it('rejects unauthenticated GET /api/v1/test-runs with 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/test-runs',
      });
      expect(res.statusCode).toBe(401);
    });

    it('rejects unauthenticated GET /api/v1/findings with 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/findings',
      });
      expect(res.statusCode).toBe(401);
    });

    it('rejects unauthenticated GET /api/v1/management/overview with 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/management/overview',
      });
      expect(res.statusCode).toBe(401);
    });

    it('rejects request with invalid API key with 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/projects',
        headers: {
          authorization: 'Bearer completely-invalid-wrong-key-999',
        },
      });

      expect(res.statusCode).toBe(401);
      const body = res.json();
      expect(body.error.code).toBe('UNAUTHORIZED');
      expect(body.error.message).toBe('Invalid API key or bearer token');
    });

    it('rejects malformed authorization header with 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/projects',
        headers: {
          authorization: 'Basic invalid-auth-format',
        },
      });

      expect(res.statusCode).toBe(401);
    });

    it('rejects empty bearer token with 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/projects',
        headers: {
          authorization: 'Bearer    ',
        },
      });

      expect(res.statusCode).toBe(401);
    });
  });

  // ---------------------------------------------------------------------------
  // 5. Operator Access
  // ---------------------------------------------------------------------------
  describe('Operator Role Privileges', () => {
    it('allows operator access to GET /api/v1/projects via Bearer token', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/projects',
        headers: {
          authorization: `Bearer ${testApiKey}`,
        },
      });

      expect(res.statusCode).toBe(200);
      expect(res.json().success).toBe(true);
    });

    it('allows operator access via X-API-Key header', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/projects',
        headers: {
          'x-api-key': testApiKey,
        },
      });

      expect(res.statusCode).toBe(200);
      expect(res.json().success).toBe(true);
    });

    it('allows operator access to GET /api/v1/management/overview', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/management/overview',
        headers: {
          authorization: `Bearer ${testApiKey}`,
        },
      });

      expect(res.statusCode).toBe(200);
      expect(res.json().success).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // 6. Role-Based Access Control: Administrative Guarding
  // ---------------------------------------------------------------------------
  describe('Administrative Route Authorization (RBAC)', () => {
    it('rejects operator key on POST /api/v1/management/purge with 403 Forbidden', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/management/purge',
        headers: {
          authorization: `Bearer ${testApiKey}`, // operator key
        },
        payload: {
          mode: 'all',
          confirmation: 'confirm_purge_all_data',
        },
      });

      expect(res.statusCode).toBe(403);
      const body = res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.error.message).toContain('Administrative authorization required');
    });

    it('rejects operator key on POST /api/v1/management/seed with 403 Forbidden', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/management/seed',
        headers: {
          authorization: `Bearer ${testApiKey}`, // operator key
        },
      });

      expect(res.statusCode).toBe(403);
      expect(res.json().error.code).toBe('FORBIDDEN');
    });

    it('rejects operator key on POST /api/v1/management/backups/restore with 403 Forbidden', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/management/backups/restore',
        headers: {
          authorization: `Bearer ${testApiKey}`,
        },
        payload: {
          version: '1.0.0',
          mode: 'merge',
          metadata: {},
          data: {},
        },
      });

      expect(res.statusCode).toBe(403);
      expect(res.json().error.code).toBe('FORBIDDEN');
    });

    it('rejects operator key on DELETE /api/v1/management/backups/:id with 403 Forbidden', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: '/api/v1/management/backups/fake-backup-id',
        headers: {
          authorization: `Bearer ${testApiKey}`,
        },
      });

      expect(res.statusCode).toBe(403);
      expect(res.json().error.code).toBe('FORBIDDEN');
    });

    it('authorizes admin key on POST /api/v1/management/purge', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/management/purge',
        headers: {
          authorization: `Bearer ${testAdminKey}`, // admin key
        },
        payload: {
          mode: 'all',
          confirmation: 'invalid_confirmation_to_prevent_actual_wipe',
        },
      });

      // Authorization succeeded; fails at confirmation validation (400) instead of auth (401/403)
      expect(res.statusCode).toBe(400);
      expect(res.json().error.code).toBe('PURGE_FAILED');
    });
  });
});
