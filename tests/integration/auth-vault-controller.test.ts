import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { FastifyInstance } from 'fastify';

vi.mock('../../apps/controller/src/services/db.js', () => {
  const db = {
    insert: vi.fn(() => ({
      values: vi.fn(() => ({
        returning: vi.fn().mockResolvedValue([{ id: 'tenant-1' }]),
      })),
    })),
    select: vi.fn(() => ({
      from: vi.fn(() => ({
        where: vi.fn(() => ({
          limit: vi.fn().mockResolvedValue([]),
          then: (resolve: any, reject: any) => Promise.resolve([]).then(resolve, reject),
        })),
        limit: vi.fn().mockResolvedValue([]),
        then: (resolve: any, reject: any) => Promise.resolve([]).then(resolve, reject),
      })),
    })),
  };
  return {
    getDatabase: () => ({ db }),
    closeDatabase: vi.fn(),
  };
});

import { buildApp } from '../../apps/controller/src/app/index.js';
import { webhookQueueService } from '../../apps/controller/src/services/webhook-queue.js';
import { signJwt, DEFAULT_WORKSPACE_ID } from '../../apps/controller/src/services/auth-token.service.js';

describe('PR-08 Integration: Auth Vault Server-Side Flow Verifier & SSRF Prevention', () => {
  let app: FastifyInstance;
  let authToken: string;

  beforeAll(async () => {
    app = buildApp({
      disableLogging: true,
      enableReaper: false,
      bypassAuth: false,
    });
    await app.ready();

    authToken = signJwt({
      userId: 'test-engineer-pr08',
      workspaceId: DEFAULT_WORKSPACE_ID,
      role: 'engineer',
    });
  });

  afterAll(async () => {
    webhookQueueService.stopWorker();
    await app.close();
  });

  describe('SSRF Boundary Checks & Target Scope Protection', () => {
    it('blocks OAuth2 token URL targeting AWS metadata (169.254.169.254)', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/auth-vault/verify-flow',
        headers: {
          authorization: `Bearer ${authToken}`,
        },
        payload: {
          targetId: 'https://staging.securitylab.internal',
          flow: {
            type: 'OAUTH2',
            oauth2Config: {
              grantType: 'client_credentials',
              tokenUrl: 'http://169.254.169.254/latest/meta-data/iam/security-credentials',
              clientId: 'test-client',
              clientSecret: 'test-secret',
            },
          },
        },
      });

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('SSRF_SCOPE_VIOLATION');
      expect(body.error.message).toContain('violates target scope');
    });

    it('blocks multi-step form login URLs targeting GCP metadata or loopback IP', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/auth-vault/verify-flow',
        headers: {
          authorization: `Bearer ${authToken}`,
        },
        payload: {
          targetId: 'https://staging.securitylab.internal',
          flow: {
            type: 'FORM',
            steps: [
              {
                name: 'Exploit GCP metadata',
                url: 'http://metadata.google.internal/computeMetadata/v1/',
                method: 'GET',
              },
            ],
          },
        },
      });

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('SSRF_SCOPE_VIOLATION');
    });

    it('returns 404 when targetId is not a URL and does not exist in the database', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/auth-vault/verify-flow',
        headers: {
          authorization: `Bearer ${authToken}`,
        },
        payload: {
          targetId: '00000000-0000-0000-0000-000000000000',
          flow: {
            type: 'BEARER',
            credentials: { token: 'sample-token' },
          },
        },
      });

      expect(response.statusCode).toBe(404);
      const body = JSON.parse(response.body);
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('TARGET_NOT_FOUND');
    });
  });

  describe('Server-Side Flow Execution Diagnostics', () => {
    it('executes server-side OAuth2 handshake and returns real diagnostics', async () => {
      const targetUrl = 'http://127.0.0.1:8080';
      const tokenUrl = 'http://127.0.0.1:8080/oauth/v2/token';

      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            access_token: 'controller-verified-jwt-999',
            token_type: 'Bearer',
            expires_in: 3600,
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        ),
      );

      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/auth-vault/verify-flow',
        headers: {
          authorization: `Bearer ${authToken}`,
        },
        payload: {
          targetId: targetUrl,
          flow: {
            type: 'OAUTH2',
            oauth2Config: {
              grantType: 'client_credentials',
              tokenUrl: tokenUrl,
              clientId: 'secops-client-id',
              clientSecret: 'secops-client-secret',
            },
          },
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.success).toBe(true);
      expect(body.finalToken).toBe('controller-verified-jwt-999');
      expect(body.stepsExecuted).toHaveLength(1);
      expect(body.stepsExecuted[0].method).toBe('POST');
      expect(body.stepsExecuted[0].statusCode).toBe(200);
      expect(body.stepsExecuted[0].url).toBe(tokenUrl);
      expect(body.totalDurationMs).toBeGreaterThanOrEqual(0);

      fetchSpy.mockRestore();
    });

    it('truthfully captures target 401 Unauthorized errors with success: false', async () => {
      const targetUrl = 'http://127.0.0.1:8080';
      const tokenUrl = 'http://127.0.0.1:8080/oauth/v2/token';

      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            error: 'invalid_client',
            error_description: 'Client credentials rejected by authorization server',
          }),
          {
            status: 401,
            headers: { 'Content-Type': 'application/json' },
          },
        ),
      );

      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/auth-vault/verify-flow',
        headers: {
          authorization: `Bearer ${authToken}`,
        },
        payload: {
          targetId: targetUrl,
          flow: {
            type: 'OAUTH2',
            oauth2Config: {
              grantType: 'client_credentials',
              tokenUrl: tokenUrl,
              clientId: 'invalid-client',
              clientSecret: 'wrong-secret',
            },
          },
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.success).toBe(false);
      expect(body.error).toContain('401');
      expect(body.stepsExecuted).toHaveLength(1);
      expect(body.stepsExecuted[0].statusCode).toBe(401);
      expect(body.finalToken).toBeUndefined();

      fetchSpy.mockRestore();
    });
  });
});
