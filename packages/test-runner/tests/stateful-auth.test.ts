import { describe, it, expect, vi } from 'vitest';
import { StatefulAuthenticator } from '../src/stateful-auth.js';
import { executeHttpRequest } from '../src/executor.js';
import { AuthFlow } from '@security-lab/contracts';
import {
  encrypt,
  decrypt,
  encryptObject,
  decryptObject,
  verifyTotp,
  redactHeaders,
  REDACTED_VALUE,
} from '@security-lab/crypto';

describe('Phase 06: Stateful Authentication & Secrets Vault Integration', () => {
  const masterKey = Buffer.alloc(32, 0x5a);

  describe('1. Envelope Encryption at Rest (AES-256-GCM)', () => {
    it('should encrypt sensitive target credentials at rest using AES-256-GCM envelope encryption', () => {
      const sensitiveCredentials = {
        username: 'sec-admin',
        password: 'P@ssw0rd!SuperSecret2026',
        apiKey: 'sk-live-target-api-key-998877',
        totpSecret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
      };

      const encrypted = encryptObject(sensitiveCredentials, masterKey);

      expect(encrypted.algorithm).toBe('aes-256-gcm');
      expect(encrypted.encryptedData).toBeDefined();
      expect(encrypted.encryptedDek).toBeDefined();
      expect(encrypted.iv).toBeDefined();
      expect(encrypted.tag).toBeDefined();

      // Plaintext values must never exist anywhere in the serialized payload
      const serialized = JSON.stringify(encrypted);
      expect(serialized).not.toContain('sec-admin');
      expect(serialized).not.toContain('P@ssw0rd');
      expect(serialized).not.toContain('sk-live');

      // Decrypt round-trip
      const decrypted = decryptObject<typeof sensitiveCredentials>(encrypted, masterKey);
      expect(decrypted).toEqual(sensitiveCredentials);
    });

    it('should detect ciphertext tampering and fail authentication decryption safely', () => {
      const payload = encrypt('sensitive-api-token', masterKey);

      const corruptedBuffer = Buffer.from(payload.encryptedData, 'base64');
      corruptedBuffer[2] = (corruptedBuffer[2] ?? 0) ^ 0xff;
      const corruptedPayload = {
        ...payload,
        encryptedData: corruptedBuffer.toString('base64'),
      };

      expect(() => decrypt(corruptedPayload, masterKey)).toThrow();
    });
  });

  describe('2. Multi-Step Form Login with CSRF & RFC-6238 TOTP', () => {
    const totpSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

    it('should successfully execute multi-step login with CSRF token extraction and dynamic TOTP generation', async () => {
      let csrfProvidedToLogin = '';
      let totpProvidedToLogin = '';

      const mockFetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
        const u = new URL(url);

        // Step 1: GET /login to extract CSRF token and receive session cookie
        if (u.pathname === '/login' && init?.method === 'GET') {
          return new Response(
            JSON.stringify({ csrfToken: 'csrf-xyz-987654' }),
            {
              status: 200,
              headers: {
                'Content-Type': 'application/json',
                'set-cookie': 'csrf_cookie=csrf-token-cookie-123; Path=/',
              },
            },
          );
        }

        // Step 2: POST /login with credentials, csrf token, and computed TOTP
        if (u.pathname === '/login' && init?.method === 'POST') {
          const body = JSON.parse(init.body as string);
          csrfProvidedToLogin = body._csrf;
          totpProvidedToLogin = body.totp;

          // Verify TOTP is valid RFC-6238 code
          const isValidTotp = verifyTotp(totpProvidedToLogin, totpSecret);

          if (
            body.username === 'admin' &&
            body.password === 'hunter2' &&
            csrfProvidedToLogin === 'csrf-xyz-987654' &&
            isValidTotp
          ) {
            return new Response(
              JSON.stringify({
                status: 'success',
                access_token: 'jwt-session-token-abc-999',
                token_type: 'Bearer',
              }),
              {
                status: 200,
                headers: {
                  'Content-Type': 'application/json',
                  'set-cookie': 'auth_session=session_authenticated_active; HttpOnly',
                },
              },
            );
          }

          return new Response(JSON.stringify({ error: 'Invalid credentials or TOTP' }), {
            status: 401,
          });
        }

        return new Response('Not Found', { status: 404 });
      });

      const flow: AuthFlow = {
        type: 'FORM',
        totpSecret,
        credentials: {
          username: 'admin',
          password: 'hunter2',
        },
        steps: [
          {
            name: 'Fetch CSRF token',
            url: 'https://target.local/login',
            method: 'GET',
            extract: [
              {
                from: 'BODY_JSON',
                key: 'csrfToken',
                saveAs: '_csrf',
              },
            ],
          },
          {
            name: 'Submit login credentials and TOTP',
            url: 'https://target.local/login',
            method: 'POST',
            body: {
              username: '{{username}}',
              password: '{{password}}',
              _csrf: '{{_csrf}}',
              totp: '{{totp}}',
            },
            extract: [
              {
                from: 'BODY_JSON',
                key: 'access_token',
                saveAs: 'token',
              },
            ],
          },
        ],
      };

      const authenticator = new StatefulAuthenticator({
        flow,
        customFetch: mockFetch as any,
      });

      const state = await authenticator.refreshSession();

      expect(csrfProvidedToLogin).toBe('csrf-xyz-987654');
      expect(totpProvidedToLogin).toMatch(/^\d{6}$/);
      expect(state.token).toBe('jwt-session-token-abc-999');
      expect(state.cookies['auth_session']).toBe('session_authenticated_active');

      const headers = authenticator.getHeaders();
      expect(headers['Authorization']).toBe('Bearer jwt-session-token-abc-999');
      expect(headers['Cookie']).toContain('auth_session=session_authenticated_active');
    });
  });

  describe('3. OAuth2 Client Credentials & Password Grants', () => {
    it('should exchange client credentials for an OAuth2 token', async () => {
      const mockFetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
        if (url === 'https://auth.target.local/oauth/v2/token' && init?.method === 'POST') {
          const bodyParams = new URLSearchParams(init.body as string);
          if (
            bodyParams.get('grant_type') === 'client_credentials' &&
            bodyParams.get('client_id') === 'client-123' &&
            bodyParams.get('client_secret') === 'secret-456'
          ) {
            return new Response(
              JSON.stringify({
                access_token: 'oauth2-access-token-777',
                token_type: 'Bearer',
                expires_in: 3600,
              }),
              { status: 200, headers: { 'Content-Type': 'application/json' } },
            );
          }
        }
        return new Response('Unauthorized', { status: 401 });
      });

      const flow: AuthFlow = {
        type: 'OAUTH2',
        oauth2Config: {
          grantType: 'client_credentials',
          tokenUrl: 'https://auth.target.local/oauth/v2/token',
          clientId: 'client-123',
          clientSecret: 'secret-456',
          scope: 'read:targets write:tests',
        },
      };

      const authenticator = new StatefulAuthenticator({
        flow,
        customFetch: mockFetch as any,
      });

      await authenticator.refreshSession();
      const headers = authenticator.getHeaders();
      expect(headers['Authorization']).toBe('Bearer oauth2-access-token-777');
      expect(authenticator.isExpired()).toBe(false);
    });
  });

  describe('4. Concurrency Mutex Lock During Authentication Refresh', () => {
    it('should coalesce simultaneous refresh calls into a single in-flight request', async () => {
      let callCount = 0;
      const mockFetch = vi.fn().mockImplementation(async () => {
        callCount++;
        // Small delay to simulate async network handshake
        await new Promise((resolve) => setTimeout(resolve, 30));
        return new Response(
          JSON.stringify({ access_token: `token-version-${callCount}` }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      });

      const flow: AuthFlow = {
        type: 'FORM',
        loginUrl: 'https://target.local/login',
        credentials: { username: 'test', password: 'pwd' },
      };

      const authenticator = new StatefulAuthenticator({
        flow,
        customFetch: mockFetch as any,
      });

      // Fire 5 concurrent refresh calls at the exact same moment
      const results = await Promise.all([
        authenticator.refreshSession(),
        authenticator.refreshSession(),
        authenticator.refreshSession(),
        authenticator.refreshSession(),
        authenticator.refreshSession(),
      ]);

      // All 5 callers should receive the exact same refreshed session state
      expect(callCount).toBe(1);
      for (const res of results) {
        expect(res.token).toBe('token-version-1');
      }
    });
  });

  describe('5. Automatic Token Refresh on 401 Unauthorized in executeHttpRequest', () => {
    it('should intercept 401 response, refresh expired token, and replay the original request successfully', async () => {
      let tokenCounter = 1;
      let targetApiCalls = 0;
      let currentValidToken = 'active-token-v1';

      // Custom fetch that simulates:
      // 1. Auth server issuing new tokens
      // 2. Protected resource rejecting expired tokens with 401, but accepting new token
      const customFetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
        const u = new URL(url);

        // Auth endpoint to issue new token
        if (u.pathname === '/auth/login') {
          tokenCounter++;
          currentValidToken = `refreshed-token-v${tokenCounter}`;
          return new Response(
            JSON.stringify({ access_token: currentValidToken }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }

        // Protected target resource
        if (u.pathname === '/api/v1/user-data') {
          targetApiCalls++;
          const authHeader = (init?.headers as any)?.get?.('Authorization') ||
            (init?.headers as Record<string, string>)?.[`Authorization`] ||
            (init?.headers as Record<string, string>)?.[`authorization`];

          // If header matches the current valid token, return 200 OK
          if (authHeader === `Bearer ${currentValidToken}`) {
            return new Response(
              JSON.stringify({ data: 'Confidential target payload', user: 'alice' }),
              { status: 200, headers: { 'Content-Type': 'application/json' } },
            );
          }

          // Otherwise return 401 Unauthorized (simulating expired session token)
          return new Response(
            JSON.stringify({ error: 'Token expired or unauthorized' }),
            { status: 401, headers: { 'Content-Type': 'application/json' } },
          );
        }

        return new Response('Not found', { status: 404 });
      });

      const flow: AuthFlow = {
        type: 'FORM',
        loginUrl: 'https://api.target.local/auth/login',
        credentials: { username: 'test-user', password: 'test-pass' },
      };

      // Authenticator initialized with an initially expired/stale token
      const authenticator = new StatefulAuthenticator({
        flow,
        initialState: {
          token: 'expired-token-v0',
        },
        customFetch: customFetch as any,
      });

      // Dispatch request to protected resource using executeHttpRequest with authenticator configured
      const response = await executeHttpRequest('https://api.target.local/api/v1/user-data', {
        authenticator,
        autoRefresh: true,
        fetchImpl: customFetch as any,
      });

      // The request should have transparently recovered and returned 200 OK
      expect(response.status).toBe(200);
      const json = await response.json();
      expect(json.data).toBe('Confidential target payload');

      // Target was called initially (got 401), re-auth fired, then target was called again (got 200)
      expect(targetApiCalls).toBe(2);

      // Authenticator now holds the refreshed token
      expect(authenticator.getState().token).toBe('refreshed-token-v2');
    });

    it('should not enter infinite loop if re-authenticated request still returns 401', async () => {
      let callCount = 0;
      const customFetch = vi.fn().mockImplementation(async (url: string) => {
        const u = new URL(url);
        if (u.pathname === '/login') {
          return new Response(
            JSON.stringify({ access_token: 'new-token' }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        callCount++;
        return new Response(
          JSON.stringify({ error: 'Permanent 401 Unauthorized' }),
          { status: 401, headers: { 'Content-Type': 'application/json' } },
        );
      });

      const flow: AuthFlow = {
        type: 'FORM',
        loginUrl: 'https://api.target.local/login',
      };

      const authenticator = new StatefulAuthenticator({
        flow,
        customFetch: customFetch as any,
      });

      const response = await executeHttpRequest('https://api.target.local/api/forbidden', {
        authenticator,
        autoRefresh: true,
        fetchImpl: customFetch as any,
      });

      // Returns the 401 without looping indefinitely
      expect(response.status).toBe(401);
      // Attempted original request (401), refreshed, retried once (401), then stopped
      expect(callCount).toBe(2);
    });
  });

  describe('6. Redaction Safety Invariant (Architecture Rule 4)', () => {
    it('should redact sensitive authorization headers and cookies from logs and evidence', () => {
      const activeHeaders = {
        Authorization: 'Bearer super-secret-jwt-token-value',
        Cookie: 'session_id=confidential_session_secret; remember_me=true',
        'X-Api-Key': 'live_key_9988776655',
        'Content-Type': 'application/json',
      };

      const redacted = redactHeaders(activeHeaders);

      expect(redacted['Authorization']).toBe(REDACTED_VALUE);
      expect(redacted['Cookie']).toBe(REDACTED_VALUE);
      expect(redacted['X-Api-Key']).toBe(REDACTED_VALUE);
      expect(redacted['Content-Type']).toBe('application/json');
    });
  });
});
