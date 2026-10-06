import http from 'node:http';
import crypto from 'node:crypto';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import {
  AuthenticationSecurityEngine,
  ExecutionContext,
  createHmacToken,
  decodeJwt,
} from '@security-lab/test-sdk';
import { logger } from '@security-lab/logger';

describe('AuthenticationSecurityEngine Integration Suite', () => {
  let server: http.Server;
  let serverPort: number;
  let serverUrl: string;

  const STRONG_SECRET = 'c7e9a8f2b1d3e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0';
  const WEAK_SECRET = 'secret';

  // Server mode configuration
  let mode: 'insecure' | 'hardened' = 'insecure';
  let failedLoginCount = 0;

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      const parsedUrl = new URL(req.url || '/', `http://127.0.0.1:${serverPort}`);
      const pathname = parsedUrl.pathname;

      if (mode === 'insecure') {
        // --- Insecure Mock Implementation ---

        // Root / Landing: Returns cookies missing security flags
        if (pathname === '/' && req.method === 'GET') {
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Set-Cookie': [
              'session_id=sess-raw-12345; Path=/', // Missing HttpOnly, Secure, SameSite
              'auth_token=jwt-preview; Path=/', // Missing HttpOnly, Secure
              '__Host-admin=bad-prefix; Domain=127.0.0.1; Path=/app', // Violates __Host- (has Domain, path not /)
            ] as unknown as string,
          });
          res.end(JSON.stringify({ status: 'ok', auth: false }));
          return;
        }

        // Protected Endpoint: Vulnerable JWT verification
        if (pathname === '/api/protected' && req.method === 'GET') {
          const authHeader = req.headers['authorization'];
          if (!authHeader || !authHeader.startsWith('Bearer ')) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Missing Authorization header' }));
            return;
          }

          const token = authHeader.slice(7).trim();
          const decoded = decodeJwt(token);

          if (!decoded) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Malformed token' }));
            return;
          }

          const alg = String(decoded.header['alg']).toLowerCase();

          // VULNERABILITY 1: Accepts alg="none"
          if (alg === 'none') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 'authorized', user: decoded.payload, bypass: 'none' }));
            return;
          }

          // VULNERABILITY 2: Accepts stripped signature
          if (!decoded.signature) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 'authorized', user: decoded.payload, bypass: 'stripped' }));
            return;
          }

          // VULNERABILITY 3: Does NOT verify exp claim
          // VULNERABILITY 4: Accepts weak secret 'secret'
          const expectedSig = crypto
            .createHmac('sha256', WEAK_SECRET)
            .update(`${decoded.headerRaw}.${decoded.payloadRaw}`)
            .digest('base64url');

          if (decoded.signature === expectedSig) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 'authorized', user: decoded.payload }));
            return;
          }

          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid token signature' }));
          return;
        }

        // Login Route: Vulnerable to session fixation and no rate limiting
        if (pathname === '/auth/login' && req.method === 'POST') {
          let body = '';
          req.on('data', (chunk) => (body += chunk));
          req.on('end', () => {
            const cookie = req.headers['cookie'] || '';
            const isExistingSession = cookie.includes('session_id=sess-raw-12345');

            // VULNERABILITY: Session Fixation (retains existing session ID)
            if (isExistingSession) {
              res.writeHead(200, {
                'Content-Type': 'application/json',
                'Set-Cookie': 'session_id=sess-raw-12345; Path=/', // No regeneration!
              });
              res.end(JSON.stringify({ success: true, user: 'audit-user' }));
              return;
            }

            // VULNERABILITY: No brute force rate limiting
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid credentials' }));
          });
          return;
        }
      } else {
        // --- Hardened Mock Implementation ---

        // Root / Landing: All cookies hardened
        if (pathname === '/' && req.method === 'GET') {
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Set-Cookie': 'session_id=sess-hardened-999; Path=/; HttpOnly; SameSite=Strict',
          });
          res.end(JSON.stringify({ status: 'ok', hardened: true }));
          return;
        }

        // Protected Endpoint: Strict JWT verification
        if (pathname === '/api/protected' && req.method === 'GET') {
          const authHeader = req.headers['authorization'];
          if (!authHeader || !authHeader.startsWith('Bearer ')) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Unauthorized' }));
            return;
          }

          const token = authHeader.slice(7).trim();
          const decoded = decodeJwt(token);

          if (!decoded) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid token' }));
            return;
          }

          // HARDENED: Strictly reject alg="none"
          if (decoded.header['alg'] !== 'HS256') {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Disallowed algorithm' }));
            return;
          }

          // HARDENED: Check expiration
          const exp = Number(decoded.payload['exp']);
          if (!exp || exp < Math.floor(Date.now() / 1000)) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Token expired' }));
            return;
          }

          // HARDENED: Verify against strong secret
          const expectedSig = crypto
            .createHmac('sha256', STRONG_SECRET)
            .update(`${decoded.headerRaw}.${decoded.payloadRaw}`)
            .digest('base64url');

          if (decoded.signature !== expectedSig) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Signature verification failed' }));
            return;
          }

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'authorized', user: decoded.payload }));
          return;
        }

        // Login Route: Regenerates session ID and rate limits
        if (pathname === '/auth/login' && req.method === 'POST') {
          failedLoginCount++;

          // HARDENED: Rate limiting after 3 failed attempts
          if (failedLoginCount > 3) {
            res.writeHead(429, {
              'Content-Type': 'application/json',
              'Retry-After': '60',
            });
            res.end(JSON.stringify({ error: 'Too many login attempts. Please wait.' }));
            return;
          }

          let body = '';
          req.on('data', (chunk) => (body += chunk));
          req.on('end', () => {
            let json = { username: '', password: '' };
            try {
              json = JSON.parse(body);
            } catch {
              // Ignore
            }

            if (json.username === 'admin' && json.password === 'hardened-password') {
              // HARDENED: Regenerate new random session ID
              res.writeHead(200, {
                'Content-Type': 'application/json',
                'Set-Cookie': `session_id=sess-regen-${crypto.randomBytes(8).toString('hex')}; Path=/; HttpOnly; SameSite=Strict`,
              });
              res.end(JSON.stringify({ success: true }));
              return;
            }

            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid credentials' }));
          });
          return;
        }
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        if (addr && typeof addr === 'object') {
          serverPort = addr.port;
          serverUrl = `http://127.0.0.1:${serverPort}`;
        }
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  const createDummyContext = (): ExecutionContext => ({
    correlationId: 'auth-corr-1',
    testRunId: '00000000-0000-0000-0000-000000000001',
    executionId: '00000000-0000-0000-0000-000000000002',
    target: {
      id: '00000000-0000-0000-0000-000000000003',
      name: 'Authentication Test Target',
      baseUrl: serverUrl,
      scope: {
        allowedHosts: ['127.0.0.1'],
        allowedPorts: [serverPort],
        excludedPaths: [],
        testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
        limits: { maxRps: 100, maxConcurrency: 10, maxDuration: '1m' },
      },
    },
    logger,
    abortSignal: new AbortController().signal,
    reportProgress: () => {},
  });

  const engine = new AuthenticationSecurityEngine();

  describe('Engine Metadata and Validation', () => {
    it('exposes valid capability metadata conforming to Class A Native execution', () => {
      expect(engine.id).toBe('engine-native-authentication');
      expect(engine.version).toBe('1.0.0');
      expect(engine.executionClass).toBe('class_a_native');

      const capabilities = engine.capabilities();
      expect(capabilities.length).toBe(4);
      const capIds = capabilities.map((c) => c.id);
      expect(capIds).toContain('auth_jwt_audit');
      expect(capIds).toContain('auth_cookie_flags');
      expect(capIds).toContain('auth_session_fixation');
      expect(capIds).toContain('auth_login_brute_force');
    });

    it('validates test inputs correctly', () => {
      expect(engine.validate({ targetUrl: 'not-a-url' }).valid).toBe(false);
      expect(engine.validate({ targetUrl: serverUrl }).valid).toBe(true);
      expect(
        engine.validate({
          targetUrl: serverUrl,
          options: { sampleToken: 12345 as unknown as string },
        }).valid,
      ).toBe(false);
    });
  });

  describe('Cookie Security Flags Audit (auth_cookie_flags)', () => {
    it('identifies missing HttpOnly, missing SameSite, and prefix violations on insecure cookies', async () => {
      mode = 'insecure';

      const result = await engine.execute(
        {
          targetUrl: serverUrl,
          options: { checkJwt: false, checkSessionFixation: false, checkBruteForce: false },
        },
        createDummyContext(),
      );

      expect(result.findings.length).toBeGreaterThanOrEqual(3);

      const httpOnlyFinding = result.findings.find((f) => f.title.includes('Missing HttpOnly Flag'));
      expect(httpOnlyFinding).toBeDefined();
      expect(httpOnlyFinding?.severity).toBe('high');

      const sameSiteFinding = result.findings.find((f) => f.title.includes('Missing SameSite Attribute'));
      expect(sameSiteFinding).toBeDefined();

      const hostPrefixFinding = result.findings.find((f) => f.title.includes('__Host- Prefix'));
      expect(hostPrefixFinding).toBeDefined();
      expect(hostPrefixFinding?.severity).toBe('high');
    });

    it('produces zero cookie findings against a hardened endpoint', async () => {
      mode = 'hardened';

      const result = await engine.execute(
        {
          targetUrl: serverUrl,
          options: { checkJwt: false, checkSessionFixation: false, checkBruteForce: false },
        },
        createDummyContext(),
      );

      const cookieFindings = result.findings.filter((f) => f.category === 'cookies');
      expect(cookieFindings.length).toBe(0);
      expect(result.success).toBe(true);
    });
  });

  describe('JWT Security & Tampering Probes (auth_jwt_audit)', () => {
    it('detects critical vulnerabilities when target accepts alg="none" and weak HMAC secret', async () => {
      mode = 'insecure';

      // Generate a sample token signed with the weak secret
      const sampleToken = createHmacToken(
        { sub: 'usr-target', role: 'admin', exp: Math.floor(Date.now() / 1000) + 3600 },
        WEAK_SECRET,
      );

      const result = await engine.execute(
        {
          targetUrl: serverUrl,
          options: {
            protectedPath: '/api/protected',
            sampleToken,
            checkCookies: false,
            checkSessionFixation: false,
            checkBruteForce: false,
          },
        },
        createDummyContext(),
      );

      expect(result.success).toBe(false);

      // Verify alg: none bypass finding
      const noneFinding = result.findings.find((f) => f.title.includes("Algorithm 'none'"));
      expect(noneFinding).toBeDefined();
      expect(noneFinding?.severity).toBe('critical');

      // Verify stripped signature finding
      const strippedFinding = result.findings.find((f) => f.title.includes('Signature-Stripped'));
      expect(strippedFinding).toBeDefined();
      expect(strippedFinding?.severity).toBe('critical');

      // Verify weak secret finding
      const weakSecretFinding = result.findings.find((f) => f.title.includes('Weak / Predictable Secret'));
      expect(weakSecretFinding).toBeDefined();
      expect(weakSecretFinding?.severity).toBe('critical');
    });

    it('passes cleanly when target strictly rejects tampered, expired, and weak JWTs', async () => {
      mode = 'hardened';

      // Valid token signed with STRONG_SECRET
      const validToken = createHmacToken(
        { sub: 'usr-hardened', role: 'user', exp: Math.floor(Date.now() / 1000) + 7200 },
        STRONG_SECRET,
      );

      const result = await engine.execute(
        {
          targetUrl: serverUrl,
          options: {
            protectedPath: '/api/protected',
            sampleToken: validToken,
            checkCookies: false,
            checkSessionFixation: false,
            checkBruteForce: false,
          },
        },
        createDummyContext(),
      );

      expect(result.success).toBe(true);
      const authFindings = result.findings.filter((f) => f.category === 'authentication');
      expect(authFindings.length).toBe(0);
    });
  });

  describe('Session Fixation Audit (auth_session_fixation)', () => {
    it('flags session fixation when session identifier is retained across login', async () => {
      mode = 'insecure';

      const result = await engine.execute(
        {
          targetUrl: serverUrl,
          options: {
            loginPath: '/auth/login',
            credentials: { username: 'admin', password: 'password' },
            checkJwt: false,
            checkCookies: false,
            checkBruteForce: false,
          },
        },
        createDummyContext(),
      );

      const fixationFinding = result.findings.find((f) => f.title.includes('Session Fixation'));
      expect(fixationFinding).toBeDefined();
      expect(fixationFinding?.severity).toBe('high');
    });

    it('produces zero fixation findings when session identifier is properly regenerated', async () => {
      mode = 'hardened';
      failedLoginCount = 0;

      const result = await engine.execute(
        {
          targetUrl: serverUrl,
          options: {
            loginPath: '/auth/login',
            credentials: { username: 'admin', password: 'hardened-password' },
            checkJwt: false,
            checkCookies: false,
            checkBruteForce: false,
          },
        },
        createDummyContext(),
      );

      const fixationFinding = result.findings.find((f) => f.title.includes('Session Fixation'));
      expect(fixationFinding).toBeUndefined();
    });
  });

  describe('Authentication Route Brute-Force Throttling (auth_login_brute_force)', () => {
    it('flags missing rate limiting when rapid failed login attempts are unthrottled', async () => {
      mode = 'insecure';

      const result = await engine.execute(
        {
          targetUrl: serverUrl,
          options: {
            loginPath: '/auth/login',
            checkBruteForce: true,
            bruteForceAttempts: 5,
            checkJwt: false,
            checkCookies: false,
            checkSessionFixation: false,
          },
        },
        createDummyContext(),
      );

      const bruteForceFinding = result.findings.find((f) => f.title.includes('Missing Rate Limiting'));
      expect(bruteForceFinding).toBeDefined();
      expect(bruteForceFinding?.severity).toBe('medium');
    });

    it('passes when login route enforces rate limiting via HTTP 429', async () => {
      mode = 'hardened';
      failedLoginCount = 0;

      const result = await engine.execute(
        {
          targetUrl: serverUrl,
          options: {
            loginPath: '/auth/login',
            checkBruteForce: true,
            bruteForceAttempts: 5,
            checkJwt: false,
            checkCookies: false,
            checkSessionFixation: false,
          },
        },
        createDummyContext(),
      );

      const bruteForceFinding = result.findings.find((f) => f.title.includes('Missing Rate Limiting'));
      expect(bruteForceFinding).toBeUndefined();
    });
  });
});
