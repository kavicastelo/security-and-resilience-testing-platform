import http from 'node:http';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import {
  AuthorizationSecurityEngine,
  ExecutionContext,
  generateAuthorizationPermutations,
} from '@security-lab/test-sdk';
import { parseAuthorizationTestSuiteYaml } from '@security-lab/domain';
import { logger } from '@security-lab/logger';

describe('AuthorizationSecurityEngine & BOLA Testing Suite', () => {
  let server: http.Server;
  let serverPort: number;
  let serverUrl: string;

  // Server state mode
  let mode: 'vulnerable' | 'hardened' = 'vulnerable';

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      const parsedUrl = new URL(req.url || '/', `http://127.0.0.1:${serverPort}`);
      const pathname = parsedUrl.pathname;
      const authHeader = req.headers['authorization'];

      // Extract bearer token
      const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7).trim() : undefined;

      if (mode === 'vulnerable') {
        // --- Vulnerable Mock Implementation ---

        // BOLA Vulnerability: Document retrieval endpoint does not verify ownership!
        if (pathname === '/api/documents/doc-101' && req.method === 'GET') {
          // If unauthenticated (no token)
          if (!token) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                id: 'doc-101',
                title: 'User A Financial Records',
                ownerId: '101',
                data: 'Extremely sensitive payroll data',
              }),
            );
            return;
          }

          // If authenticated with ANY token (User A, User B, etc.), return User A's private doc!
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              id: 'doc-101',
              title: 'User A Financial Records',
              ownerId: '101',
              data: 'Extremely sensitive payroll data',
            }),
          );
          return;
        }

        if (pathname === '/api/documents/doc-102' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              id: 'doc-102',
              title: 'User B Health Records',
              ownerId: '102',
              data: 'Medical test results',
            }),
          );
          return;
        }

        // BFLA Vulnerability: Admin endpoint accepts standard user tokens!
        if (pathname === '/api/admin/users' && req.method === 'GET') {
          if (!token) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Unauthorized' }));
            return;
          }

          // Flaw: Accepts unprivileged user tokens (e.g. token-user-a, token-user-b)
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              users: [
                { id: '101', username: 'alice', role: 'user' },
                { id: '102', username: 'bob', role: 'user' },
                { id: '999', username: 'admin', role: 'admin' },
              ],
            }),
          );
          return;
        }
      } else {
        // --- Hardened Mock Implementation ---

        // Hardened Document endpoint: Strict object-level authorization
        if (pathname === '/api/documents/doc-101' && req.method === 'GET') {
          if (!token) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Authentication required' }));
            return;
          }

          // Only owner (token-user-a-101) or admin (token-admin-999) permitted
          if (token === 'token-user-a-101' || token === 'token-admin-999') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                id: 'doc-101',
                title: 'User A Financial Records',
                ownerId: '101',
              }),
            );
            return;
          }

          // Reject other users (e.g. User B) with 403 Forbidden
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Forbidden: you do not own this document' }));
          return;
        }

        if (pathname === '/api/documents/doc-102' && req.method === 'GET') {
          if (!token) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Authentication required' }));
            return;
          }

          if (token === 'token-user-b-102' || token === 'token-admin-999') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                id: 'doc-102',
                title: 'User B Health Records',
                ownerId: '102',
              }),
            );
            return;
          }

          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Forbidden: you do not own this document' }));
          return;
        }

        // Hardened Admin endpoint: Strict role-based function access control
        if (pathname === '/api/admin/users' && req.method === 'GET') {
          if (!token) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Authentication required' }));
            return;
          }

          if (token === 'token-admin-999') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ users: [{ id: '999', role: 'admin' }] }));
            return;
          }

          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Forbidden: administrative privilege required' }));
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
    correlationId: 'authz-corr-1',
    testRunId: '00000000-0000-0000-0000-000000000001',
    executionId: '00000000-0000-0000-0000-000000000002',
    target: {
      id: '00000000-0000-0000-0000-000000000003',
      name: 'Authorization Test Target',
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

  const sampleTestSuiteYaml = `
id: suite-bola-test
name: Test Suite for BOLA and BFLA
version: 1.0.0
category: authorization
identities:
  - id: user_a
    name: Alice (User A)
    role: user
    token: token-user-a-101

  - id: user_b
    name: Bob (User B)
    role: user
    token: token-user-b-102

  - id: admin
    name: Super Admin
    role: admin
    token: token-admin-999

resources:
  - id: doc-user-a
    ownerIdentityId: user_a
    resourceType: document
    pathParam: documentId
    value: doc-101

  - id: doc-user-b
    ownerIdentityId: user_b
    resourceType: document
    pathParam: documentId
    value: doc-102

rules:
  - id: rule-docs
    name: Document Retrieval
    path: /api/documents/{documentId}
    method: GET
    resourceType: document
    allowOwner: true
    allowedRoles:
      - admin
    allowGuest: false
    expectedAllowedStatus: [200]
    expectedDeniedStatus: [401, 403, 404]

  - id: rule-admin
    name: Admin Users List
    path: /api/admin/users
    method: GET
    allowedRoles:
      - admin
    allowGuest: false
    expectedAllowedStatus: [200]
    expectedDeniedStatus: [401, 403]
`;

  const engine = new AuthorizationSecurityEngine();

  describe('Engine Metadata and Permutation Generation', () => {
    it('exposes valid capability metadata conforming to Class A Native execution', () => {
      expect(engine.id).toBe('engine-native-authorization');
      expect(engine.version).toBe('1.0.0');
      expect(engine.executionClass).toBe('class_a_native');

      const capabilities = engine.capabilities();
      expect(capabilities.length).toBe(3);
      const capIds = capabilities.map((c) => c.id);
      expect(capIds).toContain('bola_horizontal_idor');
      expect(capIds).toContain('bfla_vertical_escalation');
      expect(capIds).toContain('auth_missing_control');
    });

    it('validates test inputs correctly', () => {
      expect(engine.validate({ targetUrl: 'invalid-url' }).valid).toBe(false);
      expect(engine.validate({ targetUrl: serverUrl, options: {} }).valid).toBe(false);
      expect(
        engine.validate({
          targetUrl: serverUrl,
          options: { yaml: sampleTestSuiteYaml },
        }).valid,
      ).toBe(true);
    });

    it('generates complete test permutations across identities and resources', () => {
      const suite = parseAuthorizationTestSuiteYaml(sampleTestSuiteYaml);
      const perms = generateAuthorizationPermutations(suite, 'http://127.0.0.1:8080');

      expect(perms.length).toBeGreaterThanOrEqual(8);

      // Verify baseline owner permutations exist
      const baselines = perms.filter((p) => p.permutationType === 'baseline_owner');
      expect(baselines.length).toBeGreaterThanOrEqual(3); // User A on doc-101, User B on doc-102, Admin on /admin/users

      // Verify horizontal BOLA permutations exist
      const bolas = perms.filter((p) => p.permutationType === 'horizontal_bola');
      expect(bolas.some((b) => b.identity.id === 'user_b' && b.resource?.id === 'doc-user-a')).toBe(true);
      expect(bolas.some((b) => b.identity.id === 'user_a' && b.resource?.id === 'doc-user-b')).toBe(true);

      // Verify vertical BFLA permutations exist
      const bflas = perms.filter((p) => p.permutationType === 'vertical_bfla');
      expect(bflas.some((f) => f.identity.id === 'user_a' && f.resolvedPath === '/api/admin/users')).toBe(true);
      expect(bflas.some((f) => f.identity.id === 'user_b' && f.resolvedPath === '/api/admin/users')).toBe(true);

      // Verify unauthenticated access checks exist
      const unauth = perms.filter((p) => p.permutationType === 'unauthenticated_access');
      expect(unauth.length).toBeGreaterThanOrEqual(3);
    });
  });

  describe('BOLA and BFLA Vulnerability Detection', () => {
    it('detects critical BOLA, BFLA, and missing access control vulnerabilities against vulnerable target', async () => {
      mode = 'vulnerable';

      const result = await engine.execute(
        {
          targetUrl: serverUrl,
          options: { yaml: sampleTestSuiteYaml },
        },
        createDummyContext(),
      );

      expect(result.success).toBe(false);
      expect(result.findings.length).toBeGreaterThanOrEqual(3);

      // Verify BOLA detection
      const bolaFinding = result.findings.find((f) => f.title.includes('BOLA / IDOR'));
      expect(bolaFinding).toBeDefined();
      expect(bolaFinding?.severity).toBe('critical');
      expect(bolaFinding?.category).toBe('authorization');
      expect(bolaFinding?.description).toContain('User A');
      expect(bolaFinding?.metadata?.['vulnerabilityType']).toBe('BOLA_IDOR');
      expect(bolaFinding?.metadata?.['reproducibleCurl']).toBeDefined();

      // Verify BFLA detection
      const bflaFinding = result.findings.find((f) => f.title.includes('BFLA Vertical Privilege Escalation'));
      expect(bflaFinding).toBeDefined();
      expect(bflaFinding?.severity).toBe('critical');
      expect(bflaFinding?.description).toContain('/api/admin/users');
      expect(bflaFinding?.metadata?.['vulnerabilityType']).toBe('BFLA_VERTICAL_ESCALATION');

      // Verify Missing Auth Control detection
      const missingAuthFinding = result.findings.find((f) =>
        f.title.includes('Missing Authentication / Access Control'),
      );
      expect(missingAuthFinding).toBeDefined();
      expect(missingAuthFinding?.severity).toBe('high');

      const raw = result.rawOutput as {
        bolaCount: number;
        bflaCount: number;
        missingAuthCount: number;
      };
      expect(raw.bolaCount).toBeGreaterThanOrEqual(2);
      expect(raw.bflaCount).toBeGreaterThanOrEqual(2);
    });

    it('passes with zero findings against properly hardened authorization boundaries', async () => {
      mode = 'hardened';

      const result = await engine.execute(
        {
          targetUrl: serverUrl,
          options: { yaml: sampleTestSuiteYaml },
        },
        createDummyContext(),
      );

      expect(result.success).toBe(true);
      expect(result.findings.length).toBe(0);

      const raw = result.rawOutput as {
        bolaCount: number;
        bflaCount: number;
        missingAuthCount: number;
      };
      expect(raw.bolaCount).toBe(0);
      expect(raw.bflaCount).toBe(0);
      expect(raw.missingAuthCount).toBe(0);
    });
  });
});
