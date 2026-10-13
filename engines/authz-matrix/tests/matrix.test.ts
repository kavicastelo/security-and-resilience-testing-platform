import http from 'node:http';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { AuthzMatrixEngine } from '../src/index.js';
import {
  generateAuthzMatrixPermutations,
  isPrivilegedPath,
  extractPathParameterNames,
} from '../src/permutator.js';
import {
  normalizeResponseBody,
  isSoftErrorResponse,
  evaluateAuthzResponse,
} from '../src/comparator.js';
import { executeSandboxedEngine } from '@security-lab/test-runner';
import { ExecutionContext, TestInput } from '@security-lab/engine-sdk';
import { PersonaConfig } from '@security-lab/contracts';

describe('Phase 07: Automated BOLA / BFLA Matrix & Access Graph Evaluation', () => {
  let server: http.Server;
  let serverPort: number;
  let baseUrl: string;

  const personas: PersonaConfig[] = [
    {
      id: 'user_a',
      name: 'Tenant A User',
      role: 'user',
      token: 'token-user-a',
      headers: { Authorization: 'Bearer token-user-a' },
      resourceIds: {
        id: 'doc-101',
        orderId: 'ord-101',
      },
      isGuest: false,
      metadata: {},
    },
    {
      id: 'user_b',
      name: 'Tenant B User',
      role: 'user',
      token: 'token-user-b',
      headers: { Authorization: 'Bearer token-user-b' },
      resourceIds: {
        id: 'doc-102',
        orderId: 'ord-102',
      },
      isGuest: false,
      metadata: {},
    },
    {
      id: 'admin_user',
      name: 'System Admin',
      role: 'admin',
      token: 'token-admin',
      headers: { Authorization: 'Bearer token-admin' },
      resourceIds: {},
      isGuest: false,
      metadata: {},
    },
    {
      id: 'anonymous_user',
      name: 'Anonymous Guest',
      role: 'anonymous',
      headers: {},
      resourceIds: {},
      isGuest: true,
      metadata: {},
    },
  ];

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      const parsedUrl = new URL(req.url || '/', `http://127.0.0.1:${serverPort}`);
      const pathname = parsedUrl.pathname;
      const authHeader = req.headers['authorization'];
      const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7).trim() : undefined;

      // 1. VULNERABLE BOLA Endpoint: /api/documents/:id
      // Flaw: Returns User A's private payroll document to ANY authenticated user (e.g. User B)
      if (pathname.startsWith('/api/documents/')) {
        const docId = pathname.replace('/api/documents/', '');
        if (!token) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Unauthorized' }));
          return;
        }

        // BOLA Flaw: returns doc-101 even to User B!
        if (docId === 'doc-101') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              id: 'doc-101',
              owner: 'user_a',
              title: 'Executive Payroll and Confidential Compensation',
              payroll: '$180,000',
              timestamp: new Date().toISOString(),
              traceId: '12345678-1234-1234-1234-123456789abc',
            }),
          );
          return;
        }

        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Document not found' }));
        return;
      }

      // 2. SECURED Endpoint: /api/orders/:orderId
      // Strict object-level authorization: User B receives 403 Forbidden when accessing ord-101
      if (pathname.startsWith('/api/orders/')) {
        const orderId = pathname.replace('/api/orders/', '');
        if (!token) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Authentication required' }));
          return;
        }

        if (orderId === 'ord-101') {
          if (token === 'token-user-a' || token === 'token-admin') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ orderId: 'ord-101', owner: 'user_a', amount: 500 }));
            return;
          }
          // Correctly denied for User B
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Forbidden: Access to foreign order denied' }));
          return;
        }

        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Order not found' }));
        return;
      }

      // 3. VULNERABLE BFLA Endpoint: /api/admin/users
      // Flaw: Accepts regular user token (User A or User B) and returns sensitive admin user list
      if (pathname === '/api/admin/users') {
        if (!token) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Unauthorized' }));
          return;
        }

        // BFLA Flaw: Does not check role === 'admin'!
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            users: [
              { id: 'usr-1', username: 'admin', role: 'admin' },
              { id: 'usr-2', username: 'alice', role: 'user' },
            ],
            system: 'production-admin-directory',
          }),
        );
        return;
      }

      // 4. SECURED BFLA Endpoint: /api/admin/system-reboot
      // Correctly requires admin token
      if (pathname === '/api/admin/system-reboot') {
        if (token === 'token-admin') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'reboot_scheduled' }));
          return;
        }
        res.writeHead(token ? 403 : 401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Admin privileges required' }));
        return;
      }

      // 5. Protected Endpoint Missing Auth: /api/private/health
      if (pathname === '/api/private/health') {
        // Flaw: No auth check at all
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'healthy', database: 'connected' }));
        return;
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address() as any;
        serverPort = addr.port;
        baseUrl = `http://127.0.0.1:${serverPort}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  describe('1. Response Comparator & Normalization', () => {
    it('should ignore dynamic timestamps, epoch numbers, and UUID traces during comparison', () => {
      const rawBody = JSON.stringify({
        id: 'doc-101',
        created: '2026-10-14T00:30:00.000Z',
        epoch: 1760400000000,
        traceId: '12345678-1234-1234-1234-123456789abc',
      });

      const normalized = normalizeResponseBody(rawBody);

      expect(normalized).not.toContain('2026-10-14T');
      expect(normalized).not.toContain('1760400000000');
      expect(normalized).not.toContain('12345678-1234-1234-1234-123456789abc');
      expect(normalized).toContain('<TIMESTAMP>');
      expect(normalized).toContain('<EPOCH>');
      expect(normalized).toContain('<UUID>');
    });

    it('should detect soft errors returned with HTTP 200 status', () => {
      const softError = JSON.stringify({ error: 'access_denied', code: 403 });
      expect(isSoftErrorResponse(softError)).toBe(true);

      const validPayload = JSON.stringify({ id: 'doc-101', title: 'Valid Doc' });
      expect(isSoftErrorResponse(validPayload)).toBe(false);
    });

    it('should evaluate BOLA response and flag CRITICAL when sensitive data leaks', () => {
      const testCase = {
        id: 'test-1',
        type: 'BOLA_HORIZONTAL_IDOR' as const,
        endpointPath: '/api/documents/{id}',
        method: 'GET' as const,
        url: 'http://localhost/api/documents/doc-101',
        actorPersona: personas[1]!, // User B
        ownerPersona: personas[0]!, // User A
        targetResourceId: 'doc-101',
        expectedStatuses: [401, 403, 404],
        description: 'BOLA test',
      };

      const result = evaluateAuthzResponse(
        testCase,
        200,
        JSON.stringify({ id: 'doc-101', owner: 'user_a', payroll: '$180,000' }),
      );

      expect(result.isViolation).toBe(true);
      expect(result.violationType).toBe('BOLA_HORIZONTAL_IDOR');
      expect(result.severity).toBe('CRITICAL');
      expect(result.dataLeakageDetected).toBe(true);
    });
  });

  describe('2. Permutation Generator', () => {
    it('should correctly extract path parameter names from curly braces and colons', () => {
      expect(extractPathParameterNames('/api/users/{userId}/orders/{orderId}')).toEqual([
        'userId',
        'orderId',
      ]);
      expect(extractPathParameterNames('/api/documents/:docId')).toEqual(['docId']);
    });

    it('should identify administrative and privileged paths', () => {
      expect(isPrivilegedPath('/api/admin/users')).toBe(true);
      expect(isPrivilegedPath('/system/metrics')).toBe(true);
      expect(isPrivilegedPath('/manage/tenants')).toBe(true);
      expect(isPrivilegedPath('/api/documents/123')).toBe(false);
    });

    it('should generate permutations across personas and parameterized routes', () => {
      const sampleOpenApi = {
        openapi: '3.0.0',
        info: { title: 'Test API', version: '1.0.0' },
        paths: {
          '/api/documents/{id}': {
            get: {
              summary: 'Get Document',
              responses: { '200': { description: 'OK' } },
            },
          },
          '/api/admin/users': {
            get: {
              summary: 'Admin Users',
              responses: { '200': { description: 'OK' } },
            },
          },
        },
      };

      const { testCases, parameterizedRoutesCount, privilegedRoutesCount } =
        generateAuthzMatrixPermutations('http://localhost:3000', {
          spec: sampleOpenApi,
          personas,
        });

      expect(parameterizedRoutesCount).toBe(1);
      expect(privilegedRoutesCount).toBe(1);
      expect(testCases.length).toBeGreaterThan(0);

      // Verify BOLA test case generated: User B querying User A's doc
      const bolaCase = testCases.find(
        (tc) => tc.type === 'BOLA_HORIZONTAL_IDOR' && tc.actorPersona.id === 'user_b',
      );
      expect(bolaCase).toBeDefined();
      expect(bolaCase?.url).toContain('/api/documents/doc-101');

      // Verify BFLA test case generated: User A querying admin route
      const bflaCase = testCases.find(
        (tc) => tc.type === 'BFLA_VERTICAL_ESCALATION' && tc.actorPersona.id === 'user_a',
      );
      expect(bflaCase).toBeDefined();
      expect(bflaCase?.url).toContain('/api/admin/users');
    });
  });

  describe('3. End-to-End Matrix Engine Execution against Multi-Tenant API', () => {
    it('should identify BOLA on /api/documents/:id, BFLA on /api/admin/users, and ZERO false positives on properly secured routes', async () => {
      const openApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Multi-Tenant Security API', version: '1.0.0' },
        paths: {
          '/api/documents/{id}': {
            get: {
              summary: 'Get Document by ID',
              responses: { '200': { description: 'OK' } },
            },
          },
          '/api/orders/{orderId}': {
            get: {
              summary: 'Get Order by ID (Properly Secured)',
              responses: { '200': { description: 'OK' } },
            },
          },
          '/api/admin/users': {
            get: {
              summary: 'Admin Users Directory (BFLA Vulnerable)',
              responses: { '200': { description: 'OK' } },
            },
          },
          '/api/admin/system-reboot': {
            post: {
              summary: 'Reboot Server (Properly Secured Admin)',
              responses: { '200': { description: 'OK' } },
            },
          },
          '/api/private/health': {
            get: {
              summary: 'Private Health Check (Missing Auth)',
              responses: { '200': { description: 'OK' } },
            },
          },
        },
      };

      const engine = new AuthzMatrixEngine();
      const input: TestInput = {
        targetUrl: baseUrl,
        options: {
          spec: openApiSpec,
          personas,
        },
      };

      const context: ExecutionContext = {
        testRunId: 'test-run-matrix-001',
        environment: 'testing',
        target: {
          id: 'target-1',
          name: 'Local Test Server',
          baseUrl,
          scope: {
            allowedHosts: ['127.0.0.1', 'localhost'],
            allowedPorts: [serverPort],
            excludedPaths: [],
            testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
            limits: { maxRps: 100, maxConcurrency: 10, maxDuration: '5m' },
          },
        },
      };

      const result = await engine.execute(input, context);

      expect(result.success).toBe(true);
      expect(result.findings.length).toBeGreaterThan(0);

      // 1. Verify BOLA detection on /api/documents/{id}
      const bolaFinding = result.findings.find(
        (f) =>
          f.title.includes('BOLA') &&
          f.evidence?.request?.url?.includes('/api/documents/doc-101'),
      );
      expect(bolaFinding).toBeDefined();
      expect(bolaFinding?.severity).toBe('critical');
      expect(bolaFinding?.evidence?.metadata?.['actorPersona']).toBe('user_b');
      expect(bolaFinding?.evidence?.metadata?.['ownerPersona']).toBe('user_a');
      expect(bolaFinding?.evidence?.metadata?.['targetResourceId']).toBe('doc-101');

      // 2. Verify BFLA detection on /api/admin/users
      const bflaFinding = result.findings.find(
        (f) =>
          f.title.includes('BFLA') &&
          f.evidence?.request?.url?.includes('/api/admin/users'),
      );
      expect(bflaFinding).toBeDefined();
      expect(bflaFinding?.severity).toBe('critical');

      // 3. Verify Missing Auth detection on /api/private/health
      const missingAuthFinding = result.findings.find(
        (f) =>
          f.title.includes('Missing Authentication') &&
          f.evidence?.request?.url?.includes('/api/private/health'),
      );
      expect(missingAuthFinding).toBeDefined();

      // 4. Assert ZERO False Positives on properly secured routes
      const falsePositiveOrder = result.findings.find((f) =>
        f.evidence?.request?.url?.includes('/api/orders/'),
      );
      expect(falsePositiveOrder).toBeUndefined();

      const falsePositiveAdminReboot = result.findings.find((f) =>
        f.evidence?.request?.url?.includes('/api/admin/system-reboot'),
      );
      expect(falsePositiveAdminReboot).toBeUndefined();

      // 5. Verify Metrics
      const scannedMetric = result.metrics.find((m) => m.name === 'authz_routes_scanned');
      expect(scannedMetric?.value).toBe(5);

      const violationsMetric = result.metrics.find((m) => m.name === 'authz_violations_count');
      expect(violationsMetric?.value).toBe(result.findings.length);
    });

    it('should execute inside engine SDK worker thread sandbox without errors', async () => {
      const openApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test API', version: '1.0.0' },
        paths: {
          '/api/documents/{id}': {
            get: {
              summary: 'Get Document by ID',
              responses: { '200': { description: 'OK' } },
            },
          },
        },
      };

      const input: TestInput = {
        targetUrl: baseUrl,
        options: {
          spec: openApiSpec,
          personas: [personas[0]!, personas[1]!],
        },
      };

      const context: ExecutionContext = {
        testRunId: 'test-run-sandbox-001',
        environment: 'testing',
        target: {
          id: 'target-1',
          name: 'Local Test Server',
          baseUrl,
          scope: {
            allowedHosts: ['127.0.0.1', 'localhost'],
            allowedPorts: [serverPort],
            excludedPaths: [],
            testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
            limits: { maxRps: 100, maxConcurrency: 10, maxDuration: '5m' },
          },
        },
      };

      const result = await executeSandboxedEngine('engine-authz-matrix', input, context, {
        sandbox: true,
        timeoutMs: 15000,
      });

      expect(result.success).toBe(true);
      expect(result.findings.length).toBeGreaterThan(0);
    });
  });
});
