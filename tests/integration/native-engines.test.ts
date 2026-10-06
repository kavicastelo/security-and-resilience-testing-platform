import http from 'node:http';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import {
  HeadersSecurityEngine,
  CorsSecurityEngine,
  TlsSecurityEngine,
  DeclarativeTestEngine,
  ExecutionContext,
} from '@security-lab/test-sdk';
import { logger } from '@security-lab/logger';

describe('Class A Native Test Engines & Declarative Runner Suite', () => {
  let server: http.Server;
  let serverPort: number;
  let serverUrl: string;

  // Mode flag for mock server responses
  let mockMode: 'insecure' | 'secure' | 'custom_json' | 'workflow_api' = 'insecure';

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      if (mockMode === 'insecure') {
        // Vulnerable baseline: missing HSTS, CSP, nosniff, frame-ancestors; disclosing Server banner
        if (req.method === 'OPTIONS') {
          res.writeHead(200, {
            'Access-Control-Allow-Origin': req.headers.origin || '*',
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
          });
          res.end();
          return;
        }

        res.writeHead(200, {
          'Content-Type': 'text/html',
          Server: 'Apache/2.4.41 (Ubuntu)',
          'X-Powered-By': 'PHP/7.4.3',
        });
        res.end('<html><body>Insecure Target Application</body></html>');
      } else if (mockMode === 'secure') {
        // Hardened baseline: all defensive headers present
        if (req.method === 'OPTIONS') {
          res.writeHead(204, {
            'Access-Control-Allow-Origin': 'https://trusted.example.com',
            'Access-Control-Allow-Methods': 'GET,POST',
          });
          res.end();
          return;
        }

        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
          'Content-Security-Policy': "default-src 'self'",
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
        });
        res.end('<html><body>Hardened Target Application</body></html>');
      } else if (mockMode === 'custom_json') {
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Strict-Transport-Security': 'max-age=31536000',
        });
        res.end(
          JSON.stringify({
            status: 'operational',
            version: '2.4.0',
            data: { authenticated: false, scope: 'read_only' },
          }),
        );
      } else if (mockMode === 'workflow_api') {
        const parsedUrl = new URL(req.url || '/', `http://127.0.0.1:${serverPort}`);
        const pathname = parsedUrl.pathname;

        if (pathname === '/auth/login' && req.method === 'POST') {
          let body = '';
          req.on('data', (chunk) => {
            body += chunk;
          });
          req.on('end', () => {
            let jsonBody = {};
            try {
              jsonBody = JSON.parse(body);
            } catch {
              // Ignore parse error
            }
            res.writeHead(200, {
              'Content-Type': 'application/json',
              'Set-Cookie': 'session_id=sess-998877; Path=/; HttpOnly',
            });
            res.end(
              JSON.stringify({
                token: 'jwt.mock.token.12345',
                user: { id: 'usr-101', role: 'auditor' },
                received: jsonBody,
              }),
            );
          });
          return;
        }

        if (pathname === '/api/profile' && req.method === 'GET') {
          const auth = req.headers['authorization'];
          const cookie = req.headers['cookie'];
          if (auth === 'Bearer jwt.mock.token.12345' || cookie?.includes('session_id=sess-998877')) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                id: 'usr-101',
                email: 'auditor@example.com',
                role: 'auditor',
                active: true,
                authMethod: auth ? 'bearer' : 'cookie',
              }),
            );
          } else {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Unauthorized' }));
          }
          return;
        }

        if (pathname === '/api/items/item-456' && req.method === 'GET') {
          const view = parsedUrl.searchParams.get('view');
          const includeAudit = parsedUrl.searchParams.get('includeAudit');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              id: 'item-456',
              name: 'Secure Vault Item',
              price: 99.95,
              ownerId: 'usr-101',
              view,
              includeAudit: includeAudit === 'true',
            }),
          );
          return;
        }

        if (pathname === '/api/failing-step') {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Server error' }));
          return;
        }

        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not found' }));
        return;
      }
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
    correlationId: 'test-corr-1',
    testRunId: '00000000-0000-0000-0000-000000000001',
    executionId: '00000000-0000-0000-0000-000000000002',
    target: {
      id: '00000000-0000-0000-0000-000000000003',
      name: 'Local Mock Target',
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

  describe('HeadersSecurityEngine', () => {
    const engine = new HeadersSecurityEngine();

    it('exposes valid capability metadata', () => {
      expect(engine.id).toBe('engine-native-headers');
      expect(engine.version).toBe('1.0.0');
      const caps = engine.capabilities();
      expect(caps.length).toBeGreaterThan(0);
      expect(caps[0]?.id).toBe('headers_audit');
      expect(caps[0]?.isDisruptive).toBe(false);
    });

    it('validates test inputs correctly', () => {
      expect(engine.validate({ targetUrl: 'http://127.0.0.1:8080' }).valid).toBe(true);
      expect(engine.validate({ targetUrl: 'not-a-url' }).valid).toBe(false);
    });

    it('identifies defensive header deficiencies against insecure endpoint', async () => {
      mockMode = 'insecure';
      const result = await engine.execute({ targetUrl: serverUrl }, createDummyContext());

      expect(result.success).toBe(true);
      expect(result.engineId).toBe('engine-native-headers');
      expect(result.findings.length).toBeGreaterThanOrEqual(4);

      const titles = result.findings.map((f) => f.title);
      expect(titles).toContain('Missing HTTP Strict Transport Security (HSTS) Header');
      expect(titles).toContain('Missing Content Security Policy (CSP)');
      expect(titles).toContain('Missing or Ineffective X-Content-Type-Options Header');
      expect(titles).toContain('Missing Anti-Clickjacking Header (X-Frame-Options / CSP frame-ancestors)');
      expect(titles).toContain('Server Technology Fingerprint Disclosure');
    });

    it('produces zero findings against a hardened endpoint', async () => {
      mockMode = 'secure';
      const result = await engine.execute({ targetUrl: serverUrl }, createDummyContext());

      expect(result.success).toBe(true);
      expect(result.findings.length).toBe(0);
      expect(result.metrics.length).toBeGreaterThan(0);
    });
  });

  describe('CorsSecurityEngine', () => {
    const engine = new CorsSecurityEngine();

    it('exposes valid capability metadata', () => {
      expect(engine.id).toBe('engine-native-cors');
      const caps = engine.capabilities();
      expect(caps[0]?.id).toBe('cors_audit');
    });

    it('flags arbitrary origin reflection and wildcard with credentials', async () => {
      mockMode = 'insecure';
      const result = await engine.execute({ targetUrl: serverUrl }, createDummyContext());

      expect(result.success).toBe(true);
      expect(result.findings.length).toBeGreaterThan(0);

      const reflection = result.findings.find((f) => f.title.includes('Arbitrary Origin Reflection'));
      expect(reflection).toBeDefined();
      expect(reflection?.severity).toBe('high');
    });

    it('returns zero findings against safe CORS configuration', async () => {
      mockMode = 'secure';
      const result = await engine.execute({ targetUrl: serverUrl }, createDummyContext());

      expect(result.success).toBe(true);
      expect(result.findings.length).toBe(0);
    });
  });

  describe('TlsSecurityEngine', () => {
    const engine = new TlsSecurityEngine();

    it('flags cleartext HTTP endpoints as high risk', async () => {
      const result = await engine.execute({ targetUrl: serverUrl }, createDummyContext());

      expect(result.success).toBe(true);
      expect(result.findings.length).toBe(1);
      expect(result.findings[0]?.severity).toBe('high');
      expect(result.findings[0]?.title).toBe('Cleartext HTTP Transport in Use');
    });
  });

  describe('DeclarativeTestEngine', () => {
    const engine = new DeclarativeTestEngine();

    it('executes declarative YAML test specifications and asserts response structure', async () => {
      mockMode = 'custom_json';

      const testYaml = `
id: api-smoke-spec
name: API Smoke & Posture Test
version: 1.0.0
category: api_schema
description: Validates operational health and response fields
target:
  endpoint: /
  requiredCapabilities: []
tests:
  - id: status-and-body-check
    name: Operational Endpoint Check
    path: /
    method: GET
    expectedStatus: [200]
    assertions:
      - field: status
        operator: equals
        value: 200
      - field: body.status
        operator: equals
        value: operational
      - field: body.version
        operator: contains
        value: 2.4
      - field: headers.strict-transport-security
        operator: exists
      - field: body.missing_field
        operator: does_not_exist
`;

      const result = await engine.execute(
        {
          targetUrl: serverUrl,
          options: { yaml: testYaml },
        },
        createDummyContext(),
      );

      expect(result.success).toBe(true);
      expect(result.findings.length).toBe(0);

      const passedMetric = result.metrics.find((m) => m.name === 'assertions_passed');
      expect(passedMetric?.value).toBeGreaterThanOrEqual(5);
    });

    it('generates findings with evidence when assertions fail', async () => {
      mockMode = 'custom_json';

      const failingYaml = `
id: failing-assertions-spec
name: Failing Assertions Test
version: 1.0.0
category: api_schema
target:
  endpoint: /
tests:
  - id: check-fail
    name: Assert Impossible Value
    path: /
    method: GET
    expectedStatus: [404]
    assertions:
      - field: body.status
        operator: equals
        value: non_existent_status
        severity: high
        message: Target operational status should be non_existent_status
`;

      const result = await engine.execute(
        {
          targetUrl: serverUrl,
          options: { yaml: failingYaml },
        },
        createDummyContext(),
      );

      expect(result.success).toBe(false);
      expect(result.findings.length).toBe(2); // Unexpected status code + failed assertion

      const assertionFinding = result.findings.find((f) => f.title.includes('Assertion Failed'));
      expect(assertionFinding).toBeDefined();
      expect(assertionFinding?.severity).toBe('high');
      expect(assertionFinding?.evidence?.actual).toBe('operational');
    });

    it('executes multi-step chained workflow with variable extraction, pathParams, and query params', async () => {
      mockMode = 'workflow_api';

      const multiStepYaml = `
id: multi-step-auth-workflow
name: Multi-Step Chained Auth & Resource Access
version: 2.0.0
category: authentication
tests:
  - id: step-login
    name: Login Step
    path: /auth/login
    method: POST
    body:
      username: admin
      password: secure-password
    expectedStatus: [200]
    extract:
      - field: body.token
        as: authToken
      - field: body.user.id
        as: userId
    assertions:
      - field: body.token
        operator: exists
      - field: body.user.role
        operator: equals
        value: auditor

  - id: step-profile
    name: Fetch Profile Step
    dependsOn: step-login
    path: /api/profile
    method: GET
    headers:
      Authorization: Bearer \${authToken}
    expectedStatus: 200
    assertions:
      - field: body.id
        operator: equals
        value: \${userId}
      - field: body.role
        operator: equals
        value: auditor
      - field: body
        operator: contains_json_path
        value: email
      - field: body.email
        operator: schema_matches
        value: string
      - field: body.active
        operator: schema_matches
        value: boolean

  - id: step-item
    name: Fetch Resource with Path and Query Parameters
    dependsOn: step-login
    path: /api/items/{itemId}
    method: GET
    pathParams:
      itemId: item-456
    params:
      view: full
      includeAudit: true
    headers:
      Authorization: Bearer \${authToken}
    expectedStatus: [200]
    assertions:
      - field: body.id
        operator: equals
        value: item-456
      - field: body.ownerId
        operator: equals
        value: \${userId}
      - field: body.view
        operator: equals
        value: full
      - field: body.includeAudit
        operator: schema_matches
        value: boolean
`;

      const result = await engine.execute(
        {
          targetUrl: serverUrl,
          options: { yaml: multiStepYaml },
        },
        createDummyContext(),
      );

      expect(result.success).toBe(true);
      expect(result.findings.length).toBe(0);

      const raw = result.rawOutput as {
        extractedVariables: Record<string, unknown>;
        assertionsPassed: number;
        assertionsFailed: number;
      };
      expect(raw.extractedVariables['authToken']).toBe('jwt.mock.token.12345');
      expect(raw.extractedVariables['userId']).toBe('usr-101');
      expect(raw.assertionsPassed).toBeGreaterThanOrEqual(8);
      expect(raw.assertionsFailed).toBe(0);
    });

    it('persists session cookies across chained requests in cookie jar', async () => {
      mockMode = 'workflow_api';

      const cookieJarYaml = `
id: session-cookie-chain
name: Cookie Jar Session Persistence Test
version: 2.0.0
category: cookies
tests:
  - id: login-set-cookie
    name: Login and Receive Set-Cookie
    path: /auth/login
    method: POST
    body:
      username: cookie-user
    expectedStatus: [200]

  - id: access-with-cookie
    name: Access Protected Profile via Automatic Cookie Jar
    dependsOn: login-set-cookie
    path: /api/profile
    method: GET
    expectedStatus: [200]
    assertions:
      - field: body.authMethod
        operator: equals
        value: cookie
      - field: body.role
        operator: equals
        value: auditor
`;

      const result = await engine.execute(
        {
          targetUrl: serverUrl,
          options: { yaml: cookieJarYaml },
        },
        createDummyContext(),
      );

      expect(result.success).toBe(true);
      expect(result.findings.length).toBe(0);
    });

    it('skips dependent steps when predecessor in dependsOn fails', async () => {
      mockMode = 'workflow_api';

      const skipYaml = `
id: skip-dependency-workflow
name: Dependency Failure Skip Test
version: 2.0.0
category: api_schema
tests:
  - id: step-should-fail
    name: Endpoint That Fails
    path: /api/failing-step
    method: GET
    expectedStatus: [200] # Server returns 500, causing this step to fail

  - id: step-dependent
    name: Dependent Step That Must Be Skipped
    dependsOn: step-should-fail
    path: /api/profile
    method: GET
    expectedStatus: [200]
`;

      const result = await engine.execute(
        {
          targetUrl: serverUrl,
          options: { yaml: skipYaml },
        },
        createDummyContext(),
      );

      expect(result.success).toBe(false);
      const skippedFinding = result.findings.find((f) => f.title.includes('Step Skipped'));
      expect(skippedFinding).toBeDefined();
      expect(skippedFinding?.severity).toBe('info');
      expect(skippedFinding?.description).toContain('prerequisite dependency "step-should-fail" did not pass');
    });

    it('evaluates advanced assertion operators (contains_json_path, not_contains_json_path, schema_matches)', async () => {
      mockMode = 'custom_json';

      const advancedAssertionsYaml = `
id: advanced-operators-test
name: Advanced Operators Verification
version: 2.0.0
category: api_schema
tests:
  - id: test-operators
    name: Verify Advanced Operators
    path: /
    method: GET
    assertions:
      - field: body
        operator: contains_json_path
        value: data.scope
      - field: body
        operator: not_contains_json_path
        value: sensitive_admin_token
      - field: body.version
        operator: schema_matches
        value: string
      - field: body.data.authenticated
        operator: schema_matches
        value: boolean
`;

      const result = await engine.execute(
        {
          targetUrl: serverUrl,
          options: { yaml: advancedAssertionsYaml },
        },
        createDummyContext(),
      );

      expect(result.success).toBe(true);
      expect(result.findings.length).toBe(0);
    });

    it('blocks dynamically interpolated URLs targeting out-of-scope destinations', async () => {
      const ssrfAttackYaml = `
id: ssrf-interpolated-escape
name: SSRF Interpolation Escape Check
version: 2.0.0
category: http_security
inputs:
  evilHost: "http://169.254.169.254/latest/meta-data"
tests:
  - id: step-ssrf
    name: SSRF Probe via Interpolated URL
    path: \${evilHost}
    method: GET
`;

      const result = await engine.execute(
        {
          targetUrl: serverUrl,
          options: { yaml: ssrfAttackYaml },
        },
        createDummyContext(),
      );

      expect(result.success).toBe(false);
      const boundaryViolation = result.findings.find((f) => f.title.includes('Security Boundary Violation'));
      expect(boundaryViolation).toBeDefined();
      expect(boundaryViolation?.severity).toBe('critical');
    });
  });
});
