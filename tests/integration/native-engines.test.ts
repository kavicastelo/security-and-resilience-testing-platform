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
  let mockMode: 'insecure' | 'secure' | 'custom_json' = 'insecure';

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
  });
});
