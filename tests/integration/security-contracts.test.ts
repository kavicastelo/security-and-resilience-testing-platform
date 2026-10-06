import http from 'node:http';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import {
  parseOpenApiSpec,
  evaluateOpenApiContractRules,
  OpenApiParseError,
  TestDefinitionSchema,
} from '@security-lab/domain';
import {
  SecurityContractEngine,
  generateNegativeFuzzTestCases,
  generateOpenApiTestDefinition,
  ExecutionContext,
} from '@security-lab/test-sdk';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase } from '../../apps/controller/src/services/db.js';
import { logger } from '@security-lab/logger';

describe('Security Contract Engine & OpenAPI Discovery', () => {
  let mockServer: http.Server;
  let mockServerPort: number;
  let mockServerUrl: string;

  const validOpenApiYaml = `
openapi: 3.0.3
info:
  title: Sample E-Commerce API
  version: 1.0.0
  description: Core microservices specification
servers:
  - url: http://api.unencrypted-prod.com
    description: Insecure cleartext server
  - url: https://api.secure-prod.com
    description: Secure server
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
    legacyBasic:
      type: http
      scheme: basic
  schemas:
    UserInput:
      type: object
      required:
        - username
        - email
      properties:
        username:
          type: string
        email:
          type: string
          format: email
        age:
          type: integer
paths:
  /api/v1/users:
    post:
      summary: Register user
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UserInput'
      responses:
        '201':
          description: User created
  /api/v1/unprotected-order:
    post:
      summary: Mutating operation without authentication
      parameters:
        - name: user_token
          in: query
          required: false
          schema:
            type: string
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - itemId
              properties:
                itemId:
                  type: string
      responses:
        '200':
          description: Order placed
  /api/v1/health:
    get:
      summary: Health check
      security: []
      responses:
        '200':
          description: Healthy
  /api/v1/login:
    post:
      summary: Public authentication endpoint
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - username
                - password
              properties:
                username:
                  type: string
                password:
                  type: string
      responses:
        '200':
          description: Authenticated
`;

  beforeAll(async () => {
    // Spin up mock HTTP server for live negative schema fuzzing
    mockServer = http.createServer((req, res) => {
      let bodyData = '';
      req.on('data', (chunk) => {
        bodyData += chunk;
      });

      req.on('end', () => {
        const url = new URL(req.url || '/', `http://${req.headers.host}`);

        // Route 1: Well-behaved endpoint with strict validation (rejects invalid input with 400)
        if (url.pathname === '/api/v1/users' && req.method === 'POST') {
          try {
            const parsed = JSON.parse(bodyData || '{}');
            if (!parsed.username || !parsed.email) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Missing required field: username or email' }));
              return;
            }
            if (typeof parsed.username !== 'string' || typeof parsed.email !== 'string') {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Invalid field types' }));
              return;
            }
            res.writeHead(201, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ id: 'user-123', status: 'created' }));
          } catch {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Malformed JSON' }));
          }
          return;
        }

        // Route 2: Flawed endpoint that crashes with unhandled 500 when required field is missing!
        if (url.pathname === '/api/v1/unprotected-order' && req.method === 'POST') {
          try {
            const parsed = JSON.parse(bodyData || '{}');
            if (!parsed.itemId) {
              // Unhandled backend crash!
              res.writeHead(500, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'NullPointerException: itemId cannot be null' }));
              return;
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ orderId: 'ord-999' }));
          } catch {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Fatal backend parsing exception' }));
          }
          return;
        }

        if (url.pathname === '/api/v1/health' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'ok' }));
          return;
        }

        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not found' }));
      });
    });

    await new Promise<void>((resolve) => {
      mockServer.listen(0, '127.0.0.1', () => {
        const addr = mockServer.address();
        if (addr && typeof addr === 'object') {
          mockServerPort = addr.port;
          mockServerUrl = `http://127.0.0.1:${mockServerPort}`;
        }
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      mockServer.close((err) => (err ? reject(err) : resolve()));
    });
    await closeDatabase();
  });

  const createDummyContext = (): ExecutionContext => ({
    correlationId: 'contract-corr-1',
    testRunId: '00000000-0000-0000-0000-000000000001',
    executionId: '00000000-0000-0000-0000-000000000002',
    target: {
      id: '00000000-0000-0000-0000-000000000003',
      name: 'Contract Test Target',
      baseUrl: mockServerUrl,
      scope: {
        allowedHosts: ['127.0.0.1'],
        allowedPorts: [mockServerPort],
        allowPrivateIps: true,
        excludedPaths: [],
        testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
        limits: { maxRps: 100, maxConcurrency: 10, maxDuration: '1m' },
      },
    },
    logger,
    abortSignal: new AbortController().signal,
    reportProgress: () => {},
  });

  // ---------------------------------------------------------------------------
  // 1. OpenAPI Parser Tests
  // ---------------------------------------------------------------------------
  describe('OpenAPI Parser', () => {
    it('successfully parses valid OpenAPI 3.0.3 YAML and extracts endpoints', () => {
      const inventory = parseOpenApiSpec(validOpenApiYaml);

      expect(inventory.openapi).toBe('3.0.3');
      expect(inventory.title).toBe('Sample E-Commerce API');
      expect(inventory.version).toBe('1.0.0');
      expect(inventory.endpoints.length).toBe(4);
      expect(inventory.securitySchemes['bearerAuth']?.type).toBe('http');
      expect(inventory.securitySchemes['bearerAuth']?.scheme).toBe('bearer');
      expect(inventory.securitySchemes['legacyBasic']?.scheme).toBe('basic');

      // Verify $ref resolution for /api/v1/users
      const usersEndpoint = inventory.endpoints.find((e) => e.path === '/api/v1/users');
      expect(usersEndpoint).toBeDefined();
      expect(usersEndpoint?.requestBody?.contentTypes['application/json']?.schema).toBeDefined();
      const schema = usersEndpoint?.requestBody?.contentTypes['application/json']?.schema;
      expect(schema?.['required']).toEqual(['username', 'email']);
    });

    it('identifies explicitly public endpoints with security: []', () => {
      const inventory = parseOpenApiSpec(validOpenApiYaml);
      const healthEndpoint = inventory.endpoints.find((e) => e.path === '/api/v1/health');
      expect(healthEndpoint?.isExplicitlyPublic).toBe(true);
    });

    it('rejects unsupported specification versions', () => {
      const badSpec = `
openapi: 1.2.0
info:
  title: Ancient API
  version: 1.0.0
paths: {}
`;
      expect(() => parseOpenApiSpec(badSpec)).toThrowError(OpenApiParseError);
    });

    it('rejects malformed syntax or empty documents', () => {
      expect(() => parseOpenApiSpec('')).toThrowError(OpenApiParseError);
      expect(() => parseOpenApiSpec('   \n  ')).toThrowError(OpenApiParseError);
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Contract Rules Evaluation
  // ---------------------------------------------------------------------------
  describe('Contract Rules Evaluator', () => {
    it('evaluates static security contract rules and detects all violations', () => {
      const inventory = parseOpenApiSpec(validOpenApiYaml);
      const violations = evaluateOpenApiContractRules(inventory);

      const ruleIds = violations.map((v) => v.ruleId);

      // Rule 1: Sensitive query parameter
      expect(ruleIds).toContain('no-sensitive-query-params');
      const sensitiveParam = violations.find((v) => v.ruleId === 'no-sensitive-query-params');
      expect(sensitiveParam?.parameter).toBe('user_token');
      expect(sensitiveParam?.severity).toBe('high');

      // Rule 2: Unprotected mutating endpoint
      expect(ruleIds).toContain('no-unprotected-endpoints');
      const mutatingViolation = violations.find(
        (v) => v.ruleId === 'no-unprotected-endpoints' && v.endpoint?.path === '/api/v1/unprotected-order',
      );
      expect(mutatingViolation).toBeDefined();
      expect(mutatingViolation?.severity).toBe('critical');

      // Public /login endpoint should NOT be flagged as unprotected mutating violation
      const loginViolation = violations.find(
        (v) => v.endpoint?.path === '/api/v1/login' && v.ruleId === 'no-unprotected-endpoints',
      );
      expect(loginViolation).toBeUndefined();

      // Rule 3: Cleartext HTTP server URL
      expect(ruleIds).toContain('require-https-servers');
      const serverViolation = violations.find((v) => v.ruleId === 'require-https-servers');
      expect(serverViolation?.actual).toContain('http://api.unencrypted-prod.com');

      // Rule 4: Cleartext Basic Auth
      expect(ruleIds).toContain('no-cleartext-basic-auth');
      const basicAuthViolation = violations.find((v) => v.ruleId === 'no-cleartext-basic-auth');
      expect(basicAuthViolation?.severity).toBe('medium');
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Test Generation & Schema Fuzzing
  // ---------------------------------------------------------------------------
  describe('Schema Fuzzing & Test Generation', () => {
    it('generates negative fuzz test cases for missing required fields and invalid types', () => {
      const inventory = parseOpenApiSpec(validOpenApiYaml);
      const fuzzCases = generateNegativeFuzzTestCases(inventory);

      expect(fuzzCases.length).toBeGreaterThan(0);

      // Verify missing required field case for username
      const missingUsername = fuzzCases.find(
        (c) => c.mutationType === 'missing_required_field' && c.targetField === 'username',
      );
      expect(missingUsername).toBeDefined();
      expect(missingUsername?.expectedStatus).toEqual([400, 422]);
      expect((missingUsername?.payload as Record<string, unknown>).username).toBeUndefined();

      // Verify invalid type case for age
      const invalidAge = fuzzCases.find(
        (c) => c.mutationType === 'invalid_type' && c.targetField === 'age',
      );
      expect(invalidAge).toBeDefined();
      expect(typeof (invalidAge?.payload as Record<string, unknown>).age).toBe('string');
    });

    it('generates a complete valid Declarative TestDefinition suite', () => {
      const inventory = parseOpenApiSpec(validOpenApiYaml);
      const testDef = generateOpenApiTestDefinition(inventory, { targetUrl: mockServerUrl });

      expect(testDef.category).toBe('api_schema');
      expect(testDef.tests.length).toBeGreaterThan(inventory.endpoints.length);

      // Validate against domain TestDefinitionSchema
      const validated = TestDefinitionSchema.parse(testDef);
      expect(validated.id).toContain('contract-suite-sample-e-commerce-api');
    });
  });

  // ---------------------------------------------------------------------------
  // 4. SecurityContractEngine Execution & Live Negative Fuzzing
  // ---------------------------------------------------------------------------
  describe('SecurityContractEngine Live Execution', () => {
    it('executes static audit and catches unhandled 500 crashes during schema fuzzing', async () => {
      const engine = new SecurityContractEngine();
      const context = createDummyContext();

      const result = await engine.execute(
        {
          targetUrl: mockServerUrl,
          options: {
            yaml: validOpenApiYaml,
            fuzzing: true,
          },
        },
        context,
      );

      expect(result.success).toBe(true);
      expect(result.engineId).toBe('engine-native-contract');

      // Verify metrics
      const endpointsCount = result.metrics.find((m) => m.name === 'openapi_endpoints_count');
      expect(endpointsCount?.value).toBe(4);

      const violationsCount = result.metrics.find((m) => m.name === 'contract_violations_count');
      expect(violationsCount?.value).toBeGreaterThanOrEqual(4);

      const fuzzExecuted = result.metrics.find((m) => m.name === 'fuzz_tests_executed');
      expect(fuzzExecuted?.value).toBeGreaterThan(0);

      const serverErrors = result.metrics.find((m) => m.name === 'fuzz_server_errors');
      expect(serverErrors?.value).toBeGreaterThan(0);

      // Verify findings: Unhandled 500 error on /api/v1/unprotected-order was captured
      const errorFinding = result.findings.find(
        (f) => f.category === 'api_schema' && f.title.includes('Unhandled Server Error'),
      );
      expect(errorFinding).toBeDefined();
      expect(errorFinding?.severity).toBe('high');
      expect(errorFinding?.evidence?.response?.statusCode).toBe(500);

      // Verify static contract violations are included in findings
      const staticFinding = result.findings.find((f) => f.title.includes('Sensitive Parameter'));
      expect(staticFinding).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------------
  // 5. Controller Route POST /api/v1/contracts/verify
  // ---------------------------------------------------------------------------
  describe('Controller Route /api/v1/contracts/verify', () => {
    const app = buildApp({ disableLogging: true });

    afterAll(async () => {
      await app.close();
    });

    it('POST /api/v1/contracts/verify executes contract verification and returns findings', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/contracts/verify',
        payload: {
          spec: validOpenApiYaml,
          targetUrl: mockServerUrl,
          options: {
            fuzzing: true,
          },
        },
      });

      expect(response.statusCode).toBe(200);
      const json = JSON.parse(response.payload);
      expect(json.success).toBe(true);
      expect(json.data.engineId).toBe('engine-native-contract');
      expect(json.data.findings.length).toBeGreaterThan(0);
      expect(json.data.metrics.length).toBeGreaterThan(0);
    });

    it('POST /api/v1/contracts/verify returns 400 if specification is missing', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/contracts/verify',
        payload: {
          targetUrl: mockServerUrl,
        },
      });

      expect(response.statusCode).toBe(400);
      const json = JSON.parse(response.payload);
      expect(json.success).toBe(false);
      expect(json.error.code).toBe('CONTRACT_VALIDATION_ERROR');
    });
  });
});
