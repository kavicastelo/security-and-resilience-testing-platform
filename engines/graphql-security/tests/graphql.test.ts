import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import { graphQLSecurityEngine } from '@security-lab/graphql-security';
import { ExecutionContext, TargetExecutionContext } from '@security-lab/engine-sdk';
import { executeSandboxedEngine } from '@security-lab/test-runner';
import { TargetScope } from '@security-lab/domain';

describe('Phase 05: API Security, GraphQL Introspection & Schema Conformance', () => {
  let server: http.Server;
  let serverUrl: string;
  let serverPort: number;
  let enforceDepthLimit = false;

  beforeAll(async () => {
    // Start mock GraphQL HTTP server
    await new Promise<void>((resolve) => {
      server = http.createServer(async (req, res) => {
        const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

        // Non-GraphQL endpoint
        if (url.pathname === '/plain-rest') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'ok', api: 'rest' }));
          return;
        }

        // GraphQL endpoint at /graphql
        if (url.pathname === '/graphql') {
          let body = '';
          req.on('data', (chunk) => {
            body += chunk;
          });

          req.on('end', () => {
            let parsed: any;
            try {
              parsed = JSON.parse(body);
            } catch {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ errors: [{ message: 'Malformed JSON payload' }] }));
              return;
            }

            // A. Batch query array
            if (Array.isArray(parsed)) {
              const responses = parsed.map(() => ({
                data: { __typename: 'Query' },
              }));
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify(responses));
              return;
            }

            const query = parsed.query || '';

            // B. Introspection Query
            if (query.includes('__schema')) {
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(
                JSON.stringify({
                  data: {
                    __schema: {
                      queryType: { name: 'Query' },
                      mutationType: { name: 'Mutation' },
                      subscriptionType: null,
                      types: [
                        {
                          kind: 'OBJECT',
                          name: 'Query',
                          fields: [
                            {
                              name: 'me',
                              type: { kind: 'OBJECT', name: 'User' },
                            },
                            {
                              name: 'users',
                              type: {
                                kind: 'LIST',
                                ofType: { kind: 'OBJECT', name: 'User' },
                              },
                            },
                          ],
                        },
                        {
                          kind: 'OBJECT',
                          name: 'Mutation',
                          fields: [
                            {
                              name: 'updateUser',
                              type: { kind: 'OBJECT', name: 'User' },
                            },
                            {
                              name: 'deleteUser',
                              type: { kind: 'SCALAR', name: 'Boolean' },
                            },
                          ],
                        },
                        {
                          kind: 'OBJECT',
                          name: 'User',
                          fields: [
                            {
                              name: 'id',
                              type: { kind: 'SCALAR', name: 'ID' },
                            },
                            {
                              name: 'username',
                              type: { kind: 'SCALAR', name: 'String' },
                            },
                            {
                              name: 'email',
                              type: { kind: 'SCALAR', name: 'String' },
                            },
                            {
                              name: 'password',
                              type: { kind: 'SCALAR', name: 'String' },
                            },
                            {
                              name: 'friends',
                              type: {
                                kind: 'LIST',
                                ofType: { kind: 'OBJECT', name: 'User' },
                              },
                            },
                          ],
                        },
                      ],
                    },
                  },
                }),
              );
              return;
            }

            // C. Circular / Nested Deep Query
            if (query.includes('friends') || query.includes('DeepCircularQuery')) {
              if (enforceDepthLimit) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(
                  JSON.stringify({
                    errors: [{ message: 'Query depth limit exceeded: max allowed depth is 7' }],
                  }),
                );
                return;
              }

              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(
                JSON.stringify({
                  data: {
                    me: {
                      friends: [
                        {
                          friends: [],
                        },
                      ],
                    },
                  },
                }),
              );
              return;
            }

            // D. Field Suggestions for Misspelled Fields
            if (query.includes('passwrd')) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(
                JSON.stringify({
                  errors: [
                    {
                      message: 'Cannot query field "passwrd" on type "User". Did you mean "password"?',
                    },
                  ],
                }),
              );
              return;
            }

            // E. Basic ping / typename query
            if (query.includes('__typename')) {
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ data: { __typename: 'Query' } }));
              return;
            }

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ data: {} }));
          });
          return;
        }

        // 404
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
      });

      server.listen(0, '127.0.0.1', () => {
        const address = server.address();
        if (address && typeof address === 'object') {
          serverPort = address.port;
          serverUrl = `http://127.0.0.1:${serverPort}`;
        }
        resolve();
      });
    });
  });

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  const createMockContext = (scopeAllowedHosts: string[] = ['127.0.0.1', 'localhost']): ExecutionContext => {
    const scope: TargetScope = {
      allowedHosts: scopeAllowedHosts,
      allowedPorts: [serverPort, 80, 443],
      excludedPaths: ['/admin/forbidden'],
      testing: {
        activeScanning: true,
        loadTesting: true,
        chaosTesting: true,
      },
      limits: {
        maxRps: 100,
        maxConcurrency: 10,
        maxDuration: '10m',
      },
      allowPrivateIps: true,
    };

    const target: TargetExecutionContext = {
      id: 'target-00000000-0000-0000-0000-000000000001',
      name: 'Local GraphQL Target',
      baseUrl: serverUrl,
      scope,
    };

    return {
      correlationId: 'test-correlation-phase-05',
      testRunId: '00000000-0000-0000-0000-000000000001',
      target,
      reportProgress: () => {},
      logger: {
        info: () => {},
        warn: () => {},
        error: () => {},
        debug: () => {},
      } as any,
    };
  };

  describe('1. GraphQL Introspection Security Audit', () => {
    it('detects enabled schema introspection in production profile and reports critical finding', async () => {
      const context = createMockContext();
      const result = await graphQLSecurityEngine.execute(
        {
          targetUrl: `${serverUrl}/graphql`,
          options: {
            environment: 'production',
            testIntrospection: true,
            testDepth: false,
            testBatching: false,
            testSuggestions: false,
          },
        },
        context,
      );

      expect(result.success).toBe(true);
      expect(result.findings.length).toBe(1);

      const finding = result.findings[0]!;
      expect(finding.title).toMatch(/Schema Introspection Enabled/i);
      expect(finding.severity).toBe('critical');
      expect(finding.category).toBe('information_disclosure');
      expect(finding.evidence?.actual).toMatch(/Schema introspection is enabled/i);
      expect(finding.evidence?.immutableHash).toBeDefined();

      const typeMetric = result.metrics.find((m) => m.name === 'graphql_types_discovered');
      expect(typeMetric?.value).toBeGreaterThanOrEqual(2);
    });

    it('reports high severity for introspection in non-production environment', async () => {
      const context = createMockContext();
      const result = await graphQLSecurityEngine.execute(
        {
          targetUrl: `${serverUrl}/graphql`,
          options: {
            environment: 'staging',
            testIntrospection: true,
            testDepth: false,
            testBatching: false,
            testSuggestions: false,
          },
        },
        context,
      );

      expect(result.success).toBe(true);
      const finding = result.findings[0]!;
      expect(finding.severity).toBe('high');
    });
  });

  describe('2. Circular Query Depth Limit Fuzzing', () => {
    it('detects missing query depth limits on circular queries (DoS risk)', async () => {
      enforceDepthLimit = false;
      const context = createMockContext();
      const result = await graphQLSecurityEngine.execute(
        {
          targetUrl: `${serverUrl}/graphql`,
          options: {
            testIntrospection: false,
            testDepth: true,
            maxDepth: 15,
            testBatching: false,
            testSuggestions: false,
          },
        },
        context,
      );

      expect(result.success).toBe(true);
      const depthFinding = result.findings.find((f) => f.title.includes('Query Depth'));
      expect(depthFinding).toBeDefined();
      expect(depthFinding?.severity).toBe('medium');
      expect(depthFinding?.evidence?.actual).toMatch(/Query of depth 15 was processed without depth limit/i);
    });

    it('does not emit finding when query depth limits are enforced by server', async () => {
      enforceDepthLimit = true;
      const context = createMockContext();
      const result = await graphQLSecurityEngine.execute(
        {
          targetUrl: `${serverUrl}/graphql`,
          options: {
            testIntrospection: false,
            testDepth: true,
            maxDepth: 15,
            testBatching: false,
            testSuggestions: false,
          },
        },
        context,
      );

      expect(result.success).toBe(true);
      const depthFinding = result.findings.find((f) => f.title.includes('Query Depth'));
      expect(depthFinding).toBeUndefined();
      enforceDepthLimit = false; // Reset
    });
  });

  describe('3. Batch Query Array Amplification', () => {
    it('detects batch query amplification when array of operations is executed in single roundtrip', async () => {
      const context = createMockContext();
      const result = await graphQLSecurityEngine.execute(
        {
          targetUrl: `${serverUrl}/graphql`,
          options: {
            testIntrospection: false,
            testDepth: false,
            testBatching: true,
            batchSize: 50,
            testSuggestions: false,
          },
        },
        context,
      );

      expect(result.success).toBe(true);
      const batchFinding = result.findings.find((f) => f.title.includes('Batch Query Amplification'));
      expect(batchFinding).toBeDefined();
      expect(batchFinding?.severity).toBe('medium');
      expect(batchFinding?.evidence?.actual).toMatch(/Server processed array of 50 operations/i);
    });
  });

  describe('4. Field Suggestion Harvesting', () => {
    it('harvests error messages leaking private fields via "Did you mean ...?" suggestions', async () => {
      const context = createMockContext();
      const result = await graphQLSecurityEngine.execute(
        {
          targetUrl: `${serverUrl}/graphql`,
          options: {
            testIntrospection: false,
            testDepth: false,
            testBatching: false,
            testSuggestions: true,
          },
        },
        context,
      );

      expect(result.success).toBe(true);
      const suggestionFinding = result.findings.find((f) => f.title.includes('Field Suggestions Enabled'));
      expect(suggestionFinding).toBeDefined();
      expect(suggestionFinding?.severity).toBe('low');
      expect(suggestionFinding?.description).toMatch(/password/i);
    });
  });

  describe('5. Auto-Discovery, Scope & Non-GraphQL Handlers', () => {
    it('auto-discovers /graphql when given the root target URL', async () => {
      const context = createMockContext();
      const result = await graphQLSecurityEngine.execute(
        {
          targetUrl: serverUrl, // Root URL without /graphql path
          options: {
            testIntrospection: true,
            testDepth: false,
            testBatching: false,
            testSuggestions: false,
          },
        },
        context,
      );

      expect(result.success).toBe(true);
      expect(result.findings.some((f) => f.title.includes('Schema Introspection Enabled'))).toBe(true);
    });

    it('exits cleanly with zero findings if target endpoint is not GraphQL', async () => {
      const context = createMockContext();
      const result = await graphQLSecurityEngine.execute(
        {
          targetUrl: `${serverUrl}/plain-rest`,
          options: {
            graphqlPath: '/plain-rest',
          },
        },
        context,
      );

      expect(result.success).toBe(true);
      expect(result.findings.length).toBe(0);
      expect(result.metrics.find((m) => m.name === 'graphql_endpoints_detected')?.value).toBe(0);
    });

    it('rejects targets outside of authorized target scope', async () => {
      const context = createMockContext(['other-allowed-host.com']);
      const result = await graphQLSecurityEngine.execute(
        {
          targetUrl: `${serverUrl}/graphql`,
        },
        context,
      );

      expect(result.success).toBe(false);
      expect(result.error).toMatch(/out of authorized scope/i);
    });
  });

  describe('6. Isolated Worker Sandboxing Integration (Phase 03)', () => {
    it('executes GraphQL security engine inside isolated worker thread harness', async () => {
      const context = createMockContext();
      const result = await executeSandboxedEngine(
        graphQLSecurityEngine.id,
        {
          targetUrl: `${serverUrl}/graphql`,
          options: {
            testIntrospection: true,
            testDepth: true,
            testBatching: true,
            testSuggestions: true,
          },
        },
        context,
        { sandbox: true, timeoutMs: 15000 },
      );

      expect(result.success).toBe(true);
      expect(result.findings.length).toBeGreaterThanOrEqual(3);
      expect(result.findings.some((f) => f.title.includes('Schema Introspection Enabled'))).toBe(true);
    });
  });
});
