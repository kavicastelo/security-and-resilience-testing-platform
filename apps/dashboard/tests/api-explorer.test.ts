import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  parseOpenApiDocument,
  generateMockFromSchema,
  formatGraphQLType,
  parseGraphQLSchema,
  constructDepthAttackQuery,
  extractFieldSuggestions,
  fetchTargetSpecs,
  saveTargetSpec,
  executeGraphQLIntrospection,
} from '../src/api/contracts.js';

describe('Phase UI-06: API Security, OpenAPI Catalog & GraphQL Introspection Explorer', () => {
  describe('OpenAPI 3.0 Document Parser & Mock Payload Generator', () => {
    it('parses valid OpenAPI 3.0 document into structured endpoints and tags', () => {
      const sampleSpec = {
        openapi: '3.0.1',
        info: { title: 'Test Security API', version: '1.0.0' },
        paths: {
          '/api/v1/auth/token': {
            post: {
              tags: ['Auth'],
              summary: 'Issue access token',
              operationId: 'createToken',
              parameters: [
                { name: 'X-Client-Id', in: 'header', required: true, schema: { type: 'string' } },
              ],
              requestBody: {
                required: true,
                content: {
                  'application/json': {
                    schema: {
                      type: 'object',
                      properties: {
                        username: { type: 'string' },
                        password: { type: 'string' },
                      },
                    },
                  },
                },
              },
              responses: { '200': { description: 'Success' } },
            },
          },
          '/api/v1/users/{id}': {
            get: {
              tags: ['Users'],
              summary: 'Get user by ID',
              parameters: [
                { name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } },
              ],
              responses: { '200': { description: 'User found' } },
            },
          },
        },
      };

      const parsed = parseOpenApiDocument(sampleSpec);
      expect(parsed.title).toBe('Test Security API');
      expect(parsed.totalEndpoints).toBe(2);
      expect(parsed.tags).toContain('Auth');
      expect(parsed.tags).toContain('Users');

      const tokenEndpoint = parsed.endpoints.find((e) => e.path === '/api/v1/auth/token');
      expect(tokenEndpoint).toBeDefined();
      expect(tokenEndpoint?.method).toBe('POST');
      expect(tokenEndpoint?.parameters[0].name).toBe('X-Client-Id');
      expect(tokenEndpoint?.requestBody?.required).toBe(true);

      const userEndpoint = parsed.endpoints.find((e) => e.path === '/api/v1/users/{id}');
      expect(userEndpoint?.method).toBe('GET');
      expect(userEndpoint?.parameters[0].name).toBe('id');
    });

    it('generates mock JSON payloads from property schemas', () => {
      const schema = {
        type: 'object',
        properties: {
          email: { type: 'string', format: 'email' },
          userId: { type: 'string', format: 'uuid' },
          age: { type: 'integer', minimum: 18 },
          isActive: { type: 'boolean' },
          tags: { type: 'array', items: { type: 'string' } },
        },
      };

      const mock = generateMockFromSchema(schema) as any;
      expect(mock.email).toBe('secops-tester@securitylab.local');
      expect(mock.userId).toBe('12345678-1234-4234-8234-123456789abc');
      expect(mock.age).toBe(18);
      expect(mock.isActive).toBe(true);
      expect(Array.isArray(mock.tags)).toBe(true);
    });
  });

  describe('GraphQL Schema Introspection & AST Formatter', () => {
    it('formats GraphQL field types including non-null and list wrappers', () => {
      expect(formatGraphQLType({ kind: 'SCALAR', name: 'String' })).toBe('String');
      expect(formatGraphQLType({ kind: 'NON_NULL', ofType: { kind: 'SCALAR', name: 'ID' } })).toBe('ID!');
      expect(
        formatGraphQLType({
          kind: 'NON_NULL',
          ofType: {
            kind: 'LIST',
            ofType: { kind: 'NON_NULL', ofType: { kind: 'OBJECT', name: 'User' } },
          },
        }),
      ).toBe('[User!]!');
    });

    it('parses raw introspection JSON into queries, mutations, and object types', () => {
      const rawIntrospection = {
        data: {
          __schema: {
            queryType: { name: 'Query' },
            mutationType: { name: 'Mutation' },
            types: [
              {
                kind: 'OBJECT',
                name: 'Query',
                fields: [
                  { name: 'me', type: { kind: 'OBJECT', name: 'User' } },
                  { name: 'users', type: { kind: 'LIST', ofType: { kind: 'OBJECT', name: 'User' } } },
                ],
              },
              {
                kind: 'OBJECT',
                name: 'Mutation',
                fields: [
                  { name: 'updatePassword', type: { kind: 'SCALAR', name: 'Boolean' } },
                ],
              },
              {
                kind: 'OBJECT',
                name: 'User',
                fields: [
                  { name: 'id', type: { kind: 'NON_NULL', ofType: { kind: 'SCALAR', name: 'ID' } } },
                  { name: 'email', type: { kind: 'SCALAR', name: 'String' } },
                ],
              },
              {
                kind: 'OBJECT',
                name: '__Schema',
                fields: [],
              },
            ],
          },
        },
      };

      const parsed = parseGraphQLSchema(rawIntrospection);
      expect(parsed.queries).toHaveLength(2);
      expect(parsed.queries.map((q) => q.name)).toContain('me');
      expect(parsed.mutations).toHaveLength(1);
      expect(parsed.mutations[0].name).toBe('updatePassword');
      // Should filter out internal __Schema
      expect(parsed.types.map((t) => t.name)).toContain('User');
      expect(parsed.types.map((t) => t.name)).not.toContain('__Schema');
    });
  });

  describe('Circular Query Depth Fuzzing Constructor', () => {
    it('constructs nested recursive queries matching target depth parameter', () => {
      const queryDepth5 = constructDepthAttackQuery(5, 'user', 'friends');
      expect(queryDepth5).toContain('query DeepCircularProbe_5');
      expect(queryDepth5).toContain('user {');
      expect(queryDepth5).toContain('friends {');

      // Count occurrences of 'friends {' to verify recursion nesting depth
      const occurrences = (queryDepth5.match(/friends\s*\{/g) || []).length;
      expect(occurrences).toBe(5);
    });

    it('clamps recursion depth within safe bounds', () => {
      const queryZero = constructDepthAttackQuery(0);
      expect(queryZero).toContain('query DeepCircularProbe_1');

      const queryOverLimit = constructDepthAttackQuery(50);
      expect(queryOverLimit).toContain('query DeepCircularProbe_30');
    });
  });

  describe('Field Suggestion Error Parser & Information Leak Extraction', () => {
    it('extracts and deduplicates suggested field leaks from GraphQL error messages', () => {
      const errorMessages = [
        'Cannot query field "passwrd" on type "User". Did you mean "password"?',
        'Cannot query field "emal" on type "User". Did you mean "email"?',
        'Cannot query field "passwrd" on type "Admin". Did you mean "password"?',
        'Syntax Error: Expected Name, found )',
      ];

      const suggestions = extractFieldSuggestions(errorMessages);
      expect(suggestions).toHaveLength(2);
      expect(suggestions).toContain('password');
      expect(suggestions).toContain('email');
    });
  });

  describe('Prompt PR-09: Contract Specifications Persistence & Server-Side Introspection Client API', () => {
    let originalFetch: typeof globalThis.fetch;

    beforeEach(() => {
      originalFetch = globalThis.fetch;
    });

    afterEach(() => {
      globalThis.fetch = originalFetch;
      vi.restoreAllMocks();
    });

    it('fetches saved contract specs for target and returns clean empty array when none exist', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ success: true, data: [] }),
      });

      const specs = await fetchTargetSpecs('target-target-001');
      expect(Array.isArray(specs)).toBe(true);
      expect(specs).toHaveLength(0);
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/contracts/specs?targetId=target-target-001'),
        expect.any(Object),
      );
    });

    it('returns empty array when targetId is empty without calling network', async () => {
      globalThis.fetch = vi.fn();
      const specs = await fetchTargetSpecs('');
      expect(specs).toEqual([]);
      expect(globalThis.fetch).not.toHaveBeenCalled();
    });

    it('persists uploaded OpenAPI specification to controller backend', async () => {
      const mockRecord = {
        id: 'spec-spec-123',
        tenantId: 'default-tenant-001',
        targetId: 'target-001',
        name: 'Production Payments API',
        type: 'openapi',
        content: '{"openapi":"3.0.0","info":{"title":"Test","version":"1.0"}}',
        createdAt: '2026-10-16T00:00:00.000Z',
        updatedAt: '2026-10-16T00:00:00.000Z',
      };

      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 201,
        json: async () => ({ success: true, data: mockRecord }),
      });

      const saved = await saveTargetSpec({
        targetId: 'target-001',
        name: 'Production Payments API',
        type: 'openapi',
        content: '{"openapi":"3.0.0","info":{"title":"Test","version":"1.0"}}',
      });

      expect(saved.id).toBe('spec-spec-123');
      expect(saved.type).toBe('openapi');
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/contracts/specs'),
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('"Production Payments API"'),
        }),
      );
    });

    it('executes server-side GraphQL introspection with SSRF boundary check and returns persisted schema', async () => {
      const mockResponse = {
        schema: {
          data: {
            __schema: {
              queryType: { name: 'Query' },
              mutationType: null,
              types: [
                {
                  kind: 'OBJECT',
                  name: 'Query',
                  fields: [{ name: 'health', type: { kind: 'SCALAR', name: 'String' } }],
                },
              ],
            },
          },
        },
        specRecord: {
          id: 'spec-gql-456',
          tenantId: 'default-tenant-001',
          targetId: 'target-001',
          name: 'GraphQL Introspection: https://api.corp.local/graphql',
          type: 'graphql',
          content: '{"data":{"__schema":{}}}',
          createdAt: '2026-10-16T00:00:00.000Z',
          updatedAt: '2026-10-16T00:00:00.000Z',
        },
      };

      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ success: true, data: mockResponse }),
      });

      const result = await executeGraphQLIntrospection({
        targetId: 'target-001',
        endpointUrl: 'https://api.corp.local/graphql',
      });

      expect(result.schema).toBeDefined();
      expect(result.specRecord.id).toBe('spec-gql-456');
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/contracts/graphql/introspect'),
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            targetId: 'target-001',
            endpointUrl: 'https://api.corp.local/graphql',
          }),
        }),
      );
    });

    it('propagates SSRF and network errors from introspection endpoint', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        json: async () => ({
          success: false,
          error: { message: 'Requested URL is outside authorized target scope' },
        }),
      });

      await expect(
        executeGraphQLIntrospection({
          targetId: 'target-001',
          endpointUrl: 'http://169.254.169.254/graphql',
        }),
      ).rejects.toThrow('Requested URL is outside authorized target scope');
    });
  });
});

