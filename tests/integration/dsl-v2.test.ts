import { describe, it, expect } from 'vitest';
import {
  parseTestDefinitionYaml,
  SingleTestSpecSchema,
  interpolateString,
  interpolateValue,
  interpolateObject,
  substitutePathParams,
  extractFieldValue,
  extractFromResponse,
  evaluateAssertion,
} from '@security-lab/domain';

describe('Declarative Test DSL v2 Domain Specification Suite', () => {
  describe('Schema Validation & Parsing', () => {
    it('parses DSL v2 test spec with bodies, pathParams, params, and extraction rules', () => {
      const yaml = `
id: dsl-v2-full-spec
name: Complete DSL v2 Specification
version: 2.0.0
category: authentication
tests:
  - id: step-1-post-json
    name: Create API Token
    path: /api/v1/auth/tokens
    method: POST
    contentType: application/json
    body:
      name: test-token
      scopes:
        - read:users
        - write:reports
      ttlMinutes: 60
    params:
      dryRun: false
      notify: true
    extract:
      - field: body.token.id
        as: tokenId
      - field: body.token.jwt
        as: tokenSecret
        regex: "eyJ[a-zA-Z0-9_-]+"
      - field: headers.set-cookie
        as: rawSessionCookie
    expectedStatus: [200, 201]
    assertions:
      - field: body.token.id
        operator: exists
      - field: body.token.jwt
        operator: matches_regex
        value: "^eyJ"

  - id: step-2-access-param
    name: Access Dynamic Resource
    dependsOn: step-1-post-json
    path: /api/v1/users/{userId}/tokens/:tokenId
    method: GET
    pathParams:
      userId: usr-999
      tokenId: \${tokenId}
    headers:
      Authorization: Bearer \${tokenSecret}
    expectedStatus: 200
    assertions:
      - field: body.status
        operator: equals
        value: active
`;

      const def = parseTestDefinitionYaml(yaml);
      expect(def.id).toBe('dsl-v2-full-spec');
      expect(def.tests.length).toBe(2);

      const step1 = def.tests[0];
      expect(step1.method).toBe('POST');
      expect(step1.contentType).toBe('application/json');
      expect(step1.body).toEqual({
        name: 'test-token',
        scopes: ['read:users', 'write:reports'],
        ttlMinutes: 60,
      });
      expect(step1.params).toEqual({ dryRun: false, notify: true });
      expect(step1.extract.length).toBe(3);
      expect(step1.extract[0]).toEqual({ field: 'body.token.id', as: 'tokenId' });
      expect(step1.extract[1]).toEqual({
        field: 'body.token.jwt',
        as: 'tokenSecret',
        regex: 'eyJ[a-zA-Z0-9_-]+',
      });
      expect(step1.expectedStatus).toEqual([200, 201]);

      const step2 = def.tests[1];
      expect(step2.dependsOn).toBe('step-1-post-json');
      expect(step2.pathParams).toEqual({ userId: 'usr-999', tokenId: '${tokenId}' });
      expect(step2.expectedStatus).toEqual([200]);
    });

    it('maintains backward compatibility with DSL v1 test definitions', () => {
      const v1Yaml = `
id: dsl-v1-legacy
name: Legacy DSL v1 Test Spec
version: 1.0.0
category: headers
tests:
  - id: legacy-step
    name: Root Endpoint Headers
    path: /health
    method: GET
    expectedStatus: [200]
    assertions:
      - field: headers.strict-transport-security
        operator: exists
`;

      const def = parseTestDefinitionYaml(v1Yaml);
      expect(def.id).toBe('dsl-v1-legacy');
      expect(def.tests[0].body).toBeUndefined();
      expect(def.tests[0].extract).toEqual([]);
      expect(def.tests[0].dependsOn).toBeUndefined();
    });
  });

  describe('Variable Interpolation & Prototype Safety', () => {
    const context = new Map<string, unknown>([
      ['tenantId', 'tenant-alpha'],
      ['userId', 'usr-555'],
      ['apiKey', 'secret-key-xyz'],
      ['count', 42],
      ['isAdmin', true],
    ]);

    it('interpolates simple and prefixed variable strings', () => {
      expect(interpolateString('/api/${tenantId}/users/${userId}', context)).toBe(
        '/api/tenant-alpha/users/usr-555',
      );
      expect(interpolateString('Bearer ${variables.apiKey}', context)).toBe('Bearer secret-key-xyz');
      expect(interpolateString('${context.tenantId}', context)).toBe('tenant-alpha');
    });

    it('leaves missing variables intact without crashing', () => {
      expect(interpolateString('/items/${missingVar}/detail', context)).toBe(
        '/items/${missingVar}/detail',
      );
    });

    it('preserves native types when single variable placeholder is provided', () => {
      expect(interpolateValue('${count}', context)).toBe(42);
      expect(interpolateValue('${isAdmin}', context)).toBe(true);
      expect(interpolateValue('${tenantId}', context)).toBe('tenant-alpha');
    });

    it('recursively interpolates nested objects and arrays', () => {
      const template = {
        meta: {
          requestedBy: '${userId}',
          tenant: '${tenantId}',
        },
        tags: ['user:${userId}', 'audit'],
      };

      const result = interpolateObject(template, context);
      expect(result).toEqual({
        meta: {
          requestedBy: 'usr-555',
          tenant: 'tenant-alpha',
        },
        tags: ['user:usr-555', 'audit'],
      });
    });

    it('strictly guards against prototype pollution attacks', () => {
      const maliciousPayload = JSON.parse(`{
        "__proto__": { "polluted": true },
        "constructor": { "prototype": { "hacked": true } },
        "safeField": "hello"
      }`);

      const result = interpolateObject(maliciousPayload, context) as Record<string, unknown>;
      expect(result['safeField']).toBe('hello');
      expect((Object.prototype as Record<string, unknown>)['polluted']).toBeUndefined();
      expect((Object.prototype as Record<string, unknown>)['hacked']).toBeUndefined();

      expect(extractFieldValue(maliciousPayload, '__proto__.polluted')).toBeUndefined();
      expect(extractFieldValue(maliciousPayload, 'constructor.prototype.hacked')).toBeUndefined();
    });
  });

  describe('Path Parameter Substitution', () => {
    it('substitutes both {param} and :param styles with URI encoding', () => {
      const context = new Map<string, unknown>([['folder', 'reports & data']]);
      const pathParams = {
        userId: 'user/123',
        itemId: 456,
      };

      const path1 = substitutePathParams('/users/{userId}/items/:itemId', pathParams, context);
      expect(path1).toBe('/users/user%2F123/items/456');

      const path2 = substitutePathParams('/folders/${folder}/list', undefined, context);
      expect(path2).toBe('/folders/reports & data/list');
    });
  });

  describe('Field Extraction from Responses', () => {
    const mockResponse = {
      status: 201,
      statusText: 'Created',
      headers: {
        'content-type': 'application/json',
        'set-cookie': 'session_token=abc-123-xyz; HttpOnly; Secure',
        'x-request-id': 'req-987654',
      },
      body: {
        token: {
          access: 'jwt-header.jwt-payload.jwt-sig',
          expiresIn: 3600,
        },
        users: [
          { id: 'usr-1', name: 'Alice' },
          { id: 'usr-2', name: 'Bob' },
        ],
      },
    };

    it('extracts nested JSON fields and array indices', () => {
      expect(extractFieldValue(mockResponse, 'status')).toBe(201);
      expect(extractFieldValue(mockResponse, 'body.token.access')).toBe(
        'jwt-header.jwt-payload.jwt-sig',
      );
      expect(extractFieldValue(mockResponse, 'body.users[1].name')).toBe('Bob');
      expect(extractFieldValue(mockResponse, 'headers.x-request-id')).toBe('req-987654');
    });

    it('extracts regex patterns and applies fallback defaults', () => {
      const ruleWithRegex = {
        field: 'headers.set-cookie',
        as: 'sessionCookieVal',
        regex: 'session_token=([a-zA-Z0-9-]+)',
      };
      expect(extractFromResponse(mockResponse, ruleWithRegex)).toBe('abc-123-xyz');

      const ruleWithDefault = {
        field: 'body.nonexistent',
        as: 'fallback',
        defaultValue: 'default-status',
      };
      expect(extractFromResponse(mockResponse, ruleWithDefault)).toBe('default-status');
    });
  });

  describe('Response Assertion Operators (v2)', () => {
    const payload = {
      status: 'success',
      data: {
        user: {
          id: 'usr-100',
          active: true,
          roles: ['member', 'admin'],
          score: 98.5,
        },
      },
    };

    it('evaluates contains_json_path and not_contains_json_path correctly', () => {
      const passPath = evaluateAssertion(
        { field: 'data', operator: 'contains_json_path', value: 'user.roles' },
        payload.data,
      );
      expect(passPath.passed).toBe(true);

      const failPath = evaluateAssertion(
        { field: 'data', operator: 'contains_json_path', value: 'user.password' },
        payload.data,
      );
      expect(failPath.passed).toBe(false);

      const notContainsPass = evaluateAssertion(
        { field: 'data', operator: 'not_contains_json_path', value: 'user.secretToken' },
        payload.data,
      );
      expect(notContainsPass.passed).toBe(true);
    });

    it('evaluates schema_matches against primitive types and schemas', () => {
      expect(
        evaluateAssertion({ field: 'active', operator: 'schema_matches', value: 'boolean' }, true)
          .passed,
      ).toBe(true);

      expect(
        evaluateAssertion({ field: 'score', operator: 'schema_matches', value: 'number' }, 98.5)
          .passed,
      ).toBe(true);

      expect(
        evaluateAssertion(
          { field: 'roles', operator: 'schema_matches', value: 'array' },
          ['admin'],
        ).passed,
      ).toBe(true);

      expect(
        evaluateAssertion(
          {
            field: 'user',
            operator: 'schema_matches',
            value: { id: 'string', active: 'boolean' },
          },
          payload.data.user,
        ).passed,
      ).toBe(true);
    });

    it('supports multi-status negative assertions (e.g. 401, 403 auth gating)', () => {
      const spec = SingleTestSpecSchema.parse({
        id: 'negative-auth-check',
        name: 'Verify Protected Endpoint Rejection',
        expectedStatus: [401, 403],
      });

      expect(spec.expectedStatus).toContain(401);
      expect(spec.expectedStatus).toContain(403);
      expect(spec.expectedStatus).not.toContain(200);
    });
  });
});
