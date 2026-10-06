import {
  ApiInventory,
  HttpMethod,
  TestDefinition,
  SingleTestSpec,
} from '@security-lab/domain';

export interface OpenApiFuzzTestCase {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly endpoint: {
    readonly path: string;
    readonly method: HttpMethod;
  };
  readonly contentType: string;
  readonly payload: unknown;
  readonly mutationType: 'missing_required_field' | 'invalid_type' | 'malformed_payload' | 'oversized_payload';
  readonly targetField?: string;
  readonly expectedStatus: number[];
}

function sanitizeId(str: string): string {
  return str.toLowerCase().replace(/[^a-z0-9_-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
}

/**
 * Builds a baseline valid-like JSON payload conforming to the provided schema.
 */
export function buildBaselinePayload(schema: Record<string, unknown>): Record<string, unknown> {
  const payload: Record<string, unknown> = {};
  const properties = (schema['properties'] || {}) as Record<string, unknown>;

  for (const [key, propDef] of Object.entries(properties)) {
    if (!propDef || typeof propDef !== 'object') continue;
    const p = propDef as Record<string, unknown>;
    const type = String(p['type'] || 'string');

    switch (type) {
      case 'string':
        if (p['format'] === 'email') {
          payload[key] = 'test@example.com';
        } else if (p['format'] === 'uuid') {
          payload[key] = '123e4567-e89b-12d3-a456-426614174000';
        } else if (p['format'] === 'date-time') {
          payload[key] = new Date().toISOString();
        } else {
          payload[key] = 'valid_test_string';
        }
        break;
      case 'integer':
      case 'number':
        payload[key] = 42;
        break;
      case 'boolean':
        payload[key] = true;
        break;
      case 'array':
        payload[key] = ['test_item'];
        break;
      case 'object':
        payload[key] = {};
        break;
      default:
        payload[key] = 'sample_value';
    }
  }

  return payload;
}

/**
 * Generates deterministic negative fuzzing test cases for request bodies declared in an ApiInventory.
 */
export function generateNegativeFuzzTestCases(inventory: ApiInventory): OpenApiFuzzTestCase[] {
  const testCases: OpenApiFuzzTestCase[] = [];

  for (const endpoint of inventory.endpoints) {
    if (!endpoint.requestBody) continue;

    const jsonContent = endpoint.requestBody.contentTypes['application/json'];
    const schema = jsonContent?.schema;
    if (!schema || typeof schema !== 'object') continue;

    const rawProps = (schema['properties'] || {}) as Record<string, unknown>;
    const requiredFields = Array.isArray(schema['required']) ? (schema['required'] as string[]) : [];
    const baseline = buildBaselinePayload(schema);
    const pathSlug = sanitizeId(endpoint.path);
    const methodSlug = endpoint.method.toLowerCase();

    // 1. Missing required field mutations
    for (const reqField of requiredFields) {
      if (reqField in baseline) {
        const mutated = { ...baseline };
        delete mutated[reqField];

        testCases.push({
          id: `fuzz-${methodSlug}-${pathSlug}-missing-${sanitizeId(reqField)}`,
          name: `Missing Required Field: [${reqField}] on ${endpoint.method} ${endpoint.path}`,
          description: `Assert API rejects request body missing required field "${reqField}" with HTTP 400 or 422`,
          endpoint: {
            path: endpoint.path,
            method: endpoint.method,
          },
          contentType: 'application/json',
          payload: mutated,
          mutationType: 'missing_required_field',
          targetField: reqField,
          expectedStatus: [400, 422],
        });
      }
    }

    // 2. Invalid type mutations
    for (const [propName, propDef] of Object.entries(rawProps)) {
      if (!propDef || typeof propDef !== 'object') continue;
      const p = propDef as Record<string, unknown>;
      const expectedType = String(p['type'] || 'string');

      let invalidVal: unknown;
      switch (expectedType) {
        case 'string':
          invalidVal = 99999999;
          break;
        case 'integer':
        case 'number':
          invalidVal = 'invalid-not-a-number';
          break;
        case 'boolean':
          invalidVal = 'not-a-boolean';
          break;
        case 'array':
          invalidVal = 'not-an-array-string';
          break;
        case 'object':
          invalidVal = 'not-an-object-string';
          break;
        default:
          invalidVal = 12345;
      }

      const mutated = { ...baseline, [propName]: invalidVal };

      testCases.push({
        id: `fuzz-${methodSlug}-${pathSlug}-invalid-type-${sanitizeId(propName)}`,
        name: `Invalid Type for [${propName}] on ${endpoint.method} ${endpoint.path}`,
        description: `Assert API rejects request body when field "${propName}" has invalid type (sent ${typeof invalidVal}, expected ${expectedType}) with HTTP 400 or 422`,
        endpoint: {
          path: endpoint.path,
          method: endpoint.method,
        },
        contentType: 'application/json',
        payload: mutated,
        mutationType: 'invalid_type',
        targetField: propName,
        expectedStatus: [400, 422],
      });
    }

    // 3. Completely empty payload when fields are required or request body is required
    if (requiredFields.length > 0 || endpoint.requestBody.required) {
      testCases.push({
        id: `fuzz-${methodSlug}-${pathSlug}-empty-body`,
        name: `Empty Body on Required Schema: ${endpoint.method} ${endpoint.path}`,
        description: `Assert API rejects empty JSON payload when schema specifies required fields or required body`,
        endpoint: {
          path: endpoint.path,
          method: endpoint.method,
        },
        contentType: 'application/json',
        payload: {},
        mutationType: 'malformed_payload',
        expectedStatus: [400, 422],
      });
    }

    // 4. Oversized payload mutation on string fields
    for (const [propName, propDef] of Object.entries(rawProps)) {
      if (!propDef || typeof propDef !== 'object') continue;
      const p = propDef as Record<string, unknown>;
      if (p['type'] === 'string') {
        const oversizedString = 'A'.repeat(10000);
        const mutated = { ...baseline, [propName]: oversizedString };

        testCases.push({
          id: `fuzz-${methodSlug}-${pathSlug}-oversized-${sanitizeId(propName)}`,
          name: `Oversized String for [${propName}] on ${endpoint.method} ${endpoint.path}`,
          description: `Assert API safely handles or rejects oversized 10,000-character payload for "${propName}" without unhandled HTTP 500 error`,
          endpoint: {
            path: endpoint.path,
            method: endpoint.method,
          },
          contentType: 'application/json',
          payload: mutated,
          mutationType: 'oversized_payload',
          targetField: propName,
          expectedStatus: [400, 413, 422],
        });
        break; // One oversized payload per endpoint is sufficient
      }
    }
  }

  return testCases;
}

/**
 * Generates a full Declarative TestDefinition suite from an OpenAPI inventory,
 * incorporating both baseline endpoint verification and schema fuzzing tests.
 */
export function generateOpenApiTestDefinition(
  inventory: ApiInventory,
  options?: { targetUrl?: string; includeNegativeFuzzing?: boolean },
): TestDefinition {
  const tests: SingleTestSpec[] = [];
  const includeNegative = options?.includeNegativeFuzzing ?? true;

  // 1. Generate runtime verification tests for declared endpoints
  for (const endpoint of inventory.endpoints) {
    // Replace {param} placeholders with dummy value for testing
    const resolvedPath = endpoint.path.replace(/\{([^}]+)\}/g, 'test-$1');
    const isPublic = endpoint.isExplicitlyPublic;

    tests.push({
      id: `verify-${endpoint.method.toLowerCase()}-${sanitizeId(endpoint.path)}`,
      name: `Contract Verify: [${endpoint.method} ${endpoint.path}]`,
      description: `Verifies runtime response conforms to declared OpenAPI contract for ${endpoint.method} ${endpoint.path}`,
      path: resolvedPath,
      method: endpoint.method,
      extract: [],
      expectedStatus: isPublic ? [200, 201, 204] : [200, 201, 204, 401, 403],
      assertions: [
        {
          field: 'status',
          operator: 'not_equals',
          value: 500,
          severity: 'high',
          message: `Endpoint ${endpoint.method} ${endpoint.path} failed with unhandled HTTP 500 Internal Server Error`,
        },
      ],
    });
  }

  // 2. Generate negative schema fuzzing tests
  if (includeNegative) {
    const fuzzCases = generateNegativeFuzzTestCases(inventory);
    for (const fuzz of fuzzCases) {
      const resolvedPath = fuzz.endpoint.path.replace(/\{([^}]+)\}/g, 'test-$1');

      tests.push({
        id: fuzz.id,
        name: fuzz.name,
        description: fuzz.description,
        path: resolvedPath,
        method: fuzz.endpoint.method,
        extract: [],
        headers: {
          'Content-Type': fuzz.contentType,
        },
        body: fuzz.payload,
        expectedStatus: fuzz.expectedStatus,
        assertions: [
          {
            field: 'status',
            operator: 'not_equals',
            value: 500,
            severity: 'high',
            message: `Fuzz test on ${fuzz.endpoint.method} ${fuzz.endpoint.path} triggered HTTP 500 instead of 400 Bad Request`,
          },
        ],
      });
    }
  }

  return {
    id: `contract-suite-${sanitizeId(inventory.title || 'api')}`,
    name: `${inventory.title} Security Contract Suite`,
    version: inventory.version || '1.0.0',
    category: 'api_schema',
    description: `Automated security contract test suite generated from OpenAPI specification (${inventory.endpoints.length} endpoints)`,
    target: {
      endpoint: options?.targetUrl,
      requiredCapabilities: ['openapi_contract_audit', 'openapi_schema_fuzzing'],
    },
    inputs: {},
    authentication: { type: 'none' },
    tests: tests.length > 0 ? tests : [
      {
        id: 'no-op',
        name: 'Empty Specification Test',
        path: '/',
        method: 'GET',
        extract: [],
        expectedStatus: [200, 404],
        assertions: [],
      },
    ],
    thresholds: {
      maxAllowedFindings: {
        critical: 0,
        high: 0,
        medium: 5,
        low: 10,
        info: 50,
      },
    },
  };
}
