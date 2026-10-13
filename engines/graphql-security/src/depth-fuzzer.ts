import crypto from 'node:crypto';
import { safeFetch, RawEngineFinding, ExecutionContext } from '@security-lab/engine-sdk';
import { IntrospectionResult } from './types.js';

export async function testQueryDepth(
  endpointUrl: string,
  introspection: IntrospectionResult,
  maxDepth = 25,
  customHeaders: Record<string, string> = {},
  context: ExecutionContext,
): Promise<{ maxAllowedDepth: number; finding?: RawEngineFinding }> {
  const queryPayload = buildDeepQuery(introspection, maxDepth);
  const startTime = Date.now();
  const headers = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    ...customHeaders,
  };

  try {
    const res = await safeFetch(endpointUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({ query: queryPayload.query }),
      signal: context.abortSignal,
      scope: context.target?.scope,
    });

    const responseTimeMs = Date.now() - startTime;
    const bodyText = await res.text();

    let json: any = null;
    try {
      json = JSON.parse(bodyText);
    } catch {
      // Non-JSON response
    }

    // Check if server rejected the query due to depth limits
    const depthLimitErrorPatterns = [
      /depth/i,
      /maximum depth/i,
      /depth limit/i,
      /complexity/i,
      /query is too complex/i,
      /exceeds maximum allowed depth/i,
    ];

    const errorsArray = json?.errors || [];
    const hasDepthRejection = errorsArray.some((err: any) => {
      const msg = err.message || '';
      return depthLimitErrorPatterns.some((pattern) => pattern.test(msg));
    });

    // If query was rejected with explicit depth error or 400 Bad Request mentioning depth, DoS protection is active
    if (res.status === 400 && hasDepthRejection) {
      return { maxAllowedDepth: 0 };
    }

    // If the server processed the deep query without a depth limit rejection (200 OK or errors unrelated to depth),
    // then query depth limits are absent!
    if (!hasDepthRejection && (res.status === 200 || !json?.errors || json.errors.length === 0 || !hasDepthRejection)) {
      const evidencePayload = {
        request: {
          method: 'POST',
          url: endpointUrl,
          headers,
          body: queryPayload.query.slice(0, 1024) + `... [depth: ${maxDepth}]`,
        },
        response: {
          statusCode: res.status,
          headers: { 'content-type': res.headers.get('content-type') || 'application/json' },
          body: bodyText.slice(0, 1024),
          responseTimeMs,
        },
        expected: `GraphQL server enforces depth ceiling (<= 10) and rejects nested query of depth ${maxDepth} with HTTP 400`,
        actual: `Query of depth ${maxDepth} was processed without depth limit rejection (HTTP ${res.status})`,
      };

      const sha256 = crypto
        .createHash('sha256')
        .update(JSON.stringify(evidencePayload))
        .digest('hex');

      const finding: RawEngineFinding = {
        title: 'Unrestricted GraphQL Query Depth (Denial of Service Risk)',
        category: 'resilience_stress',
        severity: 'medium',
        description: `The GraphQL API permitted execution of a deeply nested query of depth ${maxDepth} without enforcing recursive depth limits. Malicious users can send exponential circular queries (e.g. author -> books -> author) causing server thread exhaustion and Denial of Service.`,
        recommendation:
          'Implement query depth limiting middleware (e.g. graphql-depth-limit or Apollo Server validation rules) capped at a safe production depth (recommended: 7-10).',
        evidence: {
          ...evidencePayload,
          immutableHash: sha256,
        },
      };

      return { maxAllowedDepth: maxDepth, finding };
    }
  } catch {
    // Network or parse error
  }

  return { maxAllowedDepth: 0 };
}

function buildDeepQuery(
  introspection: IntrospectionResult,
  depth: number,
): { query: string; fieldPath: string } {
  // Try to find a self-referencing or circular type from schema introspection
  let rootQueryField = 'me';
  let nestedField = 'friends';

  if (introspection.enabled && introspection.schema) {
    const queryTypeName = introspection.schema.queryType?.name || 'Query';
    const queryType = introspection.schema.types.find((t) => t.name === queryTypeName);

    if (queryType?.fields && queryType.fields.length > 0) {
      // Look for a field whose type contains child fields of the same type
      for (const qf of queryType.fields) {
        const typeName = getTypeName(qf.type);
        const resolvedType = introspection.schema.types.find((t) => t.name === typeName);
        if (resolvedType?.fields) {
          const circularField = resolvedType.fields.find((f) => getTypeName(f.type) === typeName);
          if (circularField) {
            rootQueryField = qf.name;
            nestedField = circularField.name;
            break;
          }
        }
      }
    }
  }

  // Construct nested query
  let inner = `__typename`;
  for (let i = 0; i < depth; i++) {
    inner = `${nestedField} { ${inner} }`;
  }

  const query = `query DeepCircularQuery { ${rootQueryField} { ${inner} } }`;
  return { query, fieldPath: `${rootQueryField}.${nestedField}` };
}

function getTypeName(typeObj: any): string | undefined {
  if (!typeObj) return undefined;
  if (typeObj.name) return typeObj.name;
  if (typeObj.ofType) return getTypeName(typeObj.ofType);
  return undefined;
}
