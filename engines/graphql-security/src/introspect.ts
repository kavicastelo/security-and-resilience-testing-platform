import crypto from 'node:crypto';
import { safeFetch, RawEngineFinding, ExecutionContext } from '@security-lab/engine-sdk';
import { IntrospectionResult, IntrospectionSchema } from './types.js';

export const INTROSPECTION_QUERY = `
  query IntrospectionQuery {
    __schema {
      queryType { name }
      mutationType { name }
      subscriptionType { name }
      types {
        kind
        name
        description
        fields(includeDeprecated: true) {
          name
          description
          type {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
`;

export async function checkIntrospection(
  endpointUrl: string,
  environment: 'development' | 'staging' | 'production',
  customHeaders: Record<string, string> = {},
  context: ExecutionContext,
): Promise<{ result: IntrospectionResult; finding?: RawEngineFinding }> {
  const startTime = Date.now();
  const requestPayload = JSON.stringify({ query: INTROSPECTION_QUERY });
  const headers = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    ...customHeaders,
  };

  try {
    const res = await safeFetch(endpointUrl, {
      method: 'POST',
      headers,
      body: requestPayload,
      signal: context.abortSignal,
      scope: context.target?.scope,
    });

    const responseTimeMs = Date.now() - startTime;
    const json = (await res.json()) as any;

    if (json?.data?.__schema?.types && Array.isArray(json.data.__schema.types)) {
      const schema = json.data.__schema as IntrospectionSchema;
      const types = schema.types || [];
      const userDefinedTypes = types.filter((t) => !t.name.startsWith('__'));

      let fieldsCount = 0;
      for (const t of types) {
        if (t.fields && Array.isArray(t.fields)) {
          fieldsCount += t.fields.length;
        }
      }

      const queryType = types.find((t) => t.name === schema.queryType?.name);
      const mutationType = types.find((t) => t.name === schema.mutationType?.name);

      const queries = queryType?.fields?.map((f) => f.name) || [];
      const mutations = mutationType?.fields?.map((f) => f.name) || [];

      const introspectionResult: IntrospectionResult = {
        enabled: true,
        schema,
        queryTypeName: schema.queryType?.name,
        mutationTypeName: schema.mutationType?.name,
        typesCount: userDefinedTypes.length,
        fieldsCount,
        queries,
        mutations,
      };

      // In production profile, introspection is CRITICAL. In staging/dev, it is HIGH.
      const severity = environment === 'production' ? 'critical' : 'high';

      const evidencePayload = {
        request: {
          method: 'POST',
          url: endpointUrl,
          headers,
          body: JSON.stringify({ query: 'query IntrospectionQuery { __schema { ... } }' }),
        },
        response: {
          statusCode: res.status,
          headers: { 'content-type': res.headers.get('content-type') || 'application/json' },
          body: JSON.stringify({
            typesDiscovered: userDefinedTypes.length,
            queriesCount: queries.length,
            mutationsCount: mutations.length,
            sampleQueries: queries.slice(0, 5),
            sampleMutations: mutations.slice(0, 5),
          }),
          responseTimeMs,
        },
        expected: 'GraphQL schema introspection disabled in non-development deployments',
        actual: `Schema introspection is enabled. Disclosed ${userDefinedTypes.length} types, ${queries.length} queries, and ${mutations.length} mutations.`,
      };

      const sha256 = crypto
        .createHash('sha256')
        .update(JSON.stringify(evidencePayload))
        .digest('hex');

      const finding: RawEngineFinding = {
        title: 'GraphQL Schema Introspection Enabled',
        category: 'information_disclosure',
        severity,
        description: `The GraphQL endpoint at ${endpointUrl} permits arbitrary full schema introspection. Attackers can map out the entire domain model, private administrative mutations, and undocumented API surface.`,
        recommendation:
          'Disable GraphQL schema introspection in production and staging environments (e.g. set introspection: false in Apollo Server, Yoga, or GraphQL Helix).',
        evidence: {
          ...evidencePayload,
          immutableHash: sha256,
        },
      };

      return { result: introspectionResult, finding };
    }
  } catch {
    // Introspection query failed or endpoint not GraphQL
  }

  return {
    result: {
      enabled: false,
      typesCount: 0,
      fieldsCount: 0,
      queries: [],
      mutations: [],
    },
  };
}
