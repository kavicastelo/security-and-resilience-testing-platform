import { authFetch } from './client.js';

export interface OpenApiParameter {
  name: string;
  in: 'query' | 'header' | 'path' | 'cookie' | 'body';
  required: boolean;
  description?: string;
  type?: string;
  format?: string;
  schema?: Record<string, unknown>;
}

export interface OpenApiEndpoint {
  path: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS' | 'HEAD';
  operationId?: string;
  summary?: string;
  description?: string;
  tags: string[];
  parameters: OpenApiParameter[];
  requestBody?: {
    required?: boolean;
    description?: string;
    contentTypes: string[];
    samplePayload?: unknown;
  };
  responses: Record<string, { description?: string }>;
  security?: Record<string, string[]>[];
}

export interface ParsedOpenApiSpec {
  title: string;
  version: string;
  description?: string;
  servers: { url: string; description?: string }[];
  endpoints: OpenApiEndpoint[];
  tags: string[];
  securitySchemes: Record<string, unknown>;
  totalEndpoints: number;
}

export interface GraphQLFieldType {
  kind: string;
  name?: string;
  ofType?: GraphQLFieldType;
}

export interface GraphQLField {
  name: string;
  description?: string;
  isDeprecated?: boolean;
  deprecationReason?: string;
  type: GraphQLFieldType;
  args?: {
    name: string;
    description?: string;
    type: GraphQLFieldType;
    defaultValue?: string;
  }[];
}

export interface GraphQLType {
  kind: 'OBJECT' | 'INTERFACE' | 'UNION' | 'ENUM' | 'INPUT_OBJECT' | 'SCALAR';
  name: string;
  description?: string;
  fields?: GraphQLField[];
  inputFields?: GraphQLField[];
  enumValues?: { name: string; description?: string }[];
}

export interface GraphQLParsedSchema {
  queryTypeName?: string;
  mutationTypeName?: string;
  subscriptionTypeName?: string;
  types: GraphQLType[];
  queries: GraphQLField[];
  mutations: GraphQLField[];
  subscriptions: GraphQLField[];
  typesCount: number;
  totalFieldsCount: number;
}

export interface ContractVerificationResult {
  success: boolean;
  data?: {
    engineId: string;
    findings: Array<{
      title: string;
      category: string;
      severity: 'low' | 'medium' | 'high' | 'critical';
      description: string;
      recommendation?: string;
      evidence?: Record<string, unknown>;
    }>;
    metrics: Array<{
      name: string;
      value: number;
      unit: string;
    }>;
    durationMs: number;
  };
  error?: {
    code: string;
    message: string;
    details?: unknown;
  };
}

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
          isDeprecated
          deprecationReason
          type {
            kind
            name
            ofType {
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
          args {
            name
            description
            defaultValue
            type {
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

/**
 * Format GraphQL AST type into readable string (e.g. [User!]!)
 */
export function formatGraphQLType(type?: GraphQLFieldType): string {
  if (!type) return 'Unknown';
  if (type.kind === 'NON_NULL') {
    return `${formatGraphQLType(type.ofType)}!`;
  }
  if (type.kind === 'LIST') {
    return `[${formatGraphQLType(type.ofType)}]`;
  }
  return type.name || type.kind || 'Unknown';
}

/**
 * Parses raw OpenAPI 3.0 or Swagger 2.0 object or JSON string into structured endpoints
 */
export function parseOpenApiDocument(raw: unknown): ParsedOpenApiSpec {
  let doc: any = raw;
  if (typeof raw === 'string') {
    try {
      doc = JSON.parse(raw);
    } catch {
      // If YAML, create basic fallback or error
      throw new Error('Please provide valid JSON format for OpenAPI spec parsing.');
    }
  }

  if (!doc || typeof doc !== 'object') {
    throw new Error('Invalid OpenAPI document format');
  }

  const title = doc.info?.title || 'OpenAPI Specification';
  const version = doc.info?.version || '1.0.0';
  const description = doc.info?.description || '';

  const servers: { url: string; description?: string }[] = [];
  if (Array.isArray(doc.servers)) {
    for (const s of doc.servers) {
      if (s?.url) servers.push({ url: s.url, description: s.description });
    }
  } else if (doc.host) {
    const scheme = doc.schemes?.[0] || 'https';
    const basePath = doc.basePath || '';
    servers.push({ url: `${scheme}://${doc.host}${basePath}` });
  }

  const endpoints: OpenApiEndpoint[] = [];
  const tagsSet = new Set<string>();
  const paths = doc.paths || {};

  const httpMethods: ('GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS' | 'HEAD')[] = [
    'GET',
    'POST',
    'PUT',
    'DELETE',
    'PATCH',
    'OPTIONS',
    'HEAD',
  ];

  for (const [pathStr, pathObj] of Object.entries<any>(paths)) {
    if (!pathObj || typeof pathObj !== 'object') continue;

    const commonParams = Array.isArray(pathObj.parameters) ? pathObj.parameters : [];

    for (const methodKey of Object.keys(pathObj)) {
      const upperMethod = methodKey.toUpperCase() as any;
      if (!httpMethods.includes(upperMethod)) continue;

      const op = pathObj[methodKey];
      if (!op || typeof op !== 'object') continue;

      const tags: string[] = Array.isArray(op.tags) && op.tags.length > 0 ? op.tags : ['default'];
      for (const t of tags) tagsSet.add(t);

      const allParams = [...commonParams, ...(Array.isArray(op.parameters) ? op.parameters : [])];
      const parsedParams: OpenApiParameter[] = allParams.map((p: any) => ({
        name: p.name || 'unnamed',
        in: p.in || 'query',
        required: Boolean(p.required),
        description: p.description,
        type: p.schema?.type || p.type || 'string',
        format: p.schema?.format || p.format,
        schema: p.schema,
      }));

      // Request body
      let requestBodyInfo: OpenApiEndpoint['requestBody'];
      if (op.requestBody?.content) {
        const contentTypes = Object.keys(op.requestBody.content);
        const jsonContent = op.requestBody.content['application/json'];
        let samplePayload: unknown;
        if (jsonContent?.example) {
          samplePayload = jsonContent.example;
        } else if (jsonContent?.schema) {
          samplePayload = generateMockFromSchema(jsonContent.schema);
        }
        requestBodyInfo = {
          required: Boolean(op.requestBody.required),
          description: op.requestBody.description,
          contentTypes,
          samplePayload,
        };
      }

      // Responses
      const responses: Record<string, { description?: string }> = {};
      if (op.responses && typeof op.responses === 'object') {
        for (const [code, resp] of Object.entries<any>(op.responses)) {
          responses[code] = { description: resp?.description || '' };
        }
      }

      endpoints.push({
        path: pathStr,
        method: upperMethod,
        operationId: op.operationId,
        summary: op.summary || `${upperMethod} ${pathStr}`,
        description: op.description,
        tags,
        parameters: parsedParams,
        requestBody: requestBodyInfo,
        responses,
        security: op.security || doc.security,
      });
    }
  }

  return {
    title,
    version,
    description,
    servers,
    endpoints,
    tags: Array.from(tagsSet).sort(),
    securitySchemes: doc.components?.securitySchemes || doc.securityDefinitions || {},
    totalEndpoints: endpoints.length,
  };
}

/**
 * Generate mock sample JSON object from an OpenAPI schema
 */
export function generateMockFromSchema(schema: any): unknown {
  if (!schema || typeof schema !== 'object') return {};

  if (schema.example !== undefined) return schema.example;
  if (schema.default !== undefined) return schema.default;

  const type = schema.type || (schema.properties ? 'object' : 'string');

  if (type === 'string') {
    if (schema.format === 'email') return 'secops-tester@securitylab.local';
    if (schema.format === 'uuid') return '12345678-1234-4234-8234-123456789abc';
    if (schema.format === 'date-time') return new Date().toISOString();
    return schema.enum ? schema.enum[0] : 'sample_value';
  }

  if (type === 'number' || type === 'integer') {
    return schema.minimum !== undefined ? schema.minimum : 100;
  }

  if (type === 'boolean') {
    return true;
  }

  if (type === 'array') {
    const itemSchema = schema.items || {};
    return [generateMockFromSchema(itemSchema)];
  }

  if (type === 'object' || schema.properties) {
    const result: Record<string, unknown> = {};
    const props = schema.properties || {};
    for (const [key, propSchema] of Object.entries(props)) {
      result[key] = generateMockFromSchema(propSchema);
    }
    return result;
  }

  return {};
}

/**
 * Verify contract through controller API endpoint
 */
export async function verifyContractViaApi(payload: {
  spec?: unknown;
  specUrl?: string;
  targetUrl?: string;
  options?: Record<string, unknown>;
}): Promise<ContractVerificationResult> {
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000';
  const res = await authFetch(`${apiUrl}/api/v1/contracts/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  return res.json();
}

/**
 * Parse raw GraphQL Introspection JSON response into structured Query/Mutation/Type catalog
 */
export function parseGraphQLSchema(introspectionData: any): GraphQLParsedSchema {
  const schema = introspectionData?.data?.__schema || introspectionData?.__schema;
  if (!schema || !Array.isArray(schema.types)) {
    throw new Error('Invalid GraphQL introspection schema format');
  }

  const queryTypeName = schema.queryType?.name || 'Query';
  const mutationTypeName = schema.mutationType?.name || 'Mutation';
  const subscriptionTypeName = schema.subscriptionType?.name || 'Subscription';

  const userTypes: GraphQLType[] = [];
  let queries: GraphQLField[] = [];
  let mutations: GraphQLField[] = [];
  let subscriptions: GraphQLField[] = [];
  let totalFields = 0;

  for (const t of schema.types) {
    // Filter out standard internal types starting with double underscore unless requested
    if (t.name?.startsWith('__')) continue;

    if (t.name === queryTypeName && Array.isArray(t.fields)) {
      queries = t.fields;
      totalFields += t.fields.length;
    } else if (t.name === mutationTypeName && Array.isArray(t.fields)) {
      mutations = t.fields;
      totalFields += t.fields.length;
    } else if (t.name === subscriptionTypeName && Array.isArray(t.fields)) {
      subscriptions = t.fields;
      totalFields += t.fields.length;
    } else {
      userTypes.push(t);
      if (Array.isArray(t.fields)) {
        totalFields += t.fields.length;
      }
    }
  }

  return {
    queryTypeName,
    mutationTypeName,
    subscriptionTypeName,
    types: userTypes.sort((a, b) => a.name.localeCompare(b.name)),
    queries,
    mutations,
    subscriptions,
    typesCount: userTypes.length,
    totalFieldsCount: totalFields,
  };
}

/**
 * Build a recursive circular query for depth attack simulation
 */
export function constructDepthAttackQuery(
  depth: number,
  rootField = 'user',
  nestedField = 'friends',
): string {
  const safeDepth = Math.max(1, Math.min(depth, 30));
  let inner = '__typename';

  for (let i = 0; i < safeDepth; i++) {
    const indent = '  '.repeat(safeDepth - i);
    inner = `{\n${indent}  id\n${indent}  ${nestedField} ${inner.startsWith('{') ? inner : `{\n${indent}    ${inner}\n${indent}  }`}\n${indent}}`;
  }

  return `query DeepCircularProbe_${safeDepth} {\n  ${rootField} ${inner}\n}`;
}

/**
 * Parses leaked field suggestions from GraphQL error messages
 */
export function extractFieldSuggestions(errorMessages: string[]): string[] {
  const leaked: string[] = [];
  const suggestionRegex = /did you mean\s+(["'][^"']+["']|\S+)/i;

  for (const msg of errorMessages) {
    const match = suggestionRegex.exec(msg);
    if (match && match[1]) {
      const field = match[1].replace(/["',?]/g, '').trim();
      if (field && !leaked.includes(field)) {
        leaked.push(field);
      }
    }
  }

  return leaked;
}

export interface ContractSpecRecord {
  id: string;
  tenantId?: string | null;
  targetId: string;
  name: string;
  type: 'openapi' | 'graphql';
  content: string;
  metadata?: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export interface SaveTargetSpecInput {
  targetId: string;
  name: string;
  type: 'openapi' | 'graphql';
  content: string;
  metadata?: Record<string, unknown>;
}

export interface GraphQLIntrospectInput {
  targetId: string;
  endpointUrl: string;
  headers?: Record<string, string>;
}

export interface GraphQLIntrospectResult {
  schema: any;
  specRecord: ContractSpecRecord;
}

/**
 * Fetches all saved OpenAPI and GraphQL specifications for a target
 */
export async function fetchTargetSpecs(targetId: string): Promise<ContractSpecRecord[]> {
  if (!targetId) return [];
  const res = await authFetch(`/api/v1/contracts/specs?targetId=${encodeURIComponent(targetId)}`);
  if (!res.ok) {
    const errorBody = await res.json().catch(() => null);
    throw new Error(errorBody?.error?.message || `Failed to fetch target specs: HTTP ${res.status}`);
  }
  const json = await res.json();
  return json.data || [];
}

/**
 * Persists an OpenAPI or GraphQL specification linked to a target
 */
export async function saveTargetSpec(payload: SaveTargetSpecInput): Promise<ContractSpecRecord> {
  const res = await authFetch('/api/v1/contracts/specs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const json = await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error(json?.error?.message || `Failed to save contract specification: HTTP ${res.status}`);
  }
  return json.data || json;
}

/**
 * Executes server-side GraphQL schema introspection with SSRF boundary checks
 */
export async function executeGraphQLIntrospection(
  payload: GraphQLIntrospectInput,
): Promise<GraphQLIntrospectResult> {
  const res = await authFetch('/api/v1/contracts/graphql/introspect', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const json = await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error(json?.error?.message || `GraphQL introspection failed: HTTP ${res.status}`);
  }
  return json.data || json;
}
