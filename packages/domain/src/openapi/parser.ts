import YAML from 'yaml';
import { HttpMethod } from '../authorization/index.js';

export type { HttpMethod };

export interface ApiParameter {
  readonly name: string;
  readonly in: 'query' | 'header' | 'path' | 'cookie';
  readonly required: boolean;
  readonly description?: string;
  readonly schema?: Record<string, unknown>;
}

export interface ApiRequestBody {
  readonly required: boolean;
  readonly description?: string;
  readonly contentTypes: Record<string, { schema?: Record<string, unknown> }>;
}

export interface ApiEndpoint {
  readonly path: string;
  readonly method: HttpMethod;
  readonly operationId?: string;
  readonly summary?: string;
  readonly description?: string;
  readonly tags: string[];
  readonly security?: Record<string, string[]>[];
  readonly parameters: ApiParameter[];
  readonly requestBody?: ApiRequestBody;
  readonly responses: Record<string, { description?: string; schema?: Record<string, unknown> }>;
  readonly isMutating: boolean;
  readonly isExplicitlyPublic: boolean;
}

export interface ApiSecurityScheme {
  readonly type: string;
  readonly scheme?: string;
  readonly bearerFormat?: string;
  readonly name?: string;
  readonly in?: string;
  readonly description?: string;
}

export interface ApiServer {
  readonly url: string;
  readonly description?: string;
}

export interface ApiInventory {
  readonly openapi: string;
  readonly title: string;
  readonly version: string;
  readonly description?: string;
  readonly servers: ApiServer[];
  readonly securitySchemes: Record<string, ApiSecurityScheme>;
  readonly globalSecurity: Record<string, string[]>[];
  readonly endpoints: ApiEndpoint[];
  readonly rawSpec: Record<string, unknown>;
}

export class OpenApiParseError extends Error {
  constructor(message: string, public readonly details?: unknown) {
    super(message);
    this.name = 'OpenApiParseError';
  }
}

const SUPPORTED_METHODS = new Set(['get', 'post', 'put', 'delete', 'patch', 'head', 'options']);
const MUTATING_METHODS = new Set(['POST', 'PUT', 'DELETE', 'PATCH']);

export function resolveRef(
  schema: Record<string, unknown> | undefined,
  root: Record<string, unknown>,
  depth = 0,
): Record<string, unknown> | undefined {
  if (!schema || depth > 10) return schema;
  if (typeof schema['$ref'] === 'string') {
    const ref = schema['$ref'] as string;
    if (ref.startsWith('#/')) {
      const parts = ref.slice(2).split('/');
      let current: unknown = root;
      for (const part of parts) {
        if (current && typeof current === 'object' && part in (current as Record<string, unknown>)) {
          current = (current as Record<string, unknown>)[part];
        } else {
          current = undefined;
          break;
        }
      }
      if (current && typeof current === 'object') {
        return resolveRef(current as Record<string, unknown>, root, depth + 1);
      }
    }
  }
  return schema;
}

/**
 * Parses and normalizes an OpenAPI 3.0.x or 3.1.x document into an ApiInventory.
 * Supports YAML string, JSON string, or parsed JavaScript object.
 */
export function parseOpenApiSpec(input: string | Record<string, unknown>): ApiInventory {
  let doc: Record<string, unknown>;

  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (!trimmed) {
      throw new OpenApiParseError('Empty OpenAPI specification provided');
    }

    try {
      if (trimmed.startsWith('{')) {
        doc = JSON.parse(trimmed);
      } else {
        doc = YAML.parse(trimmed, { maxAliasCount: 1000 });
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new OpenApiParseError(`Failed to parse OpenAPI document syntax: ${msg}`);
    }
  } else if (input && typeof input === 'object') {
    doc = input;
  } else {
    throw new OpenApiParseError('Invalid OpenAPI input: must be a string or object');
  }

  if (!doc || typeof doc !== 'object') {
    throw new OpenApiParseError('OpenAPI specification must be an object');
  }

  const openapiVer = String(doc['openapi'] || doc['swagger'] || '');
  if (!openapiVer.startsWith('3.') && !openapiVer.startsWith('2.')) {
    throw new OpenApiParseError(
      `Unsupported API specification version "${openapiVer}". Expected OpenAPI 3.0.x or 3.1.x.`,
    );
  }

  const info = (doc['info'] || {}) as Record<string, unknown>;
  const title = String(info['title'] || 'Untitled API');
  const version = String(info['version'] || '1.0.0');
  const description = info['description'] ? String(info['description']) : undefined;

  // Extract servers
  const servers: ApiServer[] = [];
  if (Array.isArray(doc['servers'])) {
    for (const s of doc['servers']) {
      if (s && typeof s === 'object' && s.url) {
        servers.push({
          url: String(s.url),
          description: s.description ? String(s.description) : undefined,
        });
      }
    }
  }

  // Extract security schemes
  const securitySchemes: Record<string, ApiSecurityScheme> = {};
  const components = (doc['components'] || {}) as Record<string, unknown>;
  const rawSchemes = (components['securitySchemes'] || doc['securityDefinitions'] || {}) as Record<string, unknown>;

  for (const [schemeName, schemeObj] of Object.entries(rawSchemes)) {
    if (schemeObj && typeof schemeObj === 'object') {
      const s = schemeObj as Record<string, unknown>;
      securitySchemes[schemeName] = {
        type: String(s['type'] || 'http'),
        scheme: s['scheme'] ? String(s['scheme']) : undefined,
        bearerFormat: s['bearerFormat'] ? String(s['bearerFormat']) : undefined,
        name: s['name'] ? String(s['name']) : undefined,
        in: s['in'] ? String(s['in']) : undefined,
        description: s['description'] ? String(s['description']) : undefined,
      };
    }
  }

  // Extract global security
  const globalSecurity: Record<string, string[]>[] = [];
  if (Array.isArray(doc['security'])) {
    for (const sec of doc['security']) {
      if (sec && typeof sec === 'object') {
        globalSecurity.push(sec as Record<string, string[]>);
      }
    }
  }

  // Extract paths and operations
  const endpoints: ApiEndpoint[] = [];
  const paths = (doc['paths'] || {}) as Record<string, unknown>;

  for (const [pathKey, pathObj] of Object.entries(paths)) {
    if (!pathKey.startsWith('/') || !pathObj || typeof pathObj !== 'object') {
      continue;
    }

    const pathItem = pathObj as Record<string, unknown>;
    const pathLevelParams: ApiParameter[] = [];

    if (Array.isArray(pathItem['parameters'])) {
      for (const p of pathItem['parameters']) {
        if (p && typeof p === 'object' && p.name && p.in) {
          pathLevelParams.push({
            name: String(p.name),
            in: p.in as 'query' | 'header' | 'path' | 'cookie',
            required: Boolean(p.required),
            description: p.description ? String(p.description) : undefined,
            schema: p.schema && typeof p.schema === 'object' ? (p.schema as Record<string, unknown>) : undefined,
          });
        }
      }
    }

    for (const [methodKey, opObj] of Object.entries(pathItem)) {
      const lowerMethod = methodKey.toLowerCase();
      if (!SUPPORTED_METHODS.has(lowerMethod) || !opObj || typeof opObj !== 'object') {
        continue;
      }

      const op = opObj as Record<string, unknown>;
      const method = lowerMethod.toUpperCase() as HttpMethod;
      const isMutating = MUTATING_METHODS.has(method);

      // Operation-level parameters merged with path-level parameters
      const parameters: ApiParameter[] = [...pathLevelParams];
      if (Array.isArray(op['parameters'])) {
        for (const p of op['parameters']) {
          if (p && typeof p === 'object' && p.name && p.in) {
            // Replace or add
            const existingIdx = parameters.findIndex(
              (ep) => ep.name === p.name && ep.in === p.in,
            );
            const rawParamSchema = p.schema && typeof p.schema === 'object' ? (p.schema as Record<string, unknown>) : undefined;
            const normalizedParam: ApiParameter = {
              name: String(p.name),
              in: p.in as 'query' | 'header' | 'path' | 'cookie',
              required: Boolean(p.required),
              description: p.description ? String(p.description) : undefined,
              schema: resolveRef(rawParamSchema, doc),
            };

            if (existingIdx > -1) {
              parameters[existingIdx] = normalizedParam;
            } else {
              parameters.push(normalizedParam);
            }
          }
        }
      }

      // Security requirements
      let security: Record<string, string[]>[] | undefined;
      let isExplicitlyPublic = false;

      if (Array.isArray(op['security'])) {
        security = op['security'] as Record<string, string[]>[];
        // In OpenAPI: security: [] explicitly designates a public endpoint overriding global security
        if (security.length === 0) {
          isExplicitlyPublic = true;
        }
      }

      // Request Body
      let requestBody: ApiRequestBody | undefined;
      let rawBody = op['requestBody'] as Record<string, unknown> | undefined;
      if (rawBody && typeof rawBody === 'object') {
        rawBody = resolveRef(rawBody, doc) || rawBody;
        const contentTypes: Record<string, { schema?: Record<string, unknown> }> = {};
        const content = (rawBody['content'] || {}) as Record<string, unknown>;

        for (const [cType, cVal] of Object.entries(content)) {
          if (cVal && typeof cVal === 'object') {
            const schema = (cVal as Record<string, unknown>)['schema'];
            contentTypes[cType] = {
              schema: resolveRef(
                schema && typeof schema === 'object' ? (schema as Record<string, unknown>) : undefined,
                doc,
              ),
            };
          }
        }

        requestBody = {
          required: Boolean(rawBody['required']),
          description: rawBody['description'] ? String(rawBody['description']) : undefined,
          contentTypes,
        };
      }

      // Responses
      const responses: Record<string, { description?: string; schema?: Record<string, unknown> }> = {};
      const rawResponses = (op['responses'] || {}) as Record<string, unknown>;

      for (const [code, rVal] of Object.entries(rawResponses)) {
        if (rVal && typeof rVal === 'object') {
          const rObj = resolveRef(rVal as Record<string, unknown>, doc) || (rVal as Record<string, unknown>);
          const content = (rObj['content'] || {}) as Record<string, unknown>;
          const firstContent = Object.values(content)[0] as Record<string, unknown> | undefined;
          const schema = firstContent && typeof firstContent === 'object' ? firstContent['schema'] : undefined;

          responses[code] = {
            description: rObj['description'] ? String(rObj['description']) : undefined,
            schema: resolveRef(
              schema && typeof schema === 'object' ? (schema as Record<string, unknown>) : undefined,
              doc,
            ),
          };
        }
      }

      endpoints.push({
        path: pathKey,
        method,
        operationId: op['operationId'] ? String(op['operationId']) : undefined,
        summary: op['summary'] ? String(op['summary']) : undefined,
        description: op['description'] ? String(op['description']) : undefined,
        tags: Array.isArray(op['tags']) ? op['tags'].map(String) : [],
        security,
        parameters,
        requestBody,
        responses,
        isMutating,
        isExplicitlyPublic,
      });
    }
  }

  return {
    openapi: openapiVer,
    title,
    version,
    description,
    servers,
    securitySchemes,
    globalSecurity,
    endpoints,
    rawSpec: doc,
  };
}
