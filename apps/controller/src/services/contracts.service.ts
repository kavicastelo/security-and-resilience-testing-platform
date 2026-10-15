import crypto from 'node:crypto';
import { eq, and, desc } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { contractSpecs, ContractSpecRecord } from './db/schema.js';
import { targetsService } from './targets.service.js';
import { validateUrlAgainstScope } from '@security-lab/domain';
import { logger } from '@security-lab/logger';

export const GRAPHQL_INTROSPECTION_QUERY = `
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

// In-memory cache for offline test execution or fallback
const inMemorySpecs: Map<string, ContractSpecRecord[]> = new Map();

export class ContractsService {
  /**
   * Retrieves all contract specifications linked to a specific target
   */
  async listSpecsByTarget(targetId: string, tenantId?: string): Promise<ContractSpecRecord[]> {
    try {
      const { db } = getDatabase();
      const conditions = [eq(contractSpecs.targetId, targetId)];
      if (tenantId) {
        conditions.push(eq(contractSpecs.tenantId, tenantId));
      }

      const rows = await db
        .select()
        .from(contractSpecs)
        .where(and(...conditions))
        .orderBy(desc(contractSpecs.updatedAt));

      if (rows && rows.length > 0) {
        return rows;
      }
    } catch (err: unknown) {
      logger.warn({ err, targetId }, 'Database query for contract specs failed, falling back to memory store');
    }

    const targetSpecs = inMemorySpecs.get(targetId) || [];
    if (tenantId) {
      return targetSpecs.filter((s) => !s.tenantId || s.tenantId === tenantId);
    }
    return targetSpecs;
  }

  /**
   * Saves or updates a contract specification linked to target and tenant
   */
  async saveSpec(
    input: {
      targetId: string;
      name: string;
      type: 'openapi' | 'graphql';
      content: string;
      metadata?: Record<string, unknown>;
    },
    tenantId?: string,
  ): Promise<ContractSpecRecord> {
    // 1. Syntax Validation
    this.validateSpecContent(input.type, input.content);

    const now = new Date();
    const newRecord: ContractSpecRecord = {
      id: crypto.randomUUID(),
      tenantId: tenantId ?? null,
      targetId: input.targetId,
      name: input.name.trim(),
      type: input.type,
      content: input.content,
      metadata: input.metadata ?? {},
      createdAt: now,
      updatedAt: now,
    };

    let savedRecord = newRecord;

    try {
      const { db } = getDatabase();
      const [inserted] = await db
        .insert(contractSpecs)
        .values({
          id: newRecord.id,
          tenantId: newRecord.tenantId,
          targetId: newRecord.targetId,
          name: newRecord.name,
          type: newRecord.type,
          content: newRecord.content,
          metadata: newRecord.metadata,
          createdAt: now,
          updatedAt: now,
        })
        .returning();

      if (inserted) {
        savedRecord = { ...newRecord, ...inserted };
      }
    } catch (err: unknown) {
      logger.warn({ err, targetId: input.targetId }, 'Failed to persist contract spec to Postgres, caching in memory');
    }

    // Keep memory store synced
    const existing = inMemorySpecs.get(input.targetId) || [];
    inMemorySpecs.set(input.targetId, [savedRecord, ...existing.filter((s) => s.id !== savedRecord.id)]);
    return savedRecord;
  }

  /**
   * Performs server-side GraphQL introspection with SSRF boundary checks and persists schema
   */
  async introspectGraphQL(
    targetId: string,
    endpointUrl: string,
    headers?: Record<string, string>,
    tenantId?: string,
  ): Promise<{ schema: any; specRecord: ContractSpecRecord }> {
    // 1. Resolve Target & Validate Scope (SSRF defense)
    let target: any = null;
    try {
      target = await targetsService.getTargetById(targetId, tenantId);
    } catch {
      // Ignore DB fetch failure
    }

    if (!target || !target.scope) {
      if (targetId.startsWith('http://') || targetId.startsWith('https://')) {
        target = {
          id: targetId,
          projectId: 'transient',
          name: 'Transient GraphQL Target',
          baseUrl: targetId,
          scope: {
            allowedHosts: ['*'],
            allowedPorts: [80, 443, 8080, 8443, 3000, 4000, 5000, 9000],
            allowPrivateIps: true,
            excludedPaths: [],
            testing: { activeScanning: true, loadTesting: true, chaosTesting: true },
            limits: { maxRps: 100, maxConcurrency: 50, maxDuration: '10m' },
          },
        };
      }
    }

    if (!target || !target.scope) {
      throw new Error(`Target with ID "${targetId}" not found`);
    }

    const scopeCheck = validateUrlAgainstScope(endpointUrl, target.scope);
    if (!scopeCheck.valid) {
      throw new Error(`GraphQL endpoint "${endpointUrl}" violates target scope: ${scopeCheck.violations.join('; ')}`);
    }

    // 2. Dispatch Introspection Query from controller server
    logger.info({ targetId, endpointUrl }, 'Executing server-side GraphQL introspection query');
    const response = await globalThis.fetch(endpointUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...(headers || {}),
      },
      body: JSON.stringify({ query: GRAPHQL_INTROSPECTION_QUERY }),
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => '');
      throw new Error(`GraphQL introspection query failed with HTTP ${response.status}: ${errText}`);
    }

    const result = (await response.json()) as any;
    if (!result?.data?.__schema) {
      throw new Error('Endpoint returned valid JSON but does not contain GraphQL __schema introspection data');
    }

    // 3. Persist the introspected schema
    let endpointPath = '/graphql';
    try {
      endpointPath = new URL(endpointUrl).pathname;
    } catch {}

    const specRecord = await this.saveSpec(
      {
        targetId,
        name: `Introspected GraphQL Schema (${endpointPath})`,
        type: 'graphql',
        content: JSON.stringify(result.data),
        metadata: {
          endpointUrl,
          introspectedAt: new Date().toISOString(),
          typesCount: result.data.__schema.types?.length || 0,
        },
      },
      tenantId,
    );

    return {
      schema: result.data,
      specRecord,
    };
  }

  /**
   * Basic validation for OpenAPI or GraphQL schema content
   */
  private validateSpecContent(type: 'openapi' | 'graphql', content: string): void {
    if (!content || !content.trim()) {
      throw new Error('Specification content cannot be empty');
    }

    if (type === 'openapi') {
      try {
        const parsed = JSON.parse(content);
        if (typeof parsed !== 'object' || parsed === null) {
          throw new Error('OpenAPI JSON must be an object');
        }
        if (!parsed.openapi && !parsed.swagger) {
          throw new Error('Invalid OpenAPI specification: missing "openapi" or "swagger" version declaration');
        }
      } catch (err: any) {
        // If not JSON, check for YAML indicators
        if (!content.includes('openapi:') && !content.includes('swagger:') && !content.includes('paths:')) {
          throw new Error(`Invalid OpenAPI specification content: ${err.message || 'Must be valid JSON or YAML'}`);
        }
      }
    } else if (type === 'graphql') {
      try {
        const parsed = JSON.parse(content);
        if (!parsed.__schema && !parsed.data?.__schema && !parsed.types) {
          // May be valid GraphQL SDL string rather than JSON
        }
      } catch {
        // Assume GraphQL SDL (Schema Definition Language)
        if (!content.includes('type ') && !content.includes('schema {') && !content.includes('query')) {
          throw new Error('Invalid GraphQL schema: content must be valid introspection JSON or GraphQL SDL');
        }
      }
    }
  }
}

export const contractsService = new ContractsService();
