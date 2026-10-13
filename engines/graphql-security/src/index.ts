import {
  TestEngine,
  TestCapability,
  ExecutionContext,
  TestInput,
  TestResult,
  ValidationResult,
  RawEngineFinding,
  RawEngineMetric,
  safeFetch,
} from '@security-lab/engine-sdk';
import { validateUrlAgainstScope } from '@security-lab/domain';
import { createLogger } from '@security-lab/logger';
import { checkIntrospection } from './introspect.js';
import { testQueryDepth } from './depth-fuzzer.js';
import { testBatchAmplification } from './batch-tester.js';
import { testFieldSuggestions } from './suggestions.js';
import { GraphQLSecurityOptions, IntrospectionResult } from './types.js';

export * from './types.js';
export * from './introspect.js';
export * from './depth-fuzzer.js';
export * from './batch-tester.js';
export * from './suggestions.js';

const logger = createLogger({ name: 'engine-graphql-security' });

export class GraphQLSecurityEngine implements TestEngine {
  readonly id = 'engine-graphql-security';
  readonly version = '1.0.0';
  readonly executionClass = 'class_a_native' as const;

  capabilities(): TestCapability[] {
    return [
      {
        id: 'graphql_introspection_audit',
        name: 'GraphQL Schema Introspection Audit',
        category: 'compliance_check',
        description: 'Audits production and staging GraphQL endpoints for exposed full schema introspection.',
        isDisruptive: false,
      },
      {
        id: 'graphql_depth_fuzzing',
        name: 'GraphQL Circular Query Depth DoS Fuzzer',
        category: 'resilience_stress',
        description: 'Generates deeply nested circular query structures to verify query depth limit protections.',
        isDisruptive: false,
      },
      {
        id: 'graphql_batch_amplification',
        name: 'GraphQL Batch Query Amplification Audit',
        category: 'protocol_audit',
        description: 'Verifies whether batch query arrays are permitted, enabling rate-limit bypass and DoS.',
        isDisruptive: false,
      },
      {
        id: 'graphql_field_suggestions',
        name: 'GraphQL Field Suggestion Reconnaissance',
        category: 'passive_analysis',
        description: 'Harvests validation error suggestions to reconstruct private schemas when introspection is disabled.',
        isDisruptive: false,
      },
    ];
  }

  validate(input: TestInput): ValidationResult {
    try {
      const url = new URL(input.targetUrl);
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        return {
          valid: false,
          errors: [{ path: 'targetUrl', message: 'Target URL must use http or https protocol' }],
        };
      }
      return { valid: true };
    } catch {
      return {
        valid: false,
        errors: [{ path: 'targetUrl', message: `Invalid target URL: "${input.targetUrl}"` }],
      };
    }
  }

  async execute(input: TestInput, context: ExecutionContext): Promise<TestResult> {
    const startTime = Date.now();
    const options = (input.options || {}) as GraphQLSecurityOptions;
    const scope = context.target?.scope;

    // 1. Verify scope authorization
    if (scope) {
      const scopeCheck = validateUrlAgainstScope(input.targetUrl, scope);
      if (!scopeCheck.valid) {
        return {
          engineId: this.id,
          durationMs: Date.now() - startTime,
          success: false,
          findings: [],
          metrics: [],
          error: `Target URL "${input.targetUrl}" is out of authorized scope: ${scopeCheck.violations.join('; ')}`,
        };
      }
    }

    context.reportProgress(5, `Locating GraphQL endpoint for ${input.targetUrl}...`);

    // 2. Locate active GraphQL endpoint
    const endpointUrl = await this.locateGraphqlEndpoint(input.targetUrl, options, context);
    if (!endpointUrl) {
      logger.info({ event: 'graphql.not_found', targetUrl: input.targetUrl }, 'No GraphQL endpoint detected on target URL; exiting cleanly.');
      return {
        engineId: this.id,
        durationMs: Date.now() - startTime,
        success: true,
        findings: [],
        metrics: [{ name: 'graphql_endpoints_detected', value: 0, unit: 'count' }],
      };
    }

    logger.info({ event: 'graphql.endpoint_located', endpointUrl }, `Active GraphQL endpoint confirmed at ${endpointUrl}`);
    context.reportProgress(20, `Probing GraphQL endpoint ${endpointUrl}...`);

    const environment = options.environment || 'production';
    const findings: RawEngineFinding[] = [];
    let introspectionData: IntrospectionResult = {
      enabled: false,
      typesCount: 0,
      fieldsCount: 0,
      queries: [],
      mutations: [],
    };

    // 3. Introspection Check
    if (options.testIntrospection !== false) {
      context.reportProgress(30, 'Executing GraphQL schema introspection analysis...');
      const { result, finding } = await checkIntrospection(
        endpointUrl,
        environment,
        input.customHeaders,
        context,
      );
      introspectionData = result;
      if (finding) findings.push(finding);
    }

    // 4. Circular Query Depth Limit Fuzzing
    let maxAllowedDepth = 0;
    if (options.testDepth !== false) {
      context.reportProgress(50, 'Fuzzing circular query depth limits...');
      const { maxAllowedDepth: depth, finding } = await testQueryDepth(
        endpointUrl,
        introspectionData,
        options.maxDepth || 25,
        input.customHeaders,
        context,
      );
      maxAllowedDepth = depth;
      if (finding) findings.push(finding);
    }

    // 5. Batch Amplification Test
    let processedBatchCount = 0;
    if (options.testBatching !== false) {
      context.reportProgress(70, 'Testing batch query array amplification...');
      const { processedCount, finding } = await testBatchAmplification(
        endpointUrl,
        options.batchSize || 50,
        input.customHeaders,
        context,
      );
      processedBatchCount = processedCount;
      if (finding) findings.push(finding);
    }

    // 6. Field Suggestion Harvesting
    let leakedFields: string[] = [];
    if (options.testSuggestions !== false) {
      context.reportProgress(85, 'Auditing field suggestion error disclosures...');
      const { leakedFields: lf, finding } = await testFieldSuggestions(
        endpointUrl,
        input.customHeaders,
        context,
      );
      leakedFields = lf;
      if (finding) findings.push(finding);
    }

    context.reportProgress(100, `GraphQL security audit complete. Identified ${findings.length} findings.`);

    const durationMs = Date.now() - startTime;
    const metrics: RawEngineMetric[] = [
      { name: 'graphql_types_discovered', value: introspectionData.typesCount, unit: 'count' },
      { name: 'graphql_queries_discovered', value: introspectionData.queries.length, unit: 'count' },
      { name: 'graphql_mutations_discovered', value: introspectionData.mutations.length, unit: 'count' },
      { name: 'graphql_max_depth_tested', value: maxAllowedDepth, unit: 'count' },
      { name: 'graphql_batch_amplification_count', value: processedBatchCount, unit: 'count' },
      { name: 'graphql_leaked_suggestions_count', value: leakedFields.length, unit: 'count' },
    ];

    return {
      engineId: this.id,
      durationMs,
      success: true,
      findings,
      metrics,
    };
  }

  private async locateGraphqlEndpoint(
    targetUrl: string,
    options: GraphQLSecurityOptions,
    context: ExecutionContext,
  ): Promise<string | null> {
    const candidatePaths = options.graphqlPath
      ? [options.graphqlPath]
      : ['', '/graphql', '/api/graphql', '/query', '/v1/graphql'];

    const targetBase = targetUrl.endsWith('/') ? targetUrl.slice(0, -1) : targetUrl;

    for (const p of candidatePaths) {
      if (context.abortSignal?.aborted) break;

      let candidateUrl: string;
      try {
        if (p.startsWith('http://') || p.startsWith('https://')) {
          candidateUrl = p;
        } else {
          const pathNormalized = p.startsWith('/') ? p : `/${p}`;
          candidateUrl = new URL(pathNormalized, targetBase).toString();
        }
      } catch {
        continue;
      }

      try {
        const res = await safeFetch(candidateUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
          },
          body: JSON.stringify({ query: '{ __typename }' }),
          signal: context.abortSignal,
          scope: context.target?.scope,
        });

        if (res.status === 200) {
          const json = (await res.json()) as any;
          if (json?.data?.__typename || Array.isArray(json?.errors)) {
            return candidateUrl;
          }
        } else if (res.status === 400) {
          // Some GraphQL servers return 400 with standard GraphQL JSON error payload
          const json = (await res.json()) as any;
          if (json?.errors && Array.isArray(json.errors)) {
            return candidateUrl;
          }
        }
      } catch {
        // Not a GraphQL endpoint or connection failed
      }
    }

    return null;
  }
}

export const graphQLSecurityEngine = new GraphQLSecurityEngine();

try {
  // Self-register into engine-sdk dynamic worker registry
  const { dynamicWorkerEngineRegistry } = await import('@security-lab/engine-sdk');
  dynamicWorkerEngineRegistry.register(graphQLSecurityEngine);
} catch {
  // Ignore registration errors during isolated contexts
}
