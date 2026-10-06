import fs from 'node:fs';
import {
  ApiInventory,
  parseOpenApiSpec,
  evaluateOpenApiContractRules,
  ContractViolation,
} from '@security-lab/domain';
import { TestEngine } from '../engine.js';
import { TestCapability } from '../capability.js';
import { ExecutionContext } from '../context.js';
import {
  TestInput,
  TestResult,
  ValidationResult,
  RawEngineFinding,
  RawEngineMetric,
} from '../result.js';
import { safeFetch } from '../http/index.js';
import {
  generateNegativeFuzzTestCases,
  OpenApiFuzzTestCase,
} from './openapi/test-generator.js';

export class SecurityContractEngine implements TestEngine {
  readonly id = 'engine-native-contract';
  readonly version = '1.0.0';
  readonly executionClass = 'class_a_native' as const;

  capabilities(): TestCapability[] {
    return [
      {
        id: 'openapi_contract_audit',
        name: 'OpenAPI Security Contract Audit',
        category: 'compliance_check',
        description:
          'Audits OpenAPI specifications against baseline security contracts (unprotected mutating routes, sensitive query parameters, cleartext servers, HTTP Basic auth).',
        isDisruptive: false,
      },
      {
        id: 'openapi_runtime_verification',
        name: 'OpenAPI Runtime Verification',
        category: 'protocol_audit',
        description:
          'Dispatches verification requests against declared endpoints to verify runtime availability and error handling conformity.',
        isDisruptive: false,
      },
      {
        id: 'openapi_schema_fuzzing',
        name: 'OpenAPI Schema Fuzzing',
        category: 'active_fuzzing',
        description:
          'Automatically generates negative request payloads (missing required fields, unexpected types, oversized strings) and asserts that the API returns HTTP 400 Bad Request instead of HTTP 500 Internal Server Error.',
        isDisruptive: false,
      },
    ];
  }

  validate(input: TestInput): ValidationResult {
    const errors: { path: string; message: string }[] = [];

    if (input.targetUrl) {
      try {
        new URL(input.targetUrl);
      } catch {
        errors.push({ path: 'targetUrl', message: `Invalid target URL: "${input.targetUrl}"` });
      }
    }

    const hasSpec =
      input.options?.spec !== undefined ||
      input.options?.yaml !== undefined ||
      typeof input.options?.specPath === 'string' ||
      typeof input.options?.specUrl === 'string';

    if (!hasSpec) {
      errors.push({
        path: 'options',
        message:
          'Missing OpenAPI specification in options (options.spec, options.specPath, options.specUrl, or options.yaml required)',
      });
    }

    return {
      valid: errors.length === 0,
      errors: errors.length > 0 ? errors : undefined,
    };
  }

  async execute(input: TestInput, context: ExecutionContext): Promise<TestResult> {
    const startTime = Date.now();
    let inventory: ApiInventory;

    // 1. Ingest OpenAPI document
    try {
      let rawContent: string | Record<string, unknown>;

      if (typeof input.options?.spec === 'string' || (input.options?.spec && typeof input.options.spec === 'object')) {
        rawContent = input.options.spec as string | Record<string, unknown>;
      } else if (typeof input.options?.yaml === 'string') {
        rawContent = input.options.yaml;
      } else if (typeof input.options?.specPath === 'string') {
        rawContent = await fs.promises.readFile(input.options.specPath, 'utf8');
      } else if (typeof input.options?.specUrl === 'string') {
        const fetchRes = await safeFetch(input.options.specUrl, {
          signal: context.abortSignal,
          scope: context.target?.scope,
        });
        if (!fetchRes.ok) {
          throw new Error(`Failed to fetch OpenAPI spec from ${input.options.specUrl} (HTTP ${fetchRes.status})`);
        }
        rawContent = await fetchRes.text();
      } else {
        throw new Error('No OpenAPI specification provided in input options');
      }

      inventory = parseOpenApiSpec(rawContent);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        engineId: this.id,
        durationMs: Date.now() - startTime,
        success: false,
        findings: [],
        metrics: [],
        error: `OpenAPI specification ingestion error: ${msg}`,
      };
    }

    const findings: RawEngineFinding[] = [];
    const metrics: RawEngineMetric[] = [];
    let serverErrorCount = 0;
    let schemaBypassCount = 0;

    context.reportProgress(
      15,
      `Ingested OpenAPI document "${inventory.title}" v${inventory.version} (${inventory.endpoints.length} endpoints)`,
    );

    // 2. Static Contract Audit (openapi_contract_audit)
    const violations: ContractViolation[] = evaluateOpenApiContractRules(inventory);

    for (const v of violations) {
      findings.push({
        title: v.title,
        description: v.description,
        severity: v.severity,
        category: 'compliance',
        recommendation: v.recommendation,
        evidence: {
          expected: v.recommendation,
          actual: v.actual,
        },
        metadata: {
          ruleId: v.ruleId,
          endpoint: v.endpoint,
          parameter: v.parameter,
        },
      });
    }

    context.reportProgress(35, `Contract audit evaluated 4 rules: ${violations.length} violations flagged`);

    // 3. Negative Schema Fuzzing (openapi_schema_fuzzing)
    const runFuzzing = input.options?.fuzzing !== false && Boolean(input.targetUrl);

    if (runFuzzing) {
      const fuzzCases: OpenApiFuzzTestCase[] = generateNegativeFuzzTestCases(inventory);
      const totalFuzz = fuzzCases.length;
      let executedFuzz = 0;

      for (const fuzz of fuzzCases) {
        if (context.abortSignal.aborted) {
          throw new Error('Contract engine execution aborted by signal');
        }

        executedFuzz++;
        const progressPct = 35 + Math.round((executedFuzz / Math.max(totalFuzz, 1)) * 60);
        context.reportProgress(
          progressPct,
          `Schema fuzzing [${executedFuzz}/${totalFuzz}]: ${fuzz.name}`,
        );

        // Resolve path against target URL
        const resolvedPath = fuzz.endpoint.path.replace(/\{([^}]+)\}/g, 'test-$1');
        const targetUrl = new URL(
          resolvedPath.startsWith('/') ? resolvedPath.slice(1) : resolvedPath,
          input.targetUrl.endsWith('/') ? input.targetUrl : `${input.targetUrl}/`,
        ).toString();

        let res: Response;
        let bodyText = '';

        try {
          res = await safeFetch(targetUrl, {
            method: fuzz.endpoint.method,
            headers: {
              'Content-Type': fuzz.contentType,
              ...(input.customHeaders || {}),
            },
            body: JSON.stringify(fuzz.payload),
            signal: context.abortSignal,
            scope: context.target?.scope,
          });
          bodyText = await res.text();
        } catch (err: unknown) {
          context.logger?.debug({ err, fuzzId: fuzz.id }, 'Schema fuzzing connection skipped');
          continue;
        }

        const resHeaders: Record<string, string> = {};
        res.headers.forEach((val, k) => {
          resHeaders[k.toLowerCase()] = val;
        });

        // Evaluation: Unhandled 500 Internal Server Error is a high-severity finding
        if (res.status >= 500) {
          serverErrorCount++;
          findings.push({
            title: `Unhandled Server Error (HTTP ${res.status}) on Negative Payload [${fuzz.endpoint.method} ${fuzz.endpoint.path}]`,
            category: 'api_schema',
            severity: 'high',
            description: `Fuzz test "${fuzz.name}" triggered an unhandled HTTP ${res.status} Internal Server Error instead of properly rejecting invalid input with HTTP 400 Bad Request.`,
            recommendation:
              'Implement input schema validation before business logic execution to reject malformed payloads with HTTP 400 Bad Request or 422 Unprocessable Entity.',
            evidence: {
              request: {
                method: fuzz.endpoint.method,
                url: targetUrl,
                headers: { 'content-type': fuzz.contentType },
                body: JSON.stringify(fuzz.payload),
              },
              response: {
                statusCode: res.status,
                headers: resHeaders,
                body: bodyText.slice(0, 1000),
              },
              expected: 'HTTP 400 Bad Request or 422 Unprocessable Entity',
              actual: `HTTP ${res.status} Internal Server Error`,
            },
            metadata: {
              mutationType: fuzz.mutationType,
              targetField: fuzz.targetField,
            },
          });
        } else if (res.status >= 200 && res.status < 300) {
          // Schema bypass: server accepted an explicitly invalid or missing required field payload
          schemaBypassCount++;
          findings.push({
            title: `Schema Bypass: Server Accepted Invalid Payload [${fuzz.endpoint.method} ${fuzz.endpoint.path}]`,
            category: 'api_schema',
            severity: 'medium',
            description: `Server returned HTTP ${res.status} OK for a negative fuzz payload with mutation "${fuzz.mutationType}" (field: ${fuzz.targetField || 'body'}). The API failed to enforce schema constraints.`,
            recommendation:
              'Ensure all required fields and type constraints are strictly validated by backend request validators.',
            evidence: {
              request: {
                method: fuzz.endpoint.method,
                url: targetUrl,
                headers: { 'content-type': fuzz.contentType },
                body: JSON.stringify(fuzz.payload),
              },
              response: {
                statusCode: res.status,
                headers: resHeaders,
                body: bodyText.slice(0, 1000),
              },
              expected: 'HTTP 400 Bad Request or 422 Unprocessable Entity',
              actual: `HTTP ${res.status} OK`,
            },
            metadata: {
              mutationType: fuzz.mutationType,
              targetField: fuzz.targetField,
            },
          });
        }
      }

      metrics.push({
        name: 'fuzz_tests_executed',
        value: executedFuzz,
        unit: 'tests',
      });
      metrics.push({
        name: 'fuzz_server_errors',
        value: serverErrorCount,
        unit: 'findings',
      });
      metrics.push({
        name: 'fuzz_schema_bypasses',
        value: schemaBypassCount,
        unit: 'findings',
      });
    }

    metrics.push({
      name: 'openapi_endpoints_count',
      value: inventory.endpoints.length,
      unit: 'endpoints',
    });
    metrics.push({
      name: 'contract_violations_count',
      value: violations.length,
      unit: 'violations',
    });

    context.reportProgress(100, 'Security contract audit and schema fuzzing completed');

    return {
      engineId: this.id,
      durationMs: Date.now() - startTime,
      success: true,
      findings,
      metrics,
      rawOutput: {
        title: inventory.title,
        version: inventory.version,
        endpointsCount: inventory.endpoints.length,
        contractViolations: violations.length,
        fuzzServerErrors: serverErrorCount,
      },
    };
  }
}
