import {
  TestDefinition,
  TestDefinitionSchema,
  parseTestDefinitionYaml,
  evaluateAssertion,
  extractFieldValue,
  validateUrlAgainstScope,
} from '@security-lab/domain';
import { TestEngine } from '../engine.js';
import { TestCapability } from '../capability.js';
import { ExecutionContext } from '../context.js';
import { TestInput, TestResult, ValidationResult, RawEngineFinding, RawEngineMetric } from '../result.js';
import { safeFetch } from '../http/index.js';

export class DeclarativeTestEngine implements TestEngine {
  readonly id = 'engine-native-declarative';
  readonly version = '1.0.0';
  readonly executionClass = 'class_a_native' as const;

  capabilities(): TestCapability[] {
    return [
      {
        id: 'declarative_assertions',
        name: 'Declarative YAML HTTP Assertion Runner',
        category: 'protocol_audit',
        description: 'Executes declarative YAML test specifications against target endpoints and evaluates response assertions',
        isDisruptive: false,
      },
    ];
  }

  validate(input: TestInput): ValidationResult {
    const errors: { path: string; message: string }[] = [];

    try {
      new URL(input.targetUrl);
    } catch {
      errors.push({ path: 'targetUrl', message: `Invalid target URL: "${input.targetUrl}"` });
    }

    if (!input.options?.definition && !input.options?.yaml) {
      errors.push({
        path: 'options',
        message: 'DeclarativeTestEngine requires either options.definition (TestDefinition) or options.yaml (string)',
      });
    } else if (input.options.yaml && typeof input.options.yaml === 'string') {
      try {
        parseTestDefinitionYaml(input.options.yaml);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        errors.push({ path: 'options.yaml', message: `Invalid test definition YAML: ${msg}` });
      }
    } else if (input.options.definition) {
      const parsed = TestDefinitionSchema.safeParse(input.options.definition);
      if (!parsed.success) {
        errors.push({
          path: 'options.definition',
          message: `Schema validation failed: ${parsed.error.message}`,
        });
      }
    }

    return {
      valid: errors.length === 0,
      errors: errors.length > 0 ? errors : undefined,
    };
  }

  async execute(input: TestInput, context: ExecutionContext): Promise<TestResult> {
    const startTime = Date.now();
    let definition: TestDefinition;

    try {
      if (input.options?.yaml && typeof input.options.yaml === 'string') {
        definition = parseTestDefinitionYaml(input.options.yaml);
      } else if (input.options?.definition) {
        definition = TestDefinitionSchema.parse(input.options.definition);
      } else {
        throw new Error('Missing test definition in options (options.definition or options.yaml required)');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        engineId: this.id,
        durationMs: Date.now() - startTime,
        success: false,
        findings: [],
        metrics: [],
        error: `Failed to load test definition: ${msg}`,
      };
    }

    const baseUrl = input.targetUrl.replace(/\/+$/, '');
    const findings: RawEngineFinding[] = [];
    const metrics: RawEngineMetric[] = [];
    let assertionsPassedCount = 0;
    let assertionsFailedCount = 0;

    // Resolve authentication headers
    const authHeaders: Record<string, string> = {};
    if (definition.authentication?.type === 'bearer') {
      const token =
        (input.options?.authToken as string | undefined) ||
        (definition.authentication.tokenEnvVar ? process.env[definition.authentication.tokenEnvVar] : undefined);
      if (token) {
        authHeaders['Authorization'] = `Bearer ${token}`;
      }
    } else if (definition.authentication?.type === 'api_key') {
      const keyHeader = definition.authentication.headerName || 'X-API-Key';
      const keyPrefix = definition.authentication.headerValuePrefix ? `${definition.authentication.headerValuePrefix} ` : '';
      const keyVal =
        (input.options?.apiKey as string | undefined) ||
        (definition.authentication.tokenEnvVar ? process.env[definition.authentication.tokenEnvVar] : undefined);
      if (keyVal) {
        authHeaders[keyHeader] = `${keyPrefix}${keyVal}`;
      }
    }

    const totalTests = definition.tests.length;

    for (const [i, testSpec] of definition.tests.entries()) {
      if (context.abortSignal.aborted) {
        throw new Error('Test execution aborted by signal');
      }

      const progressPercent = Math.round(((i + 1) / totalTests) * 100);
      context.reportProgress(progressPercent, `Executing test [${testSpec.id}]: ${testSpec.name}`);

      const isAbsolute = testSpec.path.startsWith('http://') || testSpec.path.startsWith('https://');
      const fullUrl = isAbsolute
        ? testSpec.path
        : `${baseUrl}${testSpec.path.startsWith('/') ? '' : '/'}${testSpec.path}`;

      // Enforce strict security boundary: absolute URLs must be authorized by target scope
      if (isAbsolute && context.target?.scope) {
        const scopeValidation = validateUrlAgainstScope(fullUrl, context.target.scope);
        if (!scopeValidation.valid) {
          findings.push({
            title: `Security Boundary Violation: [${testSpec.name}]`,
            category: definition.category,
            severity: 'critical',
            description: `Test definition specified out-of-scope absolute URL "${fullUrl}": ${scopeValidation.violations.join('; ')}`,
            recommendation: 'Ensure all test definition paths target authorized in-scope resources.',
            evidence: {
              request: { method: testSpec.method, url: fullUrl, headers: {} },
              actual: `Scope boundary violation: ${scopeValidation.violations.join('; ')}`,
            },
          });
          assertionsFailedCount++;
          continue;
        }
      }

      const requestHeaders: Record<string, string> = {
        'User-Agent': 'SecurityLab-QA/1.0',
        Accept: 'application/json, text/plain, */*',
        ...input.customHeaders,
        ...authHeaders,
        ...testSpec.headers,
      };

      const reqStartTime = Date.now();
      let res: Response;
      let responseBodyText = '';
      let parsedJson: unknown = null;

      try {
        res = await safeFetch(fullUrl, {
          method: testSpec.method,
          headers: requestHeaders,
          signal: context.abortSignal,
          scope: context.target?.scope,
        });

        responseBodyText = await res.text();
        try {
          parsedJson = JSON.parse(responseBodyText);
        } catch {
          // not JSON, keep as null
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        findings.push({
          title: `Connection Failure: [${testSpec.name}]`,
          category: definition.category,
          severity: 'high',
          description: `Failed to connect or fetch from target URL "${fullUrl}": ${msg}`,
          recommendation: 'Verify the endpoint is reachable, in scope, and responding to HTTP requests.',
          evidence: {
            request: { method: testSpec.method, url: fullUrl, headers: requestHeaders },
            actual: `Network error: ${msg}`,
          },
        });
        assertionsFailedCount++;
        continue;
      }

      const reqDuration = Date.now() - reqStartTime;
      const resHeaders: Record<string, string> = {};
      res.headers.forEach((val, key) => {
        resHeaders[key.toLowerCase()] = val;
      });

      // Data context for assertion evaluation
      const responseData: Record<string, unknown> = {
        status: res.status,
        statusText: res.statusText,
        headers: resHeaders,
        body: parsedJson !== null ? parsedJson : responseBodyText,
        text: responseBodyText,
        durationMs: reqDuration,
      };

      // 1. Expected status code evaluation
      if (testSpec.expectedStatus && testSpec.expectedStatus.length > 0) {
        if (!testSpec.expectedStatus.includes(res.status)) {
          assertionsFailedCount++;
          findings.push({
            title: `Unexpected Status Code: [${testSpec.name}]`,
            category: definition.category,
            severity: 'medium',
            description: `Endpoint returned HTTP ${res.status} (${res.statusText}), expected one of [${testSpec.expectedStatus.join(', ')}].`,
            recommendation: `Check the service endpoint behavior and route implementation at ${testSpec.path}.`,
            evidence: {
              request: { method: testSpec.method, url: fullUrl, headers: requestHeaders },
              response: {
                statusCode: res.status,
                headers: resHeaders,
                body: responseBodyText.slice(0, 1000),
                responseTimeMs: reqDuration,
              },
              expected: testSpec.expectedStatus.join(', '),
              actual: res.status,
            },
          });
        } else {
          assertionsPassedCount++;
        }
      }

      // 2. Assertions evaluation
      for (const assertion of testSpec.assertions) {
        const actualValue = extractFieldValue(responseData, assertion.field);
        const evalResult = evaluateAssertion(assertion, actualValue);

        if (!evalResult.passed) {
          assertionsFailedCount++;
          findings.push({
            title: `Assertion Failed: [${testSpec.name}] ${assertion.field} ${assertion.operator}`,
            category: definition.category,
            severity: assertion.severity,
            description: evalResult.message || `Assertion failed on field "${assertion.field}" using operator "${assertion.operator}".`,
            recommendation: `Ensure ${assertion.field} conforms to the expected test criteria: ${assertion.operator} ${assertion.value ?? ''}.`,
            evidence: {
              request: { method: testSpec.method, url: fullUrl, headers: requestHeaders },
              response: {
                statusCode: res.status,
                headers: resHeaders,
                body: responseBodyText.slice(0, 1000),
                responseTimeMs: reqDuration,
              },
              expected: assertion.value !== undefined ? String(assertion.value) : `${assertion.operator}`,
              actual: actualValue !== undefined ? String(actualValue) : 'undefined',
            },
          });
        } else {
          assertionsPassedCount++;
        }
      }
    }

    metrics.push(
      { name: 'tests_total', value: totalTests, unit: 'count' },
      { name: 'assertions_passed', value: assertionsPassedCount, unit: 'count' },
      { name: 'assertions_failed', value: assertionsFailedCount, unit: 'count' },
      { name: 'execution_duration_ms', value: Date.now() - startTime, unit: 'ms' },
    );

    return {
      engineId: this.id,
      durationMs: Date.now() - startTime,
      success: findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length === 0,
      findings,
      metrics,
      rawOutput: {
        definitionId: definition.id,
        totalTests,
        assertionsPassed: assertionsPassedCount,
        assertionsFailed: assertionsFailedCount,
      },
    };
  }
}
