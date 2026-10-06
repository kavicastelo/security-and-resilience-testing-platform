import {
  TestDefinition,
  TestDefinitionSchema,
  parseTestDefinitionYaml,
  evaluateAssertion,
  extractFieldValue,
  validateUrlAgainstScope,
  interpolateString,
  interpolateValue,
  substitutePathParams,
  extractFromResponse,
} from '@security-lab/domain';
import { TestEngine } from '../engine.js';
import { TestCapability } from '../capability.js';
import { ExecutionContext } from '../context.js';
import { TestInput, TestResult, ValidationResult, RawEngineFinding, RawEngineMetric } from '../result.js';
import { safeFetch } from '../http/index.js';

export class DeclarativeTestEngine implements TestEngine {
  readonly id = 'engine-native-declarative';
  readonly version = '2.0.0';
  readonly executionClass = 'class_a_native' as const;

  capabilities(): TestCapability[] {
    return [
      {
        id: 'declarative_assertions',
        name: 'Declarative YAML HTTP Workflow & Assertion Runner (DSL v2)',
        category: 'protocol_audit',
        description:
          'Executes multi-step declarative YAML test workflows with request bodies, variable extraction, chaining, session cookies, and assertions',
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

    // 1. Initialize Workflow State & Context
    const workflowContext = new Map<string, unknown>();
    const cookieJar = new Map<string, string>();
    const testStatusMap = new Map<string, 'passed' | 'failed' | 'skipped'>();

    // Seed workflow context with target and inputs
    workflowContext.set('targetUrl', baseUrl);
    workflowContext.set('baseUrl', baseUrl);

    if (definition.inputs && typeof definition.inputs === 'object') {
      for (const [k, v] of Object.entries(definition.inputs)) {
        workflowContext.set(k, v);
      }
    }

    if (input.options?.variables && typeof input.options.variables === 'object') {
      for (const [k, v] of Object.entries(input.options.variables as Record<string, unknown>)) {
        workflowContext.set(k, v);
      }
    }

    // Resolve static authentication headers
    const authHeaders: Record<string, string> = {};
    if (definition.authentication?.type === 'bearer') {
      const token =
        (input.options?.authToken as string | undefined) ||
        (definition.authentication.tokenEnvVar ? process.env[definition.authentication.tokenEnvVar] : undefined);
      if (token) {
        authHeaders['Authorization'] = `Bearer ${token}`;
        workflowContext.set('authToken', token);
      }
    } else if (definition.authentication?.type === 'api_key') {
      const keyHeader = definition.authentication.headerName || 'X-API-Key';
      const keyPrefix = definition.authentication.headerValuePrefix ? `${definition.authentication.headerValuePrefix} ` : '';
      const keyVal =
        (input.options?.apiKey as string | undefined) ||
        (definition.authentication.tokenEnvVar ? process.env[definition.authentication.tokenEnvVar] : undefined);
      if (keyVal) {
        authHeaders[keyHeader] = `${keyPrefix}${keyVal}`;
        workflowContext.set('apiKey', keyVal);
      }
    }

    const totalTests = definition.tests.length;

    // 2. Multi-Step Test Workflow Execution Loop
    for (const [i, testSpec] of definition.tests.entries()) {
      if (context.abortSignal.aborted) {
        throw new Error('Test execution aborted by signal');
      }

      const progressPercent = Math.round(((i + 1) / totalTests) * 100);
      context.reportProgress(progressPercent, `Executing test [${testSpec.id}]: ${testSpec.name}`);

      // Check dependsOn constraints
      if (testSpec.dependsOn) {
        const dependencies = Array.isArray(testSpec.dependsOn) ? testSpec.dependsOn : [testSpec.dependsOn];
        const failedDep = dependencies.find((dep) => testStatusMap.get(dep) !== 'passed');
        if (failedDep) {
          testStatusMap.set(testSpec.id, 'skipped');
          findings.push({
            title: `Step Skipped: [${testSpec.name}]`,
            category: definition.category,
            severity: 'info',
            description: `Test step [${testSpec.id}] was skipped because prerequisite dependency "${failedDep}" did not pass (status: ${testStatusMap.get(failedDep) || 'not executed'}).`,
            recommendation: `Ensure dependency step "${failedDep}" succeeds.`,
            evidence: {
              actual: `Dependency "${failedDep}" status: ${testStatusMap.get(failedDep) || 'not executed'}`,
            },
          });
          continue;
        }
      }

      // Path and parameter interpolation
      const resolvedPath = substitutePathParams(testSpec.path, testSpec.pathParams, workflowContext);
      const isAbsolute = resolvedPath.startsWith('http://') || resolvedPath.startsWith('https://');

      let fullUrl = isAbsolute
        ? resolvedPath
        : `${baseUrl}${resolvedPath.startsWith('/') ? '' : '/'}${resolvedPath}`;

      // Query parameters interpolation
      if (testSpec.params && typeof testSpec.params === 'object') {
        try {
          const urlObj = new URL(fullUrl);
          for (const [paramKey, rawParamVal] of Object.entries(testSpec.params)) {
            const resolvedKey = interpolateString(paramKey, workflowContext);
            const resolvedVal = interpolateValue(rawParamVal, workflowContext);
            if (resolvedVal !== undefined && resolvedVal !== null) {
              urlObj.searchParams.append(resolvedKey, String(resolvedVal));
            }
          }
          fullUrl = urlObj.toString();
        } catch {
          // If URL construction fails, continue with fullUrl
        }
      }

      // Enforce strict security boundary: URL must be authorized by target scope
      if (context.target?.scope) {
        const scopeValidation = validateUrlAgainstScope(fullUrl, context.target.scope);
        if (!scopeValidation.valid) {
          findings.push({
            title: `Security Boundary Violation: [${testSpec.name}]`,
            category: definition.category,
            severity: 'critical',
            description: `Test definition specified out-of-scope ${isAbsolute ? 'absolute URL' : 'URL'} "${fullUrl}": ${scopeValidation.violations.join('; ')}`,
            recommendation: 'Ensure all test definition paths target authorized in-scope resources.',
            evidence: {
              request: { method: testSpec.method, url: fullUrl, headers: {} },
              actual: `Scope boundary violation: ${scopeValidation.violations.join('; ')}`,
            },
          });
          assertionsFailedCount++;
          testStatusMap.set(testSpec.id, 'failed');
          continue;
        }
      }

      // Headers interpolation & session cookie injection
      const interpolatedSpecHeaders: Record<string, string> = {};
      if (testSpec.headers && typeof testSpec.headers === 'object') {
        for (const [hKey, hVal] of Object.entries(testSpec.headers)) {
          interpolatedSpecHeaders[interpolateString(hKey, workflowContext)] = interpolateString(
            String(hVal),
            workflowContext,
          );
        }
      }

      const requestHeaders: Record<string, string> = {
        'User-Agent': 'SecurityLab-QA/1.0',
        Accept: 'application/json, text/plain, */*',
        ...input.customHeaders,
        ...authHeaders,
        ...interpolatedSpecHeaders,
      };

      // Inject session cookies from jar if not explicitly overridden
      if (cookieJar.size > 0 && !requestHeaders['cookie'] && !requestHeaders['Cookie']) {
        const cookieString = Array.from(cookieJar.entries())
          .map(([name, val]) => `${name}=${val}`)
          .join('; ');
        requestHeaders['Cookie'] = cookieString;
      }

      // Request body serialization
      let bodyPayload: string | undefined;
      const canHaveBody = testSpec.method !== 'GET' && testSpec.method !== 'HEAD';

      if (canHaveBody && testSpec.body !== undefined && testSpec.body !== null) {
        const interpolatedBody = interpolateValue(testSpec.body, workflowContext);

        const explicitContentType =
          testSpec.contentType ||
          requestHeaders['Content-Type'] ||
          requestHeaders['content-type'];

        if (explicitContentType) {
          if (explicitContentType.includes('application/json')) {
            bodyPayload =
              typeof interpolatedBody === 'string'
                ? interpolatedBody
                : JSON.stringify(interpolatedBody);
          } else if (explicitContentType.includes('application/x-www-form-urlencoded')) {
            if (typeof interpolatedBody === 'object' && interpolatedBody !== null) {
              bodyPayload = new URLSearchParams(
                interpolatedBody as Record<string, string>,
              ).toString();
            } else {
              bodyPayload = String(interpolatedBody);
            }
          } else {
            bodyPayload = typeof interpolatedBody === 'string' ? interpolatedBody : JSON.stringify(interpolatedBody);
          }
          requestHeaders['Content-Type'] = explicitContentType;
        } else {
          // Default: if object/array, serialize as JSON; else as text
          if (typeof interpolatedBody === 'object' && interpolatedBody !== null) {
            bodyPayload = JSON.stringify(interpolatedBody);
            requestHeaders['Content-Type'] = 'application/json';
          } else {
            bodyPayload = String(interpolatedBody);
            requestHeaders['Content-Type'] = 'text/plain';
          }
        }
      }

      const reqStartTime = Date.now();
      let res: Response;
      let responseBodyText = '';
      let parsedJson: unknown = null;

      try {
        res = await safeFetch(fullUrl, {
          method: testSpec.method,
          headers: requestHeaders,
          body: bodyPayload,
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
        testStatusMap.set(testSpec.id, 'failed');
        continue;
      }

      const reqDuration = Date.now() - reqStartTime;
      const resHeaders: Record<string, string> = {};
      res.headers.forEach((val, key) => {
        resHeaders[key.toLowerCase()] = val;
      });

      // 3. Harvest Session Cookies
      let rawSetCookies: string[] = [];
      const headersAny = res.headers as unknown as {
        getSetCookie?: () => string[];
        raw?: () => Record<string, string[]>;
      };
      if (typeof headersAny.getSetCookie === 'function') {
        rawSetCookies = headersAny.getSetCookie();
      } else if (typeof headersAny.raw === 'function' && headersAny.raw()['set-cookie']) {
        rawSetCookies = headersAny.raw()['set-cookie'] || [];
      } else {
        const sc = res.headers.get('set-cookie');
        if (sc) {
          rawSetCookies = [sc];
        }
      }

      for (const cookieHeader of rawSetCookies) {
        const cookies = cookieHeader.split(/,(?=[a-zA-Z0-9_.-]+=)/);
        for (const cookieStr of cookies) {
          const mainPart = cookieStr.split(';')[0]?.trim();
          if (mainPart && mainPart.includes('=')) {
            const [cName, ...cValParts] = mainPart.split('=');
            if (cName) {
              cookieJar.set(cName.trim(), cValParts.join('=').trim());
            }
          }
        }
      }

      // Assemble Data context for assertion evaluation and variable extraction
      const responseData: Record<string, unknown> = {
        status: res.status,
        statusText: res.statusText,
        headers: resHeaders,
        body: parsedJson !== null ? parsedJson : responseBodyText,
        text: responseBodyText,
        durationMs: reqDuration,
      };

      // 4. Response Variable Extraction
      if (testSpec.extract && testSpec.extract.length > 0) {
        for (const rule of testSpec.extract) {
          const extractedValue = extractFromResponse(responseData, rule);
          if (extractedValue !== undefined) {
            workflowContext.set(rule.as, extractedValue);
            context.logger?.debug({ var: rule.as, value: extractedValue }, 'Variable extracted from response');
          }
        }
      }

      let stepPassed = true;

      // 5. Expected status code evaluation
      if (testSpec.expectedStatus && testSpec.expectedStatus.length > 0) {
        if (!testSpec.expectedStatus.includes(res.status)) {
          stepPassed = false;
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

      // 6. Assertions evaluation
      for (const assertion of testSpec.assertions) {
        const actualValue = extractFieldValue(responseData, assertion.field);
        const resolvedExpectedValue = interpolateValue(assertion.value, workflowContext);
        const evalResult = evaluateAssertion(
          { ...assertion, value: resolvedExpectedValue },
          actualValue,
        );

        if (!evalResult.passed) {
          stepPassed = false;
          assertionsFailedCount++;
          findings.push({
            title: `Assertion Failed: [${testSpec.name}] ${assertion.field} ${assertion.operator}`,
            category: definition.category,
            severity: assertion.severity,
            description:
              evalResult.message ||
              `Assertion failed on field "${assertion.field}" using operator "${assertion.operator}".`,
            recommendation: `Ensure ${assertion.field} conforms to the expected test criteria: ${assertion.operator} ${assertion.value ?? ''}.`,
            evidence: {
              request: { method: testSpec.method, url: fullUrl, headers: requestHeaders },
              response: {
                statusCode: res.status,
                headers: resHeaders,
                body: responseBodyText.slice(0, 1000),
                responseTimeMs: reqDuration,
              },
              expected: resolvedExpectedValue !== undefined ? String(resolvedExpectedValue) : `${assertion.operator}`,
              actual: actualValue !== undefined ? String(actualValue) : 'undefined',
            },
          });
        } else {
          assertionsPassedCount++;
        }
      }

      testStatusMap.set(testSpec.id, stepPassed ? 'passed' : 'failed');
    }

    metrics.push(
      { name: 'tests_total', value: totalTests, unit: 'count' },
      { name: 'assertions_passed', value: assertionsPassedCount, unit: 'count' },
      { name: 'assertions_failed', value: assertionsFailedCount, unit: 'count' },
      { name: 'variables_extracted', value: workflowContext.size, unit: 'count' },
      { name: 'execution_duration_ms', value: Date.now() - startTime, unit: 'ms' },
    );

    return {
      engineId: this.id,
      durationMs: Date.now() - startTime,
      success:
        assertionsFailedCount === 0 &&
        findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length === 0,
      findings,
      metrics,
      rawOutput: {
        definitionId: definition.id,
        totalTests,
        assertionsPassed: assertionsPassedCount,
        assertionsFailed: assertionsFailedCount,
        extractedVariables: Object.fromEntries(workflowContext.entries()),
      },
    };
  }
}
