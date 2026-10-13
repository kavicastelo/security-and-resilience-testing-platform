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
  dynamicWorkerEngineRegistry,
} from '@security-lab/engine-sdk';
import { validateUrlAgainstScope } from '@security-lab/domain';
import { redactHeaders, REDACTED_VALUE } from '@security-lab/crypto';
import { createLogger } from '@security-lab/logger';
import { AuthzMatrixOptions, ComparisonResult } from './types.js';
import { generateAuthzMatrixPermutations, DEFAULT_SYNTHETIC_PERSONAS } from './permutator.js';
import { evaluateAuthzResponse } from './comparator.js';
import { buildMatrixReport } from './matrix-reporter.js';

export * from './types.js';
export * from './permutator.js';
export * from './comparator.js';
export * from './matrix-reporter.js';

const logger = createLogger({ name: 'engine-authz-matrix' });

export class AuthzMatrixEngine implements TestEngine {
  readonly id = 'engine-authz-matrix';
  readonly version = '1.0.0';
  readonly executionClass = 'class_a_native' as const;

  capabilities(): TestCapability[] {
    return [
      {
        id: 'bola_horizontal_idor',
        name: 'Automated Broken Object-Level Authorization (BOLA/IDOR) Matrix',
        category: 'protocol_audit',
        description: 'Permutes resource identifiers across multiple authenticated user personas to detect horizontal unauthorized data access and cross-tenant leakage.',
        isDisruptive: false,
      },
      {
        id: 'bfla_vertical_escalation',
        name: 'Broken Function-Level Authorization (BFLA) Escalation Matrix',
        category: 'protocol_audit',
        description: 'Replays administrative and privileged functional endpoints using low-privilege user personas to detect missing function-level access controls.',
        isDisruptive: false,
      },
      {
        id: 'auth_missing_control',
        name: 'Unauthenticated Route Access Boundary Audit',
        category: 'passive_analysis',
        description: 'Asserts all declared private routes enforce authentication and reject anonymous guest requests with HTTP 401 or 403.',
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
    const options = (input.options || {}) as AuthzMatrixOptions;
    const scope = context.target?.scope;

    // 1. Target Scope Boundary Enforcement
    if (scope) {
      const scopeCheck = validateUrlAgainstScope(input.targetUrl, scope);
      if (!scopeCheck.valid) {
        return {
          engineId: this.id,
          durationMs: Date.now() - startTime,
          success: false,
          findings: [],
          metrics: [],
          error: `Target URL "${input.targetUrl}" violates security scope: ${scopeCheck.violations.join('; ')}`,
        };
      }
    }

    logger.info({ targetUrl: input.targetUrl }, 'Generating authorization permutation matrix');

    // 2. Generate Permutation Matrix
    const { testCases, routesCount, parameterizedRoutesCount, privilegedRoutesCount } =
      generateAuthzMatrixPermutations(input.targetUrl, options);

    if (testCases.length === 0) {
      logger.warn('No routes or test cases generated from input spec/routes');
      return {
        engineId: this.id,
        durationMs: Date.now() - startTime,
        success: true,
        findings: [],
        metrics: [
          { name: 'authz_routes_scanned', value: 0, unit: 'count' },
          { name: 'authz_permutations_total', value: 0, unit: 'count' },
        ],
      };
    }

    const findings: RawEngineFinding[] = [];
    const executionResults = new Map<string, { status: number; comp: ComparisonResult }>();
    const concurrency = Math.max(1, Math.min(10, options.concurrency ?? 5));
    const timeoutMs = options.timeoutMs ?? 10000;

    let bolaViolations = 0;
    let bflaViolations = 0;
    let missingAuthViolations = 0;

    // 3. Concurrency-Controlled Matrix Execution
    for (let i = 0; i < testCases.length; i += concurrency) {
      const batch = testCases.slice(i, i + concurrency);
      await Promise.all(
        batch.map(async (tc) => {
          const reqHeaders: Record<string, string> = {
            Accept: 'application/json',
            ...(tc.actorPersona.headers ?? {}),
          };

          if (tc.actorPersona.token && !reqHeaders['Authorization'] && !reqHeaders['authorization']) {
            reqHeaders['Authorization'] = `Bearer ${tc.actorPersona.token}`;
          }

          let responseStatus = 0;
          let responseText = '';
          const responseHeadersObj: Record<string, string> = {};

          try {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), timeoutMs);

            const res = await safeFetch(tc.url, {
              method: tc.method,
              headers: reqHeaders,
              scope,
              signal: controller.signal,
            });
            clearTimeout(timer);

            responseStatus = res.status;
            res.headers.forEach((v, k) => {
              responseHeadersObj[k] = v;
            });
            responseText = await res.text().catch(() => '');
          } catch (err: any) {
            responseStatus = 0;
            responseText = err?.message || 'Connection failure';
          }

          // Evaluate response
          const comp = evaluateAuthzResponse(tc, responseStatus, responseText);
          executionResults.set(tc.id, { status: responseStatus, comp });

          if (comp.isViolation) {
            if (comp.violationType === 'BOLA_HORIZONTAL_IDOR') bolaViolations++;
            if (comp.violationType === 'BFLA_VERTICAL_ESCALATION') bflaViolations++;
            if (comp.violationType === 'MISSING_AUTHENTICATION') missingAuthViolations++;

            const curlAuthHeader = reqHeaders['Authorization']
              ? `-H "Authorization: ${REDACTED_VALUE}"`
              : '';
            const curlCmd = `curl -i -X ${tc.method} "${tc.url}" ${curlAuthHeader}`.trim();

            const findingTitle = comp.violationType === 'BOLA_HORIZONTAL_IDOR'
              ? `Broken Object Level Authorization (BOLA/IDOR) on ${tc.method} ${tc.endpointPath}`
              : comp.violationType === 'BFLA_VERTICAL_ESCALATION'
              ? `Broken Function Level Authorization (BFLA) on ${tc.method} ${tc.endpointPath}`
              : `Missing Authentication Control on ${tc.method} ${tc.endpointPath}`;

            const remediationAdvice = comp.violationType === 'BOLA_HORIZONTAL_IDOR'
              ? 'Validate user ownership or tenant authorization in the handler/resolver before returning resource data or mutating state.'
              : comp.violationType === 'BFLA_VERTICAL_ESCALATION'
              ? 'Enforce administrative role-based access control (RBAC) middleware on privileged paths.'
              : 'Require valid session tokens or API keys for all non-public routes.';

            const vType = comp.violationType || 'BOLA_HORIZONTAL_IDOR';
            findings.push({
              title: findingTitle,
              description: comp.reason,
              severity: comp.severity.toLowerCase() as any,
              category: 'authorization',
              recommendation: remediationAdvice,
              evidence: {
                request: {
                  url: tc.url,
                  method: tc.method,
                  headers: redactHeaders(reqHeaders),
                },
                response: {
                  statusCode: responseStatus,
                  headers: redactHeaders(responseHeadersObj),
                  body: responseText.slice(0, 500),
                },
                metadata: {
                  actorPersona: tc.actorPersona.id,
                  actorRole: tc.actorPersona.role,
                  ownerPersona: tc.ownerPersona?.id,
                  targetResourceId: tc.targetResourceId,
                  curlCommand: curlCmd,
                },
              },
              metadata: {
                ruleId: `authz-${vType.toLowerCase().replace(/_/g, '-')}`,
                violationType: vType,
                endpoint: tc.endpointPath,
                method: tc.method,
                actorPersonaId: tc.actorPersona.id,
                targetResourceId: tc.targetResourceId,
                curlCommand: curlCmd,
              },
            });
          }
        }),
      );
    }

    // 4. Construct Matrix Report
    const report = buildMatrixReport(
      input.targetUrl,
      testCases,
      executionResults,
      options.personas ?? DEFAULT_SYNTHETIC_PERSONAS,
    );

    logger.info({ reportTable: report.markdownTable }, 'Generated authorization matrix report');

    logger.info(
      {
        routesCount,
        parameterizedRoutesCount,
        privilegedRoutesCount,
        totalTests: testCases.length,
        violations: findings.length,
        bolaViolations,
        bflaViolations,
      },
      'Authorization matrix evaluation completed',
    );

    const metrics: RawEngineMetric[] = [
      { name: 'authz_routes_scanned', value: routesCount, unit: 'count' },
      { name: 'authz_permutations_total', value: testCases.length, unit: 'count' },
      { name: 'authz_violations_count', value: findings.length, unit: 'count' },
      { name: 'authz_bola_violations', value: bolaViolations, unit: 'count' },
      { name: 'authz_bfla_violations', value: bflaViolations, unit: 'count' },
      { name: 'authz_missing_auth_violations', value: missingAuthViolations, unit: 'count' },
    ];

    return {
      engineId: this.id,
      durationMs: Date.now() - startTime,
      success: true,
      findings,
      metrics,
    };
  }
}

export const authzMatrixEngine = new AuthzMatrixEngine();
try {
  dynamicWorkerEngineRegistry.register(authzMatrixEngine);
} catch {
  // Ignore if already registered
}
export default authzMatrixEngine;

