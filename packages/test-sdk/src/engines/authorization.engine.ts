import {
  AuthorizationTestSuite,
  AuthorizationTestSuiteSchema,
  parseAuthorizationTestSuiteYaml,
} from '@security-lab/domain';
import { TestEngine } from '../engine.js';
import { TestCapability } from '../capability.js';
import { ExecutionContext } from '../context.js';
import { TestInput, TestResult, ValidationResult, RawEngineFinding, RawEngineMetric } from '../result.js';
import { safeFetch } from '../http/index.js';
import {
  generateAuthorizationPermutations,
  buildIdentityHeaders,
  isSuccessfulAuthorizedResponse,
} from './authorization/permutation-runner.js';

export class AuthorizationSecurityEngine implements TestEngine {
  readonly id = 'engine-native-authorization';
  readonly version = '1.0.0';
  readonly executionClass = 'class_a_native' as const;

  capabilities(): TestCapability[] {
    return [
      {
        id: 'bola_horizontal_idor',
        name: 'Broken Object Level Authorization (BOLA/IDOR)',
        category: 'protocol_audit',
        description:
          'Tests cross-user object access by replaying requests with unauthorized user identities against private resource IDs.',
        isDisruptive: false,
      },
      {
        id: 'bfla_vertical_escalation',
        name: 'Broken Function Level Authorization (BFLA)',
        category: 'protocol_audit',
        description:
          'Tests vertical privilege escalation by dispatching unprivileged user identities against administrative routes.',
        isDisruptive: false,
      },
      {
        id: 'auth_missing_control',
        name: 'Missing Access Control Audit',
        category: 'passive_analysis',
        description:
          'Verifies that protected routes reject unauthenticated requests with HTTP 401 or 403.',
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

    const hasYaml = typeof input.options?.yaml === 'string' && input.options.yaml.trim().length > 0;
    const hasSuite = input.options?.suite !== undefined && typeof input.options.suite === 'object';

    if (!hasYaml && !hasSuite) {
      errors.push({
        path: 'options',
        message: 'Missing authorization suite specification in options (options.suite or options.yaml required)',
      });
    }

    return {
      valid: errors.length === 0,
      errors: errors.length > 0 ? errors : undefined,
    };
  }

  async execute(input: TestInput, context: ExecutionContext): Promise<TestResult> {
    const startTime = Date.now();
    let suite: AuthorizationTestSuite;

    try {
      if (input.options?.yaml && typeof input.options.yaml === 'string') {
        suite = parseAuthorizationTestSuiteYaml(input.options.yaml);
      } else if (input.options?.suite) {
        suite = AuthorizationTestSuiteSchema.parse(input.options.suite);
      } else {
        throw new Error('Missing authorization test suite in options');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        engineId: this.id,
        durationMs: Date.now() - startTime,
        success: false,
        findings: [],
        metrics: [],
        error: `Failed to load authorization suite: ${msg}`,
      };
    }

    const findings: RawEngineFinding[] = [];
    const metrics: RawEngineMetric[] = [];
    let bolaCount = 0;
    let bflaCount = 0;
    let missingAuthCount = 0;

    // Generate permutation matrix
    const permutations = generateAuthorizationPermutations(suite, input.targetUrl);
    const totalPermutations = permutations.length;

    // Map to retain baseline responses from owners
    const baselineResults = new Map<string, { status: number; bodySnippet: string }>();

    // 1. First pass: run baseline owner permutations to confirm legitimate access
    const baselinePerms = permutations.filter((p) => p.permutationType === 'baseline_owner');
    const attackPerms = permutations.filter((p) => p.permutationType !== 'baseline_owner');

    let completedPermutations = 0;

    for (const perm of baselinePerms) {
      if (context.abortSignal.aborted) {
        throw new Error('Authorization test aborted by signal');
      }

      completedPermutations++;
      context.reportProgress(
        Math.round((completedPermutations / totalPermutations) * 100),
        `Baseline access check: ${perm.description}`,
      );

      const requestHeaders = buildIdentityHeaders(perm.identity, input.customHeaders);

      try {
        const res = await safeFetch(perm.targetUrl, {
          method: perm.method,
          headers: requestHeaders,
          body: perm.body ? JSON.stringify(perm.body) : undefined,
          signal: context.abortSignal,
          scope: context.target?.scope,
        });

        const bodyText = await res.text();
        const key = perm.resource ? perm.resource.id : perm.resolvedPath;
        baselineResults.set(key, { status: res.status, bodySnippet: bodyText.slice(0, 500) });
      } catch (err: unknown) {
        context.logger?.debug({ err, permId: perm.id }, 'Baseline owner request failed');
      }
    }

    // 2. Second pass: run attack permutations (horizontal BOLA, vertical BFLA, and unauthenticated access)
    for (const perm of attackPerms) {
      if (context.abortSignal.aborted) {
        throw new Error('Authorization test aborted by signal');
      }

      completedPermutations++;
      context.reportProgress(
        Math.round((completedPermutations / totalPermutations) * 100),
        `Executing permutation: ${perm.description}`,
      );

      const requestHeaders = buildIdentityHeaders(perm.identity, input.customHeaders);
      let res: Response;
      let bodyText = '';

      try {
        res = await safeFetch(perm.targetUrl, {
          method: perm.method,
          headers: requestHeaders,
          body: perm.body ? JSON.stringify(perm.body) : undefined,
          signal: context.abortSignal,
          scope: context.target?.scope,
        });

        bodyText = await res.text();
      } catch (err: unknown) {
        context.logger?.debug({ err, permId: perm.id }, 'Authorization probe connection error');
        continue;
      }

      const resHeaders: Record<string, string> = {};
      res.headers.forEach((val, k) => {
        resHeaders[k.toLowerCase()] = val;
      });

      // Evaluation: if access should be denied, but server returned 2xx OK with legitimate data
      const isBreached =
        perm.expectedAccess === 'DENY' && isSuccessfulAuthorizedResponse(res.status, bodyText);

      if (isBreached) {
        const bodySnippet = bodyText.slice(0, 1000);
        const baseline = perm.resource ? baselineResults.get(perm.resource.id) : undefined;
        const authHeaderVal = requestHeaders['Authorization'] || '[NONE]';
        const curlCmd = `curl -X ${perm.method} "${perm.targetUrl}" -H "Authorization: ${authHeaderVal}"`;

        if (perm.permutationType === 'horizontal_bola') {
          bolaCount++;
          findings.push({
            title: `Critical Vulnerability: BOLA / IDOR on [${perm.method} ${perm.resolvedPath}]`,
            category: 'authorization',
            severity: 'critical',
            description: `Identity "${perm.identity.name}" (ID: "${perm.identity.id}") successfully accessed private ${perm.resource?.resourceType || 'resource'} "${perm.resource?.id}" owned by "${perm.ownerIdentity?.name || perm.resource?.ownerIdentityId}". The endpoint returned HTTP ${res.status} OK without verifying object ownership.`,
            recommendation:
              'Enforce strict object-level access controls: verify that the authenticated identity is authorized to access the specific requested object ID before returning data.',
            evidence: {
              request: {
                method: perm.method,
                url: perm.targetUrl,
                headers: requestHeaders,
              },
              response: {
                statusCode: res.status,
                headers: resHeaders,
                body: bodySnippet,
              },
              expected: `HTTP ${perm.expectedStatusCodes.join(' or ')} (Access Denied for non-owner)`,
              actual: `HTTP ${res.status} OK (Private resource returned to unauthorized identity)`,
            },
            metadata: {
              vulnerabilityType: 'BOLA_IDOR',
              ruleId: perm.ruleId,
              attackerIdentity: perm.identity.id,
              ownerIdentity: perm.ownerIdentity?.id,
              resourceId: perm.resource?.id,
              reproducibleCurl: curlCmd,
              baselineOwnerStatus: baseline?.status,
            },
          });
        } else if (perm.permutationType === 'vertical_bfla') {
          bflaCount++;
          findings.push({
            title: `Critical Vulnerability: BFLA Vertical Privilege Escalation on [${perm.method} ${perm.resolvedPath}]`,
            category: 'authorization',
            severity: 'critical',
            description: `Unprivileged identity "${perm.identity.name}" (role: "${perm.identity.role}") accessed restricted function "${perm.resolvedPath}". Expected allowed roles: [${perm.expectedStatusCodes.join(', ')}]. The endpoint returned HTTP ${res.status} OK.`,
            recommendation:
              'Enforce role-based and function-level access control: check the user role and permissions in authorization middleware before processing administrative actions.',
            evidence: {
              request: {
                method: perm.method,
                url: perm.targetUrl,
                headers: requestHeaders,
              },
              response: {
                statusCode: res.status,
                headers: resHeaders,
                body: bodySnippet,
              },
              expected: `HTTP ${perm.expectedStatusCodes.join(' or ')} (Access Denied for role "${perm.identity.role}")`,
              actual: `HTTP ${res.status} OK (Privileged operation executed by unprivileged role)`,
            },
            metadata: {
              vulnerabilityType: 'BFLA_VERTICAL_ESCALATION',
              ruleId: perm.ruleId,
              identityId: perm.identity.id,
              role: perm.identity.role,
              reproducibleCurl: curlCmd,
            },
          });
        } else if (perm.permutationType === 'unauthenticated_access') {
          missingAuthCount++;
          findings.push({
            title: `Vulnerability: Missing Authentication / Access Control on [${perm.method} ${perm.resolvedPath}]`,
            category: 'authorization',
            severity: 'high',
            description: `An anonymous unauthenticated request successfully accessed protected route "${perm.resolvedPath}". The endpoint returned HTTP ${res.status} OK without requiring valid credentials.`,
            recommendation:
              'Require authentication on all private API endpoints and reject unauthenticated requests with HTTP 401 Unauthorized.',
            evidence: {
              request: {
                method: perm.method,
                url: perm.targetUrl,
                headers: requestHeaders,
              },
              response: {
                statusCode: res.status,
                headers: resHeaders,
                body: bodySnippet,
              },
              expected: 'HTTP 401 Unauthorized or 403 Forbidden',
              actual: `HTTP ${res.status} OK (Protected resource returned to anonymous caller)`,
            },
            metadata: {
              vulnerabilityType: 'MISSING_AUTHENTICATION_CONTROL',
              ruleId: perm.ruleId,
              reproducibleCurl: curlCmd,
            },
          });
        }
      }
    }

    metrics.push(
      { name: 'authz_permutations_total', value: totalPermutations, unit: 'count' },
      { name: 'authz_violations_total', value: findings.length, unit: 'count' },
      { name: 'authz_bola_violations', value: bolaCount, unit: 'count' },
      { name: 'authz_bfla_violations', value: bflaCount, unit: 'count' },
      { name: 'authz_missing_auth_violations', value: missingAuthCount, unit: 'count' },
      { name: 'execution_duration_ms', value: Date.now() - startTime, unit: 'ms' },
    );

    return {
      engineId: this.id,
      durationMs: Date.now() - startTime,
      success: findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length === 0,
      findings,
      metrics,
      rawOutput: {
        suiteId: suite.id,
        totalPermutations,
        findingsCount: findings.length,
        bolaCount,
        bflaCount,
        missingAuthCount,
      },
    };
  }
}
