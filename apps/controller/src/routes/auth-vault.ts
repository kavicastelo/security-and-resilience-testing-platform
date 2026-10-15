import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { StatefulAuthService } from '@security-lab/test-runner';
import { validateUrlAgainstScope } from '@security-lab/domain';
import { requireEngineer } from '../plugins/rbac.js';
import { extractTenantScope } from '../services/tenant-context.js';
import { targetsService } from '../services/targets.service.js';
import { logger } from '@security-lab/logger';

const AuthStepSchema = z.object({
  name: z.string().optional(),
  url: z.string(),
  method: z.string().default('GET'),
  headers: z.record(z.string()).optional(),
  body: z.union([z.string(), z.record(z.unknown())]).optional(),
  extract: z
    .array(
      z.object({
        from: z.enum(['BODY_JSON', 'BODY_REGEX', 'HEADER', 'COOKIE']),
        key: z.string(),
        saveAs: z.string(),
      }),
    )
    .optional(),
});

const OAuth2ConfigSchema = z.object({
  grantType: z.string().default('client_credentials'),
  tokenUrl: z.string(),
  clientId: z.string().optional().default(''),
  clientSecret: z.string().optional().default(''),
  username: z.string().optional(),
  password: z.string().optional(),
  scope: z.string().optional(),
  audience: z.string().optional(),
});

const CsrfConfigSchema = z.object({
  tokenUrl: z.string().optional(),
  paramName: z.string().optional(),
  headerName: z.string().optional(),
  regexPattern: z.string().optional(),
  jsonPath: z.string().optional(),
});

const VerifyFlowRequestSchema = z.object({
  targetId: z.string(),
  targetUrl: z.string().optional(),
  flow: z.object({
    type: z.enum(['OAUTH2', 'FORM', 'API_KEY', 'BEARER', 'MTLS']),
    loginUrl: z.string().optional(),
    totpSecret: z.string().optional(),
    tokenExtractionPath: z.string().optional(),
    credentials: z.record(z.string()).optional(),
    headers: z.record(z.string()).optional(),
    oauth2Config: OAuth2ConfigSchema.optional(),
    csrfConfig: CsrfConfigSchema.optional(),
    steps: z.array(AuthStepSchema).optional(),
  }),
});

export interface FlowVerificationStepLog {
  stepIndex: number;
  name: string;
  url: string;
  method: string;
  statusCode: number;
  durationMs: number;
  extractedVariables?: Record<string, string>;
  error?: string;
}

export const authVaultRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // Handler for flow verification
  const handleVerifyFlow = async (request: any, reply: any) => {
    const parsed = VerifyFlowRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: parsed.error.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join(', '),
        },
      });
    }

    const { targetId, targetUrl, flow } = parsed.data;
    const tenantId = extractTenantScope(request);

    // 1. Resolve Target and Target Scope
    let target = await targetsService.getTargetById(targetId, tenantId);

    // If target not found by ID but ad-hoc targetUrl or URL-based ID is provided, create transient target for testing
    if (!target && (targetUrl || targetId.startsWith('http://') || targetId.startsWith('https://'))) {
      const resolvedUrl = targetUrl || targetId;
      let hostname = '*';
      try {
        hostname = new URL(resolvedUrl).hostname;
      } catch {}
      target = {
        id: targetId,
        projectId: 'transient',
        name: 'Transient Auth Target',
        baseUrl: resolvedUrl,
        scope: {
          allowedHosts: [hostname, 'localhost', '127.0.0.1', '*'],
          allowedPorts: [80, 443, 8080, 8443, 3000, 4000, 5000, 9000],
          allowPrivateIps: true,
          excludedPaths: [],
          testing: { activeScanning: true, loadTesting: true, chaosTesting: true },
          limits: { maxRps: 100, maxConcurrency: 50, maxDuration: '10m' },
        },
        verificationStatus: 'VERIFIED',
        verificationMethod: 'AUTO',
        createdAt: new Date(),
        updatedAt: new Date(),
      } as any;
    }

    if (!target) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'TARGET_NOT_FOUND',
          message: `Target with ID "${targetId}" not found in current tenant workspace`,
        },
      });
    }

    // 2. Pre-flight SSRF Scope Boundary Validation
    // Validate target base URL
    const baseScopeCheck = validateUrlAgainstScope(target.baseUrl, target.scope);
    if (!baseScopeCheck.valid) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'SSRF_SCOPE_VIOLATION',
          message: `Target base URL "${target.baseUrl}" violates defined scope: ${baseScopeCheck.violations.join('; ')}`,
        },
      });
    }

    // Validate OAuth2 token URL
    if (flow.type === 'OAUTH2' && flow.oauth2Config?.tokenUrl) {
      const fullTokenUrl = flow.oauth2Config.tokenUrl.startsWith('http')
        ? flow.oauth2Config.tokenUrl
        : new URL(flow.oauth2Config.tokenUrl, target.baseUrl).toString();

      const scopeCheck = validateUrlAgainstScope(fullTokenUrl, target.scope);
      if (!scopeCheck.valid) {
        return reply.status(400).send({
          success: false,
          error: {
            code: 'SSRF_SCOPE_VIOLATION',
            message: `OAuth2 tokenUrl "${fullTokenUrl}" violates target scope boundaries: ${scopeCheck.violations.join('; ')}`,
          },
        });
      }
    }

    // Validate Form Login URL and Steps
    if (flow.type === 'FORM') {
      if (flow.loginUrl) {
        const fullLoginUrl = flow.loginUrl.startsWith('http')
          ? flow.loginUrl
          : new URL(flow.loginUrl, target.baseUrl).toString();

        const scopeCheck = validateUrlAgainstScope(fullLoginUrl, target.scope);
        if (!scopeCheck.valid) {
          return reply.status(400).send({
            success: false,
            error: {
              code: 'SSRF_SCOPE_VIOLATION',
              message: `Form loginUrl "${fullLoginUrl}" violates target scope boundaries: ${scopeCheck.violations.join('; ')}`,
            },
          });
        }
      }

      if (flow.steps && flow.steps.length > 0) {
        for (const step of flow.steps) {
          const fullStepUrl = step.url.startsWith('http')
            ? step.url
            : new URL(step.url, target.baseUrl).toString();

          const scopeCheck = validateUrlAgainstScope(fullStepUrl, target.scope);
          if (!scopeCheck.valid) {
            return reply.status(400).send({
              success: false,
              error: {
                code: 'SSRF_SCOPE_VIOLATION',
                message: `Step URL "${fullStepUrl}" violates target scope boundaries: ${scopeCheck.violations.join('; ')}`,
              },
            });
          }
        }
      }
    }

    // 3. Normalize Flow URLs to absolute URLs
    const normalizedFlow: any = {
      ...flow,
    };

    if (flow.oauth2Config) {
      normalizedFlow.oauth2Config = {
        ...flow.oauth2Config,
        tokenUrl: flow.oauth2Config.tokenUrl.startsWith('http')
          ? flow.oauth2Config.tokenUrl
          : new URL(flow.oauth2Config.tokenUrl, target.baseUrl).toString(),
      };
    }

    if (flow.loginUrl) {
      normalizedFlow.loginUrl = flow.loginUrl.startsWith('http')
        ? flow.loginUrl
        : new URL(flow.loginUrl, target.baseUrl).toString();
    }

    if (flow.steps && flow.steps.length > 0) {
      normalizedFlow.steps = flow.steps.map((step) => ({
        ...step,
        url: step.url.startsWith('http')
          ? step.url
          : new URL(step.url, target!.baseUrl).toString(),
      }));
    }

    // 4. Server-Side Execution with Request Instrumentation
    const startTime = Date.now();
    const stepsExecuted: FlowVerificationStepLog[] = [];

    const instrumentedFetch: typeof fetch = async (input, init) => {
      const stepStart = Date.now();
      let reqUrl = typeof input === 'string' ? input : (input as Request).url;
      if (!reqUrl.startsWith('http://') && !reqUrl.startsWith('https://')) {
        reqUrl = new URL(reqUrl, target!.baseUrl).toString();
      }

      // Pre-flight SSRF check inside fetch to catch dynamically resolved URLs
      const scopeCheck = validateUrlAgainstScope(reqUrl, target!.scope);
      if (!scopeCheck.valid) {
        const errorMsg = `SSRF block: URL "${reqUrl}" is forbidden: ${scopeCheck.violations.join('; ')}`;
        stepsExecuted.push({
          stepIndex: stepsExecuted.length + 1,
          name: `${init?.method || 'POST'} ${reqUrl}`,
          url: reqUrl,
          method: init?.method || 'POST',
          statusCode: 0,
          durationMs: 0,
          error: errorMsg,
        });
        throw new Error(errorMsg);
      }

      const method = init?.method || 'GET';
      const matchingStep = flow.steps?.find((s) => s.url === reqUrl || reqUrl.endsWith(s.url));
      const stepName =
        matchingStep?.name ||
        (flow.type === 'OAUTH2' ? 'OAuth2 Token Grant Request' : `${method} ${new URL(reqUrl).pathname}`);

      try {
        const res = await globalThis.fetch(reqUrl, init);
        const durationMs = Date.now() - stepStart;
        stepsExecuted.push({
          stepIndex: stepsExecuted.length + 1,
          name: stepName,
          url: reqUrl,
          method,
          statusCode: res.status,
          durationMs,
        });
        return res;
      } catch (err: any) {
        const durationMs = Date.now() - stepStart;
        stepsExecuted.push({
          stepIndex: stepsExecuted.length + 1,
          name: stepName,
          url: reqUrl,
          method,
          statusCode: 0,
          durationMs,
          error: err.message || 'Connection failed',
        });
        throw err;
      }
    };

    let finalSuccess = false;
    let finalError: string | undefined;
    let sessionState: any = null;

    try {
      const authenticator = new StatefulAuthService({
        flow: normalizedFlow,
        customFetch: instrumentedFetch,
      });

      sessionState = await authenticator.refreshSession();

      if (flow.type === 'API_KEY' || flow.type === 'BEARER' || flow.type === 'MTLS') {
        // For static tokens, issue probe request to target baseUrl with active auth headers
        const probeHeaders = authenticator.getHeaders();
        const probeRes = await instrumentedFetch(target.baseUrl, {
          method: 'GET',
          headers: probeHeaders,
        });

        if (probeRes.ok) {
          finalSuccess = true;
        } else {
          finalSuccess = false;
          finalError = `Static auth probe failed with HTTP ${probeRes.status}: ${probeRes.statusText}`;
        }
      } else {
        // For FORM or OAUTH2 flows, ensure no steps failed
        const hasFailedStep = stepsExecuted.some((s) => s.statusCode >= 400 || s.statusCode === 0);
        if (hasFailedStep) {
          finalSuccess = false;
          const failed = stepsExecuted.find((s) => s.statusCode >= 400 || s.statusCode === 0);
          finalError = failed?.error || `Authentication step failed with HTTP ${failed?.statusCode || 500}`;
        } else {
          finalSuccess = true;
        }
      }
    } catch (err: any) {
      finalSuccess = false;
      finalError = err.message || 'Authentication flow execution failed';
    }

    const totalDurationMs = Date.now() - startTime;
    const finalToken =
      sessionState?.token ||
      sessionState?.variables?.token ||
      sessionState?.variables?.access_token ||
      (flow.type === 'BEARER' || flow.type === 'API_KEY'
        ? flow.credentials?.token || flow.credentials?.apiKey
        : undefined);

    logger.info(
      {
        targetId,
        authType: flow.type,
        success: finalSuccess,
        totalDurationMs,
        stepsCount: stepsExecuted.length,
      },
      'Stateful auth flow verification completed server-side',
    );

    return reply.send({
      success: finalSuccess,
      totalDurationMs,
      stepsExecuted,
      finalToken,
      finalCookies: sessionState?.cookies,
      error: finalSuccess ? undefined : finalError,
    });
  };

  // Mount at both /verify-flow (for prefixed registration) and full path
  fastify.post('/verify-flow', { preHandler: [requireEngineer] }, handleVerifyFlow);
  fastify.post('/api/v1/auth-vault/verify-flow', { preHandler: [requireEngineer] }, handleVerifyFlow);
};
