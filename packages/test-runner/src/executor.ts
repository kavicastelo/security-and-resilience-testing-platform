import { TargetScope } from '@security-lab/domain';
import {
  createSecureHttpAgent,
  createSecureHttpsAgent,
  validateUrlAgainstScope,
  DnsPinningOptions,
} from '@security-lab/scope-engine';
import {
  TargetCircuitBreaker,
  circuitBreakerRegistry,
} from './circuit-breaker.js';
import {
  workerRunner,
  EngineSandboxingOptions,
  TestInput,
  TestResult,
  ExecutionContext,
} from '@security-lab/engine-sdk';
import { StatefulAuthenticator } from './stateful-auth.js';

export class ExecutionSecurityError extends Error {
  readonly violations: string[];

  constructor(message: string, violations: string[] = []) {
    super(message);
    this.name = 'ExecutionSecurityError';
    this.violations = violations;
  }
}

export interface SafeExecuteHttpOptions extends Omit<RequestInit, 'redirect'> {
  scope?: TargetScope;
  targetId?: string;
  circuitBreaker?: TargetCircuitBreaker;
  maxRedirects?: number;
  dnsOptions?: DnsPinningOptions;
  authenticator?: StatefulAuthenticator;
  autoRefresh?: boolean;
  fetchImpl?: typeof fetch;
}

const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);

/**
 * Executes a hardened outbound HTTP request with pre-socket DNS pinning,
 * scope boundary enforcement, redirect traversal defense, and target circuit breaking.
 */
export async function executeHttpRequest(
  inputUrl: string,
  options: SafeExecuteHttpOptions = {},
): Promise<Response> {
  const scope = options.scope;
  const maxRedirects = options.maxRedirects ?? 5;

  let parsed: URL;
  try {
    parsed = new URL(inputUrl);
  } catch {
    throw new ExecutionSecurityError(`Invalid request URL: "${inputUrl}"`, ['Malformed URL']);
  }

  // Obtain or create Circuit Breaker for target
  const targetKey = options.targetId || parsed.origin;
  const breaker = options.circuitBreaker || circuitBreakerRegistry.getBreaker(targetKey);

  // 1. Initial Target Scope Boundary Validation
  if (scope) {
    const check = validateUrlAgainstScope(inputUrl, scope);
    if (!check.valid) {
      throw new ExecutionSecurityError(
        `Target URL "${inputUrl}" violates security scope: ${check.violations.join('; ')}`,
        check.violations,
      );
    }
  }

  // Prepare secure DNS agents if scope is provided
  const httpAgent = scope ? createSecureHttpAgent(scope, options.dnsOptions) : undefined;
  const httpsAgent = scope ? createSecureHttpsAgent(scope, options.dnsOptions) : undefined;

  let currentUrl = inputUrl;
  let currentMethod = options.method || 'GET';
  let currentHeaders: SafeExecuteHttpOptions['headers'] = options.headers;
  let currentBody = options.body;
  let redirectCount = 0;
  let hasRetriedAuth = false;

  // If authenticator is configured, merge current auth headers
  if (options.authenticator) {
    const authHeaders = options.authenticator.getHeaders();
    const headersObj = new Headers(currentHeaders as any);
    for (const [k, v] of Object.entries(authHeaders)) {
      if (!headersObj.has(k)) {
        headersObj.set(k, v);
      }
    }
    currentHeaders = headersObj;
  }

  // Execute through Circuit Breaker to guard downstream targets against cascading failures
  return breaker.execute(async () => {
    while (true) {
      const isHttps = currentUrl.startsWith('https:');
      const agent = isHttps ? httpsAgent : httpAgent;

      const fetchOptions: RequestInit & { agent?: unknown } = {
        ...options,
        method: currentMethod,
        headers: currentHeaders,
        body: currentBody,
        redirect: 'manual', // Strictly intercept all redirects
        // Node.js undici / native fetch agent compatibility
        ...(agent ? { agent } : {}),
      };

      const fetchFn = options.fetchImpl ?? globalThis.fetch;
      const response = await fetchFn(currentUrl, fetchOptions as RequestInit);

      // Intercept 401 Unauthorized for automatic token refresh & request retry
      if (
        response.status === 401 &&
        options.authenticator &&
        options.autoRefresh !== false &&
        !hasRetriedAuth
      ) {
        hasRetriedAuth = true;
        // Acquire mutex lock and refresh token
        await options.authenticator.refreshSession();
        // Update request headers with refreshed token/cookies
        const refreshedHeaders = options.authenticator.getHeaders();
        const headersObj = new Headers(currentHeaders as any);
        for (const [k, v] of Object.entries(refreshedHeaders)) {
          headersObj.set(k, v);
        }
        currentHeaders = headersObj;
        continue; // Re-dispatch request immediately
      }

      if (!REDIRECT_STATUS_CODES.has(response.status)) {
        return response;
      }

      const location = response.headers.get('location');
      if (!location) {
        return response;
      }

      let nextUrl: string;
      try {
        nextUrl = new URL(location, currentUrl).toString();
      } catch {
        throw new ExecutionSecurityError(`Invalid redirect Location header: "${location}"`, [
          `Invalid redirect location: "${location}"`,
        ]);
      }

      redirectCount++;
      if (redirectCount > maxRedirects) {
        throw new ExecutionSecurityError(
          `Exceeded maximum redirect limit (${maxRedirects}). Aborting request.`,
          [`Max redirects (${maxRedirects}) exceeded`],
        );
      }

      // Re-validate redirect target URL against scope
      if (scope) {
        const redirectCheck = validateUrlAgainstScope(nextUrl, scope);
        if (!redirectCheck.valid) {
          throw new ExecutionSecurityError(
            `Redirect destination "${nextUrl}" violates security scope: ${redirectCheck.violations.join('; ')}`,
            redirectCheck.violations,
          );
        }
      }

      currentUrl = nextUrl;
      if (response.status === 303 || ((response.status === 301 || response.status === 302) && currentMethod === 'POST')) {
        currentMethod = 'GET';
        currentBody = undefined;
      }
    }
  });
}

export interface EngineExecutionOptions extends EngineSandboxingOptions {
  sandbox?: boolean;
}

/**
 * Executes a native security engine inside an isolated worker thread sandbox.
 * Enforces hard memory boundaries and execution timeouts to safeguard the runner process.
 */
export async function executeSandboxedEngine(
  engineId: string,
  input: TestInput,
  context: ExecutionContext,
  options: EngineExecutionOptions = {},
): Promise<TestResult> {
  const sandboxed = options.sandbox !== false && options.enabled !== false;
  return workerRunner.execute(engineId, input, context, {
    ...options,
    enabled: sandboxed,
  });
}
