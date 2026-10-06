import { ApiInventory, ApiEndpoint } from './parser.js';

export interface ContractViolation {
  readonly ruleId: string;
  readonly title: string;
  readonly severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  readonly description: string;
  readonly recommendation: string;
  readonly endpoint?: {
    path: string;
    method: string;
  };
  readonly parameter?: string;
  readonly actual: string;
}

const SENSITIVE_PARAM_REGEX =
  /(token|jwt|api_?key|secret|password|passwd|access_?token|auth|private_?key|session|ssn|credit_?card)/i;

const PUBLIC_PATH_PATTERNS = [
  /\/health/i,
  /\/ping/i,
  /\/status/i,
  /\/info/i,
  /\/version/i,
  /\/docs/i,
  /\/swagger/i,
  /\/openapi/i,
  /\/metrics/i,
  /\/login/i,
  /\/signup/i,
  /\/register/i,
  /\/auth\/token/i,
  /\/oauth/i,
];

/**
 * Checks whether an endpoint path typically represents an intentionally public route.
 */
export function isKnownPublicPath(path: string): boolean {
  return PUBLIC_PATH_PATTERNS.some((p) => p.test(path));
}

/**
 * Checks whether an endpoint has active security (either operation-level or global fallback).
 */
export function hasSecurityScheme(endpoint: ApiEndpoint, inventory: ApiInventory): boolean {
  if (endpoint.isExplicitlyPublic) {
    return false;
  }

  if (endpoint.security && endpoint.security.length > 0) {
    return true;
  }

  if (endpoint.security === undefined && inventory.globalSecurity.length > 0) {
    return true;
  }

  return false;
}

/**
 * Evaluates an ApiInventory against the platform's API Security Contract ruleset.
 */
export function evaluateOpenApiContractRules(inventory: ApiInventory): ContractViolation[] {
  const violations: ContractViolation[] = [];

  // ---------------------------------------------------------------------------
  // Rule 1: no-sensitive-query-params
  // ---------------------------------------------------------------------------
  for (const endpoint of inventory.endpoints) {
    for (const param of endpoint.parameters) {
      if (param.in === 'query' && SENSITIVE_PARAM_REGEX.test(param.name)) {
        violations.push({
          ruleId: 'no-sensitive-query-params',
          title: `Sensitive Parameter in Query String: [${param.name}]`,
          severity: 'high',
          description: `Endpoint ${endpoint.method} ${endpoint.path} declares sensitive parameter "${param.name}" in the query string. Query parameters are logged in web server access logs, browser history, and HTTP Referer headers.`,
          recommendation:
            'Transmit sensitive credentials, tokens, and secrets via HTTP Authorization or custom request headers, or within a POST/PUT request body.',
          endpoint: {
            path: endpoint.path,
            method: endpoint.method,
          },
          parameter: param.name,
          actual: `Query parameter: "${param.name}" (in: query)`,
        });
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Rule 2: no-unprotected-endpoints
  // ---------------------------------------------------------------------------
  for (const endpoint of inventory.endpoints) {
    const isProtected = hasSecurityScheme(endpoint, inventory);

    if (!isProtected) {
      // If mutating endpoint (POST, PUT, DELETE, PATCH) is unprotected
      if (endpoint.isMutating) {
        // Exclude /login, /register, /auth routes which legitimately accept public registration/auth
        const isAuthEntrypoint =
          endpoint.path.includes('/login') ||
          endpoint.path.includes('/register') ||
          endpoint.path.includes('/signup') ||
          endpoint.path.includes('/token');

        if (!isAuthEntrypoint) {
          violations.push({
            ruleId: 'no-unprotected-endpoints',
            title: `Unprotected Mutating Endpoint: [${endpoint.method} ${endpoint.path}]`,
            severity: 'critical',
            description: `Mutating operation ${endpoint.method} ${endpoint.path} does not declare any authentication or security requirements. Anyone can alter data anonymously.`,
            recommendation:
              'Apply an authentication scheme (e.g. Bearer JWT, OAuth2, or API Key) to all state-changing API routes.',
            endpoint: {
              path: endpoint.path,
              method: endpoint.method,
            },
            actual: 'Security definition missing for mutating endpoint',
          });
        }
      } else if (!endpoint.isExplicitlyPublic && !isKnownPublicPath(endpoint.path)) {
        // Read-only endpoint without security and not marked public
        violations.push({
          ruleId: 'no-unprotected-endpoints',
          title: `Unauthenticated API Endpoint: [${endpoint.method} ${endpoint.path}]`,
          severity: 'medium',
          description: `Endpoint ${endpoint.method} ${endpoint.path} does not declare security requirements and is not marked explicitly public.`,
          recommendation:
            'Declare security requirements in the OpenAPI document or explicitly mark public with "security: []".',
          endpoint: {
            path: endpoint.path,
            method: endpoint.method,
          },
          actual: 'Security requirements undefined',
        });
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Rule 3: require-https-servers
  // ---------------------------------------------------------------------------
  for (const server of inventory.servers) {
    try {
      const parsed = new URL(server.url);
      const isLocalhost =
        parsed.hostname === 'localhost' ||
        parsed.hostname === '127.0.0.1' ||
        parsed.hostname === '::1';

      if (parsed.protocol === 'http:' && !isLocalhost) {
        violations.push({
          ruleId: 'require-https-servers',
          title: `Insecure Cleartext Server URL: [${server.url}]`,
          severity: 'high',
          description: `OpenAPI specification declares cleartext HTTP server URL "${server.url}". Non-local traffic will be vulnerable to man-in-the-middle eavesdropping and credential theft.`,
          recommendation: 'Configure all production and staging servers to use HTTPS URLs with valid TLS encryption.',
          actual: `Server URL: "${server.url}" (Protocol: HTTP)`,
        });
      }
    } catch {
      // If relative URL like "/api/v1", allow
    }
  }

  // ---------------------------------------------------------------------------
  // Rule 4: no-cleartext-basic-auth
  // ---------------------------------------------------------------------------
  for (const [schemeName, scheme] of Object.entries(inventory.securitySchemes)) {
    if (scheme.type.toLowerCase() === 'http' && scheme.scheme?.toLowerCase() === 'basic') {
      violations.push({
        ruleId: 'no-cleartext-basic-auth',
        title: `Insecure Authentication Scheme: HTTP Basic [${schemeName}]`,
        severity: 'medium',
        description: `Security scheme "${schemeName}" specifies HTTP Basic authentication. Basic auth transmits base64-encoded credentials on every request and lacks revocation capabilities.`,
        recommendation: 'Migrate to modern token-based authentication (Bearer JWT or OAuth 2.0).',
        actual: `Security scheme "${schemeName}": type=http, scheme=basic`,
      });
    }
  }

  return violations;
}
