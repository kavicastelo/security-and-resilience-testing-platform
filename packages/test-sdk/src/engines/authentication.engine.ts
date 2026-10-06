import { TestEngine } from '../engine.js';
import { TestCapability } from '../capability.js';
import { ExecutionContext } from '../context.js';
import { TestInput, TestResult, ValidationResult, RawEngineFinding, RawEngineMetric } from '../result.js';
import { safeFetch } from '../http/index.js';
import {
  decodeJwt,
  maskJwt,
  createNoneAlgToken,
  createExpiredToken,
  createSignatureStrippedToken,
  createHmacToken,
} from './auth/jwt-auditor.js';
import { parseSetCookie, auditCookie, maskCookieValue, ParsedCookie } from './auth/cookie-auditor.js';

export interface AuthenticationEngineOptions {
  protectedPath?: string;
  loginPath?: string;
  sampleToken?: string;
  jwt?: string;
  credentials?: {
    username?: string;
    password?: string;
    [key: string]: unknown;
  };
  checkJwt?: boolean;
  checkCookies?: boolean;
  checkSessionFixation?: boolean;
  checkBruteForce?: boolean;
  bruteForceAttempts?: number;
}

export class AuthenticationSecurityEngine implements TestEngine {
  readonly id = 'engine-native-authentication';
  readonly version = '1.0.0';
  readonly executionClass = 'class_a_native' as const;

  capabilities(): TestCapability[] {
    return [
      {
        id: 'auth_jwt_audit',
        name: 'JSON Web Token (JWT) Security Audit',
        category: 'protocol_audit',
        description:
          'Audits JWT verification rigor, testing for alg: none signature bypass, expiration enforcement, and weak HMAC secrets.',
        isDisruptive: false,
      },
      {
        id: 'auth_cookie_flags',
        name: 'Cookie Security Flags Audit',
        category: 'passive_analysis',
        description:
          'Audits Set-Cookie headers for HttpOnly, Secure, SameSite, and RFC 6265bis prefix requirements (__Host-, __Secure-).',
        isDisruptive: false,
      },
      {
        id: 'auth_session_fixation',
        name: 'Session Fixation Vulnerability Audit',
        category: 'protocol_audit',
        description: 'Verifies whether session identifiers are properly regenerated upon user authentication.',
        isDisruptive: false,
      },
      {
        id: 'auth_login_brute_force',
        name: 'Authentication Route Brute-Force Resilience',
        category: 'active_fuzzing',
        description:
          'Evaluates login route resilience against rapid repeated failed attempts for rate limiting or account lockout controls.',
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

    const options = input.options as AuthenticationEngineOptions | undefined;
    if (options?.sampleToken !== undefined && typeof options.sampleToken !== 'string') {
      errors.push({ path: 'options.sampleToken', message: 'sampleToken must be a valid string' });
    }

    if (options?.jwt !== undefined && typeof options.jwt !== 'string') {
      errors.push({ path: 'options.jwt', message: 'jwt must be a valid string' });
    }

    return {
      valid: errors.length === 0,
      errors: errors.length > 0 ? errors : undefined,
    };
  }

  async execute(input: TestInput, context: ExecutionContext): Promise<TestResult> {
    const startTime = Date.now();
    const findings: RawEngineFinding[] = [];
    const metrics: RawEngineMetric[] = [];
    let probesExecuted = 0;

    const options = (input.options || {}) as AuthenticationEngineOptions;
    const baseUrl = input.targetUrl.replace(/\/+$/, '');
    const isHttps = baseUrl.startsWith('https://');

    const resolveUrl = (pathOrUrl?: string): string => {
      if (!pathOrUrl) return baseUrl;
      if (pathOrUrl.startsWith('http://') || pathOrUrl.startsWith('https://')) {
        return pathOrUrl;
      }
      return `${baseUrl}${pathOrUrl.startsWith('/') ? '' : '/'}${pathOrUrl}`;
    };

    const protectedUrl = resolveUrl(options.protectedPath || '/');
    const loginUrl = options.loginPath ? resolveUrl(options.loginPath) : undefined;
    const sampleToken = options.sampleToken || options.jwt;

    context.reportProgress(10, 'Initiating authentication testing and cookie inspection...');

    // Helper to harvest Set-Cookie headers from a Response
    const extractCookies = (res: Response): ParsedCookie[] => {
      const cookieList: string[] = [];
      const headersAny = res.headers as unknown as {
        getSetCookie?: () => string[];
        raw?: () => Record<string, string[]>;
      };

      if (typeof headersAny.getSetCookie === 'function') {
        const gsc = headersAny.getSetCookie();
        if (Array.isArray(gsc)) cookieList.push(...gsc);
      } else if (typeof headersAny.raw === 'function') {
        const r = headersAny.raw()['set-cookie'];
        if (Array.isArray(r)) cookieList.push(...r);
      } else {
        const sc = res.headers.get('set-cookie');
        if (sc) cookieList.push(sc);
      }

      const parsed: ParsedCookie[] = [];
      for (const headerVal of cookieList) {
        // Handle comma-joined cookies if combined into single header
        const individualCookies = headerVal.split(/,(?=[a-zA-Z0-9_.-]+=)/);
        for (const cookieStr of individualCookies) {
          if (cookieStr.trim()) {
            parsed.push(parseSetCookie(cookieStr.trim()));
          }
        }
      }
      return parsed;
    };

    // -------------------------------------------------------------------------
    // Phase 1: Cookie Security Flag Audit (auth_cookie_flags)
    // -------------------------------------------------------------------------
    const auditedCookieNames = new Set<string>();

    const auditResponseCookies = (cookies: ParsedCookie[], sourceUrl: string, resStatus: number) => {
      for (const cookie of cookies) {
        if (auditedCookieNames.has(cookie.name)) continue;
        auditedCookieNames.add(cookie.name);

        const violations = auditCookie(cookie, isHttps);
        for (const v of violations) {
          findings.push({
            title: v.title,
            category: 'cookies',
            severity: v.severity,
            description: v.description,
            recommendation: v.recommendation,
            evidence: {
              request: { method: 'GET', url: sourceUrl, headers: input.customHeaders || {} },
              response: {
                statusCode: resStatus,
                headers: { 'set-cookie': cookie.raw },
              },
              expected: 'Cookie with secure attributes (HttpOnly, Secure, SameSite)',
              actual: `Set-Cookie: ${cookie.name}=${maskCookieValue(cookie.value)}; ${cookie.raw}`,
            },
          });
        }
      }
    };

    // Baseline GET to targetUrl to inspect initial session cookies
    let initialRes: Response | null = null;
    let preAuthSessionCookie: ParsedCookie | null = null;

    try {
      initialRes = await safeFetch(input.targetUrl, {
        method: 'GET',
        headers: {
          'User-Agent': 'SecurityLab-QA/1.0',
          Accept: '*/*',
          ...input.customHeaders,
        },
        signal: context.abortSignal,
        scope: context.target?.scope,
      });

      probesExecuted++;
      const cookies = extractCookies(initialRes);
      auditResponseCookies(cookies, input.targetUrl, initialRes.status);

      // Find primary session cookie for fixation audit
      preAuthSessionCookie = cookies.find((c) => c.isAuthCookie) || cookies[0] || null;
    } catch (err: unknown) {
      context.logger?.warn({ err }, 'Failed initial GET connection for cookie audit');
    }

    // -------------------------------------------------------------------------
    // Phase 2: JWT Security & Tampering Probes (auth_jwt_audit)
    // -------------------------------------------------------------------------
    if (sampleToken && options.checkJwt !== false) {
      context.reportProgress(30, 'Performing JWT decoding and signature tampering probes...');

      const decoded = decodeJwt(sampleToken);
      if (!decoded) {
        findings.push({
          title: 'Malformed Sample JWT Token Provided',
          category: 'authentication',
          severity: 'low',
          description:
            'The sample JWT token provided in test options could not be decoded. Verify the token format (header.payload.signature).',
          recommendation: 'Ensure sample tokens supplied for authentication testing are well-formed JWTs.',
          evidence: {
            actual: maskJwt(sampleToken),
          },
        });
      } else {
        // 1. Check for missing exp claim
        if (decoded.payload['exp'] === undefined) {
          findings.push({
            title: 'JWT Missing Expiration (exp) Claim',
            category: 'authentication',
            severity: 'medium',
            description:
              'The sample JWT does not contain an "exp" (expiration time) claim, allowing indefinitely valid tokens if intercepted.',
            recommendation: 'Issue JWTs with explicit "exp" timestamps and short lifespans.',
            evidence: {
              actual: JSON.stringify(decoded.payload),
            },
          });
        }

        // 2. Check for alg="none" in sample token itself
        if (String(decoded.header['alg']).toLowerCase() === 'none') {
          findings.push({
            title: "Sample JWT Configured with Insecure Algorithm 'none'",
            category: 'authentication',
            severity: 'critical',
            description: 'The baseline sample token uses the "none" algorithm and is completely unsigned.',
            recommendation: 'Disallow the "none" algorithm and use strong asymmetric (RS256/ES256) or HMAC (HS256) algorithms.',
            evidence: {
              actual: JSON.stringify(decoded.header),
            },
          });
        }

        // Probe A: Algorithm "none" Bypass Probe
        context.reportProgress(40, 'Probing endpoint against alg: none signature bypass...');
        const noneToken = createNoneAlgToken(sampleToken, 'none');
        probesExecuted++;

        try {
          const noneRes = await safeFetch(protectedUrl, {
            method: 'GET',
            headers: {
              'User-Agent': 'SecurityLab-QA/1.0',
              Authorization: `Bearer ${noneToken}`,
              ...input.customHeaders,
            },
            signal: context.abortSignal,
            scope: context.target?.scope,
          });

          if (noneRes.status >= 200 && noneRes.status < 300) {
            const bodySnippet = (await noneRes.text()).slice(0, 500);
            findings.push({
              title: "Critical Vulnerability: Target Accepts Algorithm 'none' JWT Signature Bypass",
              category: 'authentication',
              severity: 'critical',
              description:
                'The protected endpoint accepted an unsigned JWT with alg="none" as valid authentication, allowing attackers to forge arbitrary tokens and bypass authentication entirely.',
              recommendation:
                'Configure the JWT verification library to explicitly whitelist allowed algorithms (e.g. RS256, HS256) and reject alg="none".',
              evidence: {
                request: {
                  method: 'GET',
                  url: protectedUrl,
                  headers: { Authorization: `Bearer ${maskJwt(noneToken)}` },
                },
                response: {
                  statusCode: noneRes.status,
                  headers: {},
                  body: bodySnippet,
                },
                expected: 'HTTP 401 Unauthorized or 403 Forbidden',
                actual: `HTTP ${noneRes.status} OK`,
              },
            });
          }
        } catch (err: unknown) {
          context.logger?.debug({ err }, 'alg: none probe connection failed');
        }

        // Probe B: Expired Token Acceptance Probe
        context.reportProgress(50, 'Probing endpoint against expired token acceptance...');
        const expiredToken = createExpiredToken(sampleToken, 86400); // Expired 24 hours ago
        probesExecuted++;

        try {
          const expRes = await safeFetch(protectedUrl, {
            method: 'GET',
            headers: {
              'User-Agent': 'SecurityLab-QA/1.0',
              Authorization: `Bearer ${expiredToken}`,
              ...input.customHeaders,
            },
            signal: context.abortSignal,
            scope: context.target?.scope,
          });

          if (expRes.status >= 200 && expRes.status < 300) {
            const bodySnippet = (await expRes.text()).slice(0, 500);
            findings.push({
              title: 'Vulnerability: Expired JWT Accepted by Protected Route',
              category: 'authentication',
              severity: 'high',
              description:
                'The protected endpoint accepted a JWT whose expiration timestamp (exp) has already elapsed.',
              recommendation:
                'Ensure the JWT verification middleware verifies token expiration and does not permit clock skew past acceptable limits.',
              evidence: {
                request: {
                  method: 'GET',
                  url: protectedUrl,
                  headers: { Authorization: `Bearer ${maskJwt(expiredToken)}` },
                },
                response: {
                  statusCode: expRes.status,
                  headers: {},
                  body: bodySnippet,
                },
                expected: 'HTTP 401 Unauthorized',
                actual: `HTTP ${expRes.status} OK`,
              },
            });
          }
        } catch (err: unknown) {
          context.logger?.debug({ err }, 'expired token probe connection failed');
        }

        // Probe C: Signature-Stripped Token Acceptance Probe
        context.reportProgress(60, 'Probing endpoint against signature-stripped token acceptance...');
        const strippedToken = createSignatureStrippedToken(sampleToken);
        probesExecuted++;

        try {
          const stripRes = await safeFetch(protectedUrl, {
            method: 'GET',
            headers: {
              'User-Agent': 'SecurityLab-QA/1.0',
              Authorization: `Bearer ${strippedToken}`,
              ...input.customHeaders,
            },
            signal: context.abortSignal,
            scope: context.target?.scope,
          });

          if (stripRes.status >= 200 && stripRes.status < 300) {
            const bodySnippet = (await stripRes.text()).slice(0, 500);
            findings.push({
              title: 'Critical Vulnerability: Unsigned / Signature-Stripped JWT Accepted',
              category: 'authentication',
              severity: 'critical',
              description:
                'The protected endpoint accepted a JWT whose signature segment was completely omitted, indicating signature verification is bypassed or disabled.',
              recommendation:
                'Require signature verification on all incoming JWTs before processing claims.',
              evidence: {
                request: {
                  method: 'GET',
                  url: protectedUrl,
                  headers: { Authorization: `Bearer ${maskJwt(strippedToken)}` },
                },
                response: {
                  statusCode: stripRes.status,
                  headers: {},
                  body: bodySnippet,
                },
                expected: 'HTTP 401 Unauthorized',
                actual: `HTTP ${stripRes.status} OK`,
              },
            });
          }
        } catch (err: unknown) {
          context.logger?.debug({ err }, 'stripped signature probe connection failed');
        }

        // Probe D: Weak HMAC Secret Probe (if alg starts with HS)
        const algStr = typeof decoded.header['alg'] === 'string' ? decoded.header['alg'] : '';
        if (algStr.startsWith('HS')) {
          context.reportProgress(70, 'Testing HMAC signature against common weak secrets...');
          const weakSecrets = ['secret', 'password', '123456'];

          for (const secret of weakSecrets) {
            const weakToken = createHmacToken(
              decoded.payload,
              secret,
              algStr as 'HS256' | 'HS384' | 'HS512',
            );
            probesExecuted++;

            try {
              const weakRes = await safeFetch(protectedUrl, {
                method: 'GET',
                headers: {
                  'User-Agent': 'SecurityLab-QA/1.0',
                  Authorization: `Bearer ${weakToken}`,
                  ...input.customHeaders,
                },
                signal: context.abortSignal,
                scope: context.target?.scope,
              });

              if (weakRes.status >= 200 && weakRes.status < 300) {
                findings.push({
                  title: 'Critical Vulnerability: JWT Signed with Weak / Predictable Secret Accepted',
                  category: 'authentication',
                  severity: 'critical',
                  description: `The protected endpoint verified and accepted a JWT signed using the trivial weak secret "${secret}".`,
                  recommendation:
                    'Generate a high-entropy secret (at least 256 bits of cryptographically secure random bytes) and store it in a secure secret manager.',
                  evidence: {
                    request: {
                      method: 'GET',
                      url: protectedUrl,
                      headers: { Authorization: `Bearer ${maskJwt(weakToken)}` },
                    },
                    response: {
                      statusCode: weakRes.status,
                      headers: {},
                    },
                    expected: 'HTTP 401 Unauthorized',
                    actual: `HTTP ${weakRes.status} OK (Signed with secret: "${secret}")`,
                  },
                });
                break; // Stop at first weak secret match
              }
            } catch (err: unknown) {
              context.logger?.debug({ err }, `Weak secret probe "${secret}" failed`);
            }
          }
        }
      }
    }

    // -------------------------------------------------------------------------
    // Phase 3: Session Fixation Audit (auth_session_fixation)
    // -------------------------------------------------------------------------
    if (loginUrl && options.checkSessionFixation !== false) {
      context.reportProgress(80, 'Auditing session identifier regeneration across authentication...');
      probesExecuted++;

      try {
        const credentials = options.credentials || { username: 'testuser', password: 'testpassword' };
        const reqHeaders: Record<string, string> = {
          'User-Agent': 'SecurityLab-QA/1.0',
          'Content-Type': 'application/json',
          Accept: 'application/json, text/plain, */*',
          ...input.customHeaders,
        };

        // If a pre-auth session cookie was established, present it with login request
        if (preAuthSessionCookie) {
          reqHeaders['Cookie'] = `${preAuthSessionCookie.name}=${preAuthSessionCookie.value}`;
        }

        const loginRes = await safeFetch(loginUrl, {
          method: 'POST',
          headers: reqHeaders,
          body: JSON.stringify(credentials),
          signal: context.abortSignal,
          scope: context.target?.scope,
        });

        const postLoginCookies = extractCookies(loginRes);
        auditResponseCookies(postLoginCookies, loginUrl, loginRes.status);

        if (preAuthSessionCookie) {
          const matchingPostCookie = postLoginCookies.find((c) => c.name === preAuthSessionCookie?.name);

          // If the server accepted login (200..299) and DID NOT issue a new session ID
          if (loginRes.status >= 200 && loginRes.status < 300) {
            if (!matchingPostCookie || matchingPostCookie.value === preAuthSessionCookie.value) {
              findings.push({
                title: 'Session Fixation: Session Identifier Not Regenerated Post-Authentication',
                category: 'authentication',
                severity: 'high',
                description: `The application failed to regenerate the session cookie "${preAuthSessionCookie.name}" upon successful authentication, leaving users vulnerable to session fixation attacks.`,
                recommendation:
                  'Always destroy existing session state and issue a newly generated session identifier immediately upon user login.',
                evidence: {
                  request: { method: 'POST', url: loginUrl, headers: reqHeaders },
                  response: { statusCode: loginRes.status, headers: {} },
                  expected: 'New session cookie with different identifier issued post-login',
                  actual: matchingPostCookie
                    ? `Same identifier retained: ${maskCookieValue(matchingPostCookie.value)}`
                    : 'No new session cookie issued in login response',
                },
              });
            }
          }
        }
      } catch (err: unknown) {
        context.logger?.debug({ err }, 'Session fixation audit request failed');
      }
    }

    // -------------------------------------------------------------------------
    // Phase 4: Login Route Brute-Force Throttling Audit (auth_login_brute_force)
    // -------------------------------------------------------------------------
    if (loginUrl && options.checkBruteForce === true) {
      context.reportProgress(90, 'Evaluating login route brute-force throttling resistance...');
      const attemptsCount = Math.min(Number(options.bruteForceAttempts) || 10, 15);
      let rateLimited = false;
      let accountLocked = false;
      const statusCodes: number[] = [];

      for (let i = 0; i < attemptsCount; i++) {
        if (context.abortSignal.aborted) break;
        probesExecuted++;

        try {
          const invalidPayload = {
            username: `audit-user-bruteforce-${i}`,
            password: `invalid-password-attempt-${i}`,
          };

          const attemptRes = await safeFetch(loginUrl, {
            method: 'POST',
            headers: {
              'User-Agent': 'SecurityLab-QA/1.0',
              'Content-Type': 'application/json',
              Accept: 'application/json',
              ...input.customHeaders,
            },
            body: JSON.stringify(invalidPayload),
            signal: context.abortSignal,
            scope: context.target?.scope,
          });

          statusCodes.push(attemptRes.status);

          if (attemptRes.status === 429) {
            rateLimited = true;
            break;
          }

          const bodyText = (await attemptRes.text()).toLowerCase();
          if (bodyText.includes('locked') || bodyText.includes('captcha') || bodyText.includes('too many attempts')) {
            accountLocked = true;
            break;
          }
        } catch {
          // Continue to next probe
        }
      }

      if (!rateLimited && !accountLocked && statusCodes.length >= attemptsCount) {
        findings.push({
          title: 'Missing Rate Limiting / Brute-Force Protection on Login Route',
          category: 'authentication',
          severity: 'medium',
          description: `Dispatched ${attemptsCount} rapid failed login attempts to "${loginUrl}" without triggering HTTP 429 (Too Many Requests), CAPTCHA challenges, or temporary lockout controls.`,
          recommendation:
            'Implement progressive rate limiting (HTTP 429) and account lockout policies to defend authentication routes against credential stuffing.',
          evidence: {
            request: { method: 'POST', url: loginUrl, headers: { 'Content-Type': 'application/json' } },
            response: {
              statusCode: statusCodes[statusCodes.length - 1] || 401,
              headers: {},
            },
            expected: 'HTTP 429 Too Many Requests or account lockout after repeated failures',
            actual: `All ${attemptsCount} attempts returned status codes: [${statusCodes.join(', ')}]`,
          },
        });
      }
    }

    metrics.push(
      { name: 'auth_probes_total', value: probesExecuted, unit: 'count' },
      { name: 'auth_findings_total', value: findings.length, unit: 'count' },
      { name: 'execution_duration_ms', value: Date.now() - startTime, unit: 'ms' },
    );

    return {
      engineId: this.id,
      durationMs: Date.now() - startTime,
      success: findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length === 0,
      findings,
      metrics,
      rawOutput: {
        probesExecuted,
        auditedCookiesCount: auditedCookieNames.size,
        findingsCount: findings.length,
      },
    };
  }
}
