export interface ParsedCookie {
  raw: string;
  name: string;
  value: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  domain?: string;
  path?: string;
  maxAge?: number;
  expires?: string;
  isSessionCookie: boolean;
  isAuthCookie: boolean;
}

export interface CookieViolation {
  code:
    | 'missing_http_only'
    | 'missing_secure'
    | 'missing_same_site'
    | 'same_site_none_without_secure'
    | 'invalid_host_prefix'
    | 'invalid_secure_prefix';
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  recommendation: string;
}

const AUTH_COOKIE_PATTERNS = [
  /session/i,
  /sess/i,
  /sid/i,
  /token/i,
  /jwt/i,
  /auth/i,
  /connect\.sid/i,
  /phpsessid/i,
  /jsessionid/i,
  /aspnet_sessionid/i,
  /id_token/i,
  /access_token/i,
  /refresh_token/i,
  /remember/i,
];

/**
 * Checks whether a cookie name or structure suggests it holds authentication or session state.
 */
export function isAuthOrSessionCookie(name: string): boolean {
  return AUTH_COOKIE_PATTERNS.some((pattern) => pattern.test(name));
}

/**
 * Parses a single raw Set-Cookie header into a structured ParsedCookie.
 */
export function parseSetCookie(headerVal: string): ParsedCookie {
  const parts = headerVal.split(';').map((p) => p.trim());
  const firstPart = parts[0] || '';
  const eqIdx = firstPart.indexOf('=');

  const name = eqIdx > -1 ? firstPart.slice(0, eqIdx).trim() : firstPart;
  const value = eqIdx > -1 ? firstPart.slice(eqIdx + 1).trim() : '';

  let httpOnly = false;
  let secure = false;
  let sameSite: 'strict' | 'lax' | 'none' | undefined;
  let domain: string | undefined;
  let path: string | undefined;
  let maxAge: number | undefined;
  let expires: string | undefined;

  for (let i = 1; i < parts.length; i++) {
    const attr = parts[i];
    if (!attr) continue;
    const lower = attr.toLowerCase();

    if (lower === 'httponly') {
      httpOnly = true;
    } else if (lower === 'secure') {
      secure = true;
    } else if (lower.startsWith('samesite=')) {
      const val = lower.slice('samesite='.length).trim();
      if (val === 'strict' || val === 'lax' || val === 'none') {
        sameSite = val;
      }
    } else if (lower.startsWith('domain=')) {
      domain = attr.slice('domain='.length).trim();
    } else if (lower.startsWith('path=')) {
      path = attr.slice('path='.length).trim();
    } else if (lower.startsWith('max-age=')) {
      const parsed = parseInt(attr.slice('max-age='.length).trim(), 10);
      if (!isNaN(parsed)) maxAge = parsed;
    } else if (lower.startsWith('expires=')) {
      expires = attr.slice('expires='.length).trim();
    }
  }

  const isAuth = isAuthOrSessionCookie(name);
  const isSessionCookie = maxAge === undefined && expires === undefined;

  return {
    raw: headerVal,
    name,
    value,
    httpOnly,
    secure,
    sameSite,
    domain,
    path,
    maxAge,
    expires,
    isSessionCookie,
    isAuthCookie: isAuth,
  };
}

/**
 * Masks a sensitive cookie value for reporting.
 */
export function maskCookieValue(val: string): string {
  if (!val || val.length <= 4) return '***';
  return `${val.slice(0, 3)}...[MASKED]`;
}

/**
 * Audits a parsed cookie against defensive security best practices and RFC 6265bis specifications.
 */
export function auditCookie(cookie: ParsedCookie, isHttps: boolean): CookieViolation[] {
  const violations: CookieViolation[] = [];

  // 1. HttpOnly enforcement on session/auth cookies
  if (cookie.isAuthCookie && !cookie.httpOnly) {
    violations.push({
      code: 'missing_http_only',
      title: `Missing HttpOnly Flag on Sensitive Cookie [${cookie.name}]`,
      severity: 'high',
      description: `Cookie "${cookie.name}" appears to store session credentials or tokens but lacks the HttpOnly attribute, allowing client-side scripts to access it via document.cookie.`,
      recommendation: `Set the "HttpOnly" attribute on cookie "${cookie.name}" to prevent XSS-based token theft.`,
    });
  }

  // 2. Secure flag enforcement on HTTPS
  if (isHttps && !cookie.secure) {
    violations.push({
      code: 'missing_secure',
      title: `Missing Secure Flag on Cookie [${cookie.name}]`,
      severity: cookie.isAuthCookie ? 'high' : 'medium',
      description: `Cookie "${cookie.name}" was served over HTTPS without the Secure attribute, allowing browsers to send it over unencrypted HTTP requests.`,
      recommendation: `Add the "Secure" flag to cookie "${cookie.name}" to ensure it is only transmitted across encrypted TLS connections.`,
    });
  }

  // 3. SameSite attribute audit
  if (!cookie.sameSite) {
    violations.push({
      code: 'missing_same_site',
      title: `Missing SameSite Attribute on Cookie [${cookie.name}]`,
      severity: cookie.isAuthCookie ? 'medium' : 'low',
      description: `Cookie "${cookie.name}" does not specify a SameSite attribute, relying on browser default behaviors and increasing risk of Cross-Site Request Forgery (CSRF).`,
      recommendation: `Explicitly set "SameSite=Lax" or "SameSite=Strict" on cookie "${cookie.name}".`,
    });
  } else if (cookie.sameSite === 'none' && !cookie.secure) {
    violations.push({
      code: 'same_site_none_without_secure',
      title: `Cookie [${cookie.name}] Has SameSite=None Without Secure`,
      severity: 'high',
      description: `Cookie "${cookie.name}" specifies SameSite=None without the Secure attribute. Modern browsers will reject this cookie, or it will be transmitted across unencrypted cross-origin contexts.`,
      recommendation: `Pair "SameSite=None" with the "Secure" attribute or switch to "SameSite=Lax".`,
    });
  }

  // 4. Prefix enforcement (__Host- and __Secure-)
  if (cookie.name.startsWith('__Host-')) {
    // RFC 6265bis: __Host- requires Secure, Path=/, and NO Domain attribute
    if (!cookie.secure || cookie.domain || cookie.path !== '/') {
      violations.push({
        code: 'invalid_host_prefix',
        title: `Cookie [${cookie.name}] Violates __Host- Prefix Specification`,
        severity: 'high',
        description: `Cookie "${cookie.name}" uses the __Host- prefix but violates RFC requirements (must have Secure, Path=/, and omit Domain attribute).`,
        recommendation: `Ensure __Host- cookies include the Secure attribute, set Path=/, and omit the Domain attribute.`,
      });
    }
  } else if (cookie.name.startsWith('__Secure-')) {
    // RFC 6265bis: __Secure- requires Secure attribute
    if (!cookie.secure) {
      violations.push({
        code: 'invalid_secure_prefix',
        title: `Cookie [${cookie.name}] Violates __Secure- Prefix Specification`,
        severity: 'high',
        description: `Cookie "${cookie.name}" uses the __Secure- prefix but lacks the Secure attribute.`,
        recommendation: `Ensure __Secure- cookies always include the Secure attribute.`,
      });
    }
  }

  return violations;
}
