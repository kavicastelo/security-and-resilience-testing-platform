import { validateUrlAgainstScope, TargetScope } from '@security-lab/domain';

export class SecurityBoundaryError extends Error {
  readonly violations: string[];

  constructor(message: string, violations: string[] = []) {
    super(message);
    this.name = 'SecurityBoundaryError';
    this.violations = violations;
  }
}

export interface SafeFetchOptions extends Omit<RequestInit, 'redirect'> {
  scope?: TargetScope;
  maxRedirects?: number;
}

const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);

/**
 * Hardened HTTP client that enforces scope boundaries and prevents SSRF attacks.
 * Features:
 * 1. Sets redirect: 'manual' to prevent Node runtime from silently following redirects.
 * 2. Intercepts 3xx status codes and validates every destination hop against TargetScope.
 * 3. Enforces a maximum redirect chain limit (default 5).
 * 4. Normalizes relative and absolute Location headers safely.
 */
export async function safeFetch(
  inputUrl: string,
  options: SafeFetchOptions = {},
): Promise<Response> {
  const maxRedirects = options.maxRedirects ?? 5;
  const scope = options.scope;

  let currentUrl = inputUrl;
  let currentMethod = options.method || 'GET';
  const currentHeaders = options.headers;
  let currentBody = options.body;

  // 1. Initial URL validation against scope if provided
  if (scope) {
    const initialValidation = validateUrlAgainstScope(currentUrl, scope);
    if (!initialValidation.valid) {
      throw new SecurityBoundaryError(
        `Initial request URL "${currentUrl}" violates security boundary: ${initialValidation.violations.join('; ')}`,
        initialValidation.violations,
      );
    }
  }

  let redirectCount = 0;

  while (true) {
    const fetchOptions: RequestInit = {
      ...options,
      method: currentMethod,
      headers: currentHeaders,
      body: currentBody,
      redirect: 'manual', // Strictly intercept all redirects
    };

    const response = await fetch(currentUrl, fetchOptions);

    if (!REDIRECT_STATUS_CODES.has(response.status)) {
      return response;
    }

    const location = response.headers.get('location');
    if (!location) {
      // 3xx response without Location header, return response directly
      return response;
    }

    // Resolve redirect location relative to currentUrl
    let targetUrl: string;
    try {
      targetUrl = new URL(location, currentUrl).toString();
    } catch {
      throw new SecurityBoundaryError(
        `Redirect location header "${location}" is an invalid URI format.`,
        [`Invalid redirect Location: "${location}"`],
      );
    }

    redirectCount++;
    if (redirectCount > maxRedirects) {
      throw new SecurityBoundaryError(
        `Exceeded maximum allowed redirect hops (${maxRedirects}). Possible redirect loop or denial of service attack.`,
        [`Max redirects (${maxRedirects}) exceeded`],
      );
    }

    // 2. Re-validate destination URL against target scope
    if (scope) {
      const redirectValidation = validateUrlAgainstScope(targetUrl, scope);
      if (!redirectValidation.valid) {
        throw new SecurityBoundaryError(
          `Redirect destination "${targetUrl}" violates security boundary: ${redirectValidation.violations.join('; ')}`,
          redirectValidation.violations,
        );
      }
    }

    // 3. Handle HTTP redirect method rewrites per RFC 7231 / RFC 7538
    if (response.status === 303) {
      currentMethod = 'GET';
      currentBody = undefined;
    } else if ((response.status === 301 || response.status === 302) && currentMethod === 'POST') {
      currentMethod = 'GET';
      currentBody = undefined;
    }

    currentUrl = targetUrl;
  }
}
