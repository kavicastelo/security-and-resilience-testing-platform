import { OidcConfig } from '@security-lab/contracts';

export interface OidcParsedClaims {
  sub: string;
  email: string;
  name?: string;
  groups: string[];
  issuer?: string;
}

/**
 * Generates an OIDC Authorization URL for initiating the login redirect.
 */
export function generateOidcAuthUrl(
  config: OidcConfig,
  state: string,
  redirectUriOverride?: string,
): string {
  const authUrl = config.authorizationUrl || `${config.issuer.replace(/\/$/, '')}/protocol/openid-connect/auth`;
  const redirectUri = redirectUriOverride || config.redirectUri || '';

  const params = new URLSearchParams({
    client_id: config.clientId,
    response_type: 'code',
    scope: 'openid email profile groups',
    redirect_uri: redirectUri,
    state,
  });

  return `${authUrl}?${params.toString()}`;
}

/**
 * Parses and validates an OIDC ID token JWT or userinfo claims payload.
 */
export function verifyAndParseOidcClaims(
  idTokenOrPayload: string | Record<string, unknown>,
  expectedClientId?: string,
  expectedIssuer?: string,
): OidcParsedClaims {
  let payload: Record<string, unknown>;

  if (typeof idTokenOrPayload === 'string') {
    const parts = idTokenOrPayload.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format in OIDC token');
    }
    try {
      const decodedJson = Buffer.from(parts[1]!, 'base64url').toString('utf-8');
      payload = JSON.parse(decodedJson);
    } catch {
      throw new Error('Failed to parse OIDC token payload');
    }
  } else {
    payload = idTokenOrPayload;
  }

  // Expiration check
  if (typeof payload.exp === 'number') {
    const now = Math.floor(Date.now() / 1000);
    if (now > payload.exp) {
      throw new Error('OIDC token has expired');
    }
  }

  // Issuer check
  if (expectedIssuer && typeof payload.iss === 'string') {
    const cleanExpected = expectedIssuer.replace(/\/$/, '');
    const cleanActual = payload.iss.replace(/\/$/, '');
    if (cleanExpected !== cleanActual) {
      throw new Error(`OIDC Issuer mismatch: expected "${cleanExpected}", got "${cleanActual}"`);
    }
  }

  // Audience check
  if (expectedClientId && payload.aud) {
    const audArray = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!audArray.includes(expectedClientId)) {
      throw new Error(`OIDC Audience mismatch: expected "${expectedClientId}"`);
    }
  }

  // Sub check
  const sub = typeof payload.sub === 'string' ? payload.sub : '';
  if (!sub) {
    throw new Error('OIDC token missing "sub" subject claim');
  }

  // Email extraction
  const email = (typeof payload.email === 'string' ? payload.email : (typeof payload.upn === 'string' ? payload.upn : sub)).toLowerCase();

  // Name extraction
  const name = typeof payload.name === 'string'
    ? payload.name
    : (typeof payload.preferred_username === 'string' ? payload.preferred_username : email.split('@')[0] || 'OIDC User');

  // Groups extraction
  const groups: string[] = [];
  if (Array.isArray(payload.groups)) {
    groups.push(...payload.groups.map(String));
  } else if (Array.isArray(payload.roles)) {
    groups.push(...payload.roles.map(String));
  } else if (Array.isArray(payload['cognito:groups'])) {
    groups.push(...(payload['cognito:groups'] as unknown[]).map(String));
  }

  return {
    sub,
    email,
    name,
    groups,
    issuer: typeof payload.iss === 'string' ? payload.iss : undefined,
  };
}
