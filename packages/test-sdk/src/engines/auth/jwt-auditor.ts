import crypto from 'node:crypto';

export interface DecodedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
  raw: string;
  headerRaw: string;
  payloadRaw: string;
}

/**
 * Base64URL decodes a string to a UTF-8 string.
 */
export function base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString('utf8');
}

/**
 * Base64URL encodes a UTF-8 string or Buffer.
 */
export function base64UrlEncode(str: string | Buffer): string {
  const buf = Buffer.isBuffer(str) ? str : Buffer.from(str, 'utf8');
  return buf
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

/**
 * Decodes a raw JWT string into header, payload, and signature without verifying cryptographic signature.
 * Returns null if string is malformed or parts are not valid JSON.
 */
export function decodeJwt(token: string): DecodedJwt | null {
  if (!token || typeof token !== 'string') {
    return null;
  }

  const parts = token.trim().split('.');
  if (parts.length !== 3) {
    return null;
  }

  const [headerRaw, payloadRaw, signature] = parts;
  if (!headerRaw || !payloadRaw || signature === undefined) {
    return null;
  }

  try {
    const headerStr = base64UrlDecode(headerRaw);
    const payloadStr = base64UrlDecode(payloadRaw);

    const header = JSON.parse(headerStr);
    const payload = JSON.parse(payloadStr);

    if (typeof header !== 'object' || header === null || typeof payload !== 'object' || payload === null) {
      return null;
    }

    return {
      header: header as Record<string, unknown>,
      payload: payload as Record<string, unknown>,
      signature,
      raw: token.trim(),
      headerRaw,
      payloadRaw,
    };
  } catch {
    return null;
  }
}

/**
 * Masks the signature and sensitive payload claims in a JWT for safe reporting and logging.
 */
export function maskJwt(token: string): string {
  const decoded = decodeJwt(token);
  if (!decoded) {
    return '[INVALID_OR_MALFORMED_JWT]';
  }

  const maskedSignature = decoded.signature ? `${decoded.signature.slice(0, 6)}...[MASKED]` : '[UNSIGNED]';
  return `${decoded.headerRaw}.${decoded.payloadRaw}.${maskedSignature}`;
}

/**
 * Creates an unsigned JWT with alg="none" (or specified casing) and an empty signature.
 */
export function createNoneAlgToken(token: string, casing: 'none' | 'None' | 'NONE' = 'none'): string {
  const decoded = decodeJwt(token);
  if (!decoded) {
    // If not decodeable, fallback to a minimal sample payload
    const header = base64UrlEncode(JSON.stringify({ alg: casing, typ: 'JWT' }));
    const payload = base64UrlEncode(JSON.stringify({ sub: 'audit-user', iat: Math.floor(Date.now() / 1000) }));
    return `${header}.${payload}.`;
  }

  const modifiedHeader: Record<string, unknown> = { ...decoded.header, alg: casing };
  // If 'crit' list exists and contains 'alg', delete it to maximize compatibility
  if (Array.isArray(modifiedHeader['crit'])) {
    modifiedHeader['crit'] = (modifiedHeader['crit'] as string[]).filter((c) => c !== 'alg');
  }

  const newHeaderRaw = base64UrlEncode(JSON.stringify(modifiedHeader));
  return `${newHeaderRaw}.${decoded.payloadRaw}.`;
}

/**
 * Creates a JWT with an expired `exp` timestamp in the payload.
 */
export function createExpiredToken(token: string, expiredBySeconds = 86400): string {
  const decoded = decodeJwt(token);
  const now = Math.floor(Date.now() / 1000);
  const expiredTime = now - expiredBySeconds;

  if (!decoded) {
    const header = base64UrlEncode(JSON.stringify({ alg: 'none', typ: 'JWT' }));
    const payload = base64UrlEncode(JSON.stringify({ sub: 'audit-user', exp: expiredTime }));
    return `${header}.${payload}.`;
  }

  const modifiedPayload = { ...decoded.payload, exp: expiredTime };
  const newPayloadRaw = base64UrlEncode(JSON.stringify(modifiedPayload));

  return `${decoded.headerRaw}.${newPayloadRaw}.${decoded.signature}`;
}

/**
 * Creates a JWT with the cryptographic signature completely stripped off (trailing dot retained).
 */
export function createSignatureStrippedToken(token: string): string {
  const decoded = decodeJwt(token);
  if (!decoded) {
    const parts = token.split('.');
    if (parts.length >= 2) {
      return `${parts[0]}.${parts[1]}.`;
    }
    return `${token}.`;
  }
  return `${decoded.headerRaw}.${decoded.payloadRaw}.`;
}

/**
 * Signs a payload with HMAC-SHA256 using a known weak secret key.
 */
export function createHmacToken(
  payload: Record<string, unknown>,
  secret: string,
  alg: 'HS256' | 'HS384' | 'HS512' = 'HS256',
): string {
  const header = { alg, typ: 'JWT' };
  const headerRaw = base64UrlEncode(JSON.stringify(header));
  const payloadRaw = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${headerRaw}.${payloadRaw}`;

  const hashAlg = alg === 'HS512' ? 'sha512' : alg === 'HS384' ? 'sha384' : 'sha256';
  const signature = crypto.createHmac(hashAlg, secret).update(signingInput).digest();
  const signatureRaw = base64UrlEncode(signature);

  return `${signingInput}.${signatureRaw}`;
}
