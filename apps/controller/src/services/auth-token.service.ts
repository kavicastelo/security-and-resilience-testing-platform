import crypto from 'node:crypto';
import { AuthTokenPayload, Role } from '@security-lab/contracts';
import { config } from '../config/index.js';

export const DEFAULT_WORKSPACE_ID = '00000000-0000-0000-0000-000000000000';
export const DEFAULT_ADMIN_USER_ID = '00000000-0000-0000-0000-000000000001';

const JWT_SECRET = process.env.JWT_SECRET || config.SECURITY_LAB_ADMIN_KEY || 'default-jwt-secret-do-not-use-in-production';

/**
 * Standard RFC 7519 HMAC-SHA256 JWT generation with base64url encoding.
 */
export function signJwt(
  payload: {
    sub: string;
    email: string;
    name?: string;
    workspaceId: string;
    role: Role;
    tenantId?: string;
  },
  secret: string = JWT_SECRET,
  expiresInSeconds: number = 24 * 3600,
): string {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const fullPayload: AuthTokenPayload = {
    ...payload,
    iat: now,
    exp: now + expiresInSeconds,
  };

  const b64Header = Buffer.from(JSON.stringify(header)).toString('base64url');
  const b64Payload = Buffer.from(JSON.stringify(fullPayload)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', secret)
    .update(`${b64Header}.${b64Payload}`)
    .digest('base64url');

  return `${b64Header}.${b64Payload}.${signature}`;
}

/**
 * Validates HMAC-SHA256 JWT signature and expiration.
 */
export function verifyJwt(
  token: string,
  secret: string = JWT_SECRET,
): { valid: true; payload: AuthTokenPayload } | { valid: false; reason: string } {
  if (typeof token !== 'string') {
    return { valid: false, reason: 'Token must be a string' };
  }

  const parts = token.split('.');
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
    return { valid: false, reason: 'Malformed token structure' };
  }

  const [b64Header, b64Payload, signature] = parts as [string, string, string];
  try {
    const headerStr = Buffer.from(b64Header, 'base64url').toString('utf8');
    const header = JSON.parse(headerStr);
    if (header.alg !== 'HS256') {
      return { valid: false, reason: 'Unsupported JWT algorithm' };
    }

    const expectedSig = crypto
      .createHmac('sha256', secret)
      .update(`${b64Header}.${b64Payload}`)
      .digest('base64url');

    const sigBuf = Buffer.from(signature);
    const expBuf = Buffer.from(expectedSig);
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return { valid: false, reason: 'Invalid token signature' };
    }

    const payloadStr = Buffer.from(b64Payload, 'base64url').toString('utf8');
    const payload = JSON.parse(payloadStr) as AuthTokenPayload;

    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      return { valid: false, reason: 'Token has expired' };
    }

    return { valid: true, payload };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Token verification failed';
    return { valid: false, reason: msg };
  }
}

/**
 * Computes SHA-256 hash of API keys for database storage and lookup.
 */
export function hashApiKey(apiKey: string): string {
  return crypto.createHash('sha256').update(apiKey).digest('hex');
}

/**
 * Generates a high-entropy cryptographically secure API key.
 * Format: sec_key_<32 random hex chars>
 */
export function generateApiKey(prefix = 'sec_key_'): { secretKey: string; keyPrefix: string; keyHash: string } {
  const randomBytes = crypto.randomBytes(24).toString('hex');
  const secretKey = `${prefix}${randomBytes}`;
  const keyPrefix = secretKey.slice(0, 12);
  const keyHash = hashApiKey(secretKey);
  return { secretKey, keyPrefix, keyHash };
}

/**
 * Salted scrypt key derivation for user password hashing.
 */
export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, 64);
  return `scrypt:${salt}:${derivedKey.toString('hex')}`;
}

/**
 * Constant-time password verification.
 */
export function verifyPassword(password: string, storedHash: string): boolean {
  if (!storedHash || !storedHash.startsWith('scrypt:')) {
    return false;
  }
  const parts = storedHash.split(':');
  if (parts.length !== 3 || !parts[1] || !parts[2]) {
    return false;
  }
  const [, salt, originalHash] = parts as [string, string, string];
  const derivedKey = crypto.scryptSync(password, salt, 64);
  const keyBuf = derivedKey;
  const origBuf = Buffer.from(originalHash, 'hex');

  if (keyBuf.length !== origBuf.length) {
    return false;
  }
  return crypto.timingSafeEqual(keyBuf, origBuf);
}
