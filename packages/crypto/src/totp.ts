import crypto from 'node:crypto';

export interface TotpOptions {
  /** Time step in seconds. Default: 30 */
  step?: number;
  /** Number of digits. Default: 6 */
  digits?: number;
  /** Cryptographic algorithm. Default: 'sha1' */
  algorithm?: 'sha1' | 'sha256' | 'sha512';
  /** Verification window (steps before and after). Default: 1 */
  window?: number;
  /** Timestamp in milliseconds. Default: Date.now() */
  timestamp?: number;
}

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Decodes a Base32 string into a Buffer.
 */
export function base32Decode(input: string): Buffer {
  const cleanInput = input.toUpperCase().replace(/[=\s-]/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (let i = 0; i < cleanInput.length; i++) {
    const char = cleanInput.charAt(i);
    const index = BASE32_CHARS.indexOf(char);
    if (index === -1) {
      throw new Error(`Invalid Base32 character: "${char}" in secret`);
    }

    value = (value << 5) | index;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

/**
 * Encodes a Buffer or string into a Base32 string.
 */
export function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i] ?? 0;
    value = (value << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      const idx = (value >>> (bits - 5)) & 31;
      output += BASE32_CHARS.charAt(idx);
      bits -= 5;
    }
  }

  if (bits > 0) {
    const idx = (value << (5 - bits)) & 31;
    output += BASE32_CHARS.charAt(idx);
  }

  return output;
}

/**
 * Generates an RFC-6238 TOTP token for a given Base32 secret seed.
 */
export function generateTotp(secret: string, options: TotpOptions = {}): string {
  const step = options.step ?? 30;
  const digits = options.digits ?? 6;
  const algorithm = options.algorithm ?? 'sha1';
  const timestamp = options.timestamp ?? Date.now();

  const secretBuffer = base32Decode(secret);
  const timeStep = Math.floor(timestamp / 1000 / step);

  // Time step counter as 8-byte big-endian Buffer
  const timeBuffer = Buffer.alloc(8);
  timeBuffer.writeBigUInt64BE(BigInt(timeStep));

  // Compute HMAC
  const hmac = crypto.createHmac(algorithm, secretBuffer).update(timeBuffer).digest();

  // Dynamic truncation (RFC 4226 Section 5.4)
  const lastByte = hmac[hmac.length - 1] ?? 0;
  const offset = lastByte & 0x0f;
  const b0 = hmac[offset] ?? 0;
  const b1 = hmac[offset + 1] ?? 0;
  const b2 = hmac[offset + 2] ?? 0;
  const b3 = hmac[offset + 3] ?? 0;

  const binary =
    ((b0 & 0x7f) << 24) |
    ((b1 & 0xff) << 16) |
    ((b2 & 0xff) << 8) |
    (b3 & 0xff);

  const otp = binary % Math.pow(10, digits);
  return otp.toString().padStart(digits, '0');
}

/**
 * Verifies an RFC-6238 TOTP token against a secret with time-window drift tolerance.
 */
export function verifyTotp(token: string, secret: string, options: TotpOptions = {}): boolean {
  const step = options.step ?? 30;
  const window = options.window ?? 1;
  const timestamp = options.timestamp ?? Date.now();
  const digits = options.digits ?? 6;

  const trimmedToken = token.trim();
  if (trimmedToken.length !== digits) {
    return false;
  }

  for (let errorWindow = -window; errorWindow <= window; errorWindow++) {
    const candidateTimestamp = timestamp + errorWindow * step * 1000;
    const candidateToken = generateTotp(secret, {
      ...options,
      timestamp: candidateTimestamp,
    });

    if (crypto.timingSafeEqual(Buffer.from(candidateToken), Buffer.from(trimmedToken))) {
      return true;
    }
  }

  return false;
}
