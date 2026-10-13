import { describe, it, expect } from 'vitest';
import {
  encrypt,
  decrypt,
  encryptObject,
  decryptObject,
  getMasterKey,
  generateTotp,
  verifyTotp,
  base32Encode,
  base32Decode,
  redactHeaders,
  redactObject,
  REDACTED_VALUE,
} from '../src/index.js';

describe('packages/crypto - Envelope Encryption (AES-256-GCM)', () => {
  it('should encrypt and decrypt a string payload successfully', () => {
    const masterKey = Buffer.alloc(32, 0x42);
    const plaintext = 'Bearer secret-customer-api-token-12345';

    const encrypted = encrypt(plaintext, masterKey);

    expect(encrypted.algorithm).toBe('aes-256-gcm');
    expect(encrypted.encryptedData).toBeDefined();
    expect(encrypted.iv).toBeDefined();
    expect(encrypted.tag).toBeDefined();
    expect(encrypted.encryptedDek).toBeDefined();
    expect(encrypted.dekIv).toBeDefined();
    expect(encrypted.dekTag).toBeDefined();

    // Verify plaintext is not in the encrypted payload
    expect(JSON.stringify(encrypted)).not.toContain(plaintext);

    const decrypted = decrypt(encrypted, masterKey);
    expect(decrypted).toBe(plaintext);
  });

  it('should reject decryption if ciphertext or tag is tampered with', () => {
    const masterKey = Buffer.alloc(32, 0x42);
    const plaintext = 'sensitive credentials';
    const encrypted = encrypt(plaintext, masterKey);

    // Tamper with encrypted data
    const tamperedData = Buffer.from(encrypted.encryptedData, 'base64');
    tamperedData[0] = (tamperedData[0] ?? 0) ^ 0xff;
    const tamperedPayload = {
      ...encrypted,
      encryptedData: tamperedData.toString('base64'),
    };

    expect(() => decrypt(tamperedPayload, masterKey)).toThrow();
  });

  it('should encrypt and decrypt arbitrary objects with encryptObject / decryptObject', () => {
    const masterKey = Buffer.alloc(32, 0x99);
    const original = {
      apiKey: 'sk_live_998877665544332211',
      headers: {
        Authorization: 'Bearer test-token',
        'X-Custom': 'value',
      },
      counter: 42,
    };

    const payload = encryptObject(original, masterKey);
    const restored = decryptObject<typeof original>(payload, masterKey);

    expect(restored).toEqual(original);
  });

  it('should resolve master key from environment or fallback', () => {
    const key = getMasterKey();
    expect(Buffer.isBuffer(key)).toBe(true);
    expect(key.length).toBe(32);
  });
});

describe('packages/crypto - RFC-6238 TOTP', () => {
  // RFC 6238 standard HMAC-SHA1 secret: "12345678901234567890" in ASCII
  // Base32 representation: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
  const rfcSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

  it('should generate expected TOTP tokens matching RFC-6238 test vectors', () => {
    // RFC 6238 Appendix B test vector for SHA1:
    // T = 59s -> Token = 287082
    const token59 = generateTotp(rfcSecret, { timestamp: 59 * 1000 });
    expect(token59).toBe('287082');

    // T = 1111111109s -> Token = 081804
    const tokenEpoch = generateTotp(rfcSecret, { timestamp: 1111111109 * 1000 });
    expect(tokenEpoch).toBe('081804');

    // T = 1234567890s -> Token = 005924
    const token1234 = generateTotp(rfcSecret, { timestamp: 1234567890 * 1000 });
    expect(token1234).toBe('005924');
  });

  it('should verify valid TOTP token within time drift window', () => {
    const now = 1700000000000;
    const token = generateTotp(rfcSecret, { timestamp: now });

    // Exact match
    expect(verifyTotp(token, rfcSecret, { timestamp: now })).toBe(true);

    // Within +1 step (30s drift)
    expect(verifyTotp(token, rfcSecret, { timestamp: now + 25000, window: 1 })).toBe(true);

    // Outside drift window (e.g. 90s later with window 1)
    expect(verifyTotp(token, rfcSecret, { timestamp: now + 90000, window: 1 })).toBe(false);

    // Invalid token
    expect(verifyTotp('999999', rfcSecret, { timestamp: now, window: 0 })).toBe(false);
  });

  it('should round-trip base32 encoding and decoding', () => {
    const original = Buffer.from('SecurityLabTesting2026');
    const encoded = base32Encode(original);
    const decoded = base32Decode(encoded);
    expect(decoded.toString()).toBe('SecurityLabTesting2026');
  });
});

describe('packages/crypto - Redaction', () => {
  it('should redact sensitive headers from request records', () => {
    const headers = {
      'Content-Type': 'application/json',
      Authorization: 'Bearer super-secret-token',
      Cookie: 'session=secret-cookie-val',
      'X-Api-Key': 'key-12345',
      'X-Normal-Header': 'public-info',
    };

    const redacted = redactHeaders(headers);

    expect(redacted['Content-Type']).toBe('application/json');
    expect(redacted['X-Normal-Header']).toBe('public-info');
    expect(redacted['Authorization']).toBe(REDACTED_VALUE);
    expect(redacted['Cookie']).toBe(REDACTED_VALUE);
    expect(redacted['X-Api-Key']).toBe(REDACTED_VALUE);
  });

  it('should redact sensitive properties deeply in objects', () => {
    const data = {
      name: 'Test target',
      credentials: {
        username: 'admin',
        password: 'super-secret-password',
      },
      apiKey: 'api-secret-key',
    };

    const redacted = redactObject(data);

    expect(redacted.name).toBe('Test target');
    expect(redacted.credentials.username).toBe('admin');
    expect(redacted.credentials.password).toBe(REDACTED_VALUE);
    expect(redacted.apiKey).toBe(REDACTED_VALUE);
  });
});
