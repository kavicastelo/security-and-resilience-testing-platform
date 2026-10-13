import crypto from 'node:crypto';
import { z } from 'zod';

export const EncryptedPayloadSchema = z.object({
  algorithm: z.literal('aes-256-gcm'),
  encryptedData: z.string(), // base64
  iv: z.string(), // base64 (96-bit / 12-byte)
  tag: z.string(), // base64 (128-bit / 16-byte)
  encryptedDek: z.string(), // base64
  dekIv: z.string(), // base64 (96-bit / 12-byte)
  dekTag: z.string(), // base64 (128-bit / 16-byte)
  keyId: z.string().optional(),
});

export type EncryptedPayload = z.infer<typeof EncryptedPayloadSchema>;

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits recommended for GCM
const DEK_LENGTH = 32; // 256 bits

// Deterministic in-memory key for testing and local mode
const LOCAL_DEV_MASTER_KEY = crypto.createHash('sha256').update('security-lab-default-local-master-key-32-bytes').digest();

/**
 * Resolves the 32-byte master encryption key from environment or fallback.
 */
export function getMasterKey(explicitKey?: string | Buffer): Buffer {
  if (Buffer.isBuffer(explicitKey)) {
    if (explicitKey.length !== 32) {
      throw new Error(`Master key Buffer must be exactly 32 bytes, received ${explicitKey.length}`);
    }
    return explicitKey;
  }

  if (typeof explicitKey === 'string' && explicitKey.trim().length > 0) {
    const raw = explicitKey.trim();
    if (raw.length === 64 && /^[0-9a-fA-F]+$/.test(raw)) {
      return Buffer.from(raw, 'hex');
    }
    try {
      const b64Buf = Buffer.from(raw, 'base64');
      if (b64Buf.length === 32) return b64Buf;
    } catch {
      // fallback to hash
    }
    return crypto.createHash('sha256').update(raw, 'utf-8').digest();
  }

  const envKey = process.env.SECURITY_LAB_MASTER_KEY;
  if (envKey && envKey.trim().length > 0) {
    const raw = envKey.trim();
    if (raw.length === 64 && /^[0-9a-fA-F]+$/.test(raw)) {
      return Buffer.from(raw, 'hex');
    }
    try {
      const b64Buf = Buffer.from(raw, 'base64');
      if (b64Buf.length === 32) return b64Buf;
    } catch {
      // fallback to hash
    }
    return crypto.createHash('sha256').update(raw, 'utf-8').digest();
  }

  // In test or local CLI environments, allow the fallback deterministic key
  if (
    process.env.NODE_ENV === 'test' ||
    process.env.SECURITY_LAB_LOCAL_MODE === 'true' ||
    process.env.SECURITY_LAB_BYPASS_AUTH_IN_TESTS === 'true' ||
    process.argv.includes('--local')
  ) {
    return LOCAL_DEV_MASTER_KEY;
  }

  throw new Error(
    'Missing master encryption key. SECURITY_LAB_MASTER_KEY environment variable must be set.',
  );
}

/**
 * Encrypts a plaintext string using envelope encryption (AES-256-GCM).
 * Generates an ephemeral Data Encryption Key (DEK), encrypts the plaintext with DEK,
 * and encrypts the DEK with the master key.
 */
export function encrypt(plaintext: string, masterKey: Buffer, keyId?: string): EncryptedPayload {
  if (masterKey.length !== 32) {
    throw new Error(`Master key must be exactly 32 bytes, got ${masterKey.length}`);
  }

  // 1. Generate ephemeral DEK (Data Encryption Key)
  const dek = crypto.randomBytes(DEK_LENGTH);

  // 2. Encrypt plaintext with DEK using AES-256-GCM
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, dek, iv);
  const encryptedData = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  // 3. Encrypt DEK with Master Key (KEK) using AES-256-GCM
  const dekIv = crypto.randomBytes(IV_LENGTH);
  const dekCipher = crypto.createCipheriv(ALGORITHM, masterKey, dekIv);
  const encryptedDek = Buffer.concat([dekCipher.update(dek), dekCipher.final()]);
  const dekTag = dekCipher.getAuthTag();

  return {
    algorithm: 'aes-256-gcm',
    encryptedData: encryptedData.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    encryptedDek: encryptedDek.toString('base64'),
    dekIv: dekIv.toString('base64'),
    dekTag: dekTag.toString('base64'),
    ...(keyId ? { keyId } : {}),
  };
}

/**
 * Decrypts an envelope-encrypted payload using the master key (AES-256-GCM).
 */
export function decrypt(payload: EncryptedPayload, masterKey: Buffer): string {
  if (masterKey.length !== 32) {
    throw new Error(`Master key must be exactly 32 bytes, got ${masterKey.length}`);
  }

  if (payload.algorithm !== 'aes-256-gcm') {
    throw new Error(`Unsupported encryption algorithm: ${payload.algorithm}`);
  }

  // 1. Decrypt DEK using Master Key (KEK)
  const dekIv = Buffer.from(payload.dekIv, 'base64');
  const dekTag = Buffer.from(payload.dekTag, 'base64');
  const encryptedDek = Buffer.from(payload.encryptedDek, 'base64');

  const dekDecipher = crypto.createDecipheriv(ALGORITHM, masterKey, dekIv);
  dekDecipher.setAuthTag(dekTag);
  const dek = Buffer.concat([dekDecipher.update(encryptedDek), dekDecipher.final()]);

  // 2. Decrypt plaintext using DEK
  const iv = Buffer.from(payload.iv, 'base64');
  const tag = Buffer.from(payload.tag, 'base64');
  const encryptedData = Buffer.from(payload.encryptedData, 'base64');

  const decipher = crypto.createDecipheriv(ALGORITHM, dek, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);

  return decrypted.toString('utf8');
}

/**
 * Encrypts an arbitrary serializable JSON object.
 */
export function encryptObject<T>(data: T, masterKey?: Buffer, keyId?: string): EncryptedPayload {
  const resolvedKey = masterKey ?? getMasterKey();
  const jsonStr = JSON.stringify(data);
  return encrypt(jsonStr, resolvedKey, keyId);
}

/**
 * Decrypts an encrypted payload back into a typed JSON object.
 */
export function decryptObject<T>(payload: EncryptedPayload, masterKey?: Buffer): T {
  const resolvedKey = masterKey ?? getMasterKey();
  const jsonStr = decrypt(payload, resolvedKey);
  return JSON.parse(jsonStr) as T;
}
