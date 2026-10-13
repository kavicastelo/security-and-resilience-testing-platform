import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export interface AgentKeypair {
  publicKey: string;
  privateKey: string;
  fingerprint: string;
}

export interface RequestSignParams {
  method: string;
  path: string;
  timestamp: number | string;
  body?: unknown;
}

export interface RequestVerifyParams extends RequestSignParams {
  signature: string;
  maxDriftMs?: number;
}

export interface VerificationResult {
  valid: boolean;
  error?: string;
  code?: 'INVALID_SIGNATURE' | 'REPLAY_ATTACK_DETECTED' | 'MALFORMED_REQUEST' | 'KEY_ERROR';
}

/**
 * Calculates SHA-256 hex fingerprint for a given SPKI PEM public key.
 */
export function computeKeyFingerprint(publicKeyPem: string): string {
  const normalized = publicKeyPem.trim().replace(/\r\n/g, '\n');
  return crypto.createHash('sha256').update(normalized, 'utf8').digest('hex');
}

/**
 * Generates an asymmetric Ed25519 keypair for cryptographic agent attestation.
 */
export function generateAgentKeypair(): AgentKeypair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  const fingerprint = computeKeyFingerprint(publicKey);

  return {
    publicKey: publicKey.trim(),
    privateKey: privateKey.trim(),
    fingerprint,
  };
}

/**
 * Calculates SHA-256 hash of request body for signature inclusion.
 */
export function computeBodyHash(body?: unknown): string {
  if (body === undefined || body === null || body === '') {
    return '';
  }
  const payloadStr = typeof body === 'string' ? body : JSON.stringify(body);
  return crypto.createHash('sha256').update(payloadStr, 'utf8').digest('hex');
}

/**
 * Formats canonical signing string:
 * METHOD:PATH:TIMESTAMP:BODY_HASH
 */
export function buildCanonicalRequest(params: RequestSignParams): string {
  const cleanMethod = (params.method || 'GET').toUpperCase().trim();
  const cleanPath = (params.path || '/').trim();
  const cleanTimestamp = String(params.timestamp).trim();
  const bodyHash = computeBodyHash(params.body);

  return `${cleanMethod}:${cleanPath}:${cleanTimestamp}:${bodyHash}`;
}

/**
 * Signs an outgoing agent HTTP request using Ed25519 private key.
 * Returns Base64-encoded signature.
 */
export function signAgentRequest(privateKeyPem: string, params: RequestSignParams): string {
  const canonical = buildCanonicalRequest(params);
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const signatureBuffer = crypto.sign(null, Buffer.from(canonical, 'utf8'), privateKey);
  return signatureBuffer.toString('base64');
}

/**
 * Verifies an incoming agent HTTP request against its registered public key.
 * Validates timestamp freshness (60s anti-replay) and Ed25519 signature.
 */
export function verifyAgentRequest(
  publicKeyPem: string,
  params: RequestVerifyParams,
): VerificationResult {
  const maxDriftMs = params.maxDriftMs ?? 60000; // 60-second replay window
  const requestTime = Number(params.timestamp);

  if (isNaN(requestTime)) {
    return {
      valid: false,
      error: 'Invalid or missing timestamp in agent request',
      code: 'MALFORMED_REQUEST',
    };
  }

  const now = Date.now();
  const drift = Math.abs(now - requestTime);
  if (drift > maxDriftMs) {
    return {
      valid: false,
      error: `Timestamp drift of ${drift}ms exceeds maximum allowable ${maxDriftMs}ms replay window`,
      code: 'REPLAY_ATTACK_DETECTED',
    };
  }

  try {
    const canonical = buildCanonicalRequest(params);
    const publicKey = crypto.createPublicKey(publicKeyPem);
    const signatureBuffer = Buffer.from(params.signature, 'base64');

    const isValid = crypto.verify(
      null,
      Buffer.from(canonical, 'utf8'),
      publicKey,
      signatureBuffer,
    );

    if (!isValid) {
      return {
        valid: false,
        error: 'Cryptographic signature verification failed',
        code: 'INVALID_SIGNATURE',
      };
    }

    return { valid: true };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      valid: false,
      error: `Key verification error: ${msg}`,
      code: 'KEY_ERROR',
    };
  }
}

/**
 * Saves an agent keypair to disk, ensuring strict file permissions (0600) on the private key.
 */
export function saveAgentKeypair(keyDir: string, keypair: AgentKeypair): void {
  fs.mkdirSync(keyDir, { recursive: true });

  const privateKeyPath = path.join(keyDir, 'agent_private.key');
  const publicKeyPath = path.join(keyDir, 'agent_public.pem');

  // Write private key with restrictive 0600 mode
  fs.writeFileSync(privateKeyPath, keypair.privateKey, { mode: 0o600 });
  try {
    fs.chmodSync(privateKeyPath, 0o600);
  } catch {
    // fs.chmod on Windows may be a no-op or throw on certain filesystems
  }

  // Write public key with standard 0644 mode
  fs.writeFileSync(publicKeyPath, keypair.publicKey, { mode: 0o644 });
}

/**
 * Loads an existing keypair from keyDir, or generates and saves a new one.
 */
export function loadOrCreateAgentKeypair(keyDir: string): AgentKeypair {
  const privateKeyPath = path.join(keyDir, 'agent_private.key');
  const publicKeyPath = path.join(keyDir, 'agent_public.pem');

  if (fs.existsSync(privateKeyPath) && fs.existsSync(publicKeyPath)) {
    const privateKey = fs.readFileSync(privateKeyPath, 'utf8').trim();
    const publicKey = fs.readFileSync(publicKeyPath, 'utf8').trim();
    const fingerprint = computeKeyFingerprint(publicKey);

    // Ensure permissions remain 0600
    try {
      fs.chmodSync(privateKeyPath, 0o600);
    } catch {
      // ignore on non-posix
    }

    return { publicKey, privateKey, fingerprint };
  }

  const generated = generateAgentKeypair();
  saveAgentKeypair(keyDir, generated);
  return generated;
}
