import crypto from 'node:crypto';
import { canonicalizeJson } from './canonical-json.js';

export class AttestationConfigurationError extends Error {
  readonly code = 'ATTESTATION_CONFIGURATION_ERROR';

  constructor(message: string) {
    super(message);
    this.name = 'AttestationConfigurationError';
  }
}

let devEphemeralKey: string | null = null;

function getDevEphemeralKey(): string {
  if (!devEphemeralKey) {
    devEphemeralKey = crypto.randomBytes(32).toString('hex');
  }
  return devEphemeralKey;
}

/**
 * Resolves the primary master secret for cryptographic attestation.
 * - In production (NODE_ENV === 'production'):
 *   AGENT_MASTER_SECRET MUST be set and >= 32 characters, or throws AttestationConfigurationError.
 * - In test/development:
 *   If AGENT_MASTER_SECRET is set, uses it.
 *   If unset, allows an explicit key or generates an ephemeral runtime key,
 *   ensuring no static fallback key is ever baked into production builds.
 */
export function getMasterKey(explicitKey?: string): string {
  if (explicitKey !== undefined && explicitKey.trim().length > 0) {
    const trimmed = explicitKey.trim();
    if (process.env.NODE_ENV === 'production' && trimmed.length < 32) {
      throw new AttestationConfigurationError(
        'Attestation secret is too short: must be at least 32 characters in production.',
      );
    }
    return trimmed;
  }

  const envKey = process.env.AGENT_MASTER_SECRET?.trim();
  if (envKey && envKey.length >= 32) {
    return envKey;
  }

  if (process.env.NODE_ENV === 'production') {
    throw new AttestationConfigurationError(
      'Missing or invalid AGENT_MASTER_SECRET: In production, AGENT_MASTER_SECRET must be configured with at least 32 characters.',
    );
  }

  if (envKey && envKey.length > 0) {
    return envKey;
  }

  // Non-production fallback (ephemeral runtime key)
  return getDevEphemeralKey();
}

/**
 * Resolves optional previous master secret for zero-downtime key rotation.
 */
export function getPreviousMasterKey(explicitPreviousKey?: string): string | undefined {
  if (explicitPreviousKey !== undefined && explicitPreviousKey.trim().length > 0) {
    return explicitPreviousKey.trim();
  }
  const envPrevious = process.env.AGENT_MASTER_SECRET_PREVIOUS?.trim();
  return envPrevious && envPrevious.length >= 32 ? envPrevious : undefined;
}

/**
 * Executes a verification check against primary key, and falls back to previous key
 * if validation fails and a previous key is provided.
 */
export function verifyWithRotationSupport(
  verifyFn: (key: string) => boolean,
  primaryKey: string = getMasterKey(),
  previousKey?: string,
): boolean {
  if (verifyFn(primaryKey)) {
    return true;
  }

  const prevKey = getPreviousMasterKey(previousKey);
  if (prevKey && prevKey !== primaryKey) {
    return verifyFn(prevKey);
  }

  return false;
}

/**
 * Derives an ephemeral job dispatch secret bound to the specific job, lease, and agent.
 * Formula: HMAC-SHA256(MasterKey, jobId:leaseId:agentId)
 */
export function computeJobDispatchSecret(
  jobId: string,
  leaseId: string,
  agentId: string,
  masterKey?: string,
): string {
  const key = getMasterKey(masterKey);
  return crypto
    .createHmac('sha256', key)
    .update(`${jobId}:${leaseId}:${agentId}`)
    .digest('hex');
}

/**
 * Alias for computeJobDispatchSecret providing standard naming.
 */
export function deriveJobLeaseSecret(
  jobId: string,
  leaseId: string,
  agentId: string,
  masterKey?: string,
): string {
  return computeJobDispatchSecret(jobId, leaseId, agentId, masterKey);
}

/**
 * Signs a job lease token for distributed worker authentication.
 */
export function signJobLeaseToken(
  jobId: string,
  leaseId: string,
  agentId: string,
  masterKey?: string,
): string {
  return computeJobDispatchSecret(jobId, leaseId, agentId, masterKey);
}

/**
 * Verifies a job lease token with dual-key rotation support.
 */
export function verifyJobLeaseToken(params: {
  jobId: string;
  leaseId: string;
  agentId: string;
  token: string;
  masterKey?: string;
  previousMasterKey?: string;
}): boolean {
  if (!params.token || typeof params.token !== 'string') {
    return false;
  }

  const primaryKey = getMasterKey(params.masterKey);
  const previousKey = getPreviousMasterKey(params.previousMasterKey);

  return verifyWithRotationSupport(
    (key) => {
      const expected = computeJobDispatchSecret(params.jobId, params.leaseId, params.agentId, key);
      try {
        const tokenBuf = Buffer.from(params.token, 'hex');
        const expectedBuf = Buffer.from(expected, 'hex');
        if (tokenBuf.length !== expectedBuf.length || tokenBuf.length === 0) {
          return false;
        }
        return crypto.timingSafeEqual(tokenBuf, expectedBuf);
      } catch {
        return false;
      }
    },
    primaryKey,
    previousKey,
  );
}

/**
 * Computes a deterministic SHA-256 hash of the reported findings and executions
 * using RFC 8785 Canonical JSON to guarantee bit-for-bit authenticity.
 * Formula: SHA-256(CanonicalJSON(findings) + CanonicalJSON(executions))
 */
export function computeFindingsHash(findings: unknown[] = [], executions: unknown[] = []): string {
  const canonicalFindings = canonicalizeJson(findings);
  const canonicalExecutions = canonicalizeJson(executions);
  return crypto
    .createHash('sha256')
    .update(canonicalFindings + canonicalExecutions)
    .digest('hex');
}

/**
 * Computes an HMAC-SHA256 signature binding the ephemeral JobDispatchSecret to the findings hash.
 * Formula: HMAC-SHA256(JobDispatchSecret, jobId:FindingsHash)
 */
export function computeResultSignature(
  jobDispatchSecret: string,
  jobId: string,
  findingsHash: string,
): string {
  return crypto
    .createHmac('sha256', jobDispatchSecret)
    .update(`${jobId}:${findingsHash}`)
    .digest('hex');
}

/**
 * Timing-safe cryptographic verification of the agent result attestation signature.
 * Supports previousJobDispatchSecret for seamless key rotation.
 */
export function verifyResultSignature(params: {
  jobDispatchSecret: string;
  jobId: string;
  findings: unknown[];
  executions: unknown[];
  signature: string;
  previousJobDispatchSecret?: string;
}): boolean {
  if (!params.signature || typeof params.signature !== 'string') {
    return false;
  }

  const findingsHash = computeFindingsHash(params.findings, params.executions);

  const checkSecret = (secret: string): boolean => {
    const expectedSignature = computeResultSignature(
      secret,
      params.jobId,
      findingsHash,
    );

    try {
      const sigBuffer = Buffer.from(params.signature, 'hex');
      const expectedBuffer = Buffer.from(expectedSignature, 'hex');

      if (sigBuffer.length !== expectedBuffer.length || sigBuffer.length === 0) {
        return false;
      }

      return crypto.timingSafeEqual(sigBuffer, expectedBuffer);
    } catch {
      return false;
    }
  };

  if (checkSecret(params.jobDispatchSecret)) {
    return true;
  }

  if (params.previousJobDispatchSecret && params.previousJobDispatchSecret !== params.jobDispatchSecret) {
    return checkSecret(params.previousJobDispatchSecret);
  }

  return false;
}

/**
 * Computes an HMAC-SHA256 signature binding the target scope to the target ID and base URL.
 * Formula: HMAC-SHA256(MasterKey, targetId + baseUrl + CanonicalJSON(scope))
 */
export function computeScopeSignature(
  targetId: string,
  baseUrl: string,
  scope: unknown,
  masterKey?: string,
): string {
  const key = getMasterKey(masterKey);
  const canonicalScope = canonicalizeJson(scope);
  return crypto
    .createHmac('sha256', key)
    .update(`${targetId}${baseUrl}${canonicalScope}`)
    .digest('hex');
}

/**
 * Creates target scope attestation signature (alias for computeScopeSignature).
 */
export function createAgentAttestation(params: {
  targetId: string;
  baseUrl: string;
  scope: unknown;
  masterKey?: string;
}): string {
  return computeScopeSignature(params.targetId, params.baseUrl, params.scope, params.masterKey);
}

/**
 * Timing-safe cryptographic verification of the target scope attestation signature
 * with dual-key rotation support.
 */
export function verifyScopeSignature(params: {
  targetId: string;
  baseUrl: string;
  scope: unknown;
  signature: string;
  masterKey?: string;
  previousMasterKey?: string;
}): boolean {
  if (!params.signature || typeof params.signature !== 'string') {
    return false;
  }

  const primaryKey = getMasterKey(params.masterKey);
  const previousKey = getPreviousMasterKey(params.previousMasterKey);

  return verifyWithRotationSupport(
    (key) => {
      const expectedSignature = computeScopeSignature(
        params.targetId,
        params.baseUrl,
        params.scope,
        key,
      );

      try {
        const sigBuffer = Buffer.from(params.signature, 'hex');
        const expectedBuffer = Buffer.from(expectedSignature, 'hex');

        if (sigBuffer.length !== expectedBuffer.length || sigBuffer.length === 0) {
          return false;
        }

        return crypto.timingSafeEqual(sigBuffer, expectedBuffer);
      } catch {
        return false;
      }
    },
    primaryKey,
    previousKey,
  );
}

/**
 * Verifies agent attestation (alias for verifyScopeSignature).
 */
export function verifyAgentAttestation(params: {
  targetId: string;
  baseUrl: string;
  scope: unknown;
  signature: string;
  masterKey?: string;
  previousMasterKey?: string;
}): boolean {
  return verifyScopeSignature(params);
}
