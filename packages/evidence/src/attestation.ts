import crypto from 'node:crypto';
import { canonicalizeJson } from './canonical-json.js';

export const DEFAULT_MASTER_KEY = 'security-lab-master-agent-secret';

/**
 * Derives an ephemeral job dispatch secret bound to the specific job, lease, and agent.
 * Formula: HMAC-SHA256(MasterKey, jobId:leaseId:agentId)
 */
export function computeJobDispatchSecret(
  jobId: string,
  leaseId: string,
  agentId: string,
  masterKey: string = process.env.AGENT_MASTER_SECRET || DEFAULT_MASTER_KEY,
): string {
  return crypto
    .createHmac('sha256', masterKey)
    .update(`${jobId}:${leaseId}:${agentId}`)
    .digest('hex');
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
 */
export function verifyResultSignature(params: {
  jobDispatchSecret: string;
  jobId: string;
  findings: unknown[];
  executions: unknown[];
  signature: string;
}): boolean {
  if (!params.signature || typeof params.signature !== 'string') {
    return false;
  }

  const findingsHash = computeFindingsHash(params.findings, params.executions);
  const expectedSignature = computeResultSignature(
    params.jobDispatchSecret,
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
}

/**
 * Computes an HMAC-SHA256 signature binding the target scope to the target ID and base URL.
 * Formula: HMAC-SHA256(MasterKey, targetId + baseUrl + CanonicalJSON(scope))
 */
export function computeScopeSignature(
  targetId: string,
  baseUrl: string,
  scope: unknown,
  masterKey: string = process.env.AGENT_MASTER_SECRET || DEFAULT_MASTER_KEY,
): string {
  const canonicalScope = canonicalizeJson(scope);
  return crypto
    .createHmac('sha256', masterKey)
    .update(`${targetId}${baseUrl}${canonicalScope}`)
    .digest('hex');
}

/**
 * Timing-safe cryptographic verification of the target scope attestation signature.
 */
export function verifyScopeSignature(params: {
  targetId: string;
  baseUrl: string;
  scope: unknown;
  signature: string;
  masterKey?: string;
}): boolean {
  if (!params.signature || typeof params.signature !== 'string') {
    return false;
  }

  const expectedSignature = computeScopeSignature(
    params.targetId,
    params.baseUrl,
    params.scope,
    params.masterKey,
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
}

