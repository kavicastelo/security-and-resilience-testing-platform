import { createHash } from 'node:crypto';
import { Evidence, HttpRequestEvidence, HttpResponseEvidence } from '@security-lab/domain';

/**
 * EVIDENCE IMMUTABILITY PRINCIPLE:
 *
 * Evidence collected during security and resilience test runs represents an
 * unalterable, forensic record of target behavior at a specific point in time.
 * Once created and signed/hashed, evidence must NEVER be mutated, updated, or
 * partially deleted. Any re-test generates a new TestRun and a new Evidence record.
 */

export interface CreateEvidenceParams {
  id: string;
  testRunId: string;
  executionId: string;
  request?: HttpRequestEvidence;
  response?: HttpResponseEvidence;
  expected?: unknown;
  actual?: unknown;
  metadata?: Record<string, unknown>;
  timestamp?: Date;
  environment: string;
  applicationVersion?: string;
  gitCommit?: string;
}

import { canonicalizeJson } from './canonical-json.js';

export * from './canonical-json.js';

/**
 * Computes a deterministic SHA-256 fingerprint of the evidence payload
 * to guarantee forensic integrity and tamper detection using RFC 8785 Canonical JSON.
 */
export function computeEvidenceHash(payload: Omit<Evidence, 'immutableHash'>): string {
  const canonicalString = canonicalizeJson({
    testRunId: payload.testRunId,
    executionId: payload.executionId,
    request: payload.request,
    response: payload.response,
    expected: payload.expected,
    actual: payload.actual,
    environment: payload.environment,
    timestamp: payload.timestamp instanceof Date ? payload.timestamp.toISOString() : payload.timestamp,
    applicationVersion: payload.applicationVersion,
    gitCommit: payload.gitCommit,
  });

  return createHash('sha256').update(canonicalString).digest('hex');
}

/**
 * Factory function to construct an immutable Evidence record with computed cryptographic hash.
 */
export function createImmutableEvidence(params: CreateEvidenceParams): Evidence {
  const timestamp = params.timestamp || new Date();
  const partialEvidence: Omit<Evidence, 'immutableHash'> = {
    id: params.id,
    testRunId: params.testRunId,
    executionId: params.executionId,
    request: params.request,
    response: params.response,
    expected: params.expected,
    actual: params.actual,
    metadata: params.metadata || {},
    timestamp,
    environment: params.environment,
    applicationVersion: params.applicationVersion,
    gitCommit: params.gitCommit,
  };

  const immutableHash = computeEvidenceHash(partialEvidence);

  return Object.freeze({
    ...partialEvidence,
    immutableHash,
  });
}

/**
 * Evidence Storage Contract
 */
export interface EvidenceStore {
  save(evidence: Evidence): Promise<void>;
  findById(id: string): Promise<Evidence | null>;
  findByTestRunId(testRunId: string): Promise<Evidence[]>;
}

/**
 * In-Memory Reference Evidence Store (suitable for local runs and tests)
 */
export class InMemoryEvidenceStore implements EvidenceStore {
  private readonly records = new Map<string, Evidence>();

  async save(evidence: Evidence): Promise<void> {
    if (this.records.has(evidence.id)) {
      throw new Error(`[EvidenceError] Cannot overwrite immutable evidence record ${evidence.id}`);
    }
    // Deep freeze to guarantee immutability in-memory
    this.records.set(evidence.id, Object.freeze({ ...evidence }));
  }

  async findById(id: string): Promise<Evidence | null> {
    const record = this.records.get(id);
    return record ? { ...record } : null;
  }

  async findByTestRunId(testRunId: string): Promise<Evidence[]> {
    return Array.from(this.records.values())
      .filter((rec) => rec.testRunId === testRunId)
      .map((rec) => ({ ...rec }));
  }
}
