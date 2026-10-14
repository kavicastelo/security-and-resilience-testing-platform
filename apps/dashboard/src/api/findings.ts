export { generateCurlSnippet } from '../lib/curl.js';
export type { RequestEvidenceLike } from '../lib/curl.js';

export interface FindingItem {
  id: string;
  fingerprint: string;
  title: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence?: string;
  status: string;
  description: string;
  risk?: string;
  recommendation?: string;
  testDefinitionId: string;
  testRunId: string;
  executionId?: string;
  targetId: string;
  evidenceId?: string;
  firstDetectedAt: string;
  fixedInRunId?: string | null;
  isFlapping?: boolean;
  flappingScore?: number;
  metadata?: {
    ruleId?: string;
    endpoint?: string;
    parameter?: string;
    tags?: string[];
    unstableFlapping?: boolean;
    runHistory?: Array<{ runId: string; status: string; timestamp?: string }>;
    [key: string]: unknown;
  };
}

export interface EvidenceRecord {
  id: string;
  testRunId: string;
  executionId?: string;
  request?: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
  };
  response?: {
    statusCode: number;
    headers: Record<string, string>;
    body?: string;
    responseTimeMs?: number;
  };
  expected?: unknown;
  actual?: unknown;
  immutableHash: string;
  timestamp: string;
  rawWireFrame?: string;
}

export interface FlappingRunSnapshot {
  runId: string;
  status: string;
  timestamp: string;
}

export interface FlappingAnalysis {
  findingId: string;
  fingerprint: string;
  targetId: string;
  totalRunsAnalyzed: number;
  transitionsCount: number;
  flappingScore: number;
  isFlapping: boolean;
  suppressReleaseGate: boolean;
  history: FlappingRunSnapshot[];
}

export type DiffCategory = 'new' | 'resolved' | 'persistent' | 'flapping';

export interface RunDiffFinding extends FindingItem {
  diffCategory: DiffCategory;
  diffNote?: string;
}

export interface RunDiffResult {
  baseRunId: string;
  targetRunId: string;
  baseRunName?: string;
  targetRunName?: string;
  computedAt: string;
  summary: {
    newCount: number;
    resolvedCount: number;
    persistentCount: number;
    flappingCount: number;
    totalDifferences: number;
  };
  categories: {
    newVulnerabilities: RunDiffFinding[];
    resolvedFindings: RunDiffFinding[];
    persistentIssues: RunDiffFinding[];
    flappingAnomalies: RunDiffFinding[];
  };
}

export interface PolicyWaiverPayload {
  findingId: string;
  fingerprint: string;
  reason: string;
  approvedBy: string;
  days: number;
  expiresAt: string;
  riskTier?: 'low' | 'medium' | 'high' | 'business_exception';
  actorId?: string;
}

export interface RetestResult {
  findingId: string;
  status: 'resolved' | 'open' | 'reopened' | 'suppressed' | 'error';
  stillDetected: boolean;
  testedEndpoint?: string;
  ruleId?: string;
  durationMs: number;
  retestRunId?: string;
  message?: string;
  timestamp: string;
}

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:4000';

/**
 * Fetch all findings, optionally filtered by targetId or testRunId
 */
export async function fetchFindings(params?: {
  targetId?: string;
  testRunId?: string;
  severity?: string;
  status?: string;
}): Promise<FindingItem[]> {
  const url = new URL(`${API_BASE}/api/v1/findings`);
  if (params?.targetId) url.searchParams.set('targetId', params.targetId);
  if (params?.testRunId) url.searchParams.set('testRunId', params.testRunId);
  if (params?.severity && params.severity !== 'all') url.searchParams.set('severity', params.severity);
  if (params?.status && params.status !== 'all') url.searchParams.set('status', params.status);

  try {
    const res = await fetch(url.toString());
    if (!res.ok) throw new Error(`Failed to fetch findings (${res.status})`);
    const json = await res.json();
    return json.data || [];
  } catch {
    return [];
  }
}

/**
 * Fetch specific evidence record by ID or testRunId
 */
export async function fetchEvidenceRecord(
  evidenceId: string,
  testRunId?: string,
): Promise<EvidenceRecord | null> {
  // First try direct evidence endpoint
  try {
    const directRes = await fetch(`${API_BASE}/api/v1/evidence/${evidenceId}`);
    if (directRes.ok) {
      const json = await directRes.json();
      if (json.data) return json.data;
    }
  } catch {
    // Continue to test run fallback
  }

  // Fallback to test-run evidence collection
  if (testRunId) {
    try {
      const runRes = await fetch(`${API_BASE}/api/v1/test-runs/${testRunId}/evidence`);
      if (runRes.ok) {
        const json = await runRes.json();
        const list: EvidenceRecord[] = json.data || [];
        const match = list.find((e) => e.id === evidenceId) || list[0];
        if (match) return match;
      }
    } catch {
      // Return null on failure
    }
  }

  return null;
}

/**
 * Fetch historical flapping analysis for a specific finding
 */
export async function fetchFlappingAnalysis(
  findingId: string,
  maxRuns = 10,
): Promise<FlappingAnalysis | null> {
  try {
    const res = await fetch(`${API_BASE}/api/v1/findings/${findingId}/flapping?maxRuns=${maxRuns}`);
    if (res.ok) {
      const json = await res.json();
      return json.data || null;
    }
  } catch {
    // Return null on fallback
  }
  return null;
}

/**
 * Execute targeted single-finding retest
 */
export async function executeSingleFindingRetest(
  findingId: string,
  timeoutMs = 5000,
): Promise<RetestResult> {
  const res = await fetch(`${API_BASE}/api/v1/findings/${findingId}/retest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ timeoutMs }),
  });
  const json = await res.json();
  if (!res.ok) {
    throw new Error(json.error?.message || 'Retest execution failed');
  }
  return json.data;
}

/**
 * Submit timed policy waiver
 */
export async function submitPolicyWaiver(
  payload: PolicyWaiverPayload,
): Promise<{ success: boolean; expiresAt: string }> {
  // 1. Post to policy waivers endpoint
  const waiverRes = await fetch(`${API_BASE}/api/v1/policies/waivers`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      fingerprint: payload.fingerprint,
      reason: payload.reason,
      approvedBy: payload.approvedBy,
      expiresAt: payload.expiresAt,
    }),
  });
  if (!waiverRes.ok) {
    const json = await waiverRes.json().catch(() => ({}));
    throw new Error(json.error?.message || 'Failed to register policy waiver');
  }

  // 2. Transition finding state to suppressed/waived
  const triageRes = await fetch(`${API_BASE}/api/v1/findings/${payload.findingId}/triage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      status: 'suppressed',
      notes: `Temporary waiver active (${payload.days}d): ${payload.reason} (Approved by: ${payload.approvedBy})`,
      expiresAt: payload.expiresAt,
      actorId: payload.approvedBy,
    }),
  });

  if (!triageRes.ok) {
    // Try PATCH fallback if triage route returned non-200
    await fetch(`${API_BASE}/api/v1/findings/${payload.findingId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        status: 'suppressed',
        notes: `Temporary waiver active (${payload.days}d): ${payload.reason}`,
      }),
    });
  }

  return { success: true, expiresAt: payload.expiresAt };
}

/**
 * Computes run-over-run diffing between two test runs.
 * Compares findings by fingerprint and title to classify:
 * - New: Detected in Target Run, absent in Base Run
 * - Resolved: Present in Base Run, absent or resolved in Target Run
 * - Persistent: Present in both Base and Target Run with active state
 * - Flapping: Finding marked with isFlapping=true or oscillating across runs
 */
export function calculateRunOverRunDiff(
  baseFindings: FindingItem[],
  targetFindings: FindingItem[],
  baseRunId: string,
  targetRunId: string,
): RunDiffResult {
  const baseMap = new Map<string, FindingItem>();
  for (const f of baseFindings) {
    baseMap.set(f.fingerprint || f.id, f);
  }

  const targetMap = new Map<string, FindingItem>();
  for (const f of targetFindings) {
    targetMap.set(f.fingerprint || f.id, f);
  }

  const newVulnerabilities: RunDiffFinding[] = [];
  const resolvedFindings: RunDiffFinding[] = [];
  const persistentIssues: RunDiffFinding[] = [];
  const flappingAnomalies: RunDiffFinding[] = [];

  // Check target findings against base
  for (const tf of targetFindings) {
    const key = tf.fingerprint || tf.id;
    const baseMatch = baseMap.get(key);

    const isFlapping =
      Boolean(tf.isFlapping) ||
      (typeof tf.flappingScore === 'number' && tf.flappingScore > 0.4) ||
      Boolean(tf.metadata?.unstableFlapping);

    if (isFlapping) {
      flappingAnomalies.push({
        ...tf,
        diffCategory: 'flapping',
        diffNote: `Oscillating finding (Flapping score: ${(tf.flappingScore ?? 0.5).toFixed(2)})`,
      });
    } else if (!baseMatch) {
      newVulnerabilities.push({
        ...tf,
        diffCategory: 'new',
        diffNote: 'New vulnerability introduced in this build run',
      });
    } else {
      // In both runs
      if (tf.status === 'resolved' || tf.status === 'fixed') {
        resolvedFindings.push({
          ...tf,
          diffCategory: 'resolved',
          diffNote: `Resolved in target run #${targetRunId.slice(0, 8)}`,
        });
      } else {
        persistentIssues.push({
          ...tf,
          diffCategory: 'persistent',
          diffNote: `Unresolved across runs (Base #${baseRunId.slice(0, 8)} -> Target #${targetRunId.slice(0, 8)})`,
        });
      }
    }
  }

  // Check base findings that are completely missing in target
  for (const bf of baseFindings) {
    const key = bf.fingerprint || bf.id;
    if (!targetMap.has(key)) {
      const isFlapping =
        Boolean(bf.isFlapping) ||
        (typeof bf.flappingScore === 'number' && bf.flappingScore > 0.4) ||
        Boolean(bf.metadata?.unstableFlapping);

      if (isFlapping) {
        if (!flappingAnomalies.some((item) => (item.fingerprint || item.id) === key)) {
          flappingAnomalies.push({
            ...bf,
            diffCategory: 'flapping',
            diffNote: 'Flapping anomaly absent in latest run',
          });
        }
      } else {
        resolvedFindings.push({
          ...bf,
          diffCategory: 'resolved',
          diffNote: `Remediated or cleared in target run #${targetRunId.slice(0, 8)}`,
        });
      }
    }
  }

  const totalDifferences =
    newVulnerabilities.length +
    resolvedFindings.length +
    flappingAnomalies.length;

  return {
    baseRunId,
    targetRunId,
    computedAt: new Date().toISOString(),
    summary: {
      newCount: newVulnerabilities.length,
      resolvedCount: resolvedFindings.length,
      persistentCount: persistentIssues.length,
      flappingCount: flappingAnomalies.length,
      totalDifferences,
    },
    categories: {
      newVulnerabilities,
      resolvedFindings,
      persistentIssues,
      flappingAnomalies,
    },
  };
}

/**
 * Hex dump generator that turns a string or byte array into standard canonical hex display:
 * 00000000: 50 4f 53 54 20 2f 61 70  69 2f 76 31 2f 74 65 73 |POST /api/v1/tes|
 */
export function generateCanonicalHexDump(input: string | Uint8Array | null | undefined): string {
  if (!input) return '00000000: (Empty Wire Buffer)';

  const bytes: number[] =
    typeof input === 'string'
      ? Array.from(new TextEncoder().encode(input))
      : Array.from(input);

  if (bytes.length === 0) return '00000000: (Empty Wire Buffer)';

  const lines: string[] = [];
  const chunkSize = 16;

  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    const chunk = bytes.slice(offset, offset + chunkSize);
    const hexOffset = offset.toString(16).padStart(8, '0');

    // First 8 bytes
    const first8 = chunk
      .slice(0, 8)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(' ');
    // Next 8 bytes
    const next8 = chunk
      .slice(8, 16)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(' ');

    // Pad hex representations to 24 chars for alignment
    const hexPart = `${first8.padEnd(23, ' ')}  ${next8.padEnd(23, ' ')}`;

    // ASCII representation: non-printable chars replaced with '.'
    const asciiPart = chunk
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
      .join('');

    lines.push(`${hexOffset}: ${hexPart} |${asciiPart}|`);
  }

  return lines.join('\n');
}

/**
 * Reconstructs raw HTTP wire socket frame preserving CRLF line endings
 */
export function reconstructRawWireFrame(evidence?: EvidenceRecord | null): string {
  if (!evidence) return '// No raw wire frame captured for this evidence';

  const parts: string[] = [];

  if (evidence.request) {
    const req = evidence.request;
    const urlObj = (() => {
      try {
        return new URL(req.url);
      } catch {
        return { pathname: req.url || '/', host: 'target.local' };
      }
    })();

    parts.push(`>>> CLIENT REQUEST SOCKET FRAME >>>`);
    parts.push(`${(req.method || 'GET').toUpperCase()} ${urlObj.pathname || '/'} HTTP/1.1\r\n`);
    parts.push(`Host: ${urlObj.host || 'target.local'}\r\n`);

    if (req.headers) {
      for (const [key, val] of Object.entries(req.headers)) {
        if (key.toLowerCase() !== 'host') {
          parts.push(`${key}: ${val}\r\n`);
        }
      }
    }
    parts.push('\r\n'); // End of headers
    if (req.body) {
      parts.push(typeof req.body === 'string' ? req.body : JSON.stringify(req.body, null, 2));
      parts.push('\r\n');
    }
  }

  if (evidence.response) {
    const res = evidence.response;
    const statusText =
      res.statusCode === 200
        ? 'OK'
        : res.statusCode === 201
        ? 'Created'
        : res.statusCode === 204
        ? 'No Content'
        : res.statusCode === 400
        ? 'Bad Request'
        : res.statusCode === 401
        ? 'Unauthorized'
        : res.statusCode === 403
        ? 'Forbidden'
        : res.statusCode === 404
        ? 'Not Found'
        : res.statusCode === 422
        ? 'Unprocessable Entity'
        : res.statusCode === 500
        ? 'Internal Server Error'
        : res.statusCode === 502
        ? 'Bad Gateway'
        : res.statusCode === 503
        ? 'Service Unavailable'
        : 'Status';

    parts.push(`\r\n<<< SERVER RESPONSE SOCKET FRAME <<<\r\n`);
    parts.push(`HTTP/1.1 ${res.statusCode || 200} ${statusText}\r\n`);

    if (res.headers) {
      for (const [key, val] of Object.entries(res.headers)) {
        parts.push(`${key}: ${val}\r\n`);
      }
    }
    parts.push('\r\n'); // End of headers
    if (res.body) {
      parts.push(typeof res.body === 'string' ? res.body : JSON.stringify(res.body, null, 2));
      parts.push('\r\n');
    }
  }

  return parts.length > 0
    ? parts.join('')
    : '// No HTTP socket frame available for this finding';
}

/**
 * Computes remaining time until waiver expiration
 */
export function calculateWaiverCountdown(expiresAtString?: string | null): {
  isExpired: boolean;
  days: number;
  hours: number;
  minutes: number;
  label: string;
} {
  if (!expiresAtString) {
    return { isExpired: true, days: 0, hours: 0, minutes: 0, label: 'No Waiver' };
  }

  const expiryTime = new Date(expiresAtString).getTime();
  const now = Date.now();
  const diff = expiryTime - now;

  if (diff <= 0) {
    return { isExpired: true, days: 0, hours: 0, minutes: 0, label: 'Waiver Expired' };
  }

  const totalMinutes = Math.floor(diff / (1000 * 60));
  const days = Math.floor(totalMinutes / (60 * 24));
  const hours = Math.floor((totalMinutes % (60 * 24)) / 60);
  const minutes = totalMinutes % 60;

  let label = '';
  if (days > 0) {
    label = `${days}d ${hours}h left`;
  } else if (hours > 0) {
    label = `${hours}h ${minutes}m left`;
  } else {
    label = `${minutes}m left`;
  }

  return { isExpired: false, days, hours, minutes, label };
}
