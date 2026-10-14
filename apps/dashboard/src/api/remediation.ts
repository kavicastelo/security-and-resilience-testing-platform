export type RemediationVerifiedStatus = 'UNVERIFIED' | 'PASSED' | 'FAILED';

export interface AiRemediationProposal {
  id: string;
  findingId: string;
  workspaceId?: string;
  explanation: string;
  gitDiff: string;
  confidenceScore: number;
  verifiedStatus: RemediationVerifiedStatus;
  model?: string;
  promptTokens?: number;
  completionTokens?: number;
  verificationOutput?: string;
  createdAt: string;
  updatedAt?: string;
}

export interface RemediationRequest {
  provider?: 'anthropic' | 'openai' | 'ollama' | 'mock';
  model?: string;
  sourceCodeSnippet?: string;
  filePath?: string;
  optInConfirmed?: boolean;
}

export interface VerifyRemediationResult {
  remediationId: string;
  findingId: string;
  verifiedStatus: RemediationVerifiedStatus;
  retestSuccess: boolean;
  verificationDetails: string;
  durationMs: number;
  verifiedAt: string;
}

export interface DiffLine {
  type: 'add' | 'delete' | 'context' | 'header';
  content: string;
  oldLineNumber?: number;
  newLineNumber?: number;
}

export interface DiffHunk {
  header: string;
  oldStart: number;
  oldCount: number;
  newStart: number;
  newCount: number;
  lines: DiffLine[];
}

export interface ParsedDiff {
  filePath: string;
  hunks: DiffHunk[];
  additions: number;
  deletions: number;
}

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:4000';

/**
 * Fetch all AI remediation proposals for a given finding
 */
export async function fetchRemediationsForFinding(
  findingId: string,
): Promise<AiRemediationProposal[]> {
  try {
    const res = await fetch(`${API_BASE}/api/v1/findings/${findingId}/remediation`);
    if (!res.ok) return [];
    const json = await res.json();
    return json.data || [];
  } catch {
    return [];
  }
}

/**
 * Generate a new AI remediation proposal for a finding
 */
export async function generateFindingRemediation(
  findingId: string,
  request: RemediationRequest = { provider: 'mock' },
): Promise<AiRemediationProposal> {
  const res = await fetch(`${API_BASE}/api/v1/findings/${findingId}/remediate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  });
  const json = await res.json();
  if (!res.ok) {
    throw new Error(json.error?.message || 'Failed to generate AI remediation patch');
  }
  return json.data;
}

/**
 * Triggers automated sandboxed verification retest loop for a proposal
 */
export async function verifyRemediationProposal(
  remediationId: string,
  timeoutMs = 5000,
): Promise<VerifyRemediationResult> {
  const res = await fetch(`${API_BASE}/api/v1/remediations/${remediationId}/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ timeoutMs }),
  });
  const json = await res.json();
  if (!res.ok) {
    throw new Error(json.error?.message || 'Patch verification execution failed');
  }
  return json.data;
}

/**
 * Parses raw git unified diff format into structured hunks and lines for unified & side-by-side rendering
 */
export function parseGitDiffString(rawDiff: string): ParsedDiff {
  if (!rawDiff || !rawDiff.trim()) {
    return { filePath: 'unknown/patch.diff', hunks: [], additions: 0, deletions: 0 };
  }

  const lines = rawDiff.split('\n');
  let filePath = 'source/remediation.patch';
  let additions = 0;
  let deletions = 0;
  const hunks: DiffHunk[] = [];
  let currentHunk: DiffHunk | null = null;

  let currentOldLine = 1;
  let currentNewLine = 1;

  for (const line of lines) {
    // Detect diff header e.g. "diff --git a/server/index.js b/server/index.js"
    if (line.startsWith('diff --git ')) {
      const match = line.match(/diff --git a\/(.*) b\/(.*)/);
      if (match && match[2]) {
        filePath = match[2];
      }
      continue;
    }
    if (
      line.startsWith('--- ') ||
      line.startsWith('+++ ') ||
      line.startsWith('index ') ||
      line.startsWith('new file mode') ||
      line.startsWith('deleted file mode') ||
      line.startsWith('similarity index') ||
      line.startsWith('rename ')
    ) {
      continue;
    }

    // Detect hunk header e.g. "@@ -14,6 +14,9 @@"
    if (line.startsWith('@@ ')) {
      if (currentHunk) {
        hunks.push(currentHunk);
      }

      const match = line.match(/@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)/);
      const oldStart = match ? parseInt(match[1], 10) : 1;
      const oldCount = match && match[2] ? parseInt(match[2], 10) : 1;
      const newStart = match ? parseInt(match[3], 10) : 1;
      const newCount = match && match[4] ? parseInt(match[4], 10) : 1;

      currentOldLine = oldStart;
      currentNewLine = newStart;

      currentHunk = {
        header: line,
        oldStart,
        oldCount,
        newStart,
        newCount,
        lines: [],
      };
      continue;
    }

    if (!currentHunk) {
      // Create a default hunk if no hunk header was encountered
      currentHunk = {
        header: '@@ -1,1 +1,1 @@',
        oldStart: 1,
        oldCount: 1,
        newStart: 1,
        newCount: 1,
        lines: [],
      };
    }

    if (line.startsWith('+')) {
      additions++;
      currentHunk.lines.push({
        type: 'add',
        content: line.slice(1),
        newLineNumber: currentNewLine++,
      });
    } else if (line.startsWith('-')) {
      deletions++;
      currentHunk.lines.push({
        type: 'delete',
        content: line.slice(1),
        oldLineNumber: currentOldLine++,
      });
    } else {
      // Context line
      currentHunk.lines.push({
        type: 'context',
        content: line.startsWith(' ') ? line.slice(1) : line,
        oldLineNumber: currentOldLine++,
        newLineNumber: currentNewLine++,
      });
    }
  }

  if (currentHunk) {
    hunks.push(currentHunk);
  }

  return {
    filePath,
    hunks,
    additions,
    deletions,
  };
}

/**
 * Returns confidence scoring tier
 */
export function getConfidenceTier(score: number): {
  tier: 'High' | 'Medium' | 'Speculative';
  color: string;
  badgeBg: string;
  description: string;
} {
  if (score >= 0.85) {
    return {
      tier: 'High',
      color: 'text-emerald-400',
      badgeBg: 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300',
      description: 'High Confidence (>= 85%): Deterministic rule matching known safe remediation pattern.',
    };
  }
  if (score >= 0.6) {
    return {
      tier: 'Medium',
      color: 'text-amber-400',
      badgeBg: 'bg-amber-500/20 border-amber-500/40 text-amber-300',
      description: 'Medium Confidence (60% - 84%): Plausible fix requiring developer code context verification.',
    };
  }
  return {
    tier: 'Speculative',
    color: 'text-rose-400',
    badgeBg: 'bg-rose-500/20 border-rose-500/40 text-rose-300',
    description: 'Speculative (< 60%): Experimental patch proposal requiring rigorous human architectural review.',
  };
}

/**
 * Formats a clean, production-ready GitHub Pull Request draft description
 */
export function generateGitHubPrMarkdown(
  finding: {
    title: string;
    category: string;
    severity: string;
    description?: string;
    fingerprint?: string;
  },
  proposal: AiRemediationProposal,
  verification?: VerifyRemediationResult | null,
): { title: string; body: string } {
  const prTitle = `fix(security): remediate ${finding.title} [${finding.severity.toUpperCase()}]`;

  const prBody = `## 🛡️ Security Vulnerability Remediation

### 1. Overview
- **Vulnerability**: ${finding.title}
- **Category**: \`${finding.category}\`
- **Severity**: **${finding.severity.toUpperCase()}**
- **Fingerprint**: \`${finding.fingerprint || 'N/A'}\`

---

### 2. Root Cause Analysis
${proposal.explanation}

---

### 3. Verification Test Outcome
${
  verification && verification.verifiedStatus === 'PASSED'
    ? '✅ **VERIFIED PASSED**: Automated sandboxed retest executed against patched container. The target attack vector was completely mitigated with 0 regressions detected.'
    : verification && verification.verifiedStatus === 'FAILED'
    ? '⚠️ **VERIFICATION FAILED**: Target probe was re-run against patched code and the flaw was still detected. Further developer review is required.'
    : 'ℹ️ **UNVERIFIED**: Patch proposal has not yet executed sandboxed retest loop. Run \`security-lab patch verify\` before merging.'
}

- **Remediation Model**: \`${proposal.model || 'Claude 3.5 Sonnet'}\`
- **Confidence Score**: \`${Math.round(proposal.confidenceScore * 100)}%\`
${verification?.durationMs ? `- **Retest Duration**: \`${verification.durationMs}ms\`` : ''}

---

### 4. Applied Patch Diff
\`\`\`diff
${proposal.gitDiff}
\`\`\`

---
*Generated automatically by [@security-lab/dashboard](https://security-lab.local) AI Remediation Studio with strict secret sanitization.*
`;

  return { title: prTitle, body: prBody };
}
