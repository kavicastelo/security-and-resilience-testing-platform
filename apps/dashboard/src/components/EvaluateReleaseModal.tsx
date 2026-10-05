import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Scale,
  X,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Download,
  ExternalLink,
  GitCommit,
  GitBranch,
  Tag,
  Loader2,
  ShieldCheck,
} from 'lucide-react';

interface EvaluateReleaseModalProps {
  isOpen: boolean;
  onClose: () => void;
  preselectedRunId?: string;
  apiUrl?: string;
}

interface PolicySummary {
  id: string;
  name: string;
  description?: string;
  rules: Array<{
    id: string;
    name: string;
    action: string;
    condition: Record<string, unknown>;
  }>;
}

interface TestRunSummary {
  id: string;
  targetId: string;
  status: string;
  createdAt: string;
  summary?: {
    totalTests: number;
    passedTests: number;
    failedTests: number;
    findingsCount: {
      critical: number;
      high: number;
      medium: number;
      low: number;
      info: number;
    };
  };
}

interface EvaluationResult {
  decision: 'allow' | 'block_release' | 'warn';
  passed: boolean;
  score: {
    score: number;
    grade: string;
    breakdown: {
      criticalCount: number;
      highCount: number;
      mediumCount: number;
      lowCount: number;
      infoCount: number;
    };
  };
  gateResult: {
    decision: 'allow' | 'block_release' | 'warn';
    passed: boolean;
    violations: Array<{
      ruleId: string;
      ruleName: string;
      action: string;
      reason: string;
      severity?: string;
    }>;
  };
  policy: PolicySummary;
  release?: {
    id: string;
    name: string;
    version: string;
    decision: string;
    reason?: string;
  };
}

export const EvaluateReleaseModal: React.FC<EvaluateReleaseModalProps> = ({
  isOpen,
  onClose,
  preselectedRunId,
  apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000',
}) => {
  const queryClient = useQueryClient();
  const [selectedRunId, setSelectedRunId] = useState<string>(preselectedRunId || '');
  const [selectedPolicyId, setSelectedPolicyId] = useState<string>('');
  const [releaseName, setReleaseName] = useState<string>('Production Release');
  const [releaseVersion, setReleaseVersion] = useState<string>('v1.0.0');
  const [gitCommit, setGitCommit] = useState<string>('main-HEAD');
  const [gitBranch, setGitBranch] = useState<string>('main');
  const [evaluationResult, setEvaluationResult] = useState<EvaluationResult | null>(null);

  // Sync preselected run
  React.useEffect(() => {
    if (preselectedRunId) {
      setSelectedRunId(preselectedRunId);
    }
  }, [preselectedRunId]);

  // Fetch policies
  const { data: policies = [] } = useQuery<PolicySummary[]>({
    queryKey: ['policies'],
    queryFn: async () => {
      const res = await fetch(`${apiUrl}/api/v1/policies`);
      const json = await res.json();
      return json.data || [];
    },
    enabled: isOpen,
  });

  // Fetch runs if not preselected
  const { data: testRuns = [] } = useQuery<TestRunSummary[]>({
    queryKey: ['test-runs'],
    queryFn: async () => {
      const res = await fetch(`${apiUrl}/api/v1/test-runs`);
      const json = await res.json();
      return (json.data || []).filter((r: TestRunSummary) => r.status === 'completed');
    },
    enabled: isOpen && !preselectedRunId,
  });

  // Evaluate Mutation
  const evaluateMutation = useMutation({
    mutationFn: async () => {
      const payload = {
        testRunId: selectedRunId,
        policyId: selectedPolicyId || undefined,
        name: releaseName.trim() || undefined,
        version: releaseVersion.trim() || undefined,
        gitCommit: gitCommit.trim() || undefined,
        gitBranch: gitBranch.trim() || undefined,
      };

      const res = await fetch(`${apiUrl}/api/v1/releases/evaluate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const errorJson = await res.json();
        throw new Error(errorJson.error?.message || 'Failed to evaluate release gate');
      }

      const json = await res.json();
      return json.data as EvaluationResult;
    },
    onSuccess: (data) => {
      setEvaluationResult(data);
      queryClient.invalidateQueries({ queryKey: ['releases'] });
    },
  });

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-card border border-border w-full max-w-2xl rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-border flex items-center justify-between bg-card/60">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400">
              <Scale className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-foreground">Release Gate Evaluation</h2>
              <p className="text-xs text-muted-foreground">
                Automated go/no-go compliance audit against security & latency SLA policies
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-5 flex-1">
          {!evaluationResult ? (
            /* Input Form */
            <div className="space-y-4">
              {/* Test Run Selection */}
              <div>
                <label className="block text-xs font-semibold text-foreground mb-1.5">
                  Select Executed Test Run <span className="text-rose-400">*</span>
                </label>
                {preselectedRunId ? (
                  <div className="p-2.5 rounded-lg bg-accent/40 border border-border font-mono text-xs text-foreground flex items-center justify-between">
                    <span>{preselectedRunId}</span>
                    <span className="text-[10px] bg-blue-500/20 text-blue-400 px-2 py-0.5 rounded">
                      Preselected
                    </span>
                  </div>
                ) : (
                  <select
                    value={selectedRunId}
                    onChange={(e) => setSelectedRunId(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground text-xs focus:outline-none focus:border-blue-500"
                  >
                    <option value="">-- Choose a completed test execution --</option>
                    {testRuns.map((r) => (
                      <option key={r.id} value={r.id}>
                        {r.id.slice(0, 12)}... (Passed: {r.summary?.passedTests ?? 0} | Fail:{' '}
                        {r.summary?.failedTests ?? 0} | Crit: {r.summary?.findingsCount?.critical ?? 0})
                      </option>
                    ))}
                  </select>
                )}
              </div>

              {/* Policy Selection */}
              <div>
                <label className="block text-xs font-semibold text-foreground mb-1.5">
                  Release Gate Policy
                </label>
                <select
                  value={selectedPolicyId}
                  onChange={(e) => setSelectedPolicyId(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground text-xs focus:outline-none focus:border-blue-500"
                >
                  <option value="">Enterprise Security Baseline Gate (Built-in Default)</option>
                  {policies.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.rules.length} rules)
                    </option>
                  ))}
                </select>
                <p className="text-[11px] text-muted-foreground mt-1">
                  Enforces zero critical vulnerabilities, latency SLA limits, and maximum acceptable risk.
                </p>
              </div>

              {/* Release Metadata */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
                <div>
                  <label className="block text-xs font-semibold text-foreground mb-1 flex items-center gap-1.5">
                    <Tag className="w-3.5 h-3.5 text-blue-400" /> Release Name
                  </label>
                  <input
                    type="text"
                    value={releaseName}
                    onChange={(e) => setReleaseName(e.target.value)}
                    placeholder="e.g. Core API Service"
                    className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground text-xs focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-foreground mb-1 flex items-center gap-1.5">
                    <Tag className="w-3.5 h-3.5 text-blue-400" /> Release Version / Tag
                  </label>
                  <input
                    type="text"
                    value={releaseVersion}
                    onChange={(e) => setReleaseVersion(e.target.value)}
                    placeholder="e.g. v2.4.0-rc1"
                    className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground text-xs focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-foreground mb-1 flex items-center gap-1.5">
                    <GitCommit className="w-3.5 h-3.5 text-blue-400" /> Git Commit SHA
                  </label>
                  <input
                    type="text"
                    value={gitCommit}
                    onChange={(e) => setGitCommit(e.target.value)}
                    placeholder="e.g. a7c9f3e"
                    className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground text-xs focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-foreground mb-1 flex items-center gap-1.5">
                    <GitBranch className="w-3.5 h-3.5 text-blue-400" /> Git Branch
                  </label>
                  <input
                    type="text"
                    value={gitBranch}
                    onChange={(e) => setGitBranch(e.target.value)}
                    placeholder="e.g. main or release/v2"
                    className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground text-xs focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              {evaluateMutation.isError && (
                <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs flex items-center gap-2">
                  <XCircle className="w-4 h-4 shrink-0" />
                  <span>{(evaluateMutation.error as Error).message}</span>
                </div>
              )}
            </div>
          ) : (
            /* Evaluation Results Screen */
            <div className="space-y-4">
              {/* Decision Hero Banner */}
              <div
                className={`p-5 rounded-xl border flex items-center justify-between ${
                  evaluationResult.passed
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                    : 'bg-rose-500/10 border-rose-500/30 text-rose-400'
                }`}
              >
                <div className="flex items-center gap-3.5">
                  <div
                    className={`p-2.5 rounded-xl border ${
                      evaluationResult.passed
                        ? 'bg-emerald-500/20 border-emerald-500/30'
                        : 'bg-rose-500/20 border-rose-500/30'
                    }`}
                  >
                    {evaluationResult.passed ? (
                      <ShieldCheck className="w-6 h-6 text-emerald-400" />
                    ) : (
                      <XCircle className="w-6 h-6 text-rose-400" />
                    )}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-base font-bold tracking-tight">
                        {evaluationResult.passed ? 'RELEASE GATE PASSED' : 'RELEASE GATE BLOCKED'}
                      </span>
                      <span
                        className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded font-semibold ${
                          evaluationResult.decision === 'block_release'
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                            : evaluationResult.decision === 'warn'
                              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                              : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                        }`}
                      >
                        {evaluationResult.decision}
                      </span>
                    </div>
                    <p className="text-xs opacity-90 mt-0.5">
                      {evaluationResult.passed
                        ? 'All security assertions and latency SLA conditions satisfied. Safe for production promotion.'
                        : 'Policy violations detected. Release does not meet enterprise deployment criteria.'}
                    </p>
                  </div>
                </div>

                {/* Posture Score Badge */}
                <div className="text-right pl-4 border-l border-border/40 shrink-0">
                  <div className="text-2xl font-black text-foreground">
                    Grade {evaluationResult.score?.grade || 'N/A'}
                  </div>
                  <div className="text-xs font-mono text-muted-foreground">
                    Score: {evaluationResult.score?.score ?? 100}/100
                  </div>
                </div>
              </div>

              {/* Policy Snapshot */}
              <div className="p-3.5 rounded-xl bg-accent/40 border border-border text-xs space-y-1">
                <div className="flex items-center justify-between text-muted-foreground">
                  <span className="font-semibold text-foreground">Policy Applied:</span>
                  <span className="font-mono text-[11px]">{evaluationResult.policy?.name}</span>
                </div>
                {evaluationResult.release && (
                  <div className="flex items-center justify-between text-muted-foreground">
                    <span>Audit Record ID:</span>
                    <span className="font-mono text-[11px] text-blue-400">
                      {evaluationResult.release.id}
                    </span>
                  </div>
                )}
              </div>

              {/* Violations / Breaches */}
              <div className="space-y-2">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Policy Assertions & Breaches (
                  {evaluationResult.gateResult?.violations?.length ?? 0})
                </h4>

                {evaluationResult.gateResult?.violations?.length === 0 ? (
                  <div className="p-3.5 rounded-lg bg-emerald-500/5 border border-emerald-500/20 text-emerald-400 text-xs flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 shrink-0" />
                    <span>0 policy violations. All zero-tolerance and SLA rules satisfied.</span>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {evaluationResult.gateResult?.violations?.map((v, i) => (
                      <div
                        key={i}
                        className={`p-3 rounded-lg border text-xs space-y-1 ${
                          v.action === 'block_release'
                            ? 'bg-rose-500/10 border-rose-500/20 text-rose-300'
                            : 'bg-amber-500/10 border-amber-500/20 text-amber-300'
                        }`}
                      >
                        <div className="flex items-center justify-between font-semibold">
                          <span className="flex items-center gap-1.5">
                            {v.action === 'block_release' ? (
                              <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                            ) : (
                              <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                            )}
                            {v.ruleName}
                          </span>
                          <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-background/50">
                            {v.action}
                          </span>
                        </div>
                        <p className="text-[11px] opacity-90 pl-5">{v.reason}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Enterprise Artifact Downloads */}
              <div className="pt-2 border-t border-border space-y-2">
                <span className="text-xs font-semibold text-muted-foreground block">
                  Export Enterprise Reports:
                </span>
                <div className="flex flex-wrap gap-2">
                  <a
                    href={`${apiUrl}/api/v1/test-runs/${selectedRunId}/report?format=html`}
                    target="_blank"
                    rel="noreferrer"
                    className="px-3 py-1.5 rounded-lg bg-blue-600/15 hover:bg-blue-600/25 border border-blue-500/30 text-blue-400 font-mono text-xs flex items-center gap-1.5 transition-colors"
                  >
                    <ExternalLink className="w-3.5 h-3.5" /> HTML Executive Audit
                  </a>
                  <a
                    href={`${apiUrl}/api/v1/test-runs/${selectedRunId}/report?format=junit`}
                    target="_blank"
                    rel="noreferrer"
                    className="px-3 py-1.5 rounded-lg bg-emerald-600/15 hover:bg-emerald-600/25 border border-emerald-500/30 text-emerald-400 font-mono text-xs flex items-center gap-1.5 transition-colors"
                  >
                    <Download className="w-3.5 h-3.5" /> JUnit XML
                  </a>
                  <a
                    href={`${apiUrl}/api/v1/test-runs/${selectedRunId}/report?format=sarif`}
                    target="_blank"
                    rel="noreferrer"
                    className="px-3 py-1.5 rounded-lg bg-purple-600/15 hover:bg-purple-600/25 border border-purple-500/30 text-purple-400 font-mono text-xs flex items-center gap-1.5 transition-colors"
                  >
                    <Download className="w-3.5 h-3.5" /> SARIF v2.1.0
                  </a>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-4 border-t border-border flex items-center justify-between bg-card/60">
          {evaluationResult ? (
            <>
              <button
                onClick={() => setEvaluationResult(null)}
                className="px-4 py-2 rounded-lg bg-accent hover:bg-accent/80 text-foreground text-xs font-medium transition-colors"
              >
                ← Back to Parameters
              </button>
              <button
                onClick={onClose}
                className="px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-colors"
              >
                Close Audit
              </button>
            </>
          ) : (
            <>
              <button
                onClick={onClose}
                className="px-4 py-2 rounded-lg bg-accent hover:bg-accent/80 text-muted-foreground text-xs font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => evaluateMutation.mutate()}
                disabled={!selectedRunId || evaluateMutation.isPending}
                className="flex items-center gap-2 px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-medium transition-colors shadow-lg shadow-blue-500/10"
              >
                {evaluateMutation.isPending ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Evaluating Gating Rules...</span>
                  </>
                ) : (
                  <>
                    <Scale className="w-4 h-4" />
                    <span>Evaluate Release Gate</span>
                  </>
                )}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
