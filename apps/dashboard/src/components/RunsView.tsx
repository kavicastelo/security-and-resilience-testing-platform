import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Play,
  RotateCw,
  Clock,
  ShieldAlert,
  ChevronDown,
  ChevronRight,
  Code,
  CheckCircle2,
  XCircle,
  Activity,
} from 'lucide-react';

interface Target {
  id: string;
  projectId: string;
  name: string;
  baseUrl: string;
}

interface TestRunSummary {
  totalTests: number;
  passedTests: number;
  failedTests: number;
  errorTests: number;
  findingsCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

interface TestRun {
  id: string;
  projectId: string;
  targetId: string;
  profileId?: string;
  status: 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  startedAt?: string;
  completedAt?: string;
  summary: TestRunSummary;
  createdAt: string;
}

interface TestRunExecutionResult {
  testRun: TestRun;
  executions: {
    id: string;
    engineId: string;
    status: string;
    durationMs?: number;
    error?: string;
  }[];
}

const DEFAULT_DECLARATIVE_YAML = `id: custom-http-security-audit
name: Custom HTTP Security Baseline
version: 1.0.0
category: http_security
description: Evaluates status codes and mandatory defensive headers
target:
  endpoint: /
  requiredCapabilities: []
tests:
  - id: status-check
    name: Root Endpoint Status
    path: /
    method: GET
    expectedStatus: [200, 301, 302]
    assertions:
      - field: headers.strict-transport-security
        operator: exists
        severity: medium
        message: HSTS header is missing
      - field: headers.x-content-type-options
        operator: equals
        value: nosniff
        severity: low
        message: X-Content-Type-Options must be set to nosniff
`;

export const RunsView: React.FC = () => {
  const queryClient = useQueryClient();
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000';

  const [selectedTargetId, setSelectedTargetId] = useState<string>('');
  const [executionMode, setExecutionMode] = useState<'class_a' | 'declarative'>('class_a');
  const [selectedEngines, setSelectedEngines] = useState<string[]>([
    'engine-native-headers',
    'engine-native-cors',
    'engine-native-tls',
  ]);
  const [declarativeYaml, setDeclarativeYaml] = useState(DEFAULT_DECLARATIVE_YAML);
  const [expandedRunId, setExpandedRunId] = useState<string | null>(null);

  // 1. Fetch Targets
  const { data: targets = [] } = useQuery<Target[]>({
    queryKey: ['targets'],
    queryFn: async () => {
      const res = await fetch(`${apiUrl}/api/v1/targets`);
      const json = await res.json();
      return json.data || [];
    },
  });

  // 2. Fetch Test Runs
  const { data: testRuns = [], isLoading: isLoadingRuns, refetch } = useQuery<TestRun[]>({
    queryKey: ['test-runs'],
    queryFn: async () => {
      const res = await fetch(`${apiUrl}/api/v1/test-runs`);
      const json = await res.json();
      return (json.data || []).sort(
        (a: TestRun, b: TestRun) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
      );
    },
  });

  // 3. Trigger Test Run Mutation
  const triggerMutation = useMutation({
    mutationFn: async () => {
      if (!selectedTargetId) throw new Error('Please select a target');
      const target = targets.find((t) => t.id === selectedTargetId);
      if (!target) throw new Error('Target not found');

      // Create Run
      const createRes = await fetch(`${apiUrl}/api/v1/test-runs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId: target.projectId || target.id,
          targetId: target.id,
          profileId: executionMode === 'declarative' ? 'declarative' : 'native-class-a',
          metadata: {
            definitionYaml: executionMode === 'declarative' ? declarativeYaml : undefined,
          },
        }),
      });
      const createJson = await createRes.json();
      if (!createJson.success) throw new Error(createJson.error?.message || 'Failed to create run');

      const runId = createJson.data.id;

      // Execute Run
      const execRes = await fetch(`${apiUrl}/api/v1/test-runs/${runId}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          engineIds: executionMode === 'class_a' ? selectedEngines : undefined,
          definitionYaml: executionMode === 'declarative' ? declarativeYaml : undefined,
        }),
      });
      const execJson = await execRes.json();
      if (!execJson.success) throw new Error(execJson.error?.message || 'Execution failed');

      return execJson.data as TestRunExecutionResult;
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['test-runs'] });
      queryClient.invalidateQueries({ queryKey: ['findings'] });
      if (data?.testRun?.id) {
        setExpandedRunId(data.testRun.id);
      }
    },
  });

  const toggleEngine = (engineId: string) => {
    setSelectedEngines((prev) =>
      prev.includes(engineId) ? prev.filter((id) => id !== engineId) : [...prev, engineId],
    );
  };

  const getStatusBadge = (status: TestRun['status']) => {
    switch (status) {
      case 'completed':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <CheckCircle2 className="w-3 h-3" /> Completed
          </span>
        );
      case 'running':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <Activity className="w-3 h-3 animate-spin" /> Running
          </span>
        );
      case 'failed':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <XCircle className="w-3 h-3" /> Failed
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <Clock className="w-3 h-3" /> {status}
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-foreground">Test Executions & Runner</h2>
          <p className="text-sm text-muted-foreground">
            Execute in-process Class A security engines and declarative assertion test definitions.
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-border bg-card hover:bg-accent text-sm text-foreground transition-colors self-start md:self-auto"
        >
          <RotateCw className="w-4 h-4 text-muted-foreground" />
          <span>Refresh</span>
        </button>
      </div>

      {/* Execution Launcher Card */}
      <div className="p-6 rounded-xl border border-border bg-card/40 backdrop-blur-sm space-y-5">
        <div className="flex items-center justify-between border-b border-border/60 pb-3">
          <div className="flex items-center space-x-2">
            <Play className="w-4 h-4 text-blue-400" />
            <span className="font-semibold text-sm text-foreground">Launch Security Test Run</span>
          </div>
          <span className="text-xs font-mono text-muted-foreground">In-Process SDK Dispatcher</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Target Selector */}
          <div>
            <label className="block text-xs font-medium text-foreground mb-1.5">
              Authorized Target <span className="text-rose-400">*</span>
            </label>
            <select
              value={selectedTargetId}
              onChange={(e) => setSelectedTargetId(e.target.value)}
              className="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              <option value="">-- Select Target --</option>
              {targets.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name} ({t.baseUrl})
                </option>
              ))}
            </select>
          </div>

          {/* Execution Mode */}
          <div>
            <label className="block text-xs font-medium text-foreground mb-1.5">Test Suite Mode</label>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => setExecutionMode('class_a')}
                className={`px-3 py-2 rounded-lg text-xs font-medium border text-center transition-colors ${
                  executionMode === 'class_a'
                    ? 'bg-blue-500/15 border-blue-500/40 text-blue-400'
                    : 'bg-background border-border text-muted-foreground hover:bg-accent'
                }`}
              >
                Class A Native Engines
              </button>
              <button
                type="button"
                onClick={() => setExecutionMode('declarative')}
                className={`px-3 py-2 rounded-lg text-xs font-medium border text-center transition-colors ${
                  executionMode === 'declarative'
                    ? 'bg-blue-500/15 border-blue-500/40 text-blue-400'
                    : 'bg-background border-border text-muted-foreground hover:bg-accent'
                }`}
              >
                Declarative YAML Runner
              </button>
            </div>
          </div>
        </div>

        {/* Engine Checklist for Class A */}
        {executionMode === 'class_a' && (
          <div className="space-y-2">
            <span className="text-xs font-medium text-foreground block">Select Active Test Engines:</span>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {[
                {
                  id: 'engine-native-headers',
                  name: 'OWASP Defensive Headers',
                  desc: 'HSTS, CSP, X-Content-Type-Options, X-Frame-Options',
                },
                {
                  id: 'engine-native-cors',
                  name: 'CORS Origin Reflection',
                  desc: 'Wildcard origins, credentials leakage, preflight headers',
                },
                {
                  id: 'engine-native-tls',
                  name: 'TLS / SSL Transport Security',
                  desc: 'Cleartext HTTP, deprecated TLS 1.0/1.1, expired certs',
                },
              ].map((engine) => (
                <label
                  key={engine.id}
                  className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${
                    selectedEngines.includes(engine.id)
                      ? 'bg-accent/40 border-blue-500/40'
                      : 'bg-background/40 border-border opacity-60'
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={selectedEngines.includes(engine.id)}
                    onChange={() => toggleEngine(engine.id)}
                    className="mt-0.5 rounded border-border text-blue-600 focus:ring-blue-500"
                  />
                  <div>
                    <div className="text-xs font-semibold text-foreground">{engine.name}</div>
                    <div className="text-[11px] text-muted-foreground leading-snug">{engine.desc}</div>
                  </div>
                </label>
              ))}
            </div>
          </div>
        )}

        {/* Declarative YAML Editor */}
        {executionMode === 'declarative' && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-foreground flex items-center gap-1.5">
                <Code className="w-3.5 h-3.5 text-blue-400" />
                Declarative YAML Definition
              </span>
              <span className="text-[11px] text-muted-foreground">Contract-driven assertions</span>
            </div>
            <textarea
              rows={8}
              value={declarativeYaml}
              onChange={(e) => setDeclarativeYaml(e.target.value)}
              className="w-full font-mono text-xs p-3 bg-background border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>
        )}

        {/* Submit Button & Error */}
        <div className="flex items-center justify-between pt-2">
          {triggerMutation.isError ? (
            <div className="text-xs text-rose-400 flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4" />
              <span>{(triggerMutation.error as Error)?.message || 'Execution error'}</span>
            </div>
          ) : (
            <span className="text-xs text-muted-foreground">
              Scope boundary validation will be strictly verified before dispatch.
            </span>
          )}

          <button
            onClick={() => triggerMutation.mutate()}
            disabled={!selectedTargetId || triggerMutation.isPending}
            className="flex items-center gap-2 px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-sm font-medium transition-colors shadow-lg shadow-blue-500/10"
          >
            <Play className={`w-4 h-4 ${triggerMutation.isPending ? 'animate-spin' : ''}`} />
            <span>{triggerMutation.isPending ? 'Executing Test Suite...' : 'Start Execution'}</span>
          </button>
        </div>
      </div>

      {/* Test Runs History */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
          Recent Test Runs ({testRuns.length})
        </h3>

        {isLoadingRuns ? (
          <div className="p-8 text-center text-sm text-muted-foreground">Loading test executions...</div>
        ) : testRuns.length === 0 ? (
          <div className="p-8 border border-dashed border-border rounded-xl text-center text-sm text-muted-foreground">
            No test runs recorded yet. Select an authorized target and click "Start Execution" above.
          </div>
        ) : (
          <div className="space-y-3">
            {testRuns.map((run) => {
              const isExpanded = expandedRunId === run.id;
              const target = targets.find((t) => t.id === run.targetId);
              const counts = run.summary?.findingsCount || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

              return (
                <div
                  key={run.id}
                  className="rounded-xl border border-border bg-card/40 overflow-hidden transition-all"
                >
                  <div
                    onClick={() => setExpandedRunId(isExpanded ? null : run.id)}
                    className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 cursor-pointer hover:bg-accent/30"
                  >
                    <div className="flex items-center gap-3">
                      {isExpanded ? (
                        <ChevronDown className="w-4 h-4 text-muted-foreground" />
                      ) : (
                        <ChevronRight className="w-4 h-4 text-muted-foreground" />
                      )}
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-sm text-foreground">
                            {target?.name || `Target ${run.targetId.slice(0, 8)}`}
                          </span>
                          {getStatusBadge(run.status)}
                          <span className="text-xs font-mono text-muted-foreground px-2 py-0.5 bg-accent rounded">
                            {run.profileId || 'default'}
                          </span>
                        </div>
                        <div className="text-xs text-muted-foreground mt-0.5 flex items-center gap-3">
                          <span>ID: {run.id.slice(0, 13)}...</span>
                          <span>•</span>
                          <span>{new Date(run.createdAt).toLocaleString()}</span>
                        </div>
                      </div>
                    </div>

                    {/* Findings Counters */}
                    <div className="flex items-center gap-2 text-xs font-mono">
                      {counts.critical > 0 && (
                        <span className="px-2 py-0.5 rounded bg-rose-500/15 text-rose-400 border border-rose-500/20">
                          {counts.critical} Crit
                        </span>
                      )}
                      {counts.high > 0 && (
                        <span className="px-2 py-0.5 rounded bg-orange-500/15 text-orange-400 border border-orange-500/20">
                          {counts.high} High
                        </span>
                      )}
                      {counts.medium > 0 && (
                        <span className="px-2 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/20">
                          {counts.medium} Med
                        </span>
                      )}
                      {counts.low > 0 && (
                        <span className="px-2 py-0.5 rounded bg-blue-500/15 text-blue-400 border border-blue-500/20">
                          {counts.low} Low
                        </span>
                      )}
                      {counts.critical === 0 && counts.high === 0 && counts.medium === 0 && (
                        <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/20">
                          0 Vulnerabilities
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Expanded Run Details */}
                  {isExpanded && (
                    <div className="p-4 border-t border-border bg-background/50 space-y-3">
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                        <div className="p-2.5 rounded bg-card border border-border/60">
                          <span className="text-muted-foreground block">Total Tests</span>
                          <span className="font-semibold text-foreground text-sm">
                            {run.summary?.totalTests ?? 0}
                          </span>
                        </div>
                        <div className="p-2.5 rounded bg-card border border-border/60">
                          <span className="text-muted-foreground block">Passed</span>
                          <span className="font-semibold text-emerald-400 text-sm">
                            {run.summary?.passedTests ?? 0}
                          </span>
                        </div>
                        <div className="p-2.5 rounded bg-card border border-border/60">
                          <span className="text-muted-foreground block">Failed</span>
                          <span className="font-semibold text-rose-400 text-sm">
                            {run.summary?.failedTests ?? 0}
                          </span>
                        </div>
                        <div className="p-2.5 rounded bg-card border border-border/60">
                          <span className="text-muted-foreground block">Findings Identified</span>
                          <span className="font-semibold text-amber-400 text-sm">
                            {(counts.critical || 0) + (counts.high || 0) + (counts.medium || 0) + (counts.low || 0)}
                          </span>
                        </div>
                      </div>

                      <div className="flex justify-end pt-2">
                        <button
                          onClick={() => {
                            // Switch tab to findings
                            const event = new CustomEvent('navigate-tab', { detail: 'findings' });
                            window.dispatchEvent(event);
                          }}
                          className="text-xs text-blue-400 hover:text-blue-300 font-medium"
                        >
                          View Full Findings & Forensic Evidence →
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
