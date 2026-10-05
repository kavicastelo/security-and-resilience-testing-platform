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
  Box,
  Cpu,
  ShieldCheck,
  Gauge,
  FileText,
  ExternalLink,
  Download,
  Scale,
  Trash2,
} from 'lucide-react';
import { EvaluateReleaseModal } from './EvaluateReleaseModal.js';

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

interface MetricItem {
  id: string;
  name: string;
  value: number;
  unit: string;
}

const RunMetricsDetails: React.FC<{ runId: string; apiUrl: string }> = ({ runId, apiUrl }) => {
  const { data: metrics = [], isLoading } = useQuery<MetricItem[]>({
    queryKey: ['test-run-metrics', runId],
    queryFn: async () => {
      const res = await fetch(`${apiUrl}/api/v1/test-runs/${runId}/metrics`);
      const json = await res.json();
      return json.data || [];
    },
  });

  if (isLoading) {
    return <div className="text-xs text-muted-foreground animate-pulse py-2">Loading performance metrics...</div>;
  }

  if (metrics.length === 0) return null;

  const metricMap: Record<string, number> = {};
  for (const m of metrics) {
    metricMap[m.name] = m.value;
  }

  const p95 = metricMap['http_req_duration_p95'];
  const p99 = metricMap['http_req_duration_p99'];
  const med = metricMap['http_req_duration_med'];
  const avg = metricMap['http_req_duration_avg'];
  const max = metricMap['http_req_duration_max'];
  const rps = metricMap['http_rps'];
  const totalReqs = metricMap['http_reqs_total'];
  const failedRatio = metricMap['http_req_failed_ratio'];
  const rateLimitEnforced = metricMap['rate_limiting_enforced'];

  return (
    <div className="space-y-3 pt-3 border-t border-border/50">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
          <Gauge className="w-3.5 h-3.5 text-blue-400" />
          Quantitative Resilience & Latency SLA Metrics
        </span>
        {p95 !== undefined && (
          <span
            className={`text-[11px] font-mono px-2 py-0.5 rounded border ${
              p95 > 500
                ? 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
            }`}
          >
            {p95 > 500 ? 'SLA Breached (>500ms)' : 'SLA Met (≤500ms)'}
          </span>
        )}
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs font-mono">
        {p95 !== undefined && (
          <div className="p-2 rounded bg-card/60 border border-border/50">
            <span className="text-[10px] text-muted-foreground uppercase block font-sans">P95 Latency</span>
            <span className={`text-sm font-bold ${p95 > 500 ? 'text-rose-400' : 'text-emerald-400'}`}>
              {p95} ms
            </span>
          </div>
        )}
        {p99 !== undefined && (
          <div className="p-2 rounded bg-card/60 border border-border/50">
            <span className="text-[10px] text-muted-foreground uppercase block font-sans">P99 Latency</span>
            <span className="text-sm font-bold text-foreground">{p99} ms</span>
          </div>
        )}
        {med !== undefined && (
          <div className="p-2 rounded bg-card/60 border border-border/50">
            <span className="text-[10px] text-muted-foreground uppercase block font-sans">Median (P50)</span>
            <span className="text-sm font-bold text-foreground">{med} ms</span>
          </div>
        )}
        {avg !== undefined && (
          <div className="p-2 rounded bg-card/60 border border-border/50">
            <span className="text-[10px] text-muted-foreground uppercase block font-sans">Average</span>
            <span className="text-sm font-bold text-foreground">{avg} ms</span>
          </div>
        )}
        {max !== undefined && (
          <div className="p-2 rounded bg-card/60 border border-border/50">
            <span className="text-[10px] text-muted-foreground uppercase block font-sans">Max Latency</span>
            <span className="text-sm font-bold text-foreground">{max} ms</span>
          </div>
        )}
        {rps !== undefined && (
          <div className="p-2 rounded bg-card/60 border border-border/50">
            <span className="text-[10px] text-muted-foreground uppercase block font-sans">Throughput</span>
            <span className="text-sm font-bold text-blue-400">{rps} req/s</span>
          </div>
        )}
        {totalReqs !== undefined && (
          <div className="p-2 rounded bg-card/60 border border-border/50">
            <span className="text-[10px] text-muted-foreground uppercase block font-sans">Total Requests</span>
            <span className="text-sm font-bold text-foreground">{totalReqs}</span>
          </div>
        )}
        {failedRatio !== undefined && (
          <div className="p-2 rounded bg-card/60 border border-border/50">
            <span className="text-[10px] text-muted-foreground uppercase block font-sans">Error Rate</span>
            <span className={`text-sm font-bold ${failedRatio > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
              {failedRatio}%
            </span>
          </div>
        )}
        {rateLimitEnforced !== undefined && (
          <div className="p-2 rounded bg-card/60 border border-border/50">
            <span className="text-[10px] text-muted-foreground uppercase block font-sans">Rate Limiting</span>
            <span className={`text-sm font-bold ${rateLimitEnforced === 1 ? 'text-emerald-400' : 'text-amber-400'}`}>
              {rateLimitEnforced === 1 ? 'Enforced (429)' : 'None Detected'}
            </span>
          </div>
        )}
      </div>
    </div>
  );
};

export const RunsView: React.FC = () => {
  const queryClient = useQueryClient();
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000';

  const [selectedTargetId, setSelectedTargetId] = useState<string>('');
  const [evaluatingRunId, setEvaluatingRunId] = useState<string | null>(null);
  const [executionMode, setExecutionMode] = useState<'class_a' | 'class_b' | 'class_c' | 'declarative'>('class_a');
  const [loadVus, setLoadVus] = useState<number>(5);
  const [loadDurationSec, setLoadDurationSec] = useState<number>(3);
  const [loadMaxP95Ms, setLoadMaxP95Ms] = useState<number>(500);
  const [includeK6, setIncludeK6] = useState<boolean>(true);
  const [includeRateLimit, setIncludeRateLimit] = useState<boolean>(true);
  const [selectedEngines, setSelectedEngines] = useState<string[]>([
    'engine-native-headers',
    'engine-native-cors',
    'engine-native-tls',
  ]);
  const [selectedClassBEngines, setSelectedClassBEngines] = useState<string[]>([
    'engine-container-zap',
    'engine-container-trivy',
  ]);
  const [enableActiveScan, setEnableActiveScan] = useState<boolean>(false);
  const [isSimulated, setIsSimulated] = useState<boolean>(true);
  const [declarativeYaml, setDeclarativeYaml] = useState(DEFAULT_DECLARATIVE_YAML);
  const [expandedRunId, setExpandedRunId] = useState<string | null>(null);

  // Delete Test Run mutation
  const deleteRunMutation = useMutation({
    mutationFn: async (runId: string) => {
      const res = await fetch(`${apiUrl}/api/v1/test-runs/${runId}`, {
        method: 'DELETE',
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error?.message || 'Failed to delete test run');
      return json;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['test-runs'] });
      queryClient.invalidateQueries({ queryKey: ['findings'] });
      setExpandedRunId(null);
    },
  });

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

      let profileId = 'native-class-a';
      let engineIds = selectedEngines;

      if (executionMode === 'declarative') {
        profileId = 'declarative';
        engineIds = ['engine-native-declarative'];
      } else if (executionMode === 'class_b') {
        profileId = 'class-b-scanners';
        engineIds = selectedClassBEngines;
      } else if (executionMode === 'class_c') {
        profileId = 'class-c-resilience';
        engineIds = [];
        if (includeK6) engineIds.push('engine-worker-k6');
        if (includeRateLimit) engineIds.push('engine-native-resilience');
        if (engineIds.length === 0) engineIds = ['engine-worker-k6'];
      }

      // Create Run
      const createRes = await fetch(`${apiUrl}/api/v1/test-runs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId: target.projectId || target.id,
          targetId: target.id,
          profileId,
          metadata: {
            definitionYaml: executionMode === 'declarative' ? declarativeYaml : undefined,
            activeScan: executionMode === 'class_b' ? enableActiveScan : false,
            simulated: executionMode === 'class_b' ? isSimulated : false,
            vus: executionMode === 'class_c' ? loadVus : undefined,
            durationSec: executionMode === 'class_c' ? loadDurationSec : undefined,
            maxP95Ms: executionMode === 'class_c' ? loadMaxP95Ms : undefined,
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
          engineIds,
          definitionYaml: executionMode === 'declarative' ? declarativeYaml : undefined,
          options: {
            activeScan: enableActiveScan,
            simulated: isSimulated,
            vus: loadVus,
            durationSec: loadDurationSec,
            maxP95Ms: loadMaxP95Ms,
          },
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

  const toggleClassBEngine = (engineId: string) => {
    setSelectedClassBEngines((prev) =>
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
            Execute in-process Class A security engines, Class B containerized scanners (ZAP / Trivy), and declarative YAML runners.
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
          <span className="text-xs font-mono text-muted-foreground">Unified TestEngine Dispatcher</span>
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
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
              <button
                type="button"
                onClick={() => setExecutionMode('class_a')}
                className={`px-2.5 py-2 rounded-lg text-xs font-medium border text-center transition-colors flex items-center justify-center gap-1.5 ${
                  executionMode === 'class_a'
                    ? 'bg-blue-500/15 border-blue-500/40 text-blue-400'
                    : 'bg-background border-border text-muted-foreground hover:bg-accent'
                }`}
              >
                <Cpu className="w-3.5 h-3.5" />
                <span>Class A Native</span>
              </button>

              <button
                type="button"
                onClick={() => setExecutionMode('class_b')}
                className={`px-2.5 py-2 rounded-lg text-xs font-medium border text-center transition-colors flex items-center justify-center gap-1.5 ${
                  executionMode === 'class_b'
                    ? 'bg-blue-500/15 border-blue-500/40 text-blue-400'
                    : 'bg-background border-border text-muted-foreground hover:bg-accent'
                }`}
              >
                <Box className="w-3.5 h-3.5" />
                <span>Class B Scanners</span>
              </button>

              <button
                type="button"
                onClick={() => setExecutionMode('class_c')}
                className={`px-2.5 py-2 rounded-lg text-xs font-medium border text-center transition-colors flex items-center justify-center gap-1.5 ${
                  executionMode === 'class_c'
                    ? 'bg-blue-500/15 border-blue-500/40 text-blue-400'
                    : 'bg-background border-border text-muted-foreground hover:bg-accent'
                }`}
              >
                <Gauge className="w-3.5 h-3.5" />
                <span>Class C Resilience</span>
              </button>

              <button
                type="button"
                onClick={() => setExecutionMode('declarative')}
                className={`px-2.5 py-2 rounded-lg text-xs font-medium border text-center transition-colors flex items-center justify-center gap-1.5 ${
                  executionMode === 'declarative'
                    ? 'bg-blue-500/15 border-blue-500/40 text-blue-400'
                    : 'bg-background border-border text-muted-foreground hover:bg-accent'
                }`}
              >
                <Code className="w-3.5 h-3.5" />
                <span>Declarative YAML</span>
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

        {/* Engine Checklist for Class B (Container Scanners) */}
        {executionMode === 'class_b' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-foreground block">
                Select Isolated Container Scanners:
              </span>
              <div className="flex items-center gap-4 text-xs">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enableActiveScan}
                    onChange={(e) => setEnableActiveScan(e.target.checked)}
                    className="rounded border-border text-blue-600 focus:ring-blue-500"
                  />
                  <span className="text-muted-foreground">
                    Enable Active Scanning (Requires Scope Opt-In)
                  </span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={isSimulated}
                    onChange={(e) => setIsSimulated(e.target.checked)}
                    className="rounded border-border text-blue-600 focus:ring-blue-500"
                  />
                  <span className="text-blue-400 font-mono text-[11px]">
                    Fast Lab Mode (Simulated Containers)
                  </span>
                </label>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {[
                {
                  id: 'engine-container-zap',
                  name: 'OWASP ZAP Scanner Container',
                  image: 'ghcr.io/zaproxy/zaproxy:stable',
                  desc: 'Automated baseline web vulnerability scanning, XSS, injection vectors, and defensive header audits.',
                },
                {
                  id: 'engine-container-trivy',
                  name: 'Aqua Trivy Security Container',
                  image: 'aquasec/trivy:latest',
                  desc: 'Software composition analysis (SCA), CVE identification in dependencies, and IaC/container misconfigurations.',
                },
              ].map((engine) => (
                <label
                  key={engine.id}
                  className={`flex items-start gap-3 p-3.5 rounded-lg border cursor-pointer transition-colors ${
                    selectedClassBEngines.includes(engine.id)
                      ? 'bg-accent/40 border-blue-500/40'
                      : 'bg-background/40 border-border opacity-60'
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={selectedClassBEngines.includes(engine.id)}
                    onChange={() => toggleClassBEngine(engine.id)}
                    className="mt-1 rounded border-border text-blue-600 focus:ring-blue-500"
                  />
                  <div className="space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-foreground">{engine.name}</span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-accent text-muted-foreground">
                        Class B
                      </span>
                    </div>
                    <div className="text-[11px] font-mono text-blue-400/80">{engine.image}</div>
                    <div className="text-[11px] text-muted-foreground leading-snug">{engine.desc}</div>
                  </div>
                </label>
              ))}
            </div>
          </div>
        )}

        {/* Class C Resilience & Load Testing Configuration */}
        {executionMode === 'class_c' && (
          <div className="space-y-4">
            <span className="text-xs font-medium text-foreground block">
              Workload Profile & Latency SLA Configuration:
            </span>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="p-3 rounded-lg border border-border bg-background/50 space-y-1.5">
                <label className="text-xs text-muted-foreground block">Virtual Users (VUs Concurrency)</label>
                <input
                  type="number"
                  min={1}
                  max={50}
                  value={loadVus}
                  onChange={(e) => setLoadVus(Math.max(1, parseInt(e.target.value, 10) || 1))}
                  className="w-full px-2.5 py-1.5 bg-background border border-border rounded text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
                <span className="text-[10px] text-muted-foreground block">Clamped by target scope limit</span>
              </div>

              <div className="p-3 rounded-lg border border-border bg-background/50 space-y-1.5">
                <label className="text-xs text-muted-foreground block">Duration (Seconds)</label>
                <input
                  type="number"
                  min={1}
                  max={30}
                  value={loadDurationSec}
                  onChange={(e) => setLoadDurationSec(Math.max(1, parseInt(e.target.value, 10) || 1))}
                  className="w-full px-2.5 py-1.5 bg-background border border-border rounded text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
                <span className="text-[10px] text-muted-foreground block">Concurrent workload window</span>
              </div>

              <div className="p-3 rounded-lg border border-border bg-background/50 space-y-1.5">
                <label className="text-xs text-muted-foreground block">P95 SLA Target Threshold (ms)</label>
                <input
                  type="number"
                  min={50}
                  max={5000}
                  step={50}
                  value={loadMaxP95Ms}
                  onChange={(e) => setLoadMaxP95Ms(Math.max(50, parseInt(e.target.value, 10) || 500))}
                  className="w-full px-2.5 py-1.5 bg-background border border-border rounded text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
                <span className="text-[10px] text-muted-foreground block">Finding generated if breached</span>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-4 text-xs pt-1">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeK6}
                  onChange={(e) => setIncludeK6(e.target.checked)}
                  className="rounded border-border text-blue-600 focus:ring-blue-500"
                />
                <span className="text-foreground font-medium">Grafana k6 Concurrency SLA Worker</span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeRateLimit}
                  onChange={(e) => setIncludeRateLimit(e.target.checked)}
                  className="rounded border-border text-blue-600 focus:ring-blue-500"
                />
                <span className="text-foreground font-medium">Burst Rate Limiting & Throttling Audit</span>
              </label>
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
            <span className="text-xs text-muted-foreground flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
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

                      {/* Quantitative Latency & SLA Metrics */}
                      <RunMetricsDetails runId={run.id} apiUrl={apiUrl} />

                      {/* Export Reports & Release Gating Toolbar */}
                      <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-border/50 text-xs">
                        <div className="flex items-center gap-2">
                          <span className="text-muted-foreground font-medium flex items-center gap-1.5">
                            <FileText className="w-3.5 h-3.5 text-blue-400" /> Export Reports:
                          </span>
                          <a
                            href={`${apiUrl}/api/v1/test-runs/${run.id}/report?format=html`}
                            target="_blank"
                            rel="noreferrer"
                            className="px-2.5 py-1 rounded bg-accent/60 hover:bg-accent border border-border text-foreground transition-colors font-mono text-[11px] flex items-center gap-1"
                          >
                            <ExternalLink className="w-3 h-3 text-blue-400" /> HTML Report
                          </a>
                          <a
                            href={`${apiUrl}/api/v1/test-runs/${run.id}/report?format=junit`}
                            target="_blank"
                            rel="noreferrer"
                            className="px-2.5 py-1 rounded bg-accent/60 hover:bg-accent border border-border text-foreground transition-colors font-mono text-[11px] flex items-center gap-1"
                          >
                            <Download className="w-3 h-3 text-emerald-400" /> JUnit XML
                          </a>
                          <a
                            href={`${apiUrl}/api/v1/test-runs/${run.id}/report?format=sarif`}
                            target="_blank"
                            rel="noreferrer"
                            className="px-2.5 py-1 rounded bg-accent/60 hover:bg-accent border border-border text-foreground transition-colors font-mono text-[11px] flex items-center gap-1"
                          >
                            <Download className="w-3 h-3 text-purple-400" /> SARIF v2.1
                          </a>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setEvaluatingRunId(run.id);
                            }}
                            className="px-2.5 py-1 rounded bg-blue-600/15 hover:bg-blue-600/25 border border-blue-500/30 text-blue-400 transition-colors font-mono text-[11px] flex items-center gap-1"
                          >
                            <Scale className="w-3 h-3 text-blue-400" /> Evaluate Gate
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              if (window.confirm(`Are you sure you want to delete test run ${run.id}? This will also delete associated test findings and metrics.`)) {
                                deleteRunMutation.mutate(run.id);
                              }
                            }}
                            disabled={deleteRunMutation.isPending}
                            title="Delete Test Run"
                            className="px-2.5 py-1 rounded bg-rose-950/30 hover:bg-rose-950/50 border border-rose-800/40 text-rose-400 hover:text-rose-300 transition-colors font-mono text-[11px] flex items-center gap-1 disabled:opacity-50"
                          >
                            <Trash2 className="w-3 h-3" /> Delete Run
                          </button>
                        </div>

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

      {/* Evaluate Release Gate Modal */}
      <EvaluateReleaseModal
        isOpen={evaluatingRunId !== null}
        onClose={() => setEvaluatingRunId(null)}
        preselectedRunId={evaluatingRunId || undefined}
        apiUrl={apiUrl}
      />
    </div>
  );
};
