import React from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Box,
  Server,
  Lock,
  Layers,
  Zap,
  Target,
  PlayCircle,
  AlertOctagon,
  Scale,
  Terminal,
  ArrowRight,
  Copy,
} from 'lucide-react';
import { useAppStore } from '../store/useAppStore.js';

interface OverviewTarget {
  id: string;
}

interface OverviewRun {
  id: string;
  status: string;
}

interface OverviewFinding {
  id: string;
  severity: string;
}

interface OverviewRelease {
  id: string;
  decision: string;
}

export const Overview: React.FC = () => {
  const { setActiveTab, showToast } = useAppStore();
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000';

  // Live KPI Queries
  const { data: targets = [] } = useQuery<OverviewTarget[]>({
    queryKey: ['targets'],
    queryFn: async () => {
      const res = await fetch(`${apiUrl}/api/v1/targets`);
      const json = await res.json();
      return json.data || [];
    },
  });

  const { data: runs = [] } = useQuery<OverviewRun[]>({
    queryKey: ['test-runs'],
    queryFn: async () => {
      const res = await fetch(`${apiUrl}/api/v1/test-runs`);
      const json = await res.json();
      return json.data || [];
    },
  });

  const { data: findings = [] } = useQuery<OverviewFinding[]>({
    queryKey: ['findings'],
    queryFn: async () => {
      const res = await fetch(`${apiUrl}/api/v1/findings`);
      const json = await res.json();
      return json.data || [];
    },
  });

  const { data: releases = [] } = useQuery<OverviewRelease[]>({
    queryKey: ['releases'],
    queryFn: async () => {
      const res = await fetch(`${apiUrl}/api/v1/releases`);
      const json = await res.json();
      return json.data || [];
    },
  });

  const criticalFindings = findings.filter((f) => f.severity === 'critical').length;
  const highFindings = findings.filter((f) => f.severity === 'high').length;
  const passedReleases = releases.filter((r) => r.decision === 'allow').length;
  const releasePassRate = releases.length > 0 ? Math.round((passedReleases / releases.length) * 100) : 100;

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    showToast(`Copied ${label} to clipboard`, 'info');
  };

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Hero Banner */}
      <div className="rounded-2xl border border-border bg-gradient-to-br from-card/90 via-card/50 to-primary/10 p-6 md:p-8 backdrop-blur-md relative overflow-hidden shadow-xl">
        <div className="absolute right-0 top-0 w-96 h-96 bg-primary/5 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20"></div>

        <div className="space-y-3 max-w-3xl relative z-10">
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center space-x-1.5 text-xs font-mono uppercase bg-emerald-950/60 text-emerald-400 border border-emerald-800/60 px-2.5 py-0.5 rounded-full">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>Local-First Security QA Platform</span>
            </span>
            <span className="text-[10px] font-mono text-blue-400 bg-blue-950/40 border border-blue-800/40 px-2 py-0.5 rounded-full">
              v1.0.0 Ready
            </span>
          </div>

          <h2 className="text-2xl md:text-3xl font-extrabold tracking-tight text-foreground">
            Security QA for Enterprise Applications
          </h2>
          <p className="text-sm md:text-base text-muted-foreground leading-relaxed">
            A developer-first, defensive security testing platform built to audit headers, CORS, TLS,
            isolated containerized scanners, and heavy k6 resilience SLAs before code merges to production.
          </p>

          <div className="flex flex-wrap items-center gap-3 pt-3">
            <button
              onClick={() => setActiveTab('runs')}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-lg shadow-blue-500/20 transition-all duration-150 hover:glow-blue"
            >
              <PlayCircle className="w-4 h-4" />
              <span>Launch Test Execution</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setActiveTab('targets')}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-accent hover:bg-accent/80 border border-border text-foreground text-xs font-semibold transition-all duration-150"
            >
              <Target className="w-4 h-4 text-blue-400" />
              <span>Manage Target Scopes</span>
            </button>
          </div>
        </div>
      </div>

      {/* Real-time KPI Stats Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {/* KPI 1: Targets */}
        <div
          onClick={() => setActiveTab('targets')}
          className="p-5 rounded-2xl border border-border bg-card/60 backdrop-blur-sm hover:border-primary/50 transition-all duration-200 cursor-pointer shadow-sm group hover:glow-blue"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Authorized Targets
            </span>
            <div className="p-2 rounded-xl bg-primary/10 border border-primary/20 text-blue-400 group-hover:scale-105 transition-transform">
              <Target className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-foreground">{targets.length}</span>
            <span className="text-xs text-muted-foreground">in scope</span>
          </div>
          <div className="mt-3 flex items-center text-[11px] text-blue-400 group-hover:underline gap-1">
            <span>Manage security allowlists</span>
            <ArrowRight className="w-3 h-3" />
          </div>
        </div>

        {/* KPI 2: Test Runs */}
        <div
          onClick={() => setActiveTab('runs')}
          className="p-5 rounded-2xl border border-border bg-card/60 backdrop-blur-sm hover:border-primary/50 transition-all duration-200 cursor-pointer shadow-sm group hover:glow-blue"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Test Executions
            </span>
            <div className="p-2 rounded-xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 group-hover:scale-105 transition-transform">
              <PlayCircle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-foreground">{runs.length}</span>
            <span className="text-xs text-muted-foreground">total runs</span>
          </div>
          <div className="mt-3 flex items-center text-[11px] text-indigo-400 group-hover:underline gap-1">
            <span>View execution history</span>
            <ArrowRight className="w-3 h-3" />
          </div>
        </div>

        {/* KPI 3: Vulnerabilities */}
        <div
          onClick={() => setActiveTab('findings')}
          className="p-5 rounded-2xl border border-border bg-card/60 backdrop-blur-sm hover:border-rose-500/50 transition-all duration-200 cursor-pointer shadow-sm group hover:glow-rose"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              High / Crit Defects
            </span>
            <div className="p-2 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 group-hover:scale-105 transition-transform">
              <AlertOctagon className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className={`text-3xl font-bold font-mono ${criticalFindings + highFindings > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
              {criticalFindings + highFindings}
            </span>
            <span className="text-xs text-muted-foreground">
              ({findings.length} total)
            </span>
          </div>
          <div className="mt-3 flex items-center text-[11px] text-rose-400 group-hover:underline gap-1">
            <span>Triage & forensic evidence</span>
            <ArrowRight className="w-3 h-3" />
          </div>
        </div>

        {/* KPI 4: Release Gating */}
        <div
          onClick={() => setActiveTab('policies')}
          className="p-5 rounded-2xl border border-border bg-card/60 backdrop-blur-sm hover:border-emerald-500/50 transition-all duration-200 cursor-pointer shadow-sm group hover:glow-emerald"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Release Gate Pass
            </span>
            <div className="p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 group-hover:scale-105 transition-transform">
              <Scale className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-emerald-400">{releasePassRate}%</span>
            <span className="text-xs text-muted-foreground">
              ({releases.length} audited)
            </span>
          </div>
          <div className="mt-3 flex items-center text-[11px] text-emerald-400 group-hover:underline gap-1">
            <span>Configure release policies</span>
            <ArrowRight className="w-3 h-3" />
          </div>
        </div>
      </div>

      {/* Architecture Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-5 rounded-2xl border border-border bg-card/60 backdrop-blur-sm space-y-3 hover:border-blue-500/40 transition-colors shadow-sm">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-xl bg-blue-950/40 border border-blue-800/40 text-blue-400">
              <Server className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-semibold text-sm text-foreground">Class A: Native Engines</h3>
              <p className="text-[11px] text-muted-foreground font-mono">In-process zero-dependency</p>
            </div>
          </div>
          <p className="text-xs text-muted-foreground leading-relaxed">
            Headers, TLS handshake evaluation, CORS policies, authentication validation, and rate-limit baselines.
          </p>
          <div className="text-[10px] font-mono text-emerald-400 bg-emerald-950/30 px-2 py-1 rounded-lg border border-emerald-800/30">
            Contract Boundary: packages/test-sdk
          </div>
        </div>

        <div className="p-5 rounded-2xl border border-border bg-card/60 backdrop-blur-sm space-y-3 hover:border-purple-500/40 transition-colors shadow-sm">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-xl bg-purple-950/40 border border-purple-800/40 text-purple-400">
              <Box className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-semibold text-sm text-foreground">Class B: Container Scanners</h3>
              <p className="text-[11px] text-muted-foreground font-mono">Isolated ephemeral tools</p>
            </div>
          </div>
          <p className="text-xs text-muted-foreground leading-relaxed">
            OWASP ZAP baseline/active scanning and Aqua Trivy SCA/IaC with normalized forensic findings.
          </p>
          <div className="text-[10px] font-mono text-emerald-400 bg-emerald-950/30 px-2 py-1 rounded-lg border border-emerald-800/30">
            Engine Workers: ZAP & Trivy (Operational)
          </div>
        </div>

        <div className="p-5 rounded-2xl border border-border bg-card/60 backdrop-blur-sm space-y-3 hover:border-indigo-500/40 transition-colors shadow-sm">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-xl bg-indigo-950/40 border border-indigo-800/40 text-indigo-400">
              <Zap className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-semibold text-sm text-foreground">Class C: Heavy Workers</h3>
              <p className="text-[11px] text-muted-foreground font-mono">Resilience & SLA Audits</p>
            </div>
          </div>
          <p className="text-xs text-muted-foreground leading-relaxed">
            Grafana k6 load resilience soak testing, rate-limit stress audits, and latency percentile SLAs.
          </p>
          <div className="text-[10px] font-mono text-emerald-400 bg-emerald-950/30 px-2 py-1 rounded-lg border border-emerald-800/30">
            Engine Worker: k6 & Resilience (Operational)
          </div>
        </div>
      </div>

      {/* CLI Quick Reference Cheat Sheet Card */}
      <div className="p-6 rounded-2xl border border-border bg-card/60 backdrop-blur-sm space-y-4 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border/60 pb-3">
          <div className="flex items-center space-x-2">
            <div className="p-1.5 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
              <Terminal className="w-4 h-4" />
            </div>
            <span className="font-semibold text-sm text-foreground">CLI Terminal Access & Commands</span>
          </div>
          <span className="text-xs font-mono text-muted-foreground">Node CLI: @security-lab/cli</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
          {[
            {
              cmd: 'security-lab target list',
              desc: 'List registered target scopes and boundaries',
            },
            {
              cmd: 'security-lab test run --target <id>',
              desc: 'Execute test suite against authorized target',
            },
            {
              cmd: 'security-lab findings list --severity critical',
              desc: 'Inspect normalized security defect findings',
            },
            {
              cmd: 'security-lab gate evaluate --policy default',
              desc: 'Evaluate CI/CD release gate decision and SLA audit',
            },
          ].map((item) => (
            <div
              key={item.cmd}
              className="p-3 rounded-xl bg-accent/40 border border-border/70 flex items-center justify-between gap-3 group hover:border-primary/40 transition-colors"
            >
              <div className="space-y-0.5 overflow-hidden">
                <code className="text-blue-400 text-xs block truncate">{item.cmd}</code>
                <span className="text-[11px] text-muted-foreground font-sans block">{item.desc}</span>
              </div>
              <button
                type="button"
                onClick={() => copyToClipboard(item.cmd, item.cmd)}
                title="Copy command"
                className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent shrink-0 transition-colors"
              >
                <Copy className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Execution Lifecycle Flow */}
      <div className="p-6 rounded-2xl border border-border bg-card/60 backdrop-blur-sm space-y-4 shadow-sm">
        <h3 className="text-sm font-semibold flex items-center space-x-2 text-foreground">
          <Layers className="w-4 h-4 text-blue-400" />
          <span>Defensive Execution Lifecycle Pipeline</span>
        </h3>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {[
            'Target Scope',
            'Scope Validation',
            'Test Definition',
            'TestRun',
            'Engine Execution',
            'Normalization',
            'Immutable Evidence',
            'Finding Model',
            'Policy Evaluation',
            'Release Gate Verdict',
          ].map((stage, idx, arr) => (
            <React.Fragment key={stage}>
              <span className="px-3 py-1.5 rounded-lg bg-accent/60 border border-border/80 text-foreground font-mono text-[11px]">
                {stage}
              </span>
              {idx < arr.length - 1 && (
                <span className="text-muted-foreground/60 text-xs">→</span>
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Safety Notice */}
      <div className="p-4 rounded-2xl border border-blue-900/40 bg-blue-950/20 backdrop-blur-sm flex items-start space-x-3 text-xs text-blue-300">
        <Lock className="w-4 h-4 text-blue-400 mt-0.5 shrink-0" />
        <div className="space-y-1">
          <div className="font-semibold text-blue-200">Security Boundary Principle:</div>
          <p className="text-blue-300/80 leading-relaxed">
            All test executions strictly require explicit target scope registration, allowed host
            validation, and active scanning consent. Potentially disruptive testing requires
            explicit capability flags and safety threshold limits.
          </p>
        </div>
      </div>
    </div>
  );
};
