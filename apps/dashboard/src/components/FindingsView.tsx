import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ShieldAlert,
  Search,
  Filter,
  ChevronDown,
  ChevronRight,
  FileCheck,
  CheckCircle2,
  AlertTriangle,
  Info,
  Trash2,
  Tag,
  Copy,
  Terminal,
  X,
} from 'lucide-react';
import { Pagination } from './Pagination.js';
import { useAppStore } from '../store/useAppStore.js';

interface Finding {
  id: string;
  fingerprint: string;
  title: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: string;
  status: string;
  description: string;
  risk?: string;
  recommendation?: string;
  testDefinitionId: string;
  testRunId: string;
  executionId: string;
  targetId: string;
  evidenceId?: string;
  firstDetectedAt: string;
}

interface Evidence {
  id: string;
  testRunId: string;
  executionId: string;
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
}

export const FindingsView: React.FC = () => {
  const queryClient = useQueryClient();
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000';
  const { showToast } = useAppStore();

  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(6);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    showToast(`Copied ${label} to clipboard`, 'info');
  };

  // 1. Fetch Findings
  const { data: findings = [], isLoading } = useQuery<Finding[]>({
    queryKey: ['findings'],
    queryFn: async () => {
      const res = await fetch(`${apiUrl}/api/v1/findings`);
      const json = await res.json();
      return (json.data || []).sort(
        (a: Finding, b: Finding) =>
          new Date(b.firstDetectedAt).getTime() - new Date(a.firstDetectedAt).getTime(),
      );
    },
  });

  // Triage update mutation
  const updateStatusMutation = useMutation({
    mutationFn: async ({ findingId, status }: { findingId: string; status: string }) => {
      const res = await fetch(`${apiUrl}/api/v1/findings/${findingId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error?.message || 'Failed to update finding status');
      return json.data;
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['findings'] });
      showToast(`Finding status updated to ${data.status}`);
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      showToast(msg, 'error');
    },
  });

  // Delete finding mutation
  const deleteFindingMutation = useMutation({
    mutationFn: async (findingId: string) => {
      const res = await fetch(`${apiUrl}/api/v1/findings/${findingId}`, {
        method: 'DELETE',
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error?.message || 'Failed to delete finding');
      return json;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['findings'] });
      showToast('Finding deleted', 'info');
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      showToast(msg, 'error');
    },
  });

  // 2. Fetch Evidence for the expanded finding
  const expandedFinding = findings.find((f) => f.id === expandedFindingId);
  const { data: evidence = null, isLoading: isLoadingEvidence } = useQuery<Evidence | null>({
    queryKey: ['evidence', expandedFinding?.testRunId],
    enabled: !!expandedFinding?.testRunId,
    queryFn: async () => {
      if (!expandedFinding?.testRunId) return null;
      const res = await fetch(`${apiUrl}/api/v1/test-runs/${expandedFinding.testRunId}/evidence`);
      const json = await res.json();
      const list: Evidence[] = json.data || [];
      return list.find((e) => e.id === expandedFinding.evidenceId) || list[0] || null;
    },
  });

  const severityCounts = {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    info: findings.filter((f) => f.severity === 'info').length,
  };

  const statusCounts = {
    all: findings.length,
    open: findings.filter((f) => !f.status || f.status === 'open').length,
    resolved: findings.filter((f) => f.status === 'resolved').length,
    false_positive: findings.filter((f) => f.status === 'false_positive').length,
    risk_accepted: findings.filter((f) => f.status === 'risk_accepted').length,
    suppressed: findings.filter((f) => f.status === 'suppressed').length,
  };

  const filteredFindings = findings.filter((f) => {
    if (selectedSeverity !== 'all' && f.severity !== selectedSeverity) return false;
    if (selectedStatus !== 'all') {
      const s = f.status || 'open';
      if (s !== selectedStatus) return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const match =
        f.title.toLowerCase().includes(q) ||
        f.category.toLowerCase().includes(q) ||
        f.description.toLowerCase().includes(q) ||
        f.fingerprint.toLowerCase().includes(q);
      if (!match) return false;
    }
    return true;
  });

  const paginatedFindings = filteredFindings.slice(
    (currentPage - 1) * pageSize,
    currentPage * pageSize,
  );

  const getSeverityBadge = (severity: Finding['severity']) => {
    switch (severity) {
      case 'critical':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/15 text-rose-400 border border-rose-500/30">
            <ShieldAlert className="w-3 h-3" /> Critical
          </span>
        );
      case 'high':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-orange-500/15 text-orange-400 border border-orange-500/30">
            <AlertTriangle className="w-3 h-3" /> High
          </span>
        );
      case 'medium':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/15 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3 h-3" /> Medium
          </span>
        );
      case 'low':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-500/15 text-blue-400 border border-blue-500/30">
            <Info className="w-3 h-3" /> Low
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-zinc-500/15 text-zinc-400 border border-zinc-500/30">
            <Info className="w-3 h-3" /> Info
          </span>
        );
    }
  };

  const getStatusBadge = (status?: string) => {
    switch (status) {
      case 'resolved':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
            Resolved
          </span>
        );
      case 'false_positive':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-zinc-500/15 text-zinc-400 border border-zinc-500/30">
            False Positive
          </span>
        );
      case 'risk_accepted':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-purple-500/15 text-purple-400 border border-purple-500/30">
            Risk Accepted
          </span>
        );
      case 'suppressed':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-slate-500/15 text-slate-400 border border-slate-500/30">
            Suppressed
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-amber-500/15 text-amber-400 border border-amber-500/30">
            Open
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* View Header */}
      <div>
        <h2 className="text-xl font-bold tracking-tight text-foreground">Findings & Risk Posture</h2>
        <p className="text-sm text-muted-foreground">
          Forensically verified security defects, misconfigurations, and non-compliant response headers.
        </p>
      </div>

      {/* Metric Stat Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <div
          onClick={() => setSelectedSeverity('critical')}
          className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
            selectedSeverity === 'critical'
              ? 'bg-rose-500/15 border-rose-500/40 shadow-sm'
              : 'bg-card/40 border-border hover:bg-accent/40'
          }`}
        >
          <span className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider block">
            Critical
          </span>
          <span className="text-2xl font-bold text-rose-400 font-mono mt-1 block">
            {severityCounts.critical}
          </span>
        </div>

        <div
          onClick={() => setSelectedSeverity('high')}
          className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
            selectedSeverity === 'high'
              ? 'bg-orange-500/15 border-orange-500/40 shadow-sm'
              : 'bg-card/40 border-border hover:bg-accent/40'
          }`}
        >
          <span className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider block">
            High
          </span>
          <span className="text-2xl font-bold text-orange-400 font-mono mt-1 block">
            {severityCounts.high}
          </span>
        </div>

        <div
          onClick={() => setSelectedSeverity('medium')}
          className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
            selectedSeverity === 'medium'
              ? 'bg-amber-500/15 border-amber-500/40 shadow-sm'
              : 'bg-card/40 border-border hover:bg-accent/40'
          }`}
        >
          <span className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider block">
            Medium
          </span>
          <span className="text-2xl font-bold text-amber-400 font-mono mt-1 block">
            {severityCounts.medium}
          </span>
        </div>

        <div
          onClick={() => setSelectedSeverity('low')}
          className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
            selectedSeverity === 'low'
              ? 'bg-blue-500/15 border-blue-500/40 shadow-sm'
              : 'bg-card/40 border-border hover:bg-accent/40'
          }`}
        >
          <span className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider block">
            Low
          </span>
          <span className="text-2xl font-bold text-blue-400 font-mono mt-1 block">
            {severityCounts.low}
          </span>
        </div>

        <div
          onClick={() => setSelectedSeverity('all')}
          className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
            selectedSeverity === 'all'
              ? 'bg-primary/15 border-primary/40 shadow-sm'
              : 'bg-card/40 border-border hover:bg-accent/40'
          }`}
        >
          <span className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider block">
            Total Findings
          </span>
          <span className="text-2xl font-bold text-foreground font-mono mt-1 block">
            {findings.length}
          </span>
        </div>
      </div>

      {/* Status Filter Tabs & Search Bar */}
      <div className="space-y-3">
        {/* Status Tabs */}
        <div className="flex flex-wrap items-center gap-1.5 border-b border-border pb-2.5">
          {(
            [
              { id: 'all', label: 'All Statuses', count: statusCounts.all },
              { id: 'open', label: 'Open', count: statusCounts.open },
              { id: 'resolved', label: 'Resolved', count: statusCounts.resolved },
              { id: 'false_positive', label: 'False Positive', count: statusCounts.false_positive },
              { id: 'risk_accepted', label: 'Risk Accepted', count: statusCounts.risk_accepted },
              { id: 'suppressed', label: 'Suppressed', count: statusCounts.suppressed },
            ] as const
          ).map((tab) => (
            <button
              key={tab.id}
              onClick={() => {
                setSelectedStatus(tab.id);
                setCurrentPage(1);
              }}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                selectedStatus === tab.id
                  ? 'bg-primary/15 text-blue-400 border border-primary/25 shadow-sm'
                  : 'text-muted-foreground hover:bg-accent/60 hover:text-foreground'
              }`}
            >
              <span>{tab.label}</span>
              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded-full bg-accent text-foreground">
                {tab.count}
              </span>
            </button>
          ))}
        </div>

        {/* Filter and Search Bar */}
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search findings by title, category, fingerprint, or description..."
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full pl-9 pr-9 py-2 bg-background border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder:text-muted-foreground/60"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => {
                  setSearchQuery('');
                  setCurrentPage(1);
                }}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground p-0.5"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-muted-foreground shrink-0" />
            <select
              value={selectedSeverity}
              onChange={(e) => {
                setSelectedSeverity(e.target.value);
                setCurrentPage(1);
              }}
              className="px-3 py-2 bg-background border border-border rounded-lg text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500 cursor-pointer"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical Only</option>
              <option value="high">High Only</option>
              <option value="medium">Medium Only</option>
              <option value="low">Low Only</option>
              <option value="info">Info Only</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-3">
        {isLoading ? (
          <div className="p-8 text-center text-sm text-muted-foreground">Loading findings database...</div>
        ) : filteredFindings.length === 0 ? (
          <div className="p-8 border border-dashed border-border rounded-xl text-center space-y-2">
            <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
            <h4 className="text-sm font-semibold text-foreground">Zero Security Findings</h4>
            <p className="text-xs text-muted-foreground max-w-sm mx-auto">
              No findings matched your current filter criteria. Run additional test executions to verify target defenses.
            </p>
          </div>
        ) : (
          paginatedFindings.map((finding) => {
            const isExpanded = expandedFindingId === finding.id;

            return (
              <div
                key={finding.id}
                className="rounded-2xl border border-border bg-card/60 backdrop-blur-sm overflow-hidden transition-all hover:border-primary/40 shadow-sm"
              >
                <div
                  onClick={() => setExpandedFindingId(isExpanded ? null : finding.id)}
                  className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 cursor-pointer hover:bg-accent/30 transition-colors"
                >
                  <div className="flex items-start gap-3">
                    {isExpanded ? (
                      <ChevronDown className="w-4 h-4 text-muted-foreground mt-1 shrink-0" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-muted-foreground mt-1 shrink-0" />
                    )}
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        {getSeverityBadge(finding.severity)}
                        {getStatusBadge(finding.status)}
                        <span className="font-semibold text-sm text-foreground">{finding.title}</span>
                        <span className="text-xs font-mono px-2 py-0.5 rounded bg-accent text-muted-foreground border border-border/50">
                          {finding.category}
                        </span>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            copyToClipboard(finding.fingerprint, 'Fingerprint');
                          }}
                          title="Copy finding fingerprint"
                          className="text-[10px] font-mono bg-accent/60 hover:bg-accent px-1.5 py-0.5 rounded text-muted-foreground flex items-center gap-1 transition-colors"
                        >
                          <span>{finding.fingerprint.slice(0, 10)}...</span>
                          <Copy className="w-2.5 h-2.5" />
                        </button>
                      </div>
                      <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
                        {finding.description}
                      </p>
                    </div>
                  </div>

                  <div className="text-xs text-muted-foreground text-right whitespace-nowrap">
                    <div>{new Date(finding.firstDetectedAt).toLocaleDateString()}</div>
                    <div className="text-[11px] font-mono text-muted-foreground/80 mt-0.5">
                      Engine: {finding.testDefinitionId}
                    </div>
                  </div>
                </div>

                {/* Expanded Details & Forensics */}
                {isExpanded && (
                  <div className="p-5 border-t border-border bg-background/50 space-y-4 animate-fade-in">
                    {/* Triage & Management Actions */}
                    <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-xl bg-accent/40 border border-border/70 text-xs">
                      <div className="flex flex-wrap items-center gap-2.5">
                        <span className="text-muted-foreground font-medium flex items-center gap-1.5">
                          <Tag className="w-3.5 h-3.5 text-blue-400" /> Triage Status:
                        </span>
                        <select
                          value={finding.status || 'open'}
                          onChange={(e) => {
                            e.stopPropagation();
                            updateStatusMutation.mutate({ findingId: finding.id, status: e.target.value });
                          }}
                          disabled={updateStatusMutation.isPending}
                          className="px-2.5 py-1 rounded-lg bg-background border border-border text-foreground font-mono text-xs focus:ring-1 focus:ring-blue-500 cursor-pointer"
                        >
                          <option value="open">Open</option>
                          <option value="resolved">Resolved / Fixed</option>
                          <option value="false_positive">False Positive</option>
                          <option value="risk_accepted">Risk Accepted</option>
                          <option value="suppressed">Suppressed</option>
                        </select>
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            copyToClipboard(`security-lab findings triage ${finding.id} --status resolved`, 'CLI triage command');
                          }}
                          title="Copy CLI command to triage finding"
                          className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-accent hover:bg-accent/80 border border-border text-muted-foreground hover:text-foreground text-xs font-mono transition-colors"
                        >
                          <Terminal className="w-3.5 h-3.5 text-blue-400" />
                          <span>CLI Triage</span>
                        </button>

                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            if (window.confirm(`Are you sure you want to delete finding "${finding.title}"?`)) {
                              deleteFindingMutation.mutate(finding.id);
                            }
                          }}
                          disabled={deleteFindingMutation.isPending}
                          className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-rose-950/30 hover:bg-rose-950/50 border border-rose-800/40 text-rose-400 hover:text-rose-300 transition-colors text-xs disabled:opacity-50"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                          <span>Delete</span>
                        </button>
                      </div>
                    </div>

                    {/* Recommendation Card */}
                    {finding.recommendation && (
                      <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-xs space-y-1">
                        <span className="font-semibold text-emerald-400 block">
                          Remediation Recommendation:
                        </span>
                        <p className="text-emerald-300 leading-relaxed font-mono">
                          {finding.recommendation}
                        </p>
                      </div>
                    )}

                    {/* Forensic Evidence Container */}
                    <div className="p-4 rounded-xl bg-card border border-border/80 space-y-3">
                      <div className="flex items-center justify-between border-b border-border/60 pb-2">
                        <div className="flex items-center gap-2">
                          <FileCheck className="w-4 h-4 text-blue-400" />
                          <span className="text-xs font-semibold text-foreground">
                            Forensic Evidence Record
                          </span>
                        </div>
                        {evidence?.immutableHash && (
                          <span className="text-[10px] font-mono bg-accent px-2 py-0.5 rounded text-blue-400">
                            SHA-256: {evidence.immutableHash.slice(0, 16)}...
                          </span>
                        )}
                      </div>

                      {isLoadingEvidence ? (
                        <div className="text-xs text-muted-foreground py-2">Loading forensic evidence...</div>
                      ) : evidence ? (
                        <div className="space-y-3 text-xs">
                          {/* Request / Response Details */}
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono">
                            {/* Request */}
                            {evidence.request && (
                              <div className="p-3 rounded-lg bg-background/80 border border-border/60 space-y-1">
                                <span className="text-muted-foreground text-[11px] block font-sans font-semibold">
                                  Captured Request:
                                </span>
                                <div className="text-blue-400">
                                  {evidence.request.method} {evidence.request.url}
                                </div>
                              </div>
                            )}

                            {/* Response */}
                            {evidence.response && (
                              <div className="p-3 rounded-lg bg-background/80 border border-border/60 space-y-1">
                                <span className="text-muted-foreground text-[11px] block font-sans font-semibold">
                                  Target Response:
                                </span>
                                <div className="flex items-center gap-3">
                                  <span className="text-emerald-400">
                                    HTTP {evidence.response.statusCode}
                                  </span>
                                  {evidence.response.responseTimeMs && (
                                    <span className="text-muted-foreground text-[11px]">
                                      {evidence.response.responseTimeMs}ms
                                    </span>
                                  )}
                                </div>
                              </div>
                            )}
                          </div>

                          {/* Expected vs Actual Box */}
                          {(evidence.expected !== undefined || evidence.actual !== undefined) && (
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
                              <div className="p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/20">
                                <span className="text-emerald-400 text-[11px] block font-sans font-semibold mb-1">
                                  Expected State:
                                </span>
                                <div className="text-foreground break-all">
                                  {typeof evidence.expected === 'object'
                                    ? JSON.stringify(evidence.expected, null, 2)
                                    : String(evidence.expected)}
                                </div>
                              </div>
                              <div className="p-3 rounded-lg bg-rose-500/5 border border-rose-500/20">
                                <span className="text-rose-400 text-[11px] block font-sans font-semibold mb-1">
                                  Actual Target Behavior:
                                </span>
                                <div className="text-foreground break-all">
                                  {typeof evidence.actual === 'object'
                                    ? JSON.stringify(evidence.actual, null, 2)
                                    : String(evidence.actual)}
                                </div>
                              </div>
                            </div>
                          )}
                        </div>
                      ) : (
                        <div className="text-xs text-muted-foreground">
                          Finding Fingerprint: <span className="font-mono">{finding.fingerprint}</span>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}

        {/* Pagination component */}
        <Pagination
          currentPage={currentPage}
          totalItems={filteredFindings.length}
          pageSize={pageSize}
          onPageChange={setCurrentPage}
          onPageSizeChange={setPageSize}
          pageSizeOptions={[4, 6, 12, 20]}
        />
      </div>
    </div>
  );
};
