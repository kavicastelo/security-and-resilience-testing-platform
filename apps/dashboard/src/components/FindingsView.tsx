import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
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
} from 'lucide-react';

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
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000';
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);

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

  const filteredFindings = findings.filter((f) => {
    if (selectedSeverity !== 'all' && f.severity !== selectedSeverity) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const match =
        f.title.toLowerCase().includes(q) ||
        f.category.toLowerCase().includes(q) ||
        f.description.toLowerCase().includes(q);
      if (!match) return false;
    }
    return true;
  });

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

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search findings by title, category, or description..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-background border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-muted-foreground" />
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="px-3 py-2 bg-background border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical Only</option>
            <option value="high">High Only</option>
            <option value="medium">Medium Only</option>
            <option value="low">Low Only</option>
          </select>
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
          filteredFindings.map((finding) => {
            const isExpanded = expandedFindingId === finding.id;

            return (
              <div
                key={finding.id}
                className="rounded-xl border border-border bg-card/40 overflow-hidden transition-all"
              >
                <div
                  onClick={() => setExpandedFindingId(isExpanded ? null : finding.id)}
                  className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 cursor-pointer hover:bg-accent/30"
                >
                  <div className="flex items-start gap-3">
                    {isExpanded ? (
                      <ChevronDown className="w-4 h-4 text-muted-foreground mt-1" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-muted-foreground mt-1" />
                    )}
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        {getSeverityBadge(finding.severity)}
                        <span className="font-semibold text-sm text-foreground">{finding.title}</span>
                        <span className="text-xs font-mono px-2 py-0.5 rounded bg-accent text-muted-foreground">
                          {finding.category}
                        </span>
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
                  <div className="p-5 border-t border-border bg-background/50 space-y-4">
                    {/* Recommendation Card */}
                    {finding.recommendation && (
                      <div className="p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs space-y-1">
                        <span className="font-semibold text-emerald-400 block">
                          Remediation Recommendation:
                        </span>
                        <p className="text-emerald-300 leading-relaxed font-mono">
                          {finding.recommendation}
                        </p>
                      </div>
                    )}

                    {/* Forensic Evidence Container */}
                    <div className="p-4 rounded-lg bg-card border border-border/80 space-y-3">
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
                              <div className="p-3 rounded bg-background/80 border border-border/60 space-y-1">
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
                              <div className="p-3 rounded bg-background/80 border border-border/60 space-y-1">
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
                              <div className="p-3 rounded bg-emerald-500/5 border border-emerald-500/20">
                                <span className="text-emerald-400 text-[11px] block font-sans font-semibold mb-1">
                                  Expected State:
                                </span>
                                <div className="text-foreground break-all">
                                  {typeof evidence.expected === 'object'
                                    ? JSON.stringify(evidence.expected, null, 2)
                                    : String(evidence.expected)}
                                </div>
                              </div>
                              <div className="p-3 rounded bg-rose-500/5 border border-rose-500/20">
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
      </div>
    </div>
  );
};
