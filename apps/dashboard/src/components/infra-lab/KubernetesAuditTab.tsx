import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Server,
  AlertTriangle,
  FolderTree,
  ChevronDown,
  ChevronRight,
  Terminal,
  FileCode,
} from 'lucide-react';
import { K8sAuditSnapshot, K8sWorkloadItem } from '../../api/infra.js';

export interface KubernetesAuditTabProps {
  auditData: K8sAuditSnapshot;
  className?: string;
}

export const KubernetesAuditTab: React.FC<KubernetesAuditTabProps> = ({
  auditData,
  className = '',
}) => {
  const [selectedNamespace, setSelectedNamespace] = useState<string>('all');
  const [expandedWorkloadId, setExpandedWorkloadId] = useState<string | null>('workload-api-gateway');
  const [pssFilter, setPssFilter] = useState<'all' | 'privileged' | 'baseline' | 'restricted'>('all');

  const filteredWorkloads = auditData.workloads.filter((w) => {
    const matchesNs = selectedNamespace === 'all' || w.namespace === selectedNamespace;
    const matchesPss = pssFilter === 'all' || w.pssLevel === pssFilter;
    return matchesNs && matchesPss;
  });

  const toggleExpand = (id: string) => {
    setExpandedWorkloadId(expandedWorkloadId === id ? null : id);
  };

  const getPssBadge = (level: K8sWorkloadItem['pssLevel']) => {
    switch (level) {
      case 'restricted':
        return (
          <span className="flex items-center gap-1 text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
            <ShieldCheck className="w-3 h-3" />
            Restricted (PSS v1.30)
          </span>
        );
      case 'baseline':
        return (
          <span className="flex items-center gap-1 text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3 h-3" />
            Baseline
          </span>
        );
      case 'privileged':
        return (
          <span className="flex items-center gap-1 text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-rose-500/15 text-rose-400 border border-rose-500/30 animate-pulse">
            <ShieldAlert className="w-3 h-3" />
            Privileged (High Risk)
          </span>
        );
    }
  };

  return (
    <div className={`space-y-5 ${className}`}>
      {/* Top Posture & PSS Compliance Gauge */}
      <div className="p-5 rounded-2xl bg-card/60 border border-border/60 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border/40">
          <div>
            <div className="flex items-center gap-2">
              <Server className="w-5 h-5 text-blue-400" />
              <h3 className="font-semibold text-foreground text-sm tracking-wide">
                Kubernetes Pod Security Standards (PSS) & CIS Benchmark Audit
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                {auditData.kubernetesVersion}
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">
              Cluster: <span className="font-mono text-foreground font-medium">{auditData.clusterName}</span>
            </p>
          </div>

          <div className="flex items-center gap-2">
            <div className="text-right">
              <span className="text-[11px] text-muted-foreground block font-mono">Cluster Compliance</span>
              <span className="text-lg font-bold font-mono text-emerald-400">
                {auditData.overallComplianceScore}%
              </span>
            </div>
          </div>
        </div>

        {/* PSS Breakdown Multi-Segment Bar */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-xs font-mono text-muted-foreground">
            <span>Workload PSS Distribution:</span>
            <div className="flex items-center gap-4">
              <span className="text-emerald-400">
                Restricted: {auditData.pssDistribution.restricted} (
                {Math.round((auditData.pssDistribution.restricted / auditData.totalWorkloads) * 100)}%)
              </span>
              <span className="text-amber-400">
                Baseline: {auditData.pssDistribution.baseline} (
                {Math.round((auditData.pssDistribution.baseline / auditData.totalWorkloads) * 100)}%)
              </span>
              <span className="text-rose-400">
                Privileged: {auditData.pssDistribution.privileged} (
                {Math.round((auditData.pssDistribution.privileged / auditData.totalWorkloads) * 100)}%)
              </span>
            </div>
          </div>

          <div className="w-full h-3 rounded-full bg-background/80 overflow-hidden flex border border-border/40">
            <div
              style={{
                width: `${(auditData.pssDistribution.restricted / auditData.totalWorkloads) * 100}%`,
              }}
              className="bg-emerald-500 h-full transition-all"
              title="Restricted PSS"
            />
            <div
              style={{
                width: `${(auditData.pssDistribution.baseline / auditData.totalWorkloads) * 100}%`,
              }}
              className="bg-amber-500 h-full transition-all"
              title="Baseline PSS"
            />
            <div
              style={{
                width: `${(auditData.pssDistribution.privileged / auditData.totalWorkloads) * 100}%`,
              }}
              className="bg-rose-500 h-full transition-all"
              title="Privileged PSS"
            />
          </div>
        </div>
      </div>

      {/* Filter Toolbar: Namespaces & PSS Level */}
      <div className="flex flex-wrap items-center justify-between gap-3 text-xs">
        {/* Namespace Pills */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 max-w-full">
          <span className="text-muted-foreground flex items-center gap-1 pr-1 font-mono text-[11px]">
            <FolderTree className="w-3.5 h-3.5" />
            Namespace:
          </span>
          <button
            type="button"
            onClick={() => setSelectedNamespace('all')}
            className={`px-2.5 py-1 rounded-lg border font-mono transition-colors ${
              selectedNamespace === 'all'
                ? 'bg-blue-500/20 text-blue-300 border-blue-500/40'
                : 'bg-background/60 text-muted-foreground border-border/40 hover:text-foreground'
            }`}
          >
            All ({auditData.totalWorkloads})
          </button>
          {auditData.namespaces.map((ns) => (
            <button
              key={ns.namespace}
              type="button"
              onClick={() => setSelectedNamespace(ns.namespace)}
              className={`px-2.5 py-1 rounded-lg border font-mono transition-colors ${
                selectedNamespace === ns.namespace
                  ? 'bg-blue-500/20 text-blue-300 border-blue-500/40'
                  : 'bg-background/60 text-muted-foreground border-border/40 hover:text-foreground'
              }`}
            >
              {ns.namespace} ({ns.totalWorkloads})
            </button>
          ))}
        </div>

        {/* PSS Filter */}
        <div className="flex items-center gap-1 bg-background/80 p-1 rounded-xl border border-border/50 font-mono text-[11px]">
          <button
            type="button"
            onClick={() => setPssFilter('all')}
            className={`px-2 py-0.5 rounded ${pssFilter === 'all' ? 'bg-muted text-foreground' : 'text-muted-foreground'}`}
          >
            All PSS
          </button>
          <button
            type="button"
            onClick={() => setPssFilter('privileged')}
            className={`px-2 py-0.5 rounded ${pssFilter === 'privileged' ? 'bg-rose-500/20 text-rose-300' : 'text-muted-foreground'}`}
          >
            Privileged
          </button>
          <button
            type="button"
            onClick={() => setPssFilter('baseline')}
            className={`px-2 py-0.5 rounded ${pssFilter === 'baseline' ? 'bg-amber-500/20 text-amber-300' : 'text-muted-foreground'}`}
          >
            Baseline
          </button>
          <button
            type="button"
            onClick={() => setPssFilter('restricted')}
            className={`px-2 py-0.5 rounded ${pssFilter === 'restricted' ? 'bg-emerald-500/20 text-emerald-300' : 'text-muted-foreground'}`}
          >
            Restricted
          </button>
        </div>
      </div>

      {/* Workload Hierarchy Cards */}
      <div className="space-y-3">
        {filteredWorkloads.map((workload) => {
          const isExpanded = expandedWorkloadId === workload.id;
          const hasCritical = workload.findings.some((f) => f.severity === 'critical');
          const hasHigh = workload.findings.some((f) => f.severity === 'high');

          return (
            <div
              key={workload.id}
              className={`rounded-2xl border transition-all overflow-hidden ${
                isExpanded
                  ? 'bg-card/90 border-blue-500/40 shadow-lg'
                  : 'bg-card/50 border-border/60 hover:border-border'
              }`}
            >
              {/* Workload Header Row */}
              <div
                onClick={() => toggleExpand(workload.id)}
                className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer select-none"
              >
                <div className="flex items-center gap-3">
                  <button type="button" className="text-muted-foreground hover:text-foreground">
                    {isExpanded ? (
                      <ChevronDown className="w-4 h-4 text-blue-400" />
                    ) : (
                      <ChevronRight className="w-4 h-4" />
                    )}
                  </button>

                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-foreground text-sm font-mono">{workload.name}</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-muted/60 text-muted-foreground border border-border/40">
                        {workload.kind}
                      </span>
                      <span className="text-xs text-muted-foreground font-mono">
                        ns:{workload.namespace}
                      </span>
                    </div>

                    {/* Quick Misconfiguration Badges */}
                    <div className="flex flex-wrap items-center gap-1.5 mt-1.5 text-[10px] font-mono">
                      {workload.hasPrivilegedContainer && (
                        <span className="px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-400 border border-rose-500/30">
                          ⚠️ Privileged Container
                        </span>
                      )}
                      {workload.runsAsRoot && (
                        <span className="px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-400 border border-rose-500/30">
                          ⚠️ Runs As Root
                        </span>
                      )}
                      {workload.hasSensitiveHostPath && (
                        <span className="px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-400 border border-rose-500/30">
                          ⚠️ HostPath Socket Mount
                        </span>
                      )}
                      {workload.addedCapabilities.length > 0 && (
                        <span className="px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/30">
                          ⚡ Added: {workload.addedCapabilities.join(', ')}
                        </span>
                      )}
                      {!workload.hasNetworkPolicy && (
                        <span className="px-1.5 py-0.5 rounded bg-muted/60 text-muted-foreground border border-border/40">
                          No NetPolicy
                        </span>
                      )}
                      {!workload.hasResourceLimits && (
                        <span className="px-1.5 py-0.5 rounded bg-muted/60 text-muted-foreground border border-border/40">
                          No Limits
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Right Metadata & PSS Badge */}
                <div className="flex items-center gap-3 self-end sm:self-center">
                  {getPssBadge(workload.pssLevel)}

                  <div className="text-right font-mono text-xs">
                    <span
                      className={`font-bold ${
                        hasCritical
                          ? 'text-rose-400'
                          : hasHigh
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                      }`}
                    >
                      {workload.findings.length} findings
                    </span>
                  </div>
                </div>
              </div>

              {/* Expanded Inspection Drawer */}
              {isExpanded && (
                <div className="p-4 border-t border-border/40 bg-background/50 space-y-4 text-xs">
                  {/* File & Manifest Path */}
                  <div className="flex items-center justify-between text-[11px] font-mono text-muted-foreground pb-2 border-b border-border/30">
                    <span className="flex items-center gap-1.5">
                      <FileCode className="w-3.5 h-3.5 text-blue-400" />
                      Manifest: {workload.manifestFilePath}
                    </span>
                    <span>Containers: {workload.containersCount}</span>
                  </div>

                  {/* Findings List */}
                  {workload.findings.length === 0 ? (
                    <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4" />
                      <span>Zero CIS/PSS misconfigurations detected. Workload adheres strictly to Restricted PSS.</span>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {workload.findings.map((f) => (
                        <div
                          key={f.ruleId}
                          className="p-3.5 rounded-xl bg-card border border-border/60 space-y-2"
                        >
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                            <div className="flex items-center gap-2 font-mono">
                              <span
                                className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${
                                  f.severity === 'critical'
                                    ? 'bg-rose-500/15 text-rose-400 border-rose-500/30'
                                    : f.severity === 'high'
                                    ? 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                                    : 'bg-blue-500/15 text-blue-400 border-blue-500/30'
                                }`}
                              >
                                {f.severity}
                              </span>
                              <span className="text-foreground font-semibold font-sans">{f.title}</span>
                            </div>
                            <span className="text-[11px] text-muted-foreground font-mono">
                              Rule: {f.ruleId} {f.lineNumber ? `(Line ${f.lineNumber})` : ''}
                            </span>
                          </div>

                          {/* Violating Code Snippet */}
                          {f.violatingSnippet && (
                            <div className="p-2.5 rounded-lg bg-black/60 border border-border/40 font-mono text-[11px] text-rose-300 overflow-x-auto whitespace-pre">
                              {f.violatingSnippet}
                            </div>
                          )}

                          {/* Remediation Action */}
                          <div className="p-2.5 rounded-lg bg-blue-500/10 border border-blue-500/20 text-[11px] flex items-start gap-2 text-blue-200">
                            <Terminal className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                            <div>
                              <strong className="text-blue-300">Remediation:</strong> {f.recommendation}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
