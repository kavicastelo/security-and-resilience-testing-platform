import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Scale,
  Plus,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  History,
  GitCommit,
  GitBranch,
  ExternalLink,
  Sliders,
  X,
  Loader2,
  Trash2,
  Pencil,
} from 'lucide-react';
import { EvaluateReleaseModal } from './EvaluateReleaseModal.js';

interface PolicyRule {
  id: string;
  name: string;
  description?: string;
  condition: {
    maxAllowedSeverity?: string;
    maxCountBySeverity?: {
      critical?: number;
      high?: number;
      medium?: number;
      low?: number;
    };
    maxP95LatencyMs?: number;
    maxErrorRatePercent?: number;
    minPassPercentage?: number;
  };
  action: 'block_release' | 'warn';
}

interface Policy {
  id: string;
  name: string;
  description?: string;
  rules: PolicyRule[];
  createdAt?: string;
  updatedAt?: string;
}

interface ReleaseAudit {
  id: string;
  projectId: string;
  name: string;
  version: string;
  gitCommit?: string;
  gitBranch?: string;
  testRunId?: string;
  policyId?: string;
  decision: 'allow' | 'block_release' | 'warn';
  reason?: string;
  evaluatedAt?: string;
  createdAt: string;
}

export const PoliciesView: React.FC = () => {
  const queryClient = useQueryClient();
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000';

  const [activeSubTab, setActiveSubTab] = useState<'policies' | 'audits'>('policies');
  const [isEvaluateModalOpen, setIsEvaluateModalOpen] = useState(false);
  const [isCreatePolicyOpen, setIsCreatePolicyOpen] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null);

  // Policy Form State
  const [newPolicyName, setNewPolicyName] = useState('');
  const [newPolicyDesc, setNewPolicyDesc] = useState('');
  const [maxCritical, setMaxCritical] = useState<number>(0);
  const [maxHigh, setMaxHigh] = useState<number>(0);
  const [maxMedium, setMaxMedium] = useState<number>(5);
  const [maxP95LatencyMs, setMaxP95LatencyMs] = useState<number>(500);
  const [maxErrorRatePercent, setMaxErrorRatePercent] = useState<number>(1.0);

  const handleOpenCreatePolicy = () => {
    setEditingPolicy(null);
    setNewPolicyName('');
    setNewPolicyDesc('');
    setMaxCritical(0);
    setMaxHigh(0);
    setMaxMedium(5);
    setMaxP95LatencyMs(500);
    setMaxErrorRatePercent(1.0);
    setIsCreatePolicyOpen(true);
  };

  const handleOpenEditPolicy = (policy: Policy) => {
    setEditingPolicy(policy);
    setNewPolicyName(policy.name);
    setNewPolicyDesc(policy.description || '');
    const sevRule = policy.rules?.find((r) => r.condition?.maxCountBySeverity);
    if (sevRule?.condition?.maxCountBySeverity) {
      setMaxCritical(sevRule.condition.maxCountBySeverity.critical ?? 0);
      setMaxHigh(sevRule.condition.maxCountBySeverity.high ?? 0);
      setMaxMedium(sevRule.condition.maxCountBySeverity.medium ?? 5);
    }
    const perfRule = policy.rules?.find((r) => r.condition?.maxP95LatencyMs);
    if (perfRule?.condition) {
      setMaxP95LatencyMs(perfRule.condition.maxP95LatencyMs ?? 500);
      setMaxErrorRatePercent(perfRule.condition.maxErrorRatePercent ?? 1.0);
    }
    setIsCreatePolicyOpen(true);
  };

  // Fetch Policies
  const { data: policies = [], isLoading: isLoadingPolicies } = useQuery<Policy[]>({
    queryKey: ['policies'],
    queryFn: async () => {
      const res = await fetch(`${apiUrl}/api/v1/policies`);
      const json = await res.json();
      return json.data || [];
    },
  });

  // Fetch Release Audits
  const { data: releases = [], isLoading: isLoadingReleases } = useQuery<ReleaseAudit[]>({
    queryKey: ['releases'],
    queryFn: async () => {
      const res = await fetch(`${apiUrl}/api/v1/releases`);
      const json = await res.json();
      return json.data || [];
    },
  });

  // Create Policy Mutation
  const createPolicyMutation = useMutation({
    mutationFn: async () => {
      const rules: PolicyRule[] = [
        {
          id: `rule-severity-${Date.now()}`,
          name: 'Vulnerability Severity Thresholds',
          description: `Zero critical findings and maximum ${maxHigh} high findings allowed`,
          condition: {
            maxCountBySeverity: {
              critical: maxCritical,
              high: maxHigh,
              medium: maxMedium,
            },
          },
          action: 'block_release',
        },
        {
          id: `rule-latency-sla-${Date.now()}`,
          name: 'P95 Latency SLA Gating',
          description: `P95 response latency under load must not exceed ${maxP95LatencyMs}ms`,
          condition: {
            maxP95LatencyMs,
            maxErrorRatePercent,
          },
          action: 'block_release',
        },
      ];

      const res = await fetch(`${apiUrl}/api/v1/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newPolicyName.trim(),
          description: newPolicyDesc.trim() || undefined,
          rules,
        }),
      });

      if (!res.ok) {
        const errorJson = await res.json();
        throw new Error(errorJson.error?.message || 'Failed to create policy');
      }

      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] });
      setIsCreatePolicyOpen(false);
      setNewPolicyName('');
      setNewPolicyDesc('');
    },
  });

  // Update Policy Mutation
  const updatePolicyMutation = useMutation({
    mutationFn: async () => {
      if (!editingPolicy) return;
      const rules: PolicyRule[] = [
        {
          id: `rule-severity-${Date.now()}`,
          name: 'Vulnerability Severity Thresholds',
          description: `Zero critical findings and maximum ${maxHigh} high findings allowed`,
          condition: {
            maxCountBySeverity: {
              critical: maxCritical,
              high: maxHigh,
              medium: maxMedium,
            },
          },
          action: 'block_release',
        },
        {
          id: `rule-latency-sla-${Date.now()}`,
          name: 'P95 Latency SLA Gating',
          description: `P95 response latency under load must not exceed ${maxP95LatencyMs}ms`,
          condition: {
            maxP95LatencyMs,
            maxErrorRatePercent,
          },
          action: 'block_release',
        },
      ];

      const res = await fetch(`${apiUrl}/api/v1/policies/${editingPolicy.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newPolicyName.trim(),
          description: newPolicyDesc.trim() || undefined,
          rules,
        }),
      });

      if (!res.ok) {
        const errorJson = await res.json();
        throw new Error(errorJson.error?.message || 'Failed to update policy');
      }

      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] });
      setIsCreatePolicyOpen(false);
      setEditingPolicy(null);
      setNewPolicyName('');
      setNewPolicyDesc('');
    },
  });

  // Delete Policy Mutation
  const deletePolicyMutation = useMutation({
    mutationFn: async (policyId: string) => {
      const res = await fetch(`${apiUrl}/api/v1/policies/${policyId}`, {
        method: 'DELETE',
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error?.message || 'Failed to delete policy');
      return json;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] });
    },
  });

  // Delete Release Audit Mutation
  const deleteReleaseMutation = useMutation({
    mutationFn: async (releaseId: string) => {
      const res = await fetch(`${apiUrl}/api/v1/releases/${releaseId}`, {
        method: 'DELETE',
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error?.message || 'Failed to delete release audit');
      return json;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['releases'] });
    },
  });

  const getDecisionBadge = (decision: string) => {
    switch (decision) {
      case 'allow':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3 h-3" /> PASSED
          </span>
        );
      case 'block_release':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-rose-500/15 text-rose-400 border border-rose-500/30">
            <XCircle className="w-3 h-3" /> BLOCKED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3 h-3" /> WARNING
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="rounded-xl border border-border bg-gradient-to-br from-card to-accent/30 p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-2 max-w-2xl">
          <div className="flex items-center gap-2">
            <span className="p-1.5 rounded-lg bg-blue-500/15 border border-blue-500/30 text-blue-400">
              <Scale className="w-4 h-4" />
            </span>
            <span className="text-xs font-mono uppercase bg-blue-950/60 text-blue-400 border border-blue-800/60 px-2.5 py-0.5 rounded-full">
              Phase 5: Release Gating & Audit
            </span>
          </div>
          <h2 className="text-xl font-bold tracking-tight text-foreground">
            Release Gate Policies & Continuous Compliance
          </h2>
          <p className="text-sm text-muted-foreground leading-relaxed">
            Automate go/no-go decisions in CI/CD pipelines by enforcing strict vulnerability thresholds,
            latency SLAs, and test pass requirements before production deployment.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            onClick={handleOpenCreatePolicy}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-accent hover:bg-accent/80 text-foreground text-xs font-medium border border-border transition-colors"
          >
            <Plus className="w-3.5 h-3.5 text-blue-400" />
            <span>New Policy</span>
          </button>
          <button
            onClick={() => setIsEvaluateModalOpen(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-colors shadow-lg shadow-blue-500/10"
          >
            <Scale className="w-4 h-4" />
            <span>Evaluate Release Gate</span>
          </button>
        </div>
      </div>

      {/* Sub Tabs */}
      <div className="flex items-center gap-2 border-b border-border pb-3">
        <button
          onClick={() => setActiveSubTab('policies')}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-medium transition-colors ${
            activeSubTab === 'policies'
              ? 'bg-primary/15 text-blue-400 border border-primary/20'
              : 'text-muted-foreground hover:bg-accent hover:text-foreground'
          }`}
        >
          <Sliders className="w-3.5 h-3.5" />
          <span>Defined Policies ({policies.length})</span>
        </button>
        <button
          onClick={() => setActiveSubTab('audits')}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-medium transition-colors ${
            activeSubTab === 'audits'
              ? 'bg-primary/15 text-blue-400 border border-primary/20'
              : 'text-muted-foreground hover:bg-accent hover:text-foreground'
          }`}
        >
          <History className="w-3.5 h-3.5" />
          <span>Release Gate Audits ({releases.length})</span>
        </button>
      </div>

      {/* Sub Tab 1: Defined Policies */}
      {activeSubTab === 'policies' && (
        <div className="space-y-4">
          {isLoadingPolicies ? (
            <div className="p-8 text-center text-sm text-muted-foreground">Loading gating policies...</div>
          ) : policies.length === 0 ? (
            <div className="p-8 border border-dashed border-border rounded-xl text-center text-sm text-muted-foreground">
              No policies registered yet.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {policies.map((policy) => {
                const isBaseline = policy.id === '00000000-0000-0000-0000-000000000001';

                return (
                  <div
                    key={policy.id}
                    className="p-5 rounded-xl border border-border bg-card/60 flex flex-col justify-between space-y-4 hover:border-border/90 transition-all"
                  >
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-sm text-foreground">{policy.name}</span>
                          {isBaseline && (
                            <span className="text-[10px] font-mono bg-blue-500/20 text-blue-400 border border-blue-500/30 px-2 py-0.5 rounded">
                              DEFAULT BASELINE
                            </span>
                          )}
                        </div>
                        <span className="text-xs font-mono text-muted-foreground">
                          {policy.rules?.length ?? 0} rules
                        </span>
                      </div>
                      <p className="text-xs text-muted-foreground leading-relaxed">
                        {policy.description || 'Enterprise release policy definition.'}
                      </p>
                    </div>

                    {/* Policy Rules List */}
                    <div className="space-y-2 border-t border-border/50 pt-3">
                      <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                        Configured Rule Enforcements
                      </span>
                      <div className="space-y-1.5">
                        {policy.rules?.map((rule, idx) => (
                          <div
                            key={rule.id || idx}
                            className="p-2.5 rounded-lg bg-accent/40 border border-border/60 text-xs flex items-center justify-between"
                          >
                            <div className="space-y-0.5">
                              <span className="font-medium text-foreground block">{rule.name}</span>
                              <div className="flex items-center gap-2 text-[11px] text-muted-foreground font-mono">
                                {rule.condition?.maxAllowedSeverity && (
                                  <span>Max Sev: {rule.condition.maxAllowedSeverity}</span>
                                )}
                                {rule.condition?.maxCountBySeverity && (
                                  <span>
                                    Crit: {rule.condition.maxCountBySeverity.critical ?? 0} | High:{' '}
                                    {rule.condition.maxCountBySeverity.high ?? 0}
                                  </span>
                                )}
                                {rule.condition?.maxP95LatencyMs && (
                                  <span>P95 &le; {rule.condition.maxP95LatencyMs}ms</span>
                                )}
                                {rule.condition?.maxErrorRatePercent && (
                                  <span>Error &le; {rule.condition.maxErrorRatePercent}%</span>
                                )}
                              </div>
                            </div>

                            <span
                              className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded font-semibold ${
                                rule.action === 'block_release'
                                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                                  : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                              }`}
                            >
                              {rule.action}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="pt-2 text-[11px] font-mono text-muted-foreground flex items-center justify-between border-t border-border/40">
                      <div className="flex items-center gap-2">
                        <span>ID: {policy.id.slice(0, 8)}...</span>
                        {!isBaseline && (
                          <div className="flex items-center gap-1">
                            <button
                              onClick={() => handleOpenEditPolicy(policy)}
                              className="p-1 rounded text-amber-400 hover:text-amber-300 hover:bg-amber-950/40 transition-colors"
                              title="Edit Policy"
                            >
                              <Pencil className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => {
                                if (window.confirm(`Are you sure you want to delete custom policy "${policy.name}"?`)) {
                                  deletePolicyMutation.mutate(policy.id);
                                }
                              }}
                              disabled={deletePolicyMutation.isPending}
                              className="p-1 rounded text-rose-400 hover:text-rose-300 hover:bg-rose-950/40 transition-colors disabled:opacity-50"
                              title="Delete Policy"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        )}
                      </div>
                      <button
                        onClick={() => setIsEvaluateModalOpen(true)}
                        className="text-blue-400 hover:text-blue-300 text-xs font-sans font-medium flex items-center gap-1"
                      >
                        Evaluate Against Run →
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Sub Tab 2: Release Gate Audits */}
      {activeSubTab === 'audits' && (
        <div className="space-y-3">
          {isLoadingReleases ? (
            <div className="p-8 text-center text-sm text-muted-foreground">Loading release audits...</div>
          ) : releases.length === 0 ? (
            <div className="p-8 border border-dashed border-border rounded-xl text-center text-sm text-muted-foreground space-y-3">
              <p>No release gate audits recorded yet.</p>
              <button
                onClick={() => setIsEvaluateModalOpen(true)}
                className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-colors"
              >
                Evaluate First Release
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              {releases.map((rel) => (
                <div
                  key={rel.id}
                  className="p-4 rounded-xl border border-border bg-card/40 flex flex-col md:flex-row md:items-center justify-between gap-4"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2.5">
                      <span className="font-semibold text-sm text-foreground">{rel.name}</span>
                      <span className="font-mono text-xs text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">
                        {rel.version}
                      </span>
                      {getDecisionBadge(rel.decision)}
                    </div>
                    <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                      {rel.gitCommit && (
                        <span className="flex items-center gap-1 font-mono text-[11px]">
                          <GitCommit className="w-3.5 h-3.5 text-blue-400" /> {rel.gitCommit.slice(0, 8)}
                        </span>
                      )}
                      {rel.gitBranch && (
                        <span className="flex items-center gap-1 font-mono text-[11px]">
                          <GitBranch className="w-3.5 h-3.5 text-emerald-400" /> {rel.gitBranch}
                        </span>
                      )}
                      <span>•</span>
                      <span>{new Date(rel.evaluatedAt || rel.createdAt).toLocaleString()}</span>
                    </div>
                    {rel.reason && (
                      <p className="text-xs text-muted-foreground/90 mt-1 max-w-2xl bg-accent/30 p-2 rounded border border-border/40 font-mono text-[11px]">
                        {rel.reason}
                      </p>
                    )}
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    {rel.testRunId && (
                      <a
                        href={`${apiUrl}/api/v1/test-runs/${rel.testRunId}/report?format=html`}
                        target="_blank"
                        rel="noreferrer"
                        className="px-3 py-1.5 rounded-lg bg-accent hover:bg-accent/80 border border-border text-foreground text-xs font-medium flex items-center gap-1.5 transition-colors"
                      >
                        <ExternalLink className="w-3.5 h-3.5 text-blue-400" />
                        <span>Executive Report</span>
                      </a>
                    )}
                    <button
                      onClick={() => {
                        if (window.confirm(`Delete release audit record for "${rel.name} (${rel.version})"?`)) {
                          deleteReleaseMutation.mutate(rel.id);
                        }
                      }}
                      disabled={deleteReleaseMutation.isPending}
                      title="Delete Release Audit"
                      className="p-1.5 rounded-lg bg-rose-950/30 hover:bg-rose-950/50 border border-rose-800/40 text-rose-400 hover:text-rose-300 transition-colors disabled:opacity-50"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Modal 1: Evaluate Release Gate */}
      <EvaluateReleaseModal
        isOpen={isEvaluateModalOpen}
        onClose={() => setIsEvaluateModalOpen(false)}
        apiUrl={apiUrl}
      />

      {/* Modal 2: Create / Edit Custom Policy */}
      {isCreatePolicyOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-card border border-border w-full max-w-lg rounded-2xl shadow-2xl overflow-hidden flex flex-col">
            <div className="px-6 py-4 border-b border-border flex items-center justify-between bg-card/60">
              <div className="flex items-center gap-2.5">
                <Sliders className="w-5 h-5 text-blue-400" />
                <h3 className="text-base font-bold text-foreground">
                  {editingPolicy ? 'Edit Release Gate Policy' : 'Create Release Gate Policy'}
                </h3>
              </div>
              <button
                onClick={() => setIsCreatePolicyOpen(false)}
                className="p-1 rounded-lg text-muted-foreground hover:text-foreground"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-4">
              <div>
                <label className="block text-xs font-semibold text-foreground mb-1">
                  Policy Name <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  value={newPolicyName}
                  onChange={(e) => setNewPolicyName(e.target.value)}
                  placeholder="e.g. Strict Production Deployment Gate"
                  className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground text-xs focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-foreground mb-1">Description</label>
                <textarea
                  value={newPolicyDesc}
                  onChange={(e) => setNewPolicyDesc(e.target.value)}
                  placeholder="Enforces zero-tolerance vulnerability policy and strict latency thresholds..."
                  rows={2}
                  className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground text-xs focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="grid grid-cols-3 gap-3 pt-2 border-t border-border">
                <div>
                  <label className="block text-xs font-semibold text-foreground mb-1">
                    Max Critical
                  </label>
                  <input
                    type="number"
                    min={0}
                    value={maxCritical}
                    onChange={(e) => setMaxCritical(parseInt(e.target.value) || 0)}
                    className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground text-xs focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-foreground mb-1">
                    Max High
                  </label>
                  <input
                    type="number"
                    min={0}
                    value={maxHigh}
                    onChange={(e) => setMaxHigh(parseInt(e.target.value) || 0)}
                    className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground text-xs focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-foreground mb-1">
                    Max Medium
                  </label>
                  <input
                    type="number"
                    min={0}
                    value={maxMedium}
                    onChange={(e) => setMaxMedium(parseInt(e.target.value) || 0)}
                    className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground text-xs focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-foreground mb-1">
                    Max P95 Latency (ms)
                  </label>
                  <input
                    type="number"
                    min={10}
                    step={10}
                    value={maxP95LatencyMs}
                    onChange={(e) => setMaxP95LatencyMs(parseInt(e.target.value) || 500)}
                    className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground text-xs focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-foreground mb-1">
                    Max Error Rate (%)
                  </label>
                  <input
                    type="number"
                    min={0}
                    max={100}
                    step={0.1}
                    value={maxErrorRatePercent}
                    onChange={(e) => setMaxErrorRatePercent(parseFloat(e.target.value) || 1.0)}
                    className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground text-xs focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              {(createPolicyMutation.isError || updatePolicyMutation.isError) && (
                <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs">
                  {((createPolicyMutation.error || updatePolicyMutation.error) as Error).message}
                </div>
              )}
            </div>

            <div className="px-6 py-4 border-t border-border flex items-center justify-end gap-2 bg-card/60">
              <button
                onClick={() => setIsCreatePolicyOpen(false)}
                className="px-4 py-2 rounded-lg bg-accent hover:bg-accent/80 text-muted-foreground text-xs font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  if (editingPolicy) {
                    updatePolicyMutation.mutate();
                  } else {
                    createPolicyMutation.mutate();
                  }
                }}
                disabled={!newPolicyName.trim() || createPolicyMutation.isPending || updatePolicyMutation.isPending}
                className="flex items-center gap-1.5 px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-medium transition-colors shadow-lg shadow-blue-500/10"
              >
                {(createPolicyMutation.isPending || updatePolicyMutation.isPending) ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Saving Policy...</span>
                  </>
                ) : (
                  <span>{editingPolicy ? 'Save Changes' : 'Create Policy'}</span>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
