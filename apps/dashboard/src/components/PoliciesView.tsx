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
  Search,
  Copy,
  Terminal,
  ShieldAlert,
  Clock,
  Layers,
} from 'lucide-react';
import { EvaluateReleaseModal } from './EvaluateReleaseModal.js';
import { Pagination } from './Pagination.js';
import { useAppStore } from '../store/useAppStore.js';

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

export interface PolicyWaiver {
  fingerprint: string;
  reason: string;
  approvedBy: string;
  expiresAt: string;
}

interface Policy {
  id: string;
  name: string;
  description?: string;
  rules: PolicyRule[];
  requiredProfiles?: string[];
  waivers?: PolicyWaiver[];
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
  const { showToast } = useAppStore();

  const [activeSubTab, setActiveSubTab] = useState<'policies' | 'audits'>('policies');
  const [isEvaluateModalOpen, setIsEvaluateModalOpen] = useState(false);
  const [isCreatePolicyOpen, setIsCreatePolicyOpen] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null);

  // Search & Pagination States
  const [policySearchQuery, setPolicySearchQuery] = useState('');
  const [releaseSearchQuery, setReleaseSearchQuery] = useState('');
  const [releaseDecisionFilter, setReleaseDecisionFilter] = useState<'all' | 'allow' | 'block_release' | 'warn'>('all');
  const [releaseCurrentPage, setReleaseCurrentPage] = useState(1);
  const [releasePageSize, setReleasePageSize] = useState(6);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    showToast(`Copied ${label} to clipboard`, 'info');
  };

  // Available test profiles for mandatory enforcement
  const AVAILABLE_PROFILES = [
    { id: 'engine-native-tls', name: 'TLS & Cipher Verification', category: 'Class A' },
    { id: 'engine-native-headers', name: 'Defensive Security Headers', category: 'Class A' },
    { id: 'engine-native-cors', name: 'CORS Access Control Rules', category: 'Class A' },
    { id: 'engine-native-auth', name: 'Authentication & Session Gate', category: 'Class A' },
    { id: 'engine-native-resilience', name: 'Burst Rate Limiting SLA', category: 'Class A' },
    { id: 'declarative', name: 'Declarative OpenAPI Contracts', category: 'Class A' },
    { id: 'class-b-scanners', name: 'Container Scanners (ZAP / Trivy)', category: 'Class B' },
    { id: 'k6', name: 'Grafana k6 Concurrency Performance', category: 'Class C' },
  ];

  // Policy Form State
  const [newPolicyName, setNewPolicyName] = useState('');
  const [newPolicyDesc, setNewPolicyDesc] = useState('');
  const [maxCritical, setMaxCritical] = useState<number>(0);
  const [maxHigh, setMaxHigh] = useState<number>(0);
  const [maxMedium, setMaxMedium] = useState<number>(5);
  const [maxP95LatencyMs, setMaxP95LatencyMs] = useState<number>(500);
  const [maxErrorRatePercent, setMaxErrorRatePercent] = useState<number>(1.0);
  const [selectedRequiredProfiles, setSelectedRequiredProfiles] = useState<string[]>([
    'engine-native-tls',
    'engine-native-headers',
  ]);
  const [activeWaivers, setActiveWaivers] = useState<PolicyWaiver[]>([]);
  const [newWaiverFingerprint, setNewWaiverFingerprint] = useState<string>('');
  const [newWaiverReason, setNewWaiverReason] = useState<string>('');
  const [newWaiverApprover, setNewWaiverApprover] = useState<string>('AppSec Lead');
  const [newWaiverDays, setNewWaiverDays] = useState<number>(30);

  const handleOpenCreatePolicy = () => {
    setEditingPolicy(null);
    setNewPolicyName('');
    setNewPolicyDesc('');
    setMaxCritical(0);
    setMaxHigh(0);
    setMaxMedium(5);
    setMaxP95LatencyMs(500);
    setMaxErrorRatePercent(1.0);
    setSelectedRequiredProfiles(['engine-native-tls', 'engine-native-headers']);
    setActiveWaivers([]);
    setNewWaiverFingerprint('');
    setNewWaiverReason('');
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
    setSelectedRequiredProfiles(policy.requiredProfiles || []);
    setActiveWaivers(policy.waivers || []);
    setNewWaiverFingerprint('');
    setNewWaiverReason('');
    setIsCreatePolicyOpen(true);
  };

  const handleAddWaiver = () => {
    if (!newWaiverFingerprint.trim()) {
      showToast('Finding fingerprint is required', 'error');
      return;
    }
    if (!newWaiverReason.trim()) {
      showToast('Waiver justification is required', 'error');
      return;
    }
    const expiresAt = new Date(Date.now() + newWaiverDays * 24 * 60 * 60 * 1000).toISOString();
    const waiver: PolicyWaiver = {
      fingerprint: newWaiverFingerprint.trim(),
      reason: newWaiverReason.trim(),
      approvedBy: newWaiverApprover.trim() || 'AppSec Lead',
      expiresAt,
    };
    setActiveWaivers((prev) => [...prev, waiver]);
    setNewWaiverFingerprint('');
    setNewWaiverReason('');
    showToast('Waiver added to policy draft');
  };

  const handleRemoveWaiver = (index: number) => {
    setActiveWaivers((prev) => prev.filter((_, i) => i !== index));
    showToast('Waiver removed from draft', 'info');
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
          requiredProfiles: selectedRequiredProfiles,
          waivers: activeWaivers,
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
      showToast('Policy created successfully');
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      showToast(msg, 'error');
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
          requiredProfiles: selectedRequiredProfiles,
          waivers: activeWaivers,
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
      showToast('Policy updated successfully');
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      showToast(msg, 'error');
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
      showToast('Policy deleted successfully', 'info');
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      showToast(msg, 'error');
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
      showToast('Release audit deleted successfully', 'info');
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      showToast(msg, 'error');
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
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="relative w-full sm:w-80">
              <Search className="w-3.5 h-3.5 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search policies by name or rule..."
                value={policySearchQuery}
                onChange={(e) => setPolicySearchQuery(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 bg-background border border-border rounded-lg text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder:text-muted-foreground/60"
              />
              {policySearchQuery && (
                <button
                  type="button"
                  onClick={() => setPolicySearchQuery('')}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            <span className="text-xs font-mono text-muted-foreground">
              CLI: <code className="text-blue-400">security-lab policy list</code>
            </span>
          </div>

          {isLoadingPolicies ? (
            <div className="p-8 text-center text-sm text-muted-foreground">Loading gating policies...</div>
          ) : policies.length === 0 ? (
            <div className="p-8 border border-dashed border-border rounded-xl text-center text-sm text-muted-foreground">
              No policies registered yet.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {policies
                .filter((p) => {
                  if (!policySearchQuery.trim()) return true;
                  const q = policySearchQuery.toLowerCase();
                  return (
                    p.name.toLowerCase().includes(q) ||
                    (p.description || '').toLowerCase().includes(q) ||
                    p.rules?.some((r) => r.name.toLowerCase().includes(q))
                  );
                })
                .map((policy) => {
                  const isBaseline = policy.id === '00000000-0000-0000-0000-000000000001';

                  return (
                    <div
                      key={policy.id}
                      className="p-5 rounded-2xl border border-border bg-card/60 backdrop-blur-sm flex flex-col justify-between space-y-4 hover:border-primary/40 transition-all shadow-sm"
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
                              className="p-2.5 rounded-xl bg-accent/40 border border-border/60 text-xs flex items-center justify-between"
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

                      {/* Mandatory Test Profiles */}
                      {policy.requiredProfiles && policy.requiredProfiles.length > 0 && (
                        <div className="space-y-1.5 border-t border-border/50 pt-3">
                          <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                            <Layers className="w-3 h-3 text-blue-400" />
                            Mandatory Test Profiles ({policy.requiredProfiles.length})
                          </span>
                          <div className="flex flex-wrap gap-1.5">
                            {policy.requiredProfiles.map((prof) => (
                              <span
                                key={prof}
                                className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20"
                              >
                                {prof}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Active Policy Waivers */}
                      {policy.waivers && policy.waivers.length > 0 && (
                        <div className="space-y-1.5 border-t border-border/50 pt-3">
                          <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                            <ShieldAlert className="w-3 h-3 text-amber-400" />
                            Active Policy Waivers ({policy.waivers.length})
                          </span>
                          <div className="space-y-1 max-h-36 overflow-y-auto pr-1">
                            {policy.waivers.map((waiver, widx) => (
                              <div
                                key={widx}
                                className="p-2 rounded-lg bg-amber-500/5 border border-amber-500/20 text-[11px] flex items-center justify-between"
                              >
                                <div className="space-y-0.5 min-w-0 pr-2">
                                  <div className="flex items-center gap-1.5">
                                    <span className="font-mono text-foreground font-semibold text-[10px]">
                                      {waiver.fingerprint.slice(0, 10)}...
                                    </span>
                                    <span className="text-muted-foreground text-[10px]">by {waiver.approvedBy}</span>
                                  </div>
                                  <p className="text-muted-foreground text-[10px] truncate">{waiver.reason}</p>
                                </div>
                                <span className="font-mono text-[9px] text-amber-300 shrink-0 flex items-center gap-1 bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/20">
                                  <Clock className="w-2.5 h-2.5" />
                                  Exp: {new Date(waiver.expiresAt).toLocaleDateString()}
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      <div className="pt-2 text-[11px] font-mono text-muted-foreground flex items-center justify-between border-t border-border/40">
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => copyToClipboard(policy.id, 'Policy ID')}
                            title="Copy Policy ID"
                            className="flex items-center gap-1 hover:text-foreground transition-colors"
                          >
                            <span>ID: {policy.id.slice(0, 8)}...</span>
                            <Copy className="w-2.5 h-2.5" />
                          </button>
                          {!isBaseline && (
                            <div className="flex items-center gap-1 pl-1 border-l border-border">
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

                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => copyToClipboard(`security-lab gate evaluate --policy ${policy.id}`, 'CLI gate command')}
                            title="Copy CLI evaluate command"
                            className="p-1 text-muted-foreground hover:text-blue-400"
                          >
                            <Terminal className="w-3 h-3" />
                          </button>
                          <button
                            onClick={() => setIsEvaluateModalOpen(true)}
                            className="text-blue-400 hover:text-blue-300 text-xs font-sans font-medium flex items-center gap-1"
                          >
                            Evaluate Gate →
                          </button>
                        </div>
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
        <div className="space-y-4">
          {(() => {
            const releaseDecisionCounts = {
              all: releases.length,
              allow: releases.filter((r) => r.decision === 'allow').length,
              block_release: releases.filter((r) => r.decision === 'block_release').length,
              warn: releases.filter((r) => r.decision === 'warn').length,
            };

            const filteredReleases = releases.filter((rel) => {
              if (releaseDecisionFilter !== 'all' && rel.decision !== releaseDecisionFilter) return false;
              if (releaseSearchQuery.trim()) {
                const q = releaseSearchQuery.toLowerCase();
                const matchName = rel.name.toLowerCase().includes(q);
                const matchVer = rel.version.toLowerCase().includes(q);
                const matchCommit = (rel.gitCommit || '').toLowerCase().includes(q);
                const matchBranch = (rel.gitBranch || '').toLowerCase().includes(q);
                if (!matchName && !matchVer && !matchCommit && !matchBranch) return false;
              }
              return true;
            });

            const paginatedReleases = filteredReleases.slice(
              (releaseCurrentPage - 1) * releasePageSize,
              releaseCurrentPage * releasePageSize,
            );

            return (
              <>
                {/* Decision Tabs & Search Bar */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex flex-wrap items-center gap-1.5 border-b sm:border-b-0 pb-2 sm:pb-0 border-border">
                    {(
                      [
                        { id: 'all', label: 'All Audits', count: releaseDecisionCounts.all },
                        { id: 'allow', label: 'Passed', count: releaseDecisionCounts.allow },
                        { id: 'block_release', label: 'Blocked', count: releaseDecisionCounts.block_release },
                        { id: 'warn', label: 'Warnings', count: releaseDecisionCounts.warn },
                      ] as const
                    ).map((tab) => (
                      <button
                        key={tab.id}
                        onClick={() => {
                          setReleaseDecisionFilter(tab.id);
                          setReleaseCurrentPage(1);
                        }}
                        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                          releaseDecisionFilter === tab.id
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

                  <div className="relative w-full sm:w-72">
                    <Search className="w-3.5 h-3.5 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      placeholder="Search release audits..."
                      value={releaseSearchQuery}
                      onChange={(e) => {
                        setReleaseSearchQuery(e.target.value);
                        setReleaseCurrentPage(1);
                      }}
                      className="w-full pl-8 pr-3 py-1.5 bg-background border border-border rounded-lg text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder:text-muted-foreground/60"
                    />
                  </div>
                </div>

                {isLoadingReleases ? (
                  <div className="p-8 text-center text-sm text-muted-foreground">Loading release audits...</div>
                ) : filteredReleases.length === 0 ? (
                  <div className="p-8 border border-dashed border-border rounded-xl text-center text-sm text-muted-foreground space-y-3">
                    <p>No release gate audits match your filter criteria.</p>
                    <button
                      onClick={() => setIsEvaluateModalOpen(true)}
                      className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-colors"
                    >
                      Evaluate Release Gate
                    </button>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {paginatedReleases.map((rel) => (
                      <div
                        key={rel.id}
                        className="p-4 rounded-2xl border border-border bg-card/60 backdrop-blur-sm flex flex-col md:flex-row md:items-center justify-between gap-4 hover:border-primary/40 transition-all shadow-sm"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2.5 flex-wrap">
                            <span className="font-semibold text-sm text-foreground">{rel.name}</span>
                            <button
                              type="button"
                              onClick={() => copyToClipboard(rel.version, 'Release Version')}
                              title="Copy version"
                              className="font-mono text-xs text-blue-400 bg-blue-500/10 hover:bg-blue-500/20 px-2 py-0.5 rounded border border-blue-500/20 flex items-center gap-1 transition-colors"
                            >
                              <span>{rel.version}</span>
                              <Copy className="w-2.5 h-2.5" />
                            </button>
                            {getDecisionBadge(rel.decision)}
                          </div>
                          <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                            {rel.gitCommit && (
                              <button
                                type="button"
                                onClick={() => copyToClipboard(rel.gitCommit || '', 'Commit SHA')}
                                title="Copy Git Commit"
                                className="flex items-center gap-1 font-mono text-[11px] hover:text-foreground transition-colors"
                              >
                                <GitCommit className="w-3.5 h-3.5 text-blue-400" />
                                <span>{rel.gitCommit.slice(0, 8)}</span>
                                <Copy className="w-2.5 h-2.5" />
                              </button>
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
                            <p className="text-xs text-muted-foreground/90 mt-1 max-w-2xl bg-accent/30 p-2 rounded-lg border border-border/40 font-mono text-[11px]">
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
                              className="px-3 py-1.5 rounded-lg bg-accent hover:bg-accent/80 border border-border text-foreground text-xs font-medium flex items-center gap-1.5 transition-colors font-mono text-[11px]"
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

                {/* Pagination */}
                <Pagination
                  currentPage={releaseCurrentPage}
                  totalItems={filteredReleases.length}
                  pageSize={releasePageSize}
                  onPageChange={setReleaseCurrentPage}
                  onPageSizeChange={setReleasePageSize}
                  pageSizeOptions={[4, 6, 12, 20]}
                />
              </>
            );
          })()}
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
          <div className="bg-card border border-border w-full max-w-2xl max-h-[92vh] rounded-2xl shadow-2xl overflow-hidden flex flex-col">
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

            <div className="p-6 space-y-5 overflow-y-auto max-h-[calc(92vh-140px)]">
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

              {/* Mandatory Test Profiles */}
              <div className="space-y-2 pt-2 border-t border-border">
                <div className="flex items-center justify-between">
                  <label className="block text-xs font-semibold text-foreground">
                    Mandatory Test Profiles
                  </label>
                  <span className="text-[11px] text-muted-foreground font-mono">
                    {selectedRequiredProfiles.length} selected
                  </span>
                </div>
                <p className="text-[11px] text-muted-foreground">
                  The release gate will automatically block if any of the selected profiles were not executed during the test run.
                </p>
                <div className="grid grid-cols-2 gap-2 pt-1">
                  {AVAILABLE_PROFILES.map((prof) => {
                    const isSelected = selectedRequiredProfiles.includes(prof.id);
                    return (
                      <button
                        key={prof.id}
                        type="button"
                        onClick={() => {
                          if (isSelected) {
                            setSelectedRequiredProfiles((prev) => prev.filter((p) => p !== prof.id));
                          } else {
                            setSelectedRequiredProfiles((prev) => [...prev, prof.id]);
                          }
                        }}
                        className={`p-2.5 rounded-xl border text-left flex items-start gap-2.5 transition-colors ${
                          isSelected
                            ? 'bg-blue-500/10 border-blue-500/40 text-blue-300'
                            : 'bg-background hover:bg-accent/40 border-border text-muted-foreground'
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => {}}
                          className="mt-0.5 rounded border-border text-blue-500 focus:ring-0"
                        />
                        <div className="space-y-0.5">
                          <span className="text-xs font-medium text-foreground block">{prof.name}</span>
                          <span className="text-[10px] font-mono text-muted-foreground">{prof.id} &bull; {prof.category}</span>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Policy Waivers Management */}
              <div className="space-y-3 pt-2 border-t border-border">
                <div className="flex items-center justify-between">
                  <label className="block text-xs font-semibold text-foreground">
                    Policy Waivers & Exemptions ({activeWaivers.length})
                  </label>
                  <span className="text-[11px] text-muted-foreground font-mono">
                    Temporary overrides
                  </span>
                </div>
                <p className="text-[11px] text-muted-foreground">
                  Exempt known vulnerabilities from blocking this policy until their expiration date.
                </p>

                {activeWaivers.length > 0 && (
                  <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
                    {activeWaivers.map((waiver, idx) => (
                      <div
                        key={idx}
                        className="p-2.5 rounded-xl bg-accent/40 border border-border/70 flex items-center justify-between text-xs"
                      >
                        <div className="space-y-0.5 min-w-0 pr-3">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-foreground font-semibold text-[11px]">
                              {waiver.fingerprint.slice(0, 14)}...
                            </span>
                            <span className="text-[10px] text-muted-foreground font-mono">
                              by {waiver.approvedBy}
                            </span>
                          </div>
                          <p className="text-[11px] text-muted-foreground truncate">{waiver.reason}</p>
                          <div className="text-[10px] text-amber-400 font-mono flex items-center gap-1">
                            <Clock className="w-2.5 h-2.5" />
                            <span>Expires: {new Date(waiver.expiresAt).toLocaleDateString()}</span>
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={() => handleRemoveWaiver(idx)}
                          className="p-1 rounded text-rose-400 hover:text-rose-300 hover:bg-rose-950/40 transition-colors shrink-0"
                          title="Remove Waiver"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}

                {/* Inline Add Waiver Form */}
                <div className="p-3 rounded-xl bg-card border border-border/80 space-y-2.5">
                  <span className="text-[11px] font-semibold text-foreground uppercase tracking-wider block">
                    + Add New Finding Waiver
                  </span>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label className="block text-[10px] font-mono text-muted-foreground mb-1">
                        Finding Fingerprint
                      </label>
                      <input
                        type="text"
                        value={newWaiverFingerprint}
                        onChange={(e) => setNewWaiverFingerprint(e.target.value)}
                        placeholder="e.g. c7a1... or SHA256"
                        className="w-full px-2.5 py-1.5 rounded-lg bg-background border border-border text-foreground font-mono text-[11px] focus:outline-none focus:border-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] font-mono text-muted-foreground mb-1">
                        Approver Name / Role
                      </label>
                      <input
                        type="text"
                        value={newWaiverApprover}
                        onChange={(e) => setNewWaiverApprover(e.target.value)}
                        placeholder="e.g. AppSec Lead"
                        className="w-full px-2.5 py-1.5 rounded-lg bg-background border border-border text-foreground text-[11px] focus:outline-none focus:border-blue-500"
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-2">
                    <div className="col-span-2">
                      <label className="block text-[10px] font-mono text-muted-foreground mb-1">
                        Waiver Justification
                      </label>
                      <input
                        type="text"
                        value={newWaiverReason}
                        onChange={(e) => setNewWaiverReason(e.target.value)}
                        placeholder="e.g. Compensating WAF rule active; vendor patch pending"
                        className="w-full px-2.5 py-1.5 rounded-lg bg-background border border-border text-foreground text-[11px] focus:outline-none focus:border-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] font-mono text-muted-foreground mb-1">
                        Duration
                      </label>
                      <select
                        value={newWaiverDays}
                        onChange={(e) => setNewWaiverDays(parseInt(e.target.value) || 30)}
                        className="w-full px-2 py-1.5 rounded-lg bg-background border border-border text-foreground text-[11px] focus:outline-none focus:border-blue-500"
                      >
                        <option value={7}>7 Days</option>
                        <option value={14}>14 Days</option>
                        <option value={30}>30 Days</option>
                        <option value={90}>90 Days</option>
                      </select>
                    </div>
                  </div>
                  <div className="flex justify-end pt-1">
                    <button
                      type="button"
                      onClick={handleAddWaiver}
                      className="px-3 py-1.5 rounded-lg bg-accent hover:bg-accent/80 border border-border text-foreground text-xs font-medium transition-colors"
                    >
                      Add Exemption Rule
                    </button>
                  </div>
                </div>
              </div>

              {(createPolicyMutation.isError || updatePolicyMutation.isError) && (
                <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs">
                  {((createPolicyMutation.error as Error)?.message || (updatePolicyMutation.error as Error)?.message || 'An error occurred')}
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
