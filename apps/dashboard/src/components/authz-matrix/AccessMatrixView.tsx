import React, { useState, useEffect } from 'react';
import {
  Grid,
  ShieldAlert,
  Building,
  Copy,
  Check,
  PlayCircle,
  BookOpen,
  RefreshCw,
} from 'lucide-react';
import { useAppStore } from '../../store/useAppStore.js';
import {
  PRESET_MATRICES,
  AuthzMatrixDataset,
  AuthzViolationEvidence,
  generateMatrixMarkdown,
  retestAuthzFinding,
  getAuthzMatrixDataset,
} from '../../api/authz.js';
import { targetsApi, Target } from '../../api/targets.js';
import { MatrixGridTable } from './MatrixGridTable.js';
import { CrossTenantIsolationGraph } from './CrossTenantIsolationGraph.js';
import { ViolationDetailModal } from './ViolationDetailModal.js';

export const AccessMatrixView: React.FC = () => {
  const { showToast, setActiveTab } = useAppStore();
  const [selectedTargetId, setSelectedTargetId] = useState<string>('');
  const [selectedDatasetKey, setSelectedDatasetKey] = useState<string>('financialSaaS');
  const [targetsList, setTargetsList] = useState<Target[]>([]);
  const [activeViewTab, setActiveViewTab] = useState<'matrix' | 'isolation' | 'playbook'>('matrix');
  const [selectedEvidence, setSelectedEvidence] = useState<AuthzViolationEvidence | null>(null);
  const [copiedMarkdown, setCopiedMarkdown] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [dataset, setDataset] = useState<AuthzMatrixDataset | null>(PRESET_MATRICES.financialSaaS);

  // Load available targets
  useEffect(() => {
    let mounted = true;
    targetsApi
      .listTargets()
      .then((tgts: Target[]) => {
        if (mounted && Array.isArray(tgts)) {
          setTargetsList(tgts);
        }
      })
      .catch(() => {});
    return () => {
      mounted = false;
    };
  }, []);

  // Hydrate or fetch matrix dataset whenever target or preset changes
  useEffect(() => {
    let mounted = true;
    setIsLoading(true);

    if (selectedTargetId) {
      getAuthzMatrixDataset(undefined, selectedTargetId)
        .then((realData) => {
          if (mounted) {
            setDataset(realData);
            setIsLoading(false);
          }
        })
        .catch(() => {
          if (mounted) {
            setDataset(null);
            setIsLoading(false);
          }
        });
    } else {
      // Demo preset mode
      const presetData = PRESET_MATRICES[selectedDatasetKey] || PRESET_MATRICES.financialSaaS;
      setDataset(presetData);
      setIsLoading(false);
    }

    return () => {
      mounted = false;
    };
  }, [selectedTargetId, selectedDatasetKey]);

  const handleCopyMarkdown = async () => {
    if (!dataset) return;
    try {
      const md = generateMatrixMarkdown(dataset);
      await navigator.clipboard.writeText(md);
      setCopiedMarkdown(true);
      showToast('Copied full authorization matrix markdown table to clipboard', 'success');
      setTimeout(() => setCopiedMarkdown(false), 2500);
    } catch {
      showToast('Failed to copy to clipboard', 'error');
    }
  };

  const handleRetestFinding = async (findingId: string) => {
    try {
      const outcome = await retestAuthzFinding(findingId);
      showToast(outcome.message, outcome.success ? 'success' : 'error');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Retest failed';
      showToast(msg, 'error');
    }
  };

  // Aggregate metrics if dataset exists
  const totalPermutations = dataset?.cells.length ?? 0;
  const endpointsCount = dataset?.routes.length ?? 0;
  const personasCount = dataset?.personas.length ?? 0;
  const bolaViolations = dataset?.cells.filter((c) => c.status === 'VIOLATION_BOLA').length ?? 0;
  const bflaViolations = dataset?.cells.filter((c) => c.status === 'VIOLATION_BFLA').length ?? 0;

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* View Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-border/60">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">
              <Grid className="w-5 h-5" />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold tracking-tight text-foreground">
                  Automated BOLA / BFLA Matrix Visualizer
                </h1>
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-purple-500/15 text-purple-400 border border-purple-500/30">
                  Engine Matrix v1.0
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-0.5">
                Multi-persona authorization permutation grid and cross-tenant boundary isolation inspector.
              </p>
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Target Selector */}
          <select
            value={selectedTargetId}
            onChange={(e) => setSelectedTargetId(e.target.value)}
            className="px-3 py-1.5 text-xs font-medium rounded-lg bg-card border border-border/80 text-foreground focus:outline-none focus:ring-1 focus:ring-purple-500"
          >
            <option value="">Demo Presets</option>
            {targetsList.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name} ({t.baseUrl})
              </option>
            ))}
          </select>

          {/* Preset Selector (Visible only in Demo mode) */}
          {!selectedTargetId && (
            <select
              value={selectedDatasetKey}
              onChange={(e) => setSelectedDatasetKey(e.target.value)}
              className="px-3 py-1.5 text-xs font-medium rounded-lg bg-card border border-border/80 text-foreground focus:outline-none focus:ring-1 focus:ring-purple-500"
            >
              <option value="financialSaaS">Apex Financial Multi-Tenant API</option>
              <option value="healthcareFhir">MedVault FHIR Clinical Records API</option>
            </select>
          )}

          {/* Export Markdown */}
          {dataset && (
            <button
              type="button"
              onClick={handleCopyMarkdown}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-card border border-border/80 text-foreground hover:bg-accent transition-colors"
            >
              {copiedMarkdown ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedMarkdown ? 'Copied Matrix!' : 'Export Matrix (MD)'}</span>
            </button>
          )}

          {/* Launch Scan via Plan Studio */}
          <button
            type="button"
            onClick={() => setActiveTab('runs')}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-purple-600 hover:bg-purple-500 text-white transition-colors"
          >
            <PlayCircle className="w-3.5 h-3.5" />
            <span>Schedule Matrix Scan</span>
          </button>
        </div>
      </div>

      {/* Loading State */}
      {isLoading && (
        <div className="flex flex-col items-center justify-center p-12 text-center rounded-2xl bg-card border border-border/70 shadow-sm space-y-3">
          <RefreshCw className="w-8 h-8 text-purple-400 animate-spin" />
          <p className="text-xs text-muted-foreground font-mono">Aggregating live authorization matrix telemetry...</p>
        </div>
      )}

      {/* Clean Target Empty State */}
      {!isLoading && dataset === null && (
        <div className="flex flex-col items-center justify-center p-12 text-center rounded-2xl bg-card border border-border/70 shadow-sm space-y-4 my-8">
          <div className="p-4 rounded-2xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <ShieldAlert className="w-10 h-10" />
          </div>
          <div className="max-w-md space-y-1.5">
            <h2 className="text-base font-bold text-foreground">
              No Authorization Matrix Generated Yet
            </h2>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Execute a multi-identity BOLA / BFLA test plan against this target to map horizontal and vertical privilege boundaries.
            </p>
          </div>
          <div className="flex items-center gap-3 pt-2">
            <button
              type="button"
              onClick={() => setActiveTab('runs')}
              className="flex items-center gap-1.5 px-4 py-2 text-xs font-semibold rounded-lg bg-purple-600 hover:bg-purple-500 text-white transition-colors shadow-sm"
            >
              <PlayCircle className="w-4 h-4" />
              <span>Run BOLA Test Suite</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setSelectedTargetId('');
                setSelectedDatasetKey('financialSaaS');
              }}
              className="flex items-center gap-1.5 px-4 py-2 text-xs font-semibold rounded-lg bg-card border border-border/80 text-foreground hover:bg-accent transition-colors"
            >
              <Grid className="w-4 h-4 text-purple-400" />
              <span>Explore Demo Preset</span>
            </button>
          </div>
        </div>
      )}

      {/* Populated Matrix Content */}
      {!isLoading && dataset !== null && (
        <>
          {/* KPI Overview Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            {/* Total Permutations */}
            <div className="p-3.5 rounded-xl bg-card border border-border/70 shadow-sm">
              <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                Permutations
              </div>
              <div className="text-xl font-bold font-mono text-foreground mt-1">{totalPermutations}</div>
              <div className="text-[10px] text-muted-foreground mt-0.5">Dual-identity pairs</div>
            </div>

            {/* Endpoints Scanned */}
            <div className="p-3.5 rounded-xl bg-card border border-border/70 shadow-sm">
              <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                Endpoints
              </div>
              <div className="text-xl font-bold font-mono text-cyan-400 mt-1">{endpointsCount}</div>
              <div className="text-[10px] text-muted-foreground mt-0.5">Parameterized routes</div>
            </div>

            {/* Identities Tested */}
            <div className="p-3.5 rounded-xl bg-card border border-border/70 shadow-sm">
              <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                Personas
              </div>
              <div className="text-xl font-bold font-mono text-foreground mt-1">{personasCount}</div>
              <div className="text-[10px] text-muted-foreground mt-0.5">Admin, users, guest</div>
            </div>

            {/* BOLA Violations */}
            <div className="p-3.5 rounded-xl bg-card border border-red-500/30 bg-red-500/5 shadow-sm">
              <div className="text-[10px] font-mono uppercase tracking-wider text-red-400 flex items-center justify-between">
                <span>BOLA (IDOR)</span>
                {bolaViolations > 0 && <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-ping" />}
              </div>
              <div className="text-xl font-bold font-mono text-red-300 mt-1">{bolaViolations}</div>
              <div className="text-[10px] text-red-400/80 mt-0.5">Critical data leaks</div>
            </div>

            {/* BFLA Escalations */}
            <div className="p-3.5 rounded-xl bg-card border border-purple-500/30 bg-purple-500/5 shadow-sm">
              <div className="text-[10px] font-mono uppercase tracking-wider text-purple-400">
                BFLA Escalation
              </div>
              <div className="text-xl font-bold font-mono text-purple-300 mt-1">{bflaViolations}</div>
              <div className="text-[10px] text-purple-400/80 mt-0.5">Admin privilege leaks</div>
            </div>

            {/* Isolation Health */}
            <div className="p-3.5 rounded-xl bg-card border border-border/70 shadow-sm">
              <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                Isolation Score
              </div>
              <div
                className={`text-xl font-bold font-mono mt-1 ${
                  dataset.isolationScore < 70 ? 'text-red-400' : 'text-emerald-400'
                }`}
              >
                {dataset.isolationScore}%
              </div>
              <div className="w-full bg-muted/40 h-1.5 rounded-full mt-1.5 overflow-hidden">
                <div
                  className={`h-full ${
                    dataset.isolationScore < 70 ? 'bg-red-500' : 'bg-emerald-500'
                  }`}
                  style={{ width: `${dataset.isolationScore}%` }}
                />
              </div>
            </div>
          </div>

          {/* Target Info Banner */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-xl bg-card/60 border border-border/60">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
                <Building className="w-4 h-4" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-foreground">{dataset.targetName}</span>
                  <span className="text-[10px] font-mono text-muted-foreground">({dataset.targetId})</span>
                </div>
                <div className="text-xs font-mono text-cyan-400 mt-0.5">{dataset.targetUrl}</div>
              </div>
            </div>

            <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
              <span>Snapshot Timestamp:</span>
              <span className="font-semibold text-foreground">
                {new Date(dataset.generatedAt).toLocaleString()}
              </span>
            </div>
          </div>

          {/* Tab Navigation */}
          <div className="flex items-center gap-2 border-b border-border/60 pb-1">
            <button
              type="button"
              onClick={() => setActiveViewTab('matrix')}
              className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg transition-colors ${
                activeViewTab === 'matrix'
                  ? 'bg-purple-600 text-white shadow-sm'
                  : 'text-muted-foreground hover:text-foreground hover:bg-accent'
              }`}
            >
              <Grid className="w-4 h-4" />
              <span>2D Permission Matrix Heatmap</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveViewTab('isolation')}
              className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg transition-colors ${
                activeViewTab === 'isolation'
                  ? 'bg-purple-600 text-white shadow-sm'
                  : 'text-muted-foreground hover:text-foreground hover:bg-accent'
              }`}
            >
              <ShieldAlert className="w-4 h-4" />
              <span>Cross-Tenant Boundary Graph</span>
              {dataset.crossTenantBreaches.length > 0 && (
                <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-red-500 text-white font-mono">
                  {dataset.crossTenantBreaches.length}
                </span>
              )}
            </button>

            <button
              type="button"
              onClick={() => setActiveViewTab('playbook')}
              className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg transition-colors ${
                activeViewTab === 'playbook'
                  ? 'bg-purple-600 text-white shadow-sm'
                  : 'text-muted-foreground hover:text-foreground hover:bg-accent'
              }`}
            >
              <BookOpen className="w-4 h-4" />
              <span>Remediation & OWASP Playbook</span>
            </button>
          </div>

          {/* Tab 1: 2D Matrix Grid */}
          {activeViewTab === 'matrix' && (
            <MatrixGridTable
              dataset={dataset}
              onSelectEvidence={(ev) => setSelectedEvidence(ev)}
            />
          )}

          {/* Tab 2: Cross-Tenant Perimeter Graph */}
          {activeViewTab === 'isolation' && (
            <CrossTenantIsolationGraph
              breaches={dataset.crossTenantBreaches}
              evidenceMap={dataset.evidenceMap}
              onSelectEvidence={(ev) => setSelectedEvidence(ev)}
            />
          )}

          {/* Tab 3: Remediation & OWASP Playbook */}
          {activeViewTab === 'playbook' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* BOLA Guidance */}
                <div className="p-5 rounded-xl bg-card border border-border/70 space-y-4">
                  <div className="flex items-center gap-2.5">
                    <span className="p-2 rounded-lg bg-red-500/10 text-red-400 border border-red-500/20">
                      <ShieldAlert className="w-5 h-5" />
                    </span>
                    <div>
                      <h3 className="text-sm font-bold text-foreground">
                        OWASP API1:2023 — Broken Object-Level Authorization (BOLA)
                      </h3>
                      <div className="text-xs text-muted-foreground">Horizontal privilege escalation & IDOR</div>
                    </div>
                  </div>

                  <p className="text-xs text-muted-foreground leading-relaxed">
                    BOLA occurs when an application receives an object identifier from the client (e.g. <code>/api/invoices/:id</code>) and performs the requested operation without validating whether the authenticated user or tenant actually owns that object.
                  </p>

                  <div className="p-3 bg-slate-950/80 rounded-lg border border-border/60 font-mono text-xs text-slate-300 space-y-1">
                    <div className="text-emerald-400 font-semibold">// Recommended ORM / SQL Tenant Isolation Pattern:</div>
                    <div className="text-slate-400">// Insecure:</div>
                    <div className="text-red-400 line-through">const invoice = await db.invoices.findById(req.params.id);</div>
                    <div className="text-slate-400 pt-1">// Secure (Contextual tenant check):</div>
                    <div className="text-emerald-300 font-semibold">
                      const invoice = await db.invoices.findOne({`{`}
                    </div>
                    <div className="text-emerald-300 pl-4 font-semibold">
                      where: {`{ id: req.params.id, tenantId: req.user.tenantId }`}
                    </div>
                    <div className="text-emerald-300 font-semibold">{`}`});</div>
                  </div>
                </div>

                {/* BFLA Guidance */}
                <div className="p-5 rounded-xl bg-card border border-border/70 space-y-4">
                  <div className="flex items-center gap-2.5">
                    <span className="p-2 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/20">
                      <ShieldAlert className="w-5 h-5" />
                    </span>
                    <div>
                      <h3 className="text-sm font-bold text-foreground">
                        OWASP API5:2023 — Broken Function-Level Authorization (BFLA)
                      </h3>
                      <div className="text-xs text-muted-foreground">Vertical privilege escalation</div>
                    </div>
                  </div>

                  <p className="text-xs text-muted-foreground leading-relaxed">
                    BFLA occurs when sensitive or administrative endpoints (e.g. <code>/api/admin/audit-logs</code>) lack role or hierarchy verification middleware, allowing regular or lower-privileged personas to execute administrative commands.
                  </p>

                  <div className="p-3 bg-slate-950/80 rounded-lg border border-border/60 font-mono text-xs text-slate-300 space-y-1">
                    <div className="text-purple-400 font-semibold">// Mandatory Route Guard Pattern:</div>
                    <div className="text-slate-400">// Ensure role check occurs BEFORE business logic execution</div>
                    <div className="text-purple-300 font-semibold">
                      fastify.get('/api/admin/audit-logs', {`{`}
                    </div>
                    <div className="text-purple-300 pl-4 font-semibold">
                      preHandler: [requireRole(['admin', 'auditor'])]
                    </div>
                    <div className="text-purple-300 font-semibold">{`}`}, handler);</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Violation Detail Modal */}
          <ViolationDetailModal
            evidence={selectedEvidence}
            onClose={() => setSelectedEvidence(null)}
            onRetest={handleRetestFinding}
          />
        </>
      )}
    </div>
  );
};
