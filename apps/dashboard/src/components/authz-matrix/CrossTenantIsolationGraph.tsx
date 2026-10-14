import React, { useState } from 'react';
import {
  ShieldAlert,
  Building,
  User,
  FileText,
  CreditCard,
  Database,
  AlertTriangle,
  Lock,
  Unlock,
  ExternalLink,
} from 'lucide-react';
import { CrossTenantBreach, AuthzViolationEvidence } from '../../api/authz.js';

interface CrossTenantIsolationGraphProps {
  breaches: CrossTenantBreach[];
  evidenceMap: Record<string, AuthzViolationEvidence>;
  onSelectEvidence: (evidence: AuthzViolationEvidence) => void;
}

export const CrossTenantIsolationGraph: React.FC<CrossTenantIsolationGraphProps> = ({
  breaches,
  evidenceMap,
  onSelectEvidence,
}) => {
  const [selectedBreachId, setSelectedBreachId] = useState<string | null>(
    breaches[0]?.id || null,
  );

  const activeBreach = breaches.find((b) => b.id === selectedBreachId) || breaches[0];

  return (
    <div className="space-y-6">
      {/* Visual Canvas Card */}
      <div className="p-6 rounded-xl bg-card border border-border/70 shadow-lg space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="p-1.5 rounded-lg bg-red-500/10 text-red-400 border border-red-500/20">
                <ShieldAlert className="w-4 h-4" />
              </span>
              <h3 className="text-base font-bold text-foreground">
                Cross-Tenant Perimeter & Isolation Graph
              </h3>
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Visualizes cross-tenant boundary crossings where identities from one tenant access private objects of another tenant without authorization (BOLA / IDOR).
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span
              className={`px-3 py-1 rounded-full text-xs font-mono font-semibold border flex items-center gap-1.5 ${
                breaches.length > 0
                  ? 'bg-red-500/15 text-red-400 border-red-500/30'
                  : 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
              }`}
            >
              {breaches.length > 0 ? (
                <>
                  <Unlock className="w-3.5 h-3.5" />
                  <span>Isolation Compromised ({breaches.length} Breaches)</span>
                </>
              ) : (
                <>
                  <Lock className="w-3.5 h-3.5" />
                  <span>Boundaries Enforced</span>
                </>
              )}
            </span>
          </div>
        </div>

        {/* Interactive 2-Tenant Visual Boundary Diagram */}
        <div className="relative p-6 rounded-xl bg-slate-950/70 border border-border/80 overflow-hidden">
          {/* Subtle grid background */}
          <div className="absolute inset-0 bg-cyber-grid opacity-20 pointer-events-none" />

          <div className="relative grid grid-cols-1 lg:grid-cols-11 gap-6 items-center">
            {/* Left Box: Tenant Alpha */}
            <div className="lg:col-span-5 p-5 rounded-xl bg-cyan-950/20 border border-cyan-500/30 space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-cyan-500/20">
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded-md bg-cyan-500/20 text-cyan-400">
                    <Building className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-bold text-cyan-200">Tenant Alpha</div>
                    <div className="text-[10px] font-mono text-cyan-400">tenant-alpha-corp</div>
                  </div>
                </div>
                <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                  Target Org
                </span>
              </div>

              {/* Identity Node */}
              <div className="p-3 rounded-lg bg-card/60 border border-border/60 flex items-center gap-3">
                <div className="p-2 rounded-full bg-cyan-500/10 text-cyan-400">
                  <User className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <div className="text-xs font-semibold text-foreground truncate">User A (Alice Smith)</div>
                  <div className="text-[10px] text-muted-foreground font-mono">finance_manager • Owner</div>
                </div>
              </div>

              {/* Private Resources */}
              <div className="space-y-2">
                <div className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
                  Encrypted Vault & Private Assets
                </div>

                <div
                  className={`p-3 rounded-lg border transition-all cursor-pointer ${
                    activeBreach?.targetResource.includes('INV')
                      ? 'bg-red-950/40 border-red-500/60 shadow-lg shadow-red-500/10 ring-1 ring-red-500'
                      : 'bg-card/40 border-border/60 hover:border-border'
                  }`}
                  onClick={() => {
                    const b = breaches.find((item) => item.targetResource.includes('INV'));
                    if (b) setSelectedBreachId(b.id);
                  }}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2.5">
                      <FileText className="w-4 h-4 text-amber-400 shrink-0" />
                      <div>
                        <div className="text-xs font-medium text-foreground">Invoice #INV-90241</div>
                        <div className="text-[10px] font-mono text-muted-foreground">$84,200.00 • Alpha Corp</div>
                      </div>
                    </div>
                    {breaches.some((b) => b.targetResource.includes('INV')) && (
                      <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/30 animate-pulse">
                        LEAKED
                      </span>
                    )}
                  </div>
                </div>

                <div
                  className={`p-3 rounded-lg border transition-all cursor-pointer ${
                    activeBreach?.targetResource.includes('Payment')
                      ? 'bg-red-950/40 border-red-500/60 shadow-lg shadow-red-500/10 ring-1 ring-red-500'
                      : 'bg-card/40 border-border/60 hover:border-border'
                  }`}
                  onClick={() => {
                    const b = breaches.find((item) => item.targetResource.includes('Payment'));
                    if (b) setSelectedBreachId(b.id);
                  }}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2.5">
                      <CreditCard className="w-4 h-4 text-emerald-400 shrink-0" />
                      <div>
                        <div className="text-xs font-medium text-foreground">Payment Vault (IBAN / ACH)</div>
                        <div className="text-[10px] font-mono text-muted-foreground">JPMorgan Chase • **4921</div>
                      </div>
                    </div>
                    {breaches.some((b) => b.targetResource.includes('Payment')) && (
                      <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/30 animate-pulse">
                        LEAKED
                      </span>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* Middle: Neon Isolation Boundary Wall */}
            <div className="lg:col-span-1 flex lg:flex-col items-center justify-center gap-2 py-4">
              <div className="h-0.5 lg:h-12 w-full lg:w-0.5 bg-red-500/40 border-l border-dashed border-red-500" />
              <div className="p-2 rounded-full bg-red-500/15 border border-red-500/40 text-red-400 shadow-lg shadow-red-500/20 animate-pulse">
                <AlertTriangle className="w-4 h-4" />
              </div>
              <div className="text-[10px] font-mono font-bold text-red-400 uppercase text-center rotate-0 lg:-rotate-90 whitespace-nowrap tracking-wider">
                Boundary Pierced
              </div>
              <div className="h-0.5 lg:h-12 w-full lg:w-0.5 bg-red-500/40 border-l border-dashed border-red-500" />
            </div>

            {/* Right Box: Tenant Beta (Attacker Context) */}
            <div className="lg:col-span-5 p-5 rounded-xl bg-purple-950/20 border border-purple-500/30 space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-purple-500/20">
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded-md bg-purple-500/20 text-purple-400">
                    <Building className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-bold text-purple-200">Tenant Beta</div>
                    <div className="text-[10px] font-mono text-purple-400">tenant-beta-inc</div>
                  </div>
                </div>
                <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/30">
                  External Tenant
                </span>
              </div>

              {/* Attacking Identity Node */}
              <div
                className={`p-3 rounded-lg border transition-all cursor-pointer ${
                  activeBreach
                    ? 'bg-purple-900/30 border-purple-500/60 shadow-lg shadow-purple-500/10 ring-1 ring-purple-500'
                    : 'bg-card/60 border-border/60'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-full bg-purple-500/10 text-purple-400">
                      <User className="w-4 h-4" />
                    </div>
                    <div className="min-w-0">
                      <div className="text-xs font-semibold text-foreground truncate">User B (Bob Martinez)</div>
                      <div className="text-[10px] text-muted-foreground font-mono">billing_analyst • Foreign Caller</div>
                    </div>
                  </div>
                  <span className="text-[10px] font-mono font-bold text-red-400">
                    BOLA ATTACKER
                  </span>
                </div>
              </div>

              {/* Own Resources */}
              <div className="space-y-2">
                <div className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
                  Tenant Beta Authorized Assets
                </div>

                <div className="p-3 rounded-lg bg-card/40 border border-border/60">
                  <div className="flex items-center gap-2.5">
                    <FileText className="w-4 h-4 text-purple-400 shrink-0" />
                    <div>
                      <div className="text-xs font-medium text-foreground">Invoice #INV-BETA-881</div>
                      <div className="text-[10px] font-mono text-muted-foreground">$12,400.00 • Authorized Access</div>
                    </div>
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-card/40 border border-border/60">
                  <div className="flex items-center gap-2.5">
                    <Database className="w-4 h-4 text-purple-400 shrink-0" />
                    <div>
                      <div className="text-xs font-medium text-foreground">Private Repository #Beta-Repo</div>
                      <div className="text-[10px] font-mono text-muted-foreground">Isolated Partition</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Detected Cross-Tenant Breaches Table */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
              Detected Cross-Tenant Data Leaks ({breaches.length})
            </h4>
            <span className="text-[11px] text-muted-foreground">
              Click any breach to open side-by-side HTTP forensic evidence
            </span>
          </div>

          <div className="overflow-x-auto rounded-lg border border-border/60">
            <table className="w-full text-left text-xs">
              <thead className="bg-muted/40 text-muted-foreground font-mono text-[11px] border-b border-border/60">
                <tr>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Foreign Caller</th>
                  <th className="py-2.5 px-3">Target Asset (Victim Tenant)</th>
                  <th className="py-2.5 px-3">Endpoint Route</th>
                  <th className="py-2.5 px-3">Leaked Payload Sample</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/40 font-mono">
                {breaches.map((breach) => {
                  const ev = evidenceMap[breach.findingId];
                  return (
                    <tr
                      key={breach.id}
                      className={`hover:bg-muted/30 transition-colors cursor-pointer ${
                        selectedBreachId === breach.id ? 'bg-red-500/5' : ''
                      }`}
                      onClick={() => {
                        setSelectedBreachId(breach.id);
                        if (ev) onSelectEvidence(ev);
                      }}
                    >
                      <td className="py-3 px-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-300 border border-red-500/30">
                          {breach.severity}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <div className="font-semibold text-foreground">{breach.sourceIdentity}</div>
                        <div className="text-[10px] text-purple-400">{breach.sourceTenant}</div>
                      </td>
                      <td className="py-3 px-3">
                        <div className="font-semibold text-cyan-300">{breach.targetResource}</div>
                        <div className="text-[10px] text-muted-foreground">{breach.targetTenant}</div>
                      </td>
                      <td className="py-3 px-3">
                        <span className="text-[11px] font-semibold text-foreground">
                          {breach.method} {breach.endpoint}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <span className="text-[11px] text-red-300/80 truncate block max-w-xs font-mono">
                          {breach.leakedDataPreview}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-right">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            if (ev) onSelectEvidence(ev);
                          }}
                          className="px-2.5 py-1 text-xs font-semibold rounded bg-red-500/10 hover:bg-red-500/20 text-red-300 border border-red-500/30 transition-colors inline-flex items-center gap-1"
                        >
                          <span>Inspect Diff</span>
                          <ExternalLink className="w-3 h-3" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
