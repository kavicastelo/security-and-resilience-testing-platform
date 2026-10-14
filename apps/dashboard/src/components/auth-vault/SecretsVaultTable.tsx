import React, { useState } from 'react';
import {
  Lock,
  ShieldCheck,
  Search,
  KeyRound,
  Play,
  Pencil,
  Trash2,
  Sparkles,
} from 'lucide-react';
import { Target } from '../../api/targets.js';
import { updateTargetAuthFlow } from '../../api/authVault.js';
import { useAppStore } from '../../store/useAppStore.js';

interface SecretsVaultTableProps {
  targets: Target[];
  onOpenFlowBuilder: (target: Target) => void;
  onRunTest: (target: Target) => void;
  onRefreshTargets: () => void;
}

export const SecretsVaultTable: React.FC<SecretsVaultTableProps> = ({
  targets,
  onOpenFlowBuilder,
  onRunTest,
  onRefreshTargets,
}) => {
  const { showToast } = useAppStore();
  const [searchFilter, setSearchFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'CONFIGURED' | 'UNCONFIGURED'>('ALL');

  const filteredTargets = targets.filter((t) => {
    const matchSearch =
      !searchFilter ||
      t.name.toLowerCase().includes(searchFilter.toLowerCase()) ||
      t.baseUrl.toLowerCase().includes(searchFilter.toLowerCase());

    const isConfigured = Boolean(t.authConfigured);
    const matchStatus =
      statusFilter === 'ALL' ||
      (statusFilter === 'CONFIGURED' && isConfigured) ||
      (statusFilter === 'UNCONFIGURED' && !isConfigured);

    return matchSearch && matchStatus;
  });

  const handleClearAuth = async (targetId: string, targetName: string) => {
    if (!window.confirm(`Clear encrypted credentials and auth profile for "${targetName}"?`)) {
      return;
    }

    try {
      await updateTargetAuthFlow(targetId, null);
      showToast(`Cleared auth credentials for ${targetName}`, 'info');
      onRefreshTargets();
    } catch (err: any) {
      showToast(err.message || 'Failed to clear credentials', 'error');
    }
  };

  const configuredCount = targets.filter((t) => t.authConfigured).length;

  return (
    <div className="space-y-4">
      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3.5 rounded-xl bg-card border border-border flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-cyan-500/15 text-cyan-400">
            <Lock className="w-4 h-4" />
          </div>
          <div>
            <span className="text-[11px] text-muted-foreground block">Vault Targets</span>
            <span className="text-lg font-bold font-mono text-foreground">{targets.length}</span>
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-card border border-border flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-emerald-500/15 text-emerald-400">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div>
            <span className="text-[11px] text-muted-foreground block">Encrypted Credentials</span>
            <span className="text-lg font-bold font-mono text-emerald-400">{configuredCount}</span>
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-card border border-border flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-purple-500/15 text-purple-400">
            <KeyRound className="w-4 h-4" />
          </div>
          <div>
            <span className="text-[11px] text-muted-foreground block">Encryption Standard</span>
            <span className="text-xs font-mono font-bold text-foreground">AES-256-GCM</span>
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-card border border-border flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-amber-500/15 text-amber-400">
            <Sparkles className="w-4 h-4" />
          </div>
          <div>
            <span className="text-[11px] text-muted-foreground block">Zero-Leak Redaction</span>
            <span className="text-xs font-mono font-bold text-amber-400">Enforced</span>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            placeholder="Search targets by name or URL..."
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-background border border-border text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as any)}
            className="px-2.5 py-1.5 rounded-lg bg-background border border-border text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500"
          >
            <option value="ALL">All Targets ({targets.length})</option>
            <option value="CONFIGURED">Encrypted Credentials ({configuredCount})</option>
            <option value="UNCONFIGURED">No Credentials ({targets.length - configuredCount})</option>
          </select>
        </div>
      </div>

      {/* Targets Secrets Table */}
      <div className="rounded-xl bg-card border border-border overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-accent/40 text-muted-foreground border-b border-border/80 font-mono text-[11px]">
              <tr>
                <th className="p-3.5">Target</th>
                <th className="p-3.5">Vault Status</th>
                <th className="p-3.5">Auth Mechanism</th>
                <th className="p-3.5">Envelope Security</th>
                <th className="p-3.5">Last Rotated / Updated</th>
                <th className="p-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {filteredTargets.length === 0 ? (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-xs text-muted-foreground">
                    No targets match the active filter criteria.
                  </td>
                </tr>
              ) : (
                filteredTargets.map((target) => {
                  const isConfigured = Boolean(target.authConfigured);
                  const authType = target.authType || 'FORM';

                  return (
                    <tr key={target.id} className="hover:bg-accent/20 transition-colors">
                      {/* Target Name & URL */}
                      <td className="p-3.5">
                        <div className="font-semibold text-foreground">{target.name}</div>
                        <span className="text-[11px] text-muted-foreground font-mono truncate max-w-xs block">
                          {target.baseUrl}
                        </span>
                      </td>

                      {/* Status */}
                      <td className="p-3.5">
                        {isConfigured ? (
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                            <ShieldCheck className="w-3.5 h-3.5" /> Encrypted Vault Active
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-zinc-500/15 text-zinc-400 border border-zinc-500/30">
                            Unconfigured (Public/None)
                          </span>
                        )}
                      </td>

                      {/* Auth Mechanism */}
                      <td className="p-3.5 font-mono">
                        {isConfigured ? (
                          <span className="px-2 py-0.5 rounded text-xs bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-semibold">
                            {authType}
                          </span>
                        ) : (
                          <span className="text-muted-foreground">--</span>
                        )}
                      </td>

                      {/* Envelope Security */}
                      <td className="p-3.5">
                        {isConfigured ? (
                          <div className="flex items-center gap-1.5 font-mono text-[11px] text-emerald-300">
                            <Lock className="w-3 h-3 text-emerald-400" />
                            <span>AES-256-GCM / 96b IV</span>
                          </div>
                        ) : (
                          <span className="text-muted-foreground text-[11px]">N/A</span>
                        )}
                      </td>

                      {/* Last Updated */}
                      <td className="p-3.5 text-muted-foreground font-mono text-[11px]">
                        {target.updatedAt
                          ? new Date(target.updatedAt).toLocaleDateString()
                          : new Date(target.createdAt).toLocaleDateString()}
                      </td>

                      {/* Actions */}
                      <td className="p-3.5 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          {isConfigured && (
                            <button
                              type="button"
                              onClick={() => onRunTest(target)}
                              className="px-2.5 py-1 rounded-lg bg-cyan-600/15 hover:bg-cyan-600/25 text-cyan-300 border border-cyan-500/30 text-xs font-medium transition-colors flex items-center gap-1"
                              title="Test Auth Flow Handshake"
                            >
                              <Play className="w-3 h-3 text-cyan-400" />
                              <span>Test Flow</span>
                            </button>
                          )}

                          <button
                            type="button"
                            onClick={() => onOpenFlowBuilder(target)}
                            className="px-2.5 py-1 rounded-lg bg-accent hover:bg-accent/80 text-foreground border border-border text-xs font-medium transition-colors flex items-center gap-1"
                          >
                            <Pencil className="w-3 h-3 text-muted-foreground" />
                            <span>{isConfigured ? 'Edit Flow' : 'Configure'}</span>
                          </button>

                          {isConfigured && (
                            <button
                              type="button"
                              onClick={() => handleClearAuth(target.id, target.name)}
                              className="p-1.5 rounded-lg text-muted-foreground hover:text-rose-400 hover:bg-rose-950/20 transition-colors"
                              title="Clear Encrypted Credentials"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
