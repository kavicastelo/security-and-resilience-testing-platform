import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Lock,
  KeyRound,
  Target as TargetIcon,
  RefreshCw,
} from 'lucide-react';
import { targetsApi, Target } from '../../api/targets.js';
import { SecretsVaultTable } from './SecretsVaultTable.js';
import { TotpVerificationCard } from './TotpVerificationCard.js';
import { AuthFlowBuilderModal } from './AuthFlowBuilderModal.js';
import { useAppStore } from '../../store/useAppStore.js';

export const AuthVaultView: React.FC = () => {
  const { setActiveTab } = useAppStore();

  const [activeTab, setActiveSubTab] = useState<'vault' | 'totp'>('vault');
  const [editingTarget, setEditingTarget] = useState<Target | null>(null);

  // Fetch all targets
  const { data: targets = [], refetch } = useQuery<Target[]>({
    queryKey: ['targets'],
    queryFn: () => targetsApi.listTargets(),
  });

  const handleOpenFlowBuilder = (target: Target) => {
    setEditingTarget(target);
  };

  const handleRunTest = (target: Target) => {
    // Open flow builder modal with test triggered
    setEditingTarget(target);
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Workbench Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-border/80 pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-cyan-500/15 border border-cyan-500/30 text-cyan-400">
              <KeyRound className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold text-foreground">
                  Stateful Authentication &amp; Encrypted Secrets Vault
                </h1>
                <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 font-semibold">
                  Phase UI-07
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-0.5">
                Manage multi-step stateful authentication sequences, automated RFC 6238 TOTP tokens, and AES-256-GCM envelope-encrypted target credentials.
              </p>
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={() => refetch()}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-card hover:bg-accent text-foreground text-xs font-medium border border-border transition-colors shadow-sm"
          >
            <RefreshCw className="w-3.5 h-3.5 text-muted-foreground" />
            <span>Refresh Vault</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('targets')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-accent hover:bg-accent/80 text-foreground text-xs font-medium border border-border transition-colors shadow-sm"
          >
            <TargetIcon className="w-3.5 h-3.5 text-cyan-400" />
            <span>Manage Target Scopes</span>
          </button>
        </div>
      </div>

      {/* Tab Switcher */}
      <div className="flex items-center gap-2 border-b border-border/70 pb-3">
        <button
          type="button"
          onClick={() => setActiveSubTab('vault')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition-all ${
            activeTab === 'vault'
              ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
              : 'text-muted-foreground hover:text-foreground hover:bg-accent/50 border border-transparent'
          }`}
        >
          <Lock className="w-4 h-4 text-cyan-400" />
          <span>Encrypted Credentials Vault</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveSubTab('totp')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition-all ${
            activeTab === 'totp'
              ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
              : 'text-muted-foreground hover:text-foreground hover:bg-accent/50 border border-transparent'
          }`}
        >
          <KeyRound className="w-4 h-4 text-cyan-400" />
          <span>Automated MFA / TOTP Simulator</span>
        </button>
      </div>

      {/* Main Views */}
      <div>
        {activeTab === 'vault' && (
          <div className="space-y-6">
            <SecretsVaultTable
              targets={targets}
              onOpenFlowBuilder={handleOpenFlowBuilder}
              onRunTest={handleRunTest}
              onRefreshTargets={refetch}
            />
          </div>
        )}

        {activeTab === 'totp' && (
          <div className="space-y-6">
            <TotpVerificationCard />
          </div>
        )}
      </div>

      {/* Auth Flow Builder Modal */}
      {editingTarget && (
        <AuthFlowBuilderModal
          isOpen={Boolean(editingTarget)}
          onClose={() => setEditingTarget(null)}
          targetId={editingTarget.id}
          targetName={editingTarget.name}
          targetUrl={editingTarget.baseUrl}
          onSaved={refetch}
        />
      )}
    </div>
  );
};
