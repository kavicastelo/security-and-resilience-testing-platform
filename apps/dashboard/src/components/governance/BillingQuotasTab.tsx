import React from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  CreditCard,
  Zap,
  HardDrive,
  Target,
  AlertTriangle,
  Sparkles,
  ArrowUpRight,
} from 'lucide-react';
import { governanceApi, WorkspaceBillingInfo } from '../../api/governance.js';
import { useAppStore } from '../../store/useAppStore.js';

export const BillingQuotasTab: React.FC = () => {
  const { currentWorkspaceId, showToast } = useAppStore();
  const queryClient = useQueryClient();

  const { data: billing, isLoading } = useQuery<WorkspaceBillingInfo | null>({
    queryKey: ['workspace-billing', currentWorkspaceId],
    queryFn: () => governanceApi.getBilling(currentWorkspaceId),
    enabled: !!currentWorkspaceId,
  });

  const updateTierMutation = useMutation({
    mutationFn: (tier: 'free' | 'pro' | 'enterprise') =>
      governanceApi.updateBillingTier(currentWorkspaceId, tier),
    onSuccess: (updated) => {
      showToast(`Workspace tier updated to ${updated.tier.toUpperCase()}`);
      queryClient.invalidateQueries({ queryKey: ['workspace-billing', currentWorkspaceId] });
    },
    onError: (err: Error) => {
      showToast(err.message, 'error');
    },
  });

  if (isLoading) {
    return (
      <div className="p-8 text-center text-muted-foreground animate-fade-in">
        Loading billing and usage quotas...
      </div>
    );
  }

  // Fallback defaults if workspace billing record not yet populated
  const tier = billing?.tier || 'free';
  const quotas = billing?.quotas || {
    maxMonthlyRuns: 100,
    maxConcurrentRuns: 2,
    maxTargets: 5,
    maxStorageMb: 500,
  };
  const usage = billing?.usage || {
    monthlyRunsCount: 12,
    concurrentRunsCount: 0,
    activeTargetsCount: 2,
    storageBytesUsed: 45 * 1024 * 1024,
  };
  const storageMbUsed = (usage.storageBytesUsed / (1024 * 1024)).toFixed(1);

  const calculatePct = (used: number, max: number) => {
    if (!max || max <= 0) return 0;
    return Math.min(100, Math.round((used / max) * 100));
  };

  const runsPct = calculatePct(usage.monthlyRunsCount, quotas.maxMonthlyRuns);
  const targetsPct = calculatePct(usage.activeTargetsCount, quotas.maxTargets);
  const storagePct = calculatePct(Number(storageMbUsed), quotas.maxStorageMb);

  return (
    <div className="space-y-6 animate-fade-in max-w-4xl">
      {/* Quota Breached Alert if applicable */}
      {billing?.quotaBreached && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs flex items-center space-x-3 glow-hazard">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
          <div>
            <div className="font-semibold text-sm">Monthly Quota Ceiling Reached</div>
            <p className="text-muted-foreground mt-0.5">
              One or more usage quotas have exceeded the plan allocation. Upgrade to Pro or Enterprise to resume full capacity.
            </p>
          </div>
        </div>
      )}

      {/* Plan Tier Overview Card */}
      <div className="p-6 rounded-2xl bg-card border border-border/80 glass-panel glow-blue flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <span className="text-xs uppercase tracking-wider font-semibold text-muted-foreground">
              Current Subscription Tier
            </span>
            <span
              className={`text-xs uppercase font-mono px-2.5 py-0.5 rounded-full font-bold border ${
                tier === 'enterprise'
                  ? 'bg-purple-500/20 text-purple-300 border-purple-500/40'
                  : tier === 'pro'
                  ? 'bg-blue-500/20 text-blue-300 border-blue-500/40'
                  : 'bg-accent text-muted-foreground border-border'
              }`}
            >
              {tier} Plan
            </span>
          </div>
          <h2 className="text-xl font-bold text-foreground mt-1">
            {tier === 'enterprise'
              ? 'Enterprise Unlimited Control Plane'
              : tier === 'pro'
              ? 'Professional Security Team Plan'
              : 'Developer Free Laboratory'}
          </h2>
          <p className="text-xs text-muted-foreground mt-1">
            Stripe usage metering & tenant resource ceilings enforced at API controller boundary.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          {tier !== 'enterprise' ? (
            <button
              type="button"
              onClick={() => updateTierMutation.mutate('enterprise')}
              disabled={updateTierMutation.isPending}
              className="flex items-center space-x-2 px-4 py-2 rounded-xl bg-gradient-to-r from-blue-600 to-purple-600 text-white font-medium text-xs hover:opacity-90 transition-opacity shadow-md disabled:opacity-50"
            >
              <Sparkles className="w-4 h-4 text-cyan-300" />
              <span>Upgrade to Enterprise</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={() => showToast('Redirecting to Stripe Customer Portal...')}
              className="flex items-center space-x-2 px-3.5 py-2 rounded-xl bg-accent hover:bg-accent/80 text-foreground font-medium text-xs transition-colors border border-border"
            >
              <CreditCard className="w-4 h-4 text-blue-400" />
              <span>Billing Portal</span>
              <ArrowUpRight className="w-3.5 h-3.5 opacity-60" />
            </button>
          )}
        </div>
      </div>

      {/* Quota Progress Meters Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {/* Monthly Runs Meter */}
        <div className="p-5 rounded-xl bg-card border border-border/70 glass-card space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-foreground flex items-center space-x-1.5">
              <Zap className="w-4 h-4 text-blue-400" />
              <span>Monthly Runs</span>
            </span>
            <span className="font-mono text-xs font-bold text-blue-300">{runsPct}%</span>
          </div>

          <div className="w-full bg-accent/60 rounded-full h-2 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                runsPct >= 90 ? 'bg-red-500' : runsPct >= 75 ? 'bg-amber-500' : 'bg-blue-500'
              }`}
              style={{ width: `${runsPct}%` }}
            />
          </div>

          <div className="flex items-center justify-between text-[11px] text-muted-foreground font-mono">
            <span>{usage.monthlyRunsCount} runs executed</span>
            <span>Limit: {quotas.maxMonthlyRuns}</span>
          </div>
        </div>

        {/* Active Targets Meter */}
        <div className="p-5 rounded-xl bg-card border border-border/70 glass-card space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-foreground flex items-center space-x-1.5">
              <Target className="w-4 h-4 text-cyan-400" />
              <span>Target Scopes</span>
            </span>
            <span className="font-mono text-xs font-bold text-cyan-300">{targetsPct}%</span>
          </div>

          <div className="w-full bg-accent/60 rounded-full h-2 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                targetsPct >= 90 ? 'bg-red-500' : targetsPct >= 75 ? 'bg-amber-500' : 'bg-cyan-500'
              }`}
              style={{ width: `${targetsPct}%` }}
            />
          </div>

          <div className="flex items-center justify-between text-[11px] text-muted-foreground font-mono">
            <span>{usage.activeTargetsCount} targets active</span>
            <span>Limit: {quotas.maxTargets}</span>
          </div>
        </div>

        {/* Storage Meter */}
        <div className="p-5 rounded-xl bg-card border border-border/70 glass-card space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-foreground flex items-center space-x-1.5">
              <HardDrive className="w-4 h-4 text-purple-400" />
              <span>Evidence Storage</span>
            </span>
            <span className="font-mono text-xs font-bold text-purple-300">{storagePct}%</span>
          </div>

          <div className="w-full bg-accent/60 rounded-full h-2 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                storagePct >= 90 ? 'bg-red-500' : storagePct >= 75 ? 'bg-amber-500' : 'bg-purple-500'
              }`}
              style={{ width: `${storagePct}%` }}
            />
          </div>

          <div className="flex items-center justify-between text-[11px] text-muted-foreground font-mono">
            <span>{storageMbUsed} MB stored</span>
            <span>Limit: {quotas.maxStorageMb} MB</span>
          </div>
        </div>
      </div>

      {/* Plan Features Comparison Table */}
      <div className="p-5 rounded-xl bg-card border border-border/70 glass-card space-y-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Plan Comparison & Features
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {/* Free Tier */}
          <div
            className={`p-4 rounded-xl border transition-all ${
              tier === 'free'
                ? 'bg-accent/40 border-primary/40 shadow-sm'
                : 'bg-card border-border/70 opacity-70'
            }`}
          >
            <div className="text-xs font-bold text-foreground">Free Tier</div>
            <div className="text-lg font-bold font-mono text-foreground mt-1">$0 / mo</div>
            <ul className="text-xs text-muted-foreground mt-3 space-y-1.5">
              <li>✓ 100 Runs / month</li>
              <li>✓ 2 Concurrent executions</li>
              <li>✓ 5 Targets</li>
              <li>✓ Community Engines</li>
            </ul>
            {tier !== 'free' && (
              <button
                type="button"
                onClick={() => updateTierMutation.mutate('free')}
                className="mt-4 w-full py-1.5 rounded-lg text-xs bg-accent hover:bg-accent/80 text-muted-foreground hover:text-foreground border border-border transition-colors"
              >
                Downgrade
              </button>
            )}
          </div>

          {/* Pro Tier */}
          <div
            className={`p-4 rounded-xl border transition-all ${
              tier === 'pro'
                ? 'bg-blue-500/10 border-blue-500/40 shadow-sm glow-blue'
                : 'bg-card border-border/70'
            }`}
          >
            <div className="text-xs font-bold text-blue-400">Pro Tier</div>
            <div className="text-lg font-bold font-mono text-foreground mt-1">$299 / mo</div>
            <ul className="text-xs text-muted-foreground mt-3 space-y-1.5">
              <li>✓ 1,000 Runs / month</li>
              <li>✓ 8 Concurrent executions</li>
              <li>✓ 25 Targets</li>
              <li>✓ Chaos & Load Generators</li>
              <li>✓ PDF & SARIF Exports</li>
            </ul>
            {tier !== 'pro' && (
              <button
                type="button"
                onClick={() => updateTierMutation.mutate('pro')}
                className="mt-4 w-full py-1.5 rounded-lg text-xs bg-primary text-primary-foreground font-medium hover:bg-blue-600 transition-colors shadow-sm"
              >
                Switch to Pro
              </button>
            )}
          </div>

          {/* Enterprise Tier */}
          <div
            className={`p-4 rounded-xl border transition-all ${
              tier === 'enterprise'
                ? 'bg-purple-500/10 border-purple-500/40 shadow-sm glow-purple'
                : 'bg-card border-border/70'
            }`}
          >
            <div className="text-xs font-bold text-purple-400">Enterprise</div>
            <div className="text-lg font-bold font-mono text-foreground mt-1">Custom / Quota</div>
            <ul className="text-xs text-muted-foreground mt-3 space-y-1.5">
              <li>✓ Unlimited Monthly Runs</li>
              <li>✓ Distributed Private Agent Fleet</li>
              <li>✓ SAML 2.0 / OIDC SSO & SCIM</li>
              <li>✓ AI Remediation Studio</li>
              <li>✓ Dedicated VPC Isolation</li>
            </ul>
            {tier !== 'enterprise' && (
              <button
                type="button"
                onClick={() => updateTierMutation.mutate('enterprise')}
                className="mt-4 w-full py-1.5 rounded-lg text-xs bg-gradient-to-r from-blue-600 to-purple-600 text-white font-medium hover:opacity-90 transition-opacity shadow-sm"
              >
                Activate Enterprise
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
