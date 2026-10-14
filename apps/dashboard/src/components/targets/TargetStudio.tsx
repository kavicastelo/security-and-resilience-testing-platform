import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Clock,
  Globe,
  Radio,
  Sliders,
  Activity,
  Terminal,
  Copy,
  Check,
  X,
  Play,
  KeyRound,
} from 'lucide-react';
import { Target } from '../../api/targets.js';
import { OwnershipWizardModal } from './OwnershipWizardModal.js';
import { ScopeSimulatorPlayground } from './ScopeSimulatorPlayground.js';
import { SafetyBudgetGauges } from './SafetyBudgetGauges.js';
import { useAppStore } from '../../store/useAppStore.js';

interface TargetStudioProps {
  target: Target;
  allTargets: Target[];
  isOpen: boolean;
  onClose: () => void;
  onEdit?: (target: Target) => void;
}

export const TargetStudio: React.FC<TargetStudioProps> = ({
  target,
  allTargets,
  isOpen,
  onClose,
  onEdit,
}) => {
  const { showToast, setActiveTab } = useAppStore();
  const [activeStudioTab, setActiveStudioTab] = useState<
    'overview' | 'ownership' | 'simulator' | 'safety'
  >('overview');
  const [isOwnershipModalOpen, setIsOwnershipModalOpen] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  if (!isOpen) return null;

  const copyToClipboard = (text: string, key: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    showToast(`Copied ${label} to clipboard`, 'info');
    setTimeout(() => {
      setCopiedKey((curr) => (curr === key ? null : curr));
    }, 2000);
  };

  const domain = (() => {
    try {
      return new URL(target.baseUrl).hostname;
    } catch {
      return target.baseUrl;
    }
  })();

  const isVerified = target.verificationStatus === 'VERIFIED';
  const isFailed = target.verificationStatus === 'FAILED';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-2 sm:p-4 bg-background/80 backdrop-blur-md animate-fade-in">
      <div className="relative w-full max-w-5xl bg-card border border-border/80 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        {/* Studio Header Bar */}
        <div className="p-6 border-b border-border/60 bg-gradient-to-r from-card via-accent/20 to-card flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center space-x-3">
              <div className="p-2.5 rounded-xl bg-primary/10 border border-primary/30 text-primary">
                <Globe className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <h2 className="text-lg font-bold text-foreground tracking-tight">
                    {target.name}
                  </h2>
                  <span
                    className={`text-[10px] font-mono uppercase px-2.5 py-0.5 rounded-full border flex items-center gap-1 ${
                      isVerified
                        ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60'
                        : isFailed
                        ? 'bg-red-950/60 text-red-400 border-red-800/60'
                        : 'bg-amber-950/60 text-amber-400 border-amber-800/60'
                    }`}
                  >
                    {isVerified ? (
                      <>
                        <ShieldCheck className="w-3 h-3 text-emerald-400" />
                        <span>Verified</span>
                      </>
                    ) : isFailed ? (
                      <>
                        <ShieldAlert className="w-3 h-3 text-red-400" />
                        <span>Verification Failed</span>
                      </>
                    ) : (
                      <>
                        <Clock className="w-3 h-3 text-amber-400" />
                        <span>Pending Verification</span>
                      </>
                    )}
                  </span>
                </div>
                <div className="flex items-center space-x-2 text-xs text-muted-foreground font-mono mt-0.5">
                  <span>{target.baseUrl}</span>
                  <span>•</span>
                  <span>ID: {target.id.slice(0, 8)}...</span>
                </div>
              </div>
            </div>
          </div>

          {/* Quick Header Actions */}
          <div className="flex items-center space-x-2.5 self-end sm:self-auto">
            {!isVerified && (
              <button
                type="button"
                onClick={() => setIsOwnershipModalOpen(true)}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-amber-500/20 text-amber-300 border border-amber-500/40 text-xs font-medium hover:bg-amber-500/30 transition-colors"
              >
                <KeyRound className="w-3.5 h-3.5" />
                <span>Verify Ownership</span>
              </button>
            )}

            <button
              type="button"
              onClick={() => {
                onClose();
                setActiveTab('runs');
              }}
              className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-primary hover:bg-primary/90 text-white text-xs font-medium shadow-sm transition-all hover:glow-blue"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Launch Test Run</span>
            </button>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent/60 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Studio Navigation Tabs */}
        <div className="flex border-b border-border/60 bg-accent/20 px-6">
          <button
            type="button"
            onClick={() => setActiveStudioTab('overview')}
            className={`flex items-center space-x-2 py-3 px-4 text-xs font-medium border-b-2 transition-colors ${
              activeStudioTab === 'overview'
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            }`}
          >
            <Sliders className="w-3.5 h-3.5" />
            <span>Scope Boundaries</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveStudioTab('ownership')}
            className={`flex items-center space-x-2 py-3 px-4 text-xs font-medium border-b-2 transition-colors ${
              activeStudioTab === 'ownership'
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Ownership Verification</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveStudioTab('simulator')}
            className={`flex items-center space-x-2 py-3 px-4 text-xs font-medium border-b-2 transition-colors ${
              activeStudioTab === 'simulator'
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            <span>Scope Simulator</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveStudioTab('safety')}
            className={`flex items-center space-x-2 py-3 px-4 text-xs font-medium border-b-2 transition-colors ${
              activeStudioTab === 'safety'
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Safety & Circuit Breaker</span>
          </button>
        </div>

        {/* Studio Content Area */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          {/* TAB 1: OVERVIEW */}
          {activeStudioTab === 'overview' && (
            <div className="space-y-6 animate-fade-in">
              {/* Scope Invariants Summary */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-card border border-border/80 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs uppercase font-mono text-muted-foreground tracking-wider">
                      Authorized Hostnames ({target.scope.allowedHosts.length})
                    </span>
                    <button
                      type="button"
                      onClick={() =>
                        copyToClipboard(
                          target.scope.allowedHosts.join(', '),
                          'hosts',
                          'Allowed Hosts',
                        )
                      }
                      className="text-[11px] text-primary flex items-center gap-1 hover:underline"
                    >
                      {copiedKey === 'hosts' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                      <span>Copy All</span>
                    </button>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {target.scope.allowedHosts.map((host) => (
                      <span
                        key={host}
                        className="px-2.5 py-1 rounded-md bg-accent font-mono text-xs text-foreground border border-border/80"
                      >
                        {host}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-card border border-border/80 space-y-3">
                  <span className="text-xs uppercase font-mono text-muted-foreground tracking-wider block">
                    Permitted Ports & Paths
                  </span>
                  <div className="space-y-2 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="text-muted-foreground">Allowed Ports:</span>
                      <span className="font-mono text-foreground font-semibold">
                        {target.scope.allowedPorts?.join(', ') || '80, 443'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-muted-foreground">Excluded Paths:</span>
                      <span className="font-mono text-foreground">
                        {target.scope.excludedPaths?.length
                          ? target.scope.excludedPaths.join(', ')
                          : 'None configured'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-muted-foreground">Private Subnets (RFC-1918):</span>
                      <span
                        className={`font-mono font-semibold ${
                          target.scope.allowPrivateIps
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }`}
                      >
                        {target.scope.allowPrivateIps ? 'Allowed' : 'Blocked (Anti-SSRF)'}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Testing Capabilities Card */}
              <div className="p-4 rounded-xl bg-card border border-border/80 space-y-3">
                <h4 className="text-xs font-semibold text-foreground uppercase tracking-wider text-muted-foreground">
                  Authorized Testing Capabilities
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div
                    className={`p-3 rounded-lg border flex items-center justify-between ${
                      target.scope.testing.activeScanning
                        ? 'bg-emerald-950/20 border-emerald-800/40 text-emerald-300'
                        : 'bg-muted/30 border-border text-muted-foreground'
                    }`}
                  >
                    <span className="text-xs font-medium">Active Vulnerability Scan</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold">
                      {target.scope.testing.activeScanning ? 'ENABLED' : 'DISABLED'}
                    </span>
                  </div>

                  <div
                    className={`p-3 rounded-lg border flex items-center justify-between ${
                      target.scope.testing.loadTesting
                        ? 'bg-indigo-950/20 border-indigo-800/40 text-indigo-300'
                        : 'bg-muted/30 border-border text-muted-foreground'
                    }`}
                  >
                    <span className="text-xs font-medium">Load & Resilience Testing</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold">
                      {target.scope.testing.loadTesting ? 'ENABLED' : 'DISABLED'}
                    </span>
                  </div>

                  <div
                    className={`p-3 rounded-lg border flex items-center justify-between ${
                      target.scope.testing.chaosTesting
                        ? 'bg-purple-950/20 border-purple-800/40 text-purple-300'
                        : 'bg-muted/30 border-border text-muted-foreground'
                    }`}
                  >
                    <span className="text-xs font-medium">Chaos Fault Injection</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold">
                      {target.scope.testing.chaosTesting ? 'ENABLED' : 'DISABLED'}
                    </span>
                  </div>
                </div>
              </div>

              {/* CLI Command & Automation Snippet */}
              <div className="p-4 rounded-xl bg-black/40 border border-border/80 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2 text-xs text-muted-foreground">
                    <Terminal className="w-3.5 h-3.5 text-blue-400" />
                    <span>Run Target Directly from CLI</span>
                  </div>
                  <button
                    type="button"
                    onClick={() =>
                      copyToClipboard(
                        `security-lab test run --target ${target.id}`,
                        'cli-run',
                        'CLI Command',
                      )
                    }
                    className="text-[11px] text-primary flex items-center gap-1 hover:underline"
                  >
                    {copiedKey === 'cli-run' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                    <span>Copy</span>
                  </button>
                </div>
                <code className="block font-mono text-xs text-blue-300 select-all">
                  security-lab test run --target {target.id}
                </code>
              </div>
            </div>
          )}

          {/* TAB 2: OWNERSHIP VERIFICATION */}
          {activeStudioTab === 'ownership' && (
            <div className="space-y-6 animate-fade-in">
              <div className="p-5 rounded-xl bg-card border border-border/80 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <h3 className="text-sm font-semibold text-foreground">
                      Cryptographic Domain Verification Status
                    </h3>
                    <p className="text-xs text-muted-foreground">
                      Proof of control via DNS TXT record challenge or HTTP well-known endpoint.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setIsOwnershipModalOpen(true)}
                    className="px-4 py-2 rounded-lg bg-primary hover:bg-primary/90 text-white text-xs font-medium shadow-md transition-all hover:glow-blue flex items-center gap-1.5"
                  >
                    <KeyRound className="w-3.5 h-3.5" />
                    <span>Open Verification Wizard</span>
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2 text-xs">
                  <div className="p-3 rounded-lg bg-accent/40 border border-border/60">
                    <span className="text-[10px] text-muted-foreground uppercase font-mono block">
                      Verification Status
                    </span>
                    <span
                      className={`font-mono font-bold mt-1 block ${
                        isVerified
                          ? 'text-emerald-400'
                          : isFailed
                          ? 'text-red-400'
                          : 'text-amber-400'
                      }`}
                    >
                      {target.verificationStatus || 'PENDING'}
                    </span>
                  </div>
                  <div className="p-3 rounded-lg bg-accent/40 border border-border/60">
                    <span className="text-[10px] text-muted-foreground uppercase font-mono block">
                      Verification Method
                    </span>
                    <span className="font-mono text-foreground font-medium mt-1 block">
                      {target.verificationMethod || 'None'}
                    </span>
                  </div>
                  <div className="p-3 rounded-lg bg-accent/40 border border-border/60">
                    <span className="text-[10px] text-muted-foreground uppercase font-mono block">
                      Verified Timestamp
                    </span>
                    <span className="font-mono text-foreground mt-1 block">
                      {target.verifiedAt
                        ? new Date(target.verifiedAt).toLocaleDateString()
                        : 'Unverified'}
                    </span>
                  </div>
                </div>
              </div>

              {/* DNS Challenge Guidance */}
              <div className="p-4 rounded-xl bg-accent/20 border border-border/60 space-y-2 text-xs">
                <h4 className="font-semibold text-foreground">
                  Expected DNS Challenge Host
                </h4>
                <p className="text-muted-foreground font-mono text-[11px]">
                  _security-lab-challenge.{domain}
                </p>
                <p className="text-muted-foreground text-[11px] leading-relaxed">
                  DNS TXT verification guarantees no third party can initiate denial-of-service or active fuzzing probes without possessing domain administrative control.
                </p>
              </div>
            </div>
          )}

          {/* TAB 3: SCOPE SIMULATOR */}
          {activeStudioTab === 'simulator' && (
            <div className="animate-fade-in">
              <ScopeSimulatorPlayground
                targets={allTargets}
                selectedTargetId={target.id}
                className="border-none p-0 bg-transparent shadow-none"
              />
            </div>
          )}

          {/* TAB 4: SAFETY BUDGET & CIRCUIT BREAKER */}
          {activeStudioTab === 'safety' && (
            <div className="animate-fade-in">
              <SafetyBudgetGauges
                limits={target.scope.limits}
                allowPrivateIps={target.scope.allowPrivateIps}
              />
            </div>
          )}
        </div>

        {/* Studio Footer */}
        <div className="p-4 border-t border-border/60 bg-accent/20 flex items-center justify-between text-xs">
          <span className="text-muted-foreground font-mono text-[11px]">
            Target Safety Invariant: Pre-Socket DNS Pinning Enabled
          </span>
          <div className="flex items-center space-x-3">
            {onEdit && (
              <button
                type="button"
                onClick={() => {
                  onClose();
                  onEdit(target);
                }}
                className="px-3 py-1.5 rounded-lg border border-border text-foreground hover:bg-accent text-xs transition-colors"
              >
                Edit Target Scope
              </button>
            )}
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-1.5 rounded-lg bg-accent text-foreground hover:bg-accent/80 text-xs transition-colors"
            >
              Close Studio
            </button>
          </div>
        </div>
      </div>

      {/* Ownership Wizard Modal */}
      <OwnershipWizardModal
        target={target}
        isOpen={isOwnershipModalOpen}
        onClose={() => setIsOwnershipModalOpen(false)}
      />
    </div>
  );
};
