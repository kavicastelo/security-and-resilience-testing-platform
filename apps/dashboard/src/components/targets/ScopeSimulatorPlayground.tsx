import React, { useState, useEffect } from 'react';
import { useMutation } from '@tanstack/react-query';
import {
  ShieldCheck,
  ShieldAlert,
  Play,
  Zap,
  Radio,
  AlertTriangle,
  CheckCircle2,
  Lock,
} from 'lucide-react';
import {
  targetsApi,
  Target,
  ScopeValidationResult,
} from '../../api/targets.js';
import { useAppStore } from '../../store/useAppStore.js';

interface ScopeSimulatorPlaygroundProps {
  targets: Target[];
  selectedTargetId?: string;
  onSelectTargetId?: (id: string) => void;
  className?: string;
}

export const ScopeSimulatorPlayground: React.FC<ScopeSimulatorPlaygroundProps> = ({
  targets,
  selectedTargetId: initialTargetId,
  onSelectTargetId,
  className = '',
}) => {
  const { showToast } = useAppStore();
  const [targetId, setTargetId] = useState<string>(
    initialTargetId || targets[0]?.id || '',
  );
  const [candidateUrl, setCandidateUrl] = useState<string>('');
  const [capability, setCapability] = useState<
    'passive' | 'activeScanning' | 'loadTesting' | 'chaosTesting'
  >('passive');
  const [requestedRps, setRequestedRps] = useState<number>(50);
  const [requestedConcurrency, setRequestedConcurrency] = useState<number>(10);
  const [result, setResult] = useState<ScopeValidationResult | null>(null);

  // Sync targetId if initialTargetId prop changes
  useEffect(() => {
    if (initialTargetId) {
      setTargetId(initialTargetId);
    } else if (!targetId && targets.length > 0) {
      setTargetId(targets[0].id);
    }
  }, [initialTargetId, targets, targetId]);

  const activeTarget = targets.find((t) => t.id === targetId);

  // Set default candidate URL based on active target
  useEffect(() => {
    if (activeTarget && (!candidateUrl || candidateUrl.includes('example.com'))) {
      const base = activeTarget.baseUrl.replace(/\/+$/, '');
      setCandidateUrl(`${base}/api/v1/health`);
    }
  }, [activeTarget]);

  const handleTargetChange = (newId: string) => {
    setTargetId(newId);
    if (onSelectTargetId) onSelectTargetId(newId);
    setResult(null);
  };

  const setPresetUrl = (presetType: 'health' | 'subdomain' | 'excluded' | 'metadata' | 'loopback' | 'rfc1918') => {
    if (!activeTarget) return;
    const base = activeTarget.baseUrl.replace(/\/+$/, '');
    let host = 'example.com';
    try {
      host = new URL(activeTarget.baseUrl).hostname;
    } catch {
      // ignore
    }

    switch (presetType) {
      case 'health':
        setCandidateUrl(`${base}/api/v1/health`);
        break;
      case 'subdomain':
        setCandidateUrl(`https://api.${host}/v1/status`);
        break;
      case 'excluded':
        setCandidateUrl(`${base}/admin/delete`);
        break;
      case 'metadata':
        setCandidateUrl('http://169.254.169.254/latest/meta-data');
        break;
      case 'loopback':
        setCandidateUrl('http://127.0.0.1:8080/internal/debug');
        break;
      case 'rfc1918':
        setCandidateUrl('http://10.0.0.1/admin');
        break;
    }
  };

  const validateMutation = useMutation({
    mutationFn: async () => {
      if (!targetId) throw new Error('Please select a target first');
      if (!candidateUrl.trim()) throw new Error('Please enter a candidate URL');

      return await targetsApi.validateScope(targetId, candidateUrl.trim(), {
        capability: capability === 'passive' ? undefined : capability,
        requestedRps,
        requestedConcurrency,
      });
    },
    onSuccess: (data) => {
      setResult(data);
      if (data.valid) {
        showToast('Scope boundary check PASSED: Target is authorized', 'success');
      } else {
        showToast('Scope boundary VIOLATION: Execution will be blocked', 'error');
      }
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      setResult({
        candidateUrl,
        valid: false,
        violations: [msg],
      });
      showToast(msg, 'error');
    },
  });

  return (
    <div
      className={`p-6 rounded-2xl border border-blue-900/40 bg-card/70 backdrop-blur-md space-y-6 shadow-xl ${className}`}
    >
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border/60 pb-4">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-xl bg-blue-950/40 border border-blue-800/60 text-blue-400">
            <Radio className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
              <span>Interactive Scope Safety Simulator</span>
              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-blue-950/60 text-blue-400 border border-blue-800/60">
                Pre-Flight Sandbox
              </span>
            </h3>
            <p className="text-xs text-muted-foreground">
              Test candidate URLs, alternative IP encodings, and capability demands against defensive boundaries.
            </p>
          </div>
        </div>

        {/* Target Selector */}
        <div className="w-full sm:w-64">
          <select
            value={targetId}
            onChange={(e) => handleTargetChange(e.target.value)}
            className="w-full px-3 py-2 rounded-lg bg-accent/80 border border-border text-xs text-foreground focus:ring-1 focus:ring-blue-500 cursor-pointer"
          >
            <option value="">Select target scope...</option>
            {targets.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name} ({t.baseUrl})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Target Scope Boundaries Snapshot */}
      {activeTarget && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-[11px] bg-accent/30 border border-border/60 p-3 rounded-xl">
          <div>
            <span className="text-muted-foreground block text-[10px] uppercase tracking-wider mb-0.5">
              Allowed Hosts
            </span>
            <div className="font-mono text-foreground font-medium truncate">
              {activeTarget.scope.allowedHosts.join(', ')}
            </div>
          </div>
          <div>
            <span className="text-muted-foreground block text-[10px] uppercase tracking-wider mb-0.5">
              Allowed Ports
            </span>
            <div className="font-mono text-foreground font-medium">
              {activeTarget.scope.allowedPorts?.join(', ') || '80, 443'}
            </div>
          </div>
          <div>
            <span className="text-muted-foreground block text-[10px] uppercase tracking-wider mb-0.5">
              Excluded Paths
            </span>
            <div className="font-mono text-foreground font-medium truncate">
              {activeTarget.scope.excludedPaths?.length
                ? activeTarget.scope.excludedPaths.join(', ')
                : 'None'}
            </div>
          </div>
          <div>
            <span className="text-muted-foreground block text-[10px] uppercase tracking-wider mb-0.5">
              Safety Budget
            </span>
            <div className="font-mono text-foreground font-medium">
              {activeTarget.scope.limits.maxRps} RPS / {activeTarget.scope.limits.maxConcurrency} VUs
            </div>
          </div>
        </div>
      )}

      {/* Simulator Form */}
      <div className="space-y-4">
        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label className="block text-xs font-medium text-foreground">
              Candidate Execution URL
            </label>
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[10px] text-muted-foreground uppercase font-mono mr-1">
                Presets:
              </span>
              <button
                type="button"
                onClick={() => setPresetUrl('health')}
                className="text-[10px] font-mono px-2 py-0.5 rounded bg-accent hover:bg-accent/80 text-foreground transition-colors"
              >
                Health
              </button>
              <button
                type="button"
                onClick={() => setPresetUrl('subdomain')}
                className="text-[10px] font-mono px-2 py-0.5 rounded bg-accent hover:bg-accent/80 text-foreground transition-colors"
              >
                Subdomain
              </button>
              <button
                type="button"
                onClick={() => setPresetUrl('excluded')}
                className="text-[10px] font-mono px-2 py-0.5 rounded bg-accent hover:bg-accent/80 text-foreground transition-colors"
              >
                Excluded
              </button>
              <button
                type="button"
                onClick={() => setPresetUrl('metadata')}
                className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950/40 text-rose-300 border border-rose-800/40 hover:bg-rose-950/60 transition-colors"
              >
                SSRF (Metadata)
              </button>
              <button
                type="button"
                onClick={() => setPresetUrl('loopback')}
                className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950/40 text-amber-300 border border-amber-800/40 hover:bg-amber-950/60 transition-colors"
              >
                Loopback
              </button>
              <button
                type="button"
                onClick={() => setPresetUrl('rfc1918')}
                className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950/40 text-purple-300 border border-purple-800/40 hover:bg-purple-950/60 transition-colors"
              >
                RFC1918
              </button>
            </div>
          </div>
          <div className="relative">
            <input
              type="text"
              value={candidateUrl}
              onChange={(e) => setCandidateUrl(e.target.value)}
              placeholder="https://target.domain.com/api/v1/endpoint"
              className="w-full px-3.5 py-2.5 rounded-xl bg-accent/60 border border-border text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>
        </div>

        {/* Execution Capabilities & Parameters */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-1">
          {/* Capability Radio Selector */}
          <div className="space-y-2 md:col-span-1">
            <label className="block text-xs font-medium text-foreground">
              Requested Capability
            </label>
            <div className="space-y-1.5 text-xs">
              <label className="flex items-center space-x-2 p-2 rounded-lg bg-accent/40 border border-border/50 cursor-pointer hover:bg-accent/70 transition-colors">
                <input
                  type="radio"
                  name="sim-cap"
                  checked={capability === 'passive'}
                  onChange={() => setCapability('passive')}
                  className="text-primary focus:ring-0"
                />
                <span className="text-foreground text-[11px]">Passive Probing (Safe)</span>
              </label>
              <label className="flex items-center space-x-2 p-2 rounded-lg bg-accent/40 border border-border/50 cursor-pointer hover:bg-accent/70 transition-colors">
                <input
                  type="radio"
                  name="sim-cap"
                  checked={capability === 'activeScanning'}
                  onChange={() => setCapability('activeScanning')}
                  className="text-primary focus:ring-0"
                />
                <span className="text-foreground text-[11px]">Active Fuzzing / Attacks</span>
              </label>
              <label className="flex items-center space-x-2 p-2 rounded-lg bg-accent/40 border border-border/50 cursor-pointer hover:bg-accent/70 transition-colors">
                <input
                  type="radio"
                  name="sim-cap"
                  checked={capability === 'loadTesting'}
                  onChange={() => setCapability('loadTesting')}
                  className="text-primary focus:ring-0"
                />
                <span className="text-foreground text-[11px]">Load & Stress Capacity</span>
              </label>
            </div>
          </div>

          {/* Rate & Concurrency Simulation */}
          <div className="space-y-3 md:col-span-2">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[11px] text-muted-foreground mb-1">
                  Requested Rate (RPS)
                </label>
                <input
                  type="number"
                  min={1}
                  max={5000}
                  value={requestedRps}
                  onChange={(e) => setRequestedRps(parseInt(e.target.value, 10) || 10)}
                  className="w-full px-3 py-2 rounded-lg bg-accent/50 border border-border text-xs font-mono text-foreground focus:ring-1 focus:ring-blue-500"
                />
                <span className="text-[10px] text-muted-foreground mt-0.5 block">
                  Limit: {activeTarget?.scope.limits.maxRps ?? 100} RPS
                </span>
              </div>
              <div>
                <label className="block text-[11px] text-muted-foreground mb-1">
                  Requested Concurrency (VUs)
                </label>
                <input
                  type="number"
                  min={1}
                  max={1000}
                  value={requestedConcurrency}
                  onChange={(e) => setRequestedConcurrency(parseInt(e.target.value, 10) || 5)}
                  className="w-full px-3 py-2 rounded-lg bg-accent/50 border border-border text-xs font-mono text-foreground focus:ring-1 focus:ring-blue-500"
                />
                <span className="text-[10px] text-muted-foreground mt-0.5 block">
                  Limit: {activeTarget?.scope.limits.maxConcurrency ?? 20} VUs
                </span>
              </div>
            </div>

            {/* Anti-SSRF Defense Badges */}
            <div className="p-2.5 rounded-xl bg-accent/20 border border-border/60 flex flex-wrap items-center gap-2 text-[10px] font-mono text-muted-foreground">
              <span className="text-foreground font-semibold flex items-center gap-1">
                <Lock className="w-3 h-3 text-blue-400" />
                <span>SSRF Defenses:</span>
              </span>
              <span className="px-2 py-0.5 rounded bg-muted text-foreground">
                Cloud Metadata: Blocked
              </span>
              <span className="px-2 py-0.5 rounded bg-muted text-foreground">
                Loopback: Blocked
              </span>
              <span className="px-2 py-0.5 rounded bg-muted text-foreground">
                RFC1918 Private: {activeTarget?.scope.allowPrivateIps ? 'Allowed' : 'Blocked'}
              </span>
            </div>
          </div>
        </div>

        {/* Action Trigger */}
        <div className="flex justify-end pt-2">
          <button
            type="button"
            onClick={() => validateMutation.mutate()}
            disabled={validateMutation.isPending || !targetId || !candidateUrl}
            className="flex items-center space-x-2 px-5 py-2.5 rounded-xl bg-primary hover:bg-primary/90 disabled:opacity-50 text-white font-medium text-xs shadow-md transition-all hover:glow-blue"
          >
            {validateMutation.isPending ? (
              <>
                <Zap className="w-4 h-4 animate-spin" />
                <span>Simulating Boundary Inspection...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                <span>Evaluate Scope Boundary</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Simulator Verdict Result */}
      {result && (
        <div
          className={`p-5 rounded-xl border space-y-3 animate-fade-in ${
            result.valid
              ? 'bg-emerald-950/30 border-emerald-800/60 text-emerald-200'
              : 'bg-red-950/30 border-red-800/60 text-red-200'
          }`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2.5">
              {result.valid ? (
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
              ) : (
                <ShieldAlert className="w-5 h-5 text-red-400" />
              )}
              <h4 className="text-xs font-bold uppercase tracking-wider">
                {result.valid ? 'BOUNDARY CHECK PASSED' : 'DEFENSIVE BOUNDARY VIOLATION'}
              </h4>
            </div>
            <span
              className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${
                result.valid
                  ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800/60'
                  : 'bg-red-950/60 text-red-300 border-red-800/60'
              }`}
            >
              {result.valid ? 'EXECUTION AUTHORIZED' : 'EXECUTION PROHIBITED'}
            </span>
          </div>

          {result.valid ? (
            <div className="space-y-2 text-xs text-emerald-300/90 leading-relaxed">
              <p>
                Candidate URL is within registered target scope. All anti-SSRF protections, allowed hosts,
                and safety budget ceilings are respected.
              </p>
              <div className="flex flex-wrap gap-2 pt-1 font-mono text-[11px]">
                {result.matchedHost && (
                  <span className="px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-800/50 flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                    <span>Host: {result.matchedHost}</span>
                  </span>
                )}
                {result.normalizedUrl && (
                  <span className="px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-800/50">
                    Normalized: {result.normalizedUrl}
                  </span>
                )}
              </div>
            </div>
          ) : (
            <div className="space-y-2 text-xs">
              <p className="text-red-300 font-medium">
                The execution was rejected by defensive safety checks:
              </p>
              <ul className="space-y-1.5 font-mono text-[11px] text-red-200">
                {result.violations.map((violation, idx) => (
                  <li
                    key={idx}
                    className="flex items-start gap-2 bg-red-950/50 p-2 rounded-lg border border-red-900/40"
                  >
                    <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                    <span className="break-all">{violation}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
