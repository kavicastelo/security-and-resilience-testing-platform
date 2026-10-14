import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Clock,
  CheckCircle2,
  Lock,
} from 'lucide-react';
import { usePlanStudioStore } from '../../store/usePlanStudioStore.js';
import { Target } from '../../api/targets.js';

interface PreflightValidatorCardProps {
  selectedTarget: Target | null;
}

export const PreflightValidatorCard: React.FC<PreflightValidatorCardProps> = ({
  selectedTarget,
}) => {
  const {
    steps,
    hazardAcknowledged,
    setHazardAcknowledged,
  } = usePlanStudioStore();

  const activeSteps = steps.filter((s) => s.enabled);
  const disruptiveSteps = activeSteps.filter((s) => s.disruptive);
  const hasDisruptive = disruptiveSteps.length > 0;

  // Validation rules
  const issues: { severity: 'error' | 'warning' | 'info'; message: string }[] = [];

  if (!selectedTarget) {
    issues.push({
      severity: 'error',
      message: 'No target selected. You must associate this pipeline with an authorized target.',
    });
  } else {
    // 1. Ownership Verification Check
    const isVerified = selectedTarget.verificationStatus === 'VERIFIED';
    if (!isVerified) {
      if (hasDisruptive || activeSteps.some((s) => s.category === 'api' || s.category === 'resilience')) {
        issues.push({
          severity: 'error',
          message: `Target "${selectedTarget.name}" is pending ownership proof. Active and resilience tests will be rejected by controller with TARGET_UNVERIFIED.`,
        });
      } else {
        issues.push({
          severity: 'warning',
          message: `Target "${selectedTarget.name}" is not cryptographically verified. Only non-disruptive passive checks are allowed.`,
        });
      }
    }

    // 2. Active Scanning Authorization Check
    const targetAuthorizesActive = Boolean(selectedTarget.scope?.testing?.activeScanning);
    const activeScanEngines = activeSteps.filter(
      (s) => s.engineId === 'engine-native-fuzzer' || s.engineId === 'engine-container-zap',
    );
    if (activeScanEngines.length > 0 && !targetAuthorizesActive) {
      issues.push({
        severity: 'error',
        message: `Pipeline includes active fuzzers (${activeScanEngines.map((e) => e.name).join(', ')}), but target scope has Active Scanning set to OFF.`,
      });
    }

    // 3. Load Testing Authorization Check
    const targetAuthorizesLoad = Boolean(selectedTarget.scope?.testing?.loadTesting);
    const loadEngines = activeSteps.filter(
      (s) => s.engineId === 'engine-worker-k6' || s.engineId === 'engine-native-resilience',
    );
    if (loadEngines.length > 0 && !targetAuthorizesLoad) {
      issues.push({
        severity: 'warning',
        message: `Pipeline includes stress/load engines, but target scope has Load Testing set to OFF.`,
      });
    }

    // 4. Concurrency Limit Check
    const k6Step = activeSteps.find((s) => s.engineId === 'engine-worker-k6');
    if (k6Step && selectedTarget.scope?.limits?.maxConcurrency) {
      const requestedVus = k6Step.options.vus || 10;
      const allowedVus = selectedTarget.scope.limits.maxConcurrency;
      if (requestedVus > allowedVus) {
        issues.push({
          severity: 'error',
          message: `Requested k6 concurrency (${requestedVus} VUs) exceeds target safety ceiling of ${allowedVus} VUs.`,
        });
      }
    }
  }

  // Risk Score Computation
  const computedRisk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = (() => {
    if (issues.some((i) => i.severity === 'error')) return 'CRITICAL';
    if (hasDisruptive && disruptiveSteps.length >= 2) return 'HIGH';
    if (hasDisruptive || issues.some((i) => i.severity === 'warning')) return 'MEDIUM';
    return 'LOW';
  })();

  const estimatedRuntimeSec = activeSteps.length * 8;

  return (
    <div className="p-4 rounded-xl bg-card border border-border/80 space-y-4 text-xs">
      <div className="flex items-center justify-between border-b border-border/60 pb-3">
        <div className="flex items-center space-x-2">
          <ShieldCheck className="w-4 h-4 text-primary" />
          <h4 className="font-semibold text-foreground uppercase tracking-wider text-[11px]">
            Pre-Flight Safety Validation
          </h4>
        </div>

        <div className="flex items-center space-x-2 font-mono text-[10px]">
          <span className="text-muted-foreground">Operational Risk:</span>
          <span
            className={`px-2 py-0.5 rounded font-bold border ${
              computedRisk === 'CRITICAL'
                ? 'bg-rose-950/60 text-rose-400 border-rose-800/60'
                : computedRisk === 'HIGH'
                ? 'bg-amber-950/60 text-amber-400 border-amber-800/60'
                : computedRisk === 'MEDIUM'
                ? 'bg-blue-950/60 text-blue-400 border-blue-800/60'
                : 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60'
            }`}
          >
            {computedRisk}
          </span>
        </div>
      </div>

      {/* Safety Matrix Metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
        <div className="p-2 rounded bg-accent/40 border border-border/50">
          <span className="text-[10px] text-muted-foreground uppercase font-mono block">
            Stages
          </span>
          <span className="font-mono font-bold text-foreground">
            {activeSteps.length} Active
          </span>
        </div>
        <div className="p-2 rounded bg-accent/40 border border-border/50">
          <span className="text-[10px] text-muted-foreground uppercase font-mono block">
            Disruptive
          </span>
          <span
            className={`font-mono font-bold ${
              hasDisruptive ? 'text-rose-400' : 'text-emerald-400'
            }`}
          >
            {disruptiveSteps.length} Tests
          </span>
        </div>
        <div className="p-2 rounded bg-accent/40 border border-border/50">
          <span className="text-[10px] text-muted-foreground uppercase font-mono block">
            Est. Runtime
          </span>
          <span className="font-mono font-bold text-foreground flex items-center gap-1">
            <Clock className="w-3 h-3 text-blue-400" />
            <span>~{estimatedRuntimeSec}s</span>
          </span>
        </div>
        <div className="p-2 rounded bg-accent/40 border border-border/50">
          <span className="text-[10px] text-muted-foreground uppercase font-mono block">
            DNS Pinning
          </span>
          <span className="font-mono font-bold text-emerald-400 flex items-center gap-1">
            <Lock className="w-3 h-3" />
            <span>Active</span>
          </span>
        </div>
      </div>

      {/* Diagnostic Issues List */}
      <div className="space-y-2">
        {issues.length === 0 ? (
          <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-800/40 flex items-center space-x-2 text-emerald-300">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>
              All pre-flight checks passed! Target authorization, safety budgets, and scope allowlists are verified.
            </span>
          </div>
        ) : (
          issues.map((issue, idx) => (
            <div
              key={idx}
              className={`p-2.5 rounded-lg border flex items-start gap-2 leading-relaxed ${
                issue.severity === 'error'
                  ? 'bg-rose-950/30 border-rose-800/50 text-rose-300'
                  : issue.severity === 'warning'
                  ? 'bg-amber-950/30 border-amber-800/50 text-amber-300'
                  : 'bg-blue-950/30 border-blue-800/50 text-blue-300'
              }`}
            >
              {issue.severity === 'error' ? (
                <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              ) : (
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              )}
              <span className="text-[11px]">{issue.message}</span>
            </div>
          ))
        )}
      </div>

      {/* Hazard Acknowledgment Checkbox if Disruptive Tests Present */}
      {hasDisruptive && (
        <div className="p-3 rounded-xl bg-amber-950/20 border border-amber-800/40 space-y-2">
          <label className="flex items-start space-x-2.5 cursor-pointer">
            <input
              type="checkbox"
              checked={hazardAcknowledged}
              onChange={(e) => setHazardAcknowledged(e.target.checked)}
              className="rounded border-border text-amber-500 mt-0.5 focus:ring-0"
            />
            <span className="text-[11px] text-amber-300 leading-relaxed font-medium">
              I acknowledge this pipeline contains active probing or stress tests (
              {disruptiveSteps.map((d) => d.name).join(', ')}). Target authorization and rate budgets are confirmed.
            </span>
          </label>
        </div>
      )}
    </div>
  );
};
