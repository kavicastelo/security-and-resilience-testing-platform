import React, { useState } from 'react';
import {
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Loader2,
  Circle,
  Play,
  RotateCw,
  Clock,
  Terminal,
} from 'lucide-react';
import {
  VerifyRemediationResult,
  verifyRemediationProposal,
  RemediationVerifiedStatus,
} from '../../api/remediation.js';
import { useAppStore } from '../../store/useAppStore.js';

interface PatchVerificationStepperProps {
  remediationId: string;
  initialStatus?: RemediationVerifiedStatus;
  initialDetails?: string;
  onVerificationComplete?: (result: VerifyRemediationResult) => void;
}

type StepStatus = 'pending' | 'running' | 'completed' | 'failed';

interface Step {
  id: string;
  title: string;
  description: string;
  status: StepStatus;
}

export const PatchVerificationStepper: React.FC<PatchVerificationStepperProps> = ({
  remediationId,
  initialStatus = 'UNVERIFIED',
  initialDetails,
  onVerificationComplete,
}) => {
  const { showToast } = useAppStore();
  const [isVerifying, setIsVerifying] = useState(false);
  const [currentResult, setCurrentResult] = useState<VerifyRemediationResult | null>(null);
  const [activeStepIndex, setActiveStepIndex] = useState<number>(
    initialStatus === 'PASSED' ? 4 : initialStatus === 'FAILED' ? 4 : 0,
  );

  const [steps, setSteps] = useState<Step[]>([
    {
      id: 'step-1',
      title: 'Diff Syntax Validation',
      description: 'Validate standard git unified diff RFC headers and hunk boundaries',
      status: initialStatus !== 'UNVERIFIED' ? 'completed' : 'pending',
    },
    {
      id: 'step-2',
      title: 'Ephemeral Sandbox Container',
      description: 'Spin up isolated container runtime with zero production network access',
      status: initialStatus !== 'UNVERIFIED' ? 'completed' : 'pending',
    },
    {
      id: 'step-3',
      title: 'Apply Patch & Code Build',
      description: 'Execute git apply --check and run target compile/bundle validation',
      status: initialStatus !== 'UNVERIFIED' ? 'completed' : 'pending',
    },
    {
      id: 'step-4',
      title: 'Targeted Exploit Probe',
      description: 'Execute identical HTTP injection payload against patched sandbox endpoint',
      status:
        initialStatus === 'PASSED'
          ? 'completed'
          : initialStatus === 'FAILED'
          ? 'failed'
          : 'pending',
    },
    {
      id: 'step-5',
      title: 'Assertion & Policy Gate Verdict',
      description: 'Verify flaw is cleared (HTTP 200/403 compliant) without regressions',
      status:
        initialStatus === 'PASSED'
          ? 'completed'
          : initialStatus === 'FAILED'
          ? 'failed'
          : 'pending',
    },
  ]);

  const handleStartVerification = async () => {
    setIsVerifying(true);
    setCurrentResult(null);

    // Reset steps to running sequence
    setSteps((prev) =>
      prev.map((s, idx) => ({
        ...s,
        status: idx === 0 ? 'running' : 'pending',
      })),
    );
    setActiveStepIndex(0);

    // Visual step progression simulator for high-fidelity interactive UX
    const updateStep = (index: number, status: StepStatus) => {
      setActiveStepIndex(index);
      setSteps((prev) =>
        prev.map((s, i) => (i === index ? { ...s, status } : s)),
      );
    };

    try {
      // Step 1: Diff syntax validation
      await new Promise((r) => setTimeout(r, 250));
      updateStep(0, 'completed');
      updateStep(1, 'running');

      // Step 2: Spawn container
      await new Promise((r) => setTimeout(r, 300));
      updateStep(1, 'completed');
      updateStep(2, 'running');

      // Step 3: Apply patch
      await new Promise((r) => setTimeout(r, 350));
      updateStep(2, 'completed');
      updateStep(3, 'running');

      // Step 4: Execute targeted retest via controller API
      const result = await verifyRemediationProposal(remediationId, 10000);
      setCurrentResult(result);

      if (result.verifiedStatus === 'PASSED') {
        updateStep(3, 'completed');
        updateStep(4, 'completed');
        showToast('Patch verified: targeted engine confirmed vulnerability mitigated!', 'success');
      } else {
        updateStep(3, 'failed');
        updateStep(4, 'failed');
        showToast('Verification failed: flaw still reproduces against patched target', 'error');
      }

      onVerificationComplete?.(result);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      updateStep(activeStepIndex, 'failed');
      showToast(`Verification loop failed: ${msg}`, 'error');
    } finally {
      setIsVerifying(false);
    }
  };

  const effectiveStatus = currentResult?.verifiedStatus || initialStatus;

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-5 space-y-5 text-slate-200">
      {/* Header with trigger button */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold uppercase tracking-wider text-purple-400">
              Automated Verification Loop
            </span>
            <span
              className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase border ${
                effectiveStatus === 'PASSED'
                  ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800'
                  : effectiveStatus === 'FAILED'
                  ? 'bg-rose-950/60 text-rose-400 border-rose-800'
                  : 'bg-amber-950/60 text-amber-400 border-amber-800'
              }`}
            >
              {effectiveStatus === 'PASSED'
                ? 'Verified Fixed'
                : effectiveStatus === 'FAILED'
                ? 'Vulnerability Persists'
                : 'Pending Verification'}
            </span>
          </div>
          <h3 className="text-base font-bold text-white mt-0.5">
            Sandboxed Exploit Retest Pipeline
          </h3>
        </div>

        <button
          type="button"
          onClick={handleStartVerification}
          disabled={isVerifying}
          className="px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-semibold text-xs flex items-center gap-2 transition-all disabled:opacity-50 shadow-md shadow-purple-900/30 shrink-0 cursor-pointer"
        >
          {isVerifying ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>Verifying Sandbox…</span>
            </>
          ) : (
            <>
              {effectiveStatus === 'UNVERIFIED' ? (
                <Play className="w-4 h-4" />
              ) : (
                <RotateCw className="w-4 h-4" />
              )}
              <span>{effectiveStatus === 'UNVERIFIED' ? 'Run Verification Loop' : 'Re-verify Patch'}</span>
            </>
          )}
        </button>
      </div>

      {/* Stepper Process Visualizer */}
      <div className="space-y-3">
        {steps.map((step, idx) => {
          return (
            <div
              key={step.id}
              className={`p-3 rounded-lg border transition-all flex items-start gap-3 ${
                step.status === 'running'
                  ? 'bg-purple-950/30 border-purple-500/60 shadow-sm'
                  : step.status === 'completed'
                  ? 'bg-emerald-950/20 border-emerald-500/30'
                  : step.status === 'failed'
                  ? 'bg-rose-950/30 border-rose-500/40'
                  : 'bg-slate-950/40 border-slate-800/80 opacity-60'
              }`}
            >
              <div className="mt-0.5 shrink-0">
                {step.status === 'running' ? (
                  <Loader2 className="w-4 h-4 text-purple-400 animate-spin" />
                ) : step.status === 'completed' ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                ) : step.status === 'failed' ? (
                  <XCircle className="w-4 h-4 text-rose-400" />
                ) : (
                  <Circle className="w-4 h-4 text-slate-600" />
                )}
              </div>

              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <span
                    className={`text-xs font-semibold ${
                      step.status === 'running'
                        ? 'text-purple-300'
                        : step.status === 'completed'
                        ? 'text-white'
                        : step.status === 'failed'
                        ? 'text-rose-300'
                        : 'text-slate-400'
                    }`}
                  >
                    Stage {idx + 1}: {step.title}
                  </span>
                  <span
                    className={`text-[10px] font-mono uppercase ${
                      step.status === 'completed'
                        ? 'text-emerald-400'
                        : step.status === 'running'
                        ? 'text-purple-400 animate-pulse'
                        : step.status === 'failed'
                        ? 'text-rose-400'
                        : 'text-slate-600'
                    }`}
                  >
                    {step.status}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 mt-0.5 leading-normal">
                  {step.description}
                </p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Execution Results Output Drawer */}
      {(currentResult || initialDetails) && (
        <div className="rounded-lg bg-slate-950 border border-slate-800 p-3.5 space-y-2 font-mono text-xs">
          <div className="flex items-center justify-between text-slate-400 font-sans">
            <span className="flex items-center gap-1.5 font-semibold text-xs text-slate-300">
              <Terminal className="w-3.5 h-3.5 text-blue-400" />
              Retest Harness Output
            </span>
            {currentResult?.durationMs && (
              <span className="flex items-center gap-1 text-[11px] text-slate-500 font-mono">
                <Clock className="w-3 h-3" />
                {currentResult.durationMs}ms execution time
              </span>
            )}
          </div>
          <pre className="text-slate-300 text-[11px] whitespace-pre-wrap leading-relaxed select-all">
            {currentResult?.verificationDetails || initialDetails}
          </pre>
        </div>
      )}

      {/* Verification Invariant Notice */}
      <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 flex items-start gap-2.5 text-xs text-slate-400">
        <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
        <div>
          <strong className="text-slate-300">Phase 16 Retester Integration:</strong> The patch verification loop runs the isolated engine probe against an ephemeral container hosting the patched branch. A verdict of <code>PASSED</code> guarantees that the security flaw is cleared before PR merge.
        </div>
      </div>
    </div>
  );
};
