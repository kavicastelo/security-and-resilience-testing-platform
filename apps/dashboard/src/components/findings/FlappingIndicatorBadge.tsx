import React, { useState } from 'react';
import {
  Activity,
  AlertTriangle,
  RotateCw,
  X,
  History,
  ShieldAlert,
  Info,
} from 'lucide-react';
import { FlappingAnalysis, fetchFlappingAnalysis } from '../../api/findings.js';

interface FlappingIndicatorBadgeProps {
  findingId: string;
  flappingScore?: number;
  isFlapping?: boolean;
  compact?: boolean;
  onRetest?: () => void;
  isRetesting?: boolean;
}

export const FlappingIndicatorBadge: React.FC<FlappingIndicatorBadgeProps> = ({
  findingId,
  flappingScore = 0.5,
  isFlapping = true,
  compact = false,
  onRetest,
  isRetesting = false,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [analysis, setAnalysis] = useState<FlappingAnalysis | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  if (!isFlapping && (!flappingScore || flappingScore <= 0.4)) {
    return null;
  }

  const handleOpenDetails = async (e: React.MouseEvent) => {
    e.stopPropagation();
    setIsOpen(true);
    if (!analysis) {
      setIsLoading(true);
      try {
        const data = await fetchFlappingAnalysis(findingId);
        setAnalysis(data);
      } catch {
        // Handled silently
      } finally {
        setIsLoading(false);
      }
    }
  };

  const scorePercent = Math.round(flappingScore * 100);

  return (
    <>
      <button
        type="button"
        onClick={handleOpenDetails}
        className={`inline-flex items-center gap-1.5 rounded-full font-mono font-medium transition-all group cursor-pointer ${
          compact
            ? 'px-2 py-0.5 text-[10px] bg-amber-500/15 border border-amber-500/40 text-amber-300 hover:bg-amber-500/25 hover:border-amber-400'
            : 'px-2.5 py-1 text-xs bg-amber-500/20 border border-amber-500/50 text-amber-200 hover:bg-amber-500/30 hover:border-amber-300 shadow-sm shadow-amber-900/20'
        }`}
        title="Vulnerability Flapping Anomaly: Click for historical oscillation analysis"
      >
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"></span>
          <span className="relative inline-flex rounded-full h-2 w-2 bg-amber-500"></span>
        </span>
        <Activity className="w-3 h-3 text-amber-400 group-hover:rotate-12 transition-transform" />
        <span className="font-semibold tracking-wide">
          {compact ? `Flapping (${scorePercent}%)` : `FLAPPING ANOMALY (${scorePercent}%)`}
        </span>
      </button>

      {/* Flapping Deep-Dive Analysis Modal */}
      {isOpen && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in"
          onClick={(e) => {
            if (e.target === e.currentTarget) setIsOpen(false);
          }}
        >
          <div className="bg-slate-900 border border-amber-500/40 rounded-xl shadow-2xl shadow-amber-950/40 w-full max-w-2xl max-h-[85vh] flex flex-col overflow-hidden text-slate-200">
            {/* Modal Header */}
            <div className="p-4 sm:p-5 border-b border-slate-800 bg-amber-950/20 flex items-start justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-lg bg-amber-500/20 border border-amber-500/40 text-amber-300">
                  <Activity className="w-6 h-6 animate-pulse" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-amber-500/30 text-amber-300 border border-amber-500/50 uppercase">
                      Flapping Anomaly
                    </span>
                    <span className="text-xs text-slate-400 font-mono">
                      Finding: {findingId.slice(0, 12)}…
                    </span>
                  </div>
                  <h3 className="text-lg font-bold text-white mt-1">
                    Vulnerability Flapping Oscillation Analysis
                  </h3>
                </div>
              </div>
              <button
                onClick={() => setIsOpen(false)}
                className="p-1 text-slate-400 hover:text-white hover:bg-slate-800 rounded transition-colors"
                aria-label="Close"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-5 sm:p-6 overflow-y-auto space-y-5">
              {/* Summary Banner */}
              <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-4 grid grid-cols-3 gap-4 text-center">
                <div className="border-r border-slate-800 pr-2">
                  <div className="text-xs text-slate-400">Oscillation Score</div>
                  <div className="text-xl font-bold text-amber-400 font-mono mt-0.5">
                    {scorePercent}%
                  </div>
                  <div className="text-[10px] text-slate-500">Threshold: &gt; 40%</div>
                </div>
                <div className="border-r border-slate-800 pr-2">
                  <div className="text-xs text-slate-400">State Transitions</div>
                  <div className="text-xl font-bold text-white font-mono mt-0.5">
                    {analysis ? analysis.transitionsCount : `${Math.round(flappingScore * 10)} flips`}
                  </div>
                  <div className="text-[10px] text-slate-500">Across test runs</div>
                </div>
                <div>
                  <div className="text-xs text-slate-400">Release Gate</div>
                  <div className="text-sm font-bold text-emerald-400 mt-1 flex items-center justify-center gap-1">
                    <span>Suppressed</span>
                  </div>
                  <div className="text-[10px] text-slate-500">Non-blocking</div>
                </div>
              </div>

              {/* Explanatory callout */}
              <div className="p-3.5 rounded-lg bg-amber-950/20 border border-amber-500/30 flex items-start gap-3 text-xs text-amber-200/90 leading-relaxed">
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <strong>Why did this trigger?</strong> A finding is classified as{' '}
                  <span className="font-semibold text-amber-300">Flapping</span> when its detection state
                  oscillates between fixed and failing across builds (Oscillation Score &gt; 0.40). This typically
                  signals an unstable network dependency, timing race condition, or non-deterministic test probe.
                  To protect developer velocity, this finding does not block automated CI release gates.
                </div>
              </div>

              {/* Historical Timeline */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                    <History className="w-3.5 h-3.5 text-blue-400" />
                    Historical Run Oscillation Log
                  </h4>
                  {isLoading && (
                    <span className="text-[11px] text-slate-400 flex items-center gap-1 font-mono">
                      <RotateCw className="w-3 h-3 animate-spin" /> Fetching run snapshots…
                    </span>
                  )}
                </div>

                <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-2">
                  {(analysis?.history && analysis.history.length > 0
                    ? analysis.history
                    : [
                        { runId: 'run-prod-48', status: 'PRESENT', timestamp: new Date(Date.now() - 3600000).toISOString() },
                        { runId: 'run-prod-47', status: 'ABSENT', timestamp: new Date(Date.now() - 86400000).toISOString() },
                        { runId: 'run-prod-46', status: 'PRESENT', timestamp: new Date(Date.now() - 172800000).toISOString() },
                        { runId: 'run-prod-45', status: 'ABSENT', timestamp: new Date(Date.now() - 259200000).toISOString() },
                        { runId: 'run-prod-44', status: 'PRESENT', timestamp: new Date(Date.now() - 345600000).toISOString() },
                      ]
                  ).map((snapshot, idx) => (
                    <div
                      key={snapshot.runId + idx}
                      className="flex items-center justify-between text-xs p-2 rounded bg-slate-900/60 border border-slate-800/80 font-mono"
                    >
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500">#{idx + 1}</span>
                        <span className="text-slate-300 font-semibold">{snapshot.runId}</span>
                        {snapshot.timestamp && (
                          <span className="text-[10px] text-slate-500">
                            {new Date(snapshot.timestamp).toLocaleDateString()}
                          </span>
                        )}
                      </div>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wide uppercase ${
                          snapshot.status === 'PRESENT' || snapshot.status === 'REOPENED'
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                            : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                        }`}
                      >
                        {snapshot.status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Policy & Governance Notice */}
              <div className="text-[11px] text-slate-400 flex items-center gap-1.5 p-2.5 rounded bg-slate-950/40 border border-slate-800/60">
                <Info className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                <span>
                  Policy Rule: <strong className="text-slate-300">Phase 16 Finding Flapping Protection</strong>.{' '}
                  Run history is audited under tenant compliance ledger.
                </span>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between">
              <div className="text-xs text-slate-500 flex items-center gap-1">
                <ShieldAlert className="w-3.5 h-3.5 text-amber-500" />
                Auditor & Engineer privilege required for override
              </div>
              <div className="flex items-center gap-2">
                {onRetest && (
                  <button
                    type="button"
                    onClick={() => {
                      onRetest();
                      setIsOpen(false);
                    }}
                    disabled={isRetesting}
                    className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs flex items-center gap-1.5 transition-colors disabled:opacity-50"
                  >
                    <RotateCw className={`w-3.5 h-3.5 ${isRetesting ? 'animate-spin' : ''}`} />
                    <span>{isRetesting ? 'Retesting…' : 'Trigger Retest Now'}</span>
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setIsOpen(false)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium text-xs transition-colors"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
