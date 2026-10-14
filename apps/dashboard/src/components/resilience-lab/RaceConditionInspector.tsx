import React, { useState } from 'react';
import {
  ShieldAlert,
  AlertOctagon,
  CheckCircle2,
  Check,
  Copy,
} from 'lucide-react';
import { RaceConditionBurstModel } from '../../api/resilience.js';

interface RaceConditionInspectorProps {
  model: RaceConditionBurstModel;
}

export const RaceConditionInspector: React.FC<RaceConditionInspectorProps> = ({ model }) => {
  const [filterMode, setFilterMode] = useState<'all' | 'anomalies' | 'success'>('all');
  const [copiedCode, setCopiedCode] = useState(false);

  const filteredRequests = model.requests.filter((r) => {
    if (filterMode === 'anomalies') return r.isAnomaly;
    if (filterMode === 'success') return r.statusCode === 200;
    return true;
  });

  const handleCopyRemediation = async () => {
    try {
      await navigator.clipboard.writeText(model.remediation);
      setCopiedCode(true);
      setTimeout(() => setCopiedCode(false), 2000);
    } catch {
      // Fallback
    }
  };

  return (
    <div className="space-y-6">
      <div className="p-6 rounded-xl bg-card border border-border/80 shadow-lg space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border/60">
          <div>
            <div className="flex items-center gap-2">
              <span className="p-1.5 rounded-lg bg-red-500/10 text-red-400 border border-red-500/20">
                <AlertOctagon className="w-4 h-4" />
              </span>
              <h3 className="text-base font-bold text-foreground">
                Synchronized Socket Burst & Race Condition Inspector
              </h3>
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">
              Simulates synchronized single-packet TCP barrier release across 20+ concurrent sockets to detect concurrency race conditions and double-spending.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span
              className={`px-3 py-1 rounded-full text-xs font-mono font-bold border flex items-center gap-1.5 ${
                model.isVulnerable
                  ? 'bg-red-500/20 text-red-300 border-red-500/40 animate-pulse'
                  : 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
              }`}
            >
              {model.isVulnerable ? (
                <>
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>RACE CONDITION CONFIRMED ({model.actualSuccessCount} Successes)</span>
                </>
              ) : (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Atomic Locks Intact</span>
                </>
              )}
            </span>
          </div>
        </div>

        {/* Test Summary Banner */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 font-mono text-xs">
          <div className="p-3 rounded-lg bg-slate-950/60 border border-border/70">
            <span className="text-[10px] text-muted-foreground uppercase block">Concurrent Sockets</span>
            <span className="text-base font-bold text-foreground">{model.concurrency} Threads</span>
            <span className="text-[10px] text-muted-foreground block mt-0.5">Dispatched in parallel</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-950/60 border border-border/70">
            <span className="text-[10px] text-muted-foreground uppercase block">TCP Barrier Jitter</span>
            <span className="text-base font-bold text-cyan-400">±{model.barrierReleaseJitterMs} ms</span>
            <span className="text-[10px] text-muted-foreground block mt-0.5">Microsecond precision</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-950/60 border border-border/70">
            <span className="text-[10px] text-muted-foreground uppercase block">Max Allowed Success</span>
            <span className="text-base font-bold text-emerald-400">{model.maxAllowedSuccess} Allowed</span>
            <span className="text-[10px] text-muted-foreground block mt-0.5">Single-use rule</span>
          </div>

          <div className="p-3 rounded-lg bg-red-950/30 border border-red-500/40">
            <span className="text-[10px] text-red-400 uppercase block">Actual Server Successes</span>
            <span className="text-base font-bold text-red-300">{model.actualSuccessCount} Dispatched</span>
            <span className="text-[10px] text-red-400 block mt-0.5">
              +{model.actualSuccessCount - model.maxAllowedSuccess} Duplicate Exploits!
            </span>
          </div>
        </div>

        {/* Filter Toolbar */}
        <div className="flex items-center justify-between">
          <div className="flex items-center rounded-lg border border-border/70 p-0.5 bg-muted/30 text-xs">
            <button
              type="button"
              onClick={() => setFilterMode('all')}
              className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                filterMode === 'all'
                  ? 'bg-blue-600 text-white'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              All Threads ({model.requests.length})
            </button>
            <button
              type="button"
              onClick={() => setFilterMode('anomalies')}
              className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                filterMode === 'anomalies'
                  ? 'bg-red-600 text-white'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              Anomalies Only ({model.requests.filter((r) => r.isAnomaly).length})
            </button>
            <button
              type="button"
              onClick={() => setFilterMode('success')}
              className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                filterMode === 'success'
                  ? 'bg-emerald-600 text-white'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              200 OKs ({model.requests.filter((r) => r.statusCode === 200).length})
            </button>
          </div>

          <div className="text-xs font-mono text-muted-foreground">
            Target Endpoint: <span className="font-bold text-cyan-300">{model.method} {model.endpoint}</span>
          </div>
        </div>

        {/* Thread Timeline List */}
        <div className="space-y-1.5 max-h-80 overflow-y-auto pr-1">
          {filteredRequests.map((req) => {
            const isFirst = req.threadId === 1;
            const isAnomaly = req.isAnomaly;

            return (
              <div
                key={req.threadId}
                className={`p-2.5 rounded-lg border text-xs font-mono flex items-center justify-between transition-colors ${
                  isAnomaly
                    ? 'bg-red-950/30 border-red-500/50 text-red-200'
                    : isFirst
                    ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-200'
                    : 'bg-slate-950/40 border-border/50 text-slate-400'
                }`}
              >
                <div className="flex items-center gap-3">
                  <span className="w-16 text-muted-foreground font-semibold">
                    Thread #{req.threadId}
                  </span>
                  <span className="text-[11px] text-cyan-400 font-semibold">
                    +{req.sentDeltaMs.toFixed(2)} ms
                  </span>
                  <span className="text-[11px] text-muted-foreground">
                    ({req.durationMs}ms latency)
                  </span>
                </div>

                <div className="flex items-center gap-3">
                  <span className="text-[11px] truncate max-w-xs text-slate-400">
                    {req.responsePreview}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                      isAnomaly
                        ? 'bg-red-500/20 text-red-300 border-red-500/40'
                        : isFirst
                        ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                        : 'bg-zinc-800 text-zinc-400 border-zinc-700'
                    }`}
                  >
                    HTTP {req.statusCode} {isAnomaly ? '🚨 DUPLICATE EXPLOIT' : isFirst ? '✅ FIRST REDEEM' : 'DENIED'}
                  </span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Remediation Playbook */}
        <div className="p-4 rounded-xl bg-blue-950/20 border border-blue-500/30 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-blue-400 uppercase tracking-wider">
              Concurrency Remediation Strategy
            </span>
            <button
              type="button"
              onClick={handleCopyRemediation}
              className="flex items-center gap-1 text-[11px] text-blue-300 hover:text-white transition-colors"
            >
              {copiedCode ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedCode ? 'Copied!' : 'Copy Code'}</span>
            </button>
          </div>
          <p className="text-xs text-blue-200/90 leading-relaxed">{model.remediation}</p>
          <pre className="p-3 bg-slate-950/80 rounded-lg border border-blue-500/20 font-mono text-xs text-blue-300 overflow-x-auto">
{`-- Atomic SQL Decrement with Optimistic Locking:
UPDATE coupons
SET remaining_uses = remaining_uses - 1,
    redeemed_at = NOW()
WHERE code = :coupon_code
  AND remaining_uses > 0;
-- Assert affected rows == 1; if 0, throw 409 Conflict.`}
          </pre>
        </div>
      </div>
    </div>
  );
};
