import React, { useState } from 'react';
import {
  GitCommit,
  ArrowRight,
  ShieldAlert,
  AlertTriangle,
  CreditCard,
  PackageCheck,
  FileCode,
  Terminal,
} from 'lucide-react';
import { StateMachineModel } from '../../api/resilience.js';

interface StateMachineGraphProps {
  model: StateMachineModel;
}

export const StateMachineGraph: React.FC<StateMachineGraphProps> = ({ model }) => {
  const [selectedExploitId, setSelectedExploitId] = useState<string | null>(
    model.bypassExploits[0]?.id || null,
  );

  const activeExploit =
    model.bypassExploits.find((e) => e.id === selectedExploitId) ||
    model.bypassExploits[0];

  return (
    <div className="space-y-6">
      {/* Visual State Graph Container */}
      <div className="p-6 rounded-xl bg-card border border-border/80 shadow-lg space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="p-1.5 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/20">
                <GitCommit className="w-4 h-4" />
              </span>
              <h3 className="text-base font-bold text-foreground">
                Business Logic State Machine & Transition Invariants
              </h3>
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">
              Validates multi-step business state flows and detects unauthorized step-skipping invariants (e.g. bypassing payment).
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-red-500/15 text-red-300 border border-red-500/30 flex items-center gap-1.5 animate-pulse">
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>{model.bypassExploits.length} State Bypass Exploits Detected</span>
            </span>
          </div>
        </div>

        {/* State Machine Node Canvas */}
        <div className="relative p-6 rounded-xl bg-slate-950/80 border border-border/80 overflow-x-auto">
          {/* Subtle cyber grid */}
          <div className="absolute inset-0 bg-cyber-grid opacity-20 pointer-events-none" />

          {/* Illegal Bypass Arch Indicator */}
          <div
            onClick={() => setSelectedExploitId('fnd-bypass-skip-pay')}
            className="relative mb-6 p-4 rounded-xl bg-red-950/20 border border-red-500/40 space-y-2 cursor-pointer hover:bg-red-950/30 transition-colors"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-bold text-red-400 uppercase tracking-wider">
                <AlertTriangle className="w-4 h-4 animate-bounce" />
                <span>🚨 Detected Workflow Transition Bypass (Step-Skipping Exploit)</span>
              </div>
              <span className="text-[10px] font-mono text-red-300 bg-red-500/20 px-2 py-0.5 rounded border border-red-500/30">
                Severity: CRITICAL
              </span>
            </div>
            <p className="text-xs text-red-200/90 font-mono">
              Observed Transition: <span className="font-bold text-cyan-300">Step #2 (Add Items)</span> ──[BYPASSED PAYMENT]──▶{' '}
              <span className="font-bold text-red-300">Step #5 (Fulfill Order)</span> (Returned HTTP 200 OK!)
            </p>
          </div>

          {/* Stepped Workflow Pipeline */}
          <div className="relative flex items-center justify-between min-w-[750px] gap-3 py-4">
            {model.states.map((state, idx) => {
              const isLast = idx === model.states.length - 1;
              const isPayment = state.isPaymentOrTerminal;

              return (
                <React.Fragment key={state.id}>
                  {/* State Node Card */}
                  <div
                    className={`relative flex-1 p-4 rounded-xl border transition-all ${
                      isPayment
                        ? 'bg-amber-950/20 border-amber-500/50 shadow-md shadow-amber-500/10'
                        : isLast
                        ? 'bg-purple-950/20 border-purple-500/50 shadow-md shadow-purple-500/10'
                        : 'bg-card/70 border-border/70'
                    }`}
                  >
                    <div className="flex items-center justify-between pb-2 border-b border-border/40">
                      <span className="text-[10px] font-mono font-bold text-muted-foreground uppercase">
                        Step #{state.order}
                      </span>
                      {isPayment && (
                        <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 flex items-center gap-1">
                          <CreditCard className="w-3 h-3" />
                          <span>Payment Guard</span>
                        </span>
                      )}
                      {isLast && (
                        <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 flex items-center gap-1">
                          <PackageCheck className="w-3 h-3" />
                          <span>Terminal</span>
                        </span>
                      )}
                    </div>

                    <div className="pt-2">
                      <div className="text-xs font-bold text-foreground truncate">{state.name}</div>
                      <div className="text-[11px] font-mono text-cyan-400 mt-1 truncate">
                        <span className="text-slate-400 font-normal mr-1">{state.method}</span>
                        {state.path}
                      </div>
                      <div className="text-[10px] text-muted-foreground mt-1 line-clamp-2">
                        {state.description}
                      </div>
                    </div>
                  </div>

                  {/* Connecting Arrow */}
                  {!isLast && (
                    <div className="shrink-0 flex items-center justify-center">
                      <div className="w-6 h-0.5 bg-emerald-500/60" />
                      <ArrowRight className="w-4 h-4 text-emerald-400 -ml-1" />
                    </div>
                  )}
                </React.Fragment>
              );
            })}
          </div>
        </div>

        {/* State Bypass Exploit Forensic Inspection */}
        {activeExploit && (
          <div className="p-5 rounded-xl bg-slate-950/70 border border-border/70 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-border/60">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-500/20 text-red-300 border border-red-500/30">
                  {activeExploit.severity}
                </span>
                <h4 className="text-sm font-bold text-foreground">{activeExploit.name}</h4>
              </div>
              <div className="flex items-center gap-2 text-xs font-mono">
                <span className="text-muted-foreground">Expected:</span>
                <span className="text-emerald-400 font-bold">HTTP {activeExploit.expectedStatus}</span>
                <span className="text-muted-foreground ml-2">Actual:</span>
                <span className="text-red-400 font-bold">HTTP {activeExploit.actualStatus}</span>
              </div>
            </div>

            <p className="text-xs text-muted-foreground leading-relaxed">{activeExploit.description}</p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Request */}
              <div className="space-y-1.5">
                <div className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-blue-400" />
                  <span>Exploit Request (Bypassing Payment Token)</span>
                </div>
                <pre className="p-3 bg-black/70 border border-border/60 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto whitespace-pre">
                  {activeExploit.requestSnippet}
                </pre>
              </div>

              {/* Response */}
              <div className="space-y-1.5">
                <div className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                  <FileCode className="w-3.5 h-3.5 text-red-400" />
                  <span>Vulnerable Server Response (Dispatched)</span>
                </div>
                <pre className="p-3 bg-black/70 border border-border/60 rounded-lg font-mono text-xs text-red-300 overflow-x-auto whitespace-pre">
                  {activeExploit.responseSnippet}
                </pre>
              </div>
            </div>

            {/* Remediation */}
            <div className="p-3.5 rounded-lg bg-blue-950/20 border border-blue-500/30 text-xs">
              <span className="font-bold text-blue-400 block mb-1">State Invariant Remediation:</span>
              <p className="text-blue-200/90 leading-relaxed font-mono">{activeExploit.remediation}</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
