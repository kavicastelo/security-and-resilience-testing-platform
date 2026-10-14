import React, { useState, useEffect } from 'react';
import {
  X,
  Clock,
  Play,
  CheckCircle,
  AlertOctagon,
  Globe,
  Layers,
  StopCircle,
  Check,
} from 'lucide-react';
import { AgentFleetNode, AgentJobLease, fetchAgentJobLeases, cancelAgentJobLease } from '../../api/agents.js';

export interface AgentJobLeaseDrawerProps {
  node: AgentFleetNode | null;
  isOpen: boolean;
  onClose: () => void;
  className?: string;
}

export const AgentJobLeaseDrawer: React.FC<AgentJobLeaseDrawerProps> = ({
  node,
  isOpen,
  onClose,
  className = '',
}) => {
  const [leases, setLeases] = useState<AgentJobLease[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [cancellingJobId, setCancellingJobId] = useState<string | null>(null);

  useEffect(() => {
    if (!isOpen || !node) return;
    const loadLeases = async () => {
      setIsLoading(true);
      const data = await fetchAgentJobLeases(node.id);
      setLeases(data);
      setIsLoading(false);
    };
    loadLeases();
  }, [isOpen, node]);

  if (!isOpen || !node) return null;

  const handleCancelLease = async (jobId: string) => {
    setCancellingJobId(jobId);
    await cancelAgentJobLease(jobId);
    setLeases((prev) =>
      prev.map((l) => (l.jobId === jobId ? { ...l, status: 'cancelled' } : l))
    );
    setTimeout(() => setCancellingJobId(null), 2000);
  };

  return (
    <div className={`fixed inset-0 z-50 flex justify-end bg-background/80 backdrop-blur-sm animate-in fade-in duration-200 ${className}`}>
      <div className="relative w-full max-w-xl h-full bg-card border-l border-border/80 shadow-2xl flex flex-col animate-in slide-in-from-right duration-300">
        {/* Drawer Header */}
        <div className="p-5 border-b border-border/40 flex items-center justify-between">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Clock className="w-5 h-5 text-blue-400" />
              <h2 className="text-base font-bold text-foreground font-mono">
                Job Leases: {node.name}
              </h2>
            </div>
            <p className="text-xs text-muted-foreground font-mono">
              Node ID: {node.id} • IP: {node.ipAddress}
            </p>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Leases List */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4 text-xs">
          {isLoading ? (
            <div className="p-8 text-center text-muted-foreground font-mono animate-pulse">
              Loading active and historical leases...
            </div>
          ) : leases.length === 0 ? (
            <div className="p-8 text-center text-muted-foreground font-mono border border-border/40 rounded-xl bg-background/40">
              No active or historical job leases recorded for this node.
            </div>
          ) : (
            leases.map((lease) => {
              const isRunning = lease.status === 'running';
              const isCompleted = lease.status === 'completed';

              return (
                <div
                  key={lease.leaseId}
                  className={`p-4 rounded-xl border space-y-3 ${
                    isRunning
                      ? 'bg-blue-500/10 border-blue-500/40 shadow-lg'
                      : 'bg-background/80 border-border/50'
                  }`}
                >
                  <div className="flex items-center justify-between pb-2 border-b border-border/30">
                    <div className="flex items-center gap-2 font-mono">
                      <span className="font-bold text-foreground">{lease.jobId}</span>
                      <span className="text-[10px] text-muted-foreground">
                        Lease: {lease.leaseId}
                      </span>
                    </div>

                    <span
                      className={`flex items-center gap-1 text-[10px] uppercase font-mono font-bold px-2 py-0.5 rounded border ${
                        isRunning
                          ? 'bg-blue-500/20 text-blue-300 border-blue-500/40'
                          : isCompleted
                          ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                          : 'bg-muted text-muted-foreground border-border/40'
                      }`}
                    >
                      {isRunning ? (
                        <>
                          <Play className="w-3 h-3 animate-pulse" />
                          Running
                        </>
                      ) : isCompleted ? (
                        <>
                          <CheckCircle className="w-3 h-3" />
                          Completed
                        </>
                      ) : (
                        <>
                          <AlertOctagon className="w-3 h-3" />
                          {lease.status}
                        </>
                      )}
                    </span>
                  </div>

                  {/* Target & Engines */}
                  <div className="space-y-1 font-mono text-[11px]">
                    <div className="flex items-center gap-1.5 text-foreground">
                      <Globe className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                      <span className="font-semibold">{lease.targetName}</span>
                    </div>
                    <div className="text-muted-foreground truncate pl-5">
                      {lease.targetUrl}
                    </div>

                    <div className="flex items-center gap-1.5 pt-1 pl-5">
                      <Layers className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                      <div className="flex flex-wrap gap-1">
                        {lease.engines.map((e) => (
                          <span
                            key={e}
                            className="px-1.5 py-0.2 rounded bg-muted/60 text-muted-foreground text-[10px]"
                          >
                            {e}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Progress & Log Message */}
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-[11px] font-mono text-muted-foreground">
                      <span>Progress:</span>
                      <span className="font-bold text-foreground">{lease.progressPercent}%</span>
                    </div>
                    <div className="w-full h-1.5 rounded-full bg-background/80 overflow-hidden">
                      <div
                        style={{ width: `${lease.progressPercent}%` }}
                        className={`h-full rounded-full transition-all ${
                          isRunning ? 'bg-blue-400' : 'bg-emerald-400'
                        }`}
                      />
                    </div>
                    <p className="text-[10px] text-muted-foreground font-mono truncate">
                      Log: {lease.lastLogMessage}
                    </p>
                  </div>

                  {/* Cancel Lease Action */}
                  {isRunning && (
                    <div className="flex justify-end pt-1">
                      <button
                        type="button"
                        onClick={() => handleCancelLease(lease.jobId)}
                        disabled={cancellingJobId === lease.jobId}
                        className="flex items-center gap-1 px-3 py-1 rounded-lg text-xs font-mono bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30 transition-colors"
                      >
                        {cancellingJobId === lease.jobId ? (
                          <>
                            <Check className="w-3 h-3 text-rose-400" />
                            <span>Cancelling...</span>
                          </>
                        ) : (
                          <>
                            <StopCircle className="w-3 h-3" />
                            <span>Cancel Lease</span>
                          </>
                        )}
                      </button>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>

        {/* Drawer Footer */}
        <div className="p-4 border-t border-border/40 bg-background/50 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-medium text-foreground bg-muted hover:bg-muted/80 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
