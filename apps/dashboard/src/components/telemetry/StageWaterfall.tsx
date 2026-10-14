import React from 'react';
import {
  CheckCircle2,
  XCircle,
  Clock,
  Activity,
  Layers,
  ShieldCheck,
  AlertTriangle,
} from 'lucide-react';
import { EngineStageState } from '../../hooks/useRunEventStream.js';

interface StageWaterfallProps {
  engineStates: Record<string, EngineStageState>;
  activeEngine: string | null;
  selectedEngineFilter: string | null;
  onSelectEngineFilter: (engineId: string | null) => void;
  className?: string;
}

export const StageWaterfall: React.FC<StageWaterfallProps> = ({
  engineStates,
  activeEngine,
  selectedEngineFilter,
  onSelectEngineFilter,
  className = '',
}) => {
  const stageList = Object.values(engineStates);

  const getStatusIcon = (status: EngineStageState['status']) => {
    switch (status) {
      case 'running':
        return <Activity className="w-4 h-4 text-primary animate-spin shrink-0" />;
      case 'completed':
        return <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />;
      case 'failed':
        return <XCircle className="w-4 h-4 text-rose-400 shrink-0" />;
      case 'cancelled':
        return <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />;
      default:
        return <Clock className="w-4 h-4 text-muted-foreground shrink-0" />;
    }
  };

  return (
    <div
      className={`rounded-2xl border border-border/80 bg-card/60 backdrop-blur-md overflow-hidden shadow-sm flex flex-col ${className}`}
    >
      {/* Header */}
      <div className="p-3.5 bg-accent/20 border-b border-border/60 flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Layers className="w-4 h-4 text-primary" />
          <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground">
            Stage Waterfall ({stageList.length} Engines)
          </h3>
        </div>

        {selectedEngineFilter && (
          <button
            type="button"
            onClick={() => onSelectEngineFilter(null)}
            className="text-[10px] font-mono text-primary hover:underline"
          >
            Clear Filter
          </button>
        )}
      </div>

      {/* Waterfall List */}
      <div className="p-3 space-y-2 overflow-y-auto max-h-[480px]">
        {stageList.length === 0 ? (
          <div className="py-12 text-center text-xs text-muted-foreground/60 space-y-1">
            <Clock className="w-5 h-5 mx-auto text-muted-foreground/40 animate-pulse" />
            <p>Initializing execution stages...</p>
            <p className="text-[10px]">Awaiting engine dispatch from scheduler</p>
          </div>
        ) : (
          stageList.map((stage, idx) => {
            const isSelected = selectedEngineFilter === stage.engineId;
            const isActive = activeEngine === stage.engineId || stage.status === 'running';

            return (
              <div
                key={stage.engineId}
                onClick={() =>
                  onSelectEngineFilter(isSelected ? null : stage.engineId)
                }
                className={`p-3 rounded-xl border text-xs cursor-pointer transition-all duration-150 space-y-1.5 ${
                  isSelected
                    ? 'bg-primary/10 border-primary ring-1 ring-primary/40'
                    : isActive
                    ? 'bg-blue-950/20 border-blue-800/60 shadow-sm'
                    : stage.status === 'completed'
                    ? 'bg-card border-border/60 hover:bg-accent/40'
                    : stage.status === 'failed'
                    ? 'bg-rose-950/20 border-rose-800/50'
                    : 'bg-card/40 border-border/40 opacity-70'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center space-x-2.5">
                    <span className="font-mono text-[10px] text-muted-foreground w-4 text-center shrink-0">
                      {idx + 1}
                    </span>
                    {getStatusIcon(stage.status)}
                    <span className="font-semibold text-foreground truncate max-w-[140px] sm:max-w-[180px]">
                      {stage.engineId}
                    </span>
                  </div>

                  <div className="flex items-center space-x-2 shrink-0 font-mono text-[10px]">
                    {stage.durationMs !== undefined && (
                      <span className="text-muted-foreground">
                        {stage.durationMs}ms
                      </span>
                    )}

                    <span
                      className={`px-1.5 py-0.5 rounded uppercase font-semibold text-[9px] border ${
                        stage.status === 'completed'
                          ? 'bg-emerald-950/40 text-emerald-400 border-emerald-800/50'
                          : stage.status === 'running'
                          ? 'bg-blue-950/50 text-blue-400 border-blue-800/50 animate-pulse'
                          : stage.status === 'failed'
                          ? 'bg-rose-950/40 text-rose-400 border-rose-800/50'
                          : 'bg-muted text-muted-foreground border-border'
                      }`}
                    >
                      {stage.status}
                    </span>
                  </div>
                </div>

                {/* Findings Count Strip */}
                {(stage.findingsCount ?? 0) > 0 && (
                  <div className="flex items-center justify-between pt-1 border-t border-border/40 text-[10px] font-mono text-amber-400">
                    <span className="flex items-center gap-1">
                      <ShieldCheck className="w-3 h-3" />
                      <span>Findings Detected:</span>
                    </span>
                    <span className="font-bold">{stage.findingsCount}</span>
                  </div>
                )}

                {/* Failure Error Display */}
                {stage.error && (
                  <div className="p-1.5 rounded bg-rose-950/40 border border-rose-900/50 text-rose-300 text-[10px] font-mono break-all">
                    {stage.error}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
