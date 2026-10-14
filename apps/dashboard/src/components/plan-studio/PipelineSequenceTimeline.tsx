import React from 'react';
import {
  ArrowDown,
  ChevronUp,
  ChevronDown,
  Trash2,
  Sliders,
  AlertTriangle,
  Layers,
  Clock,
  ShieldCheck,
  Zap,
  Lock,
  Activity,
} from 'lucide-react';
import {
  usePlanStudioStore,
  EngineCategory,
  PlanStep,
} from '../../store/usePlanStudioStore.js';

export const PipelineSequenceTimeline: React.FC = () => {
  const {
    steps,
    reorderStep,
    removeStep,
    toggleStep,
    setActiveConfigStepId,
    activeConfigStepId,
    resetPlan,
  } = usePlanStudioStore();

  const getCategoryIcon = (category: EngineCategory) => {
    switch (category) {
      case 'web':
        return <ShieldCheck className="w-4 h-4 text-emerald-400" />;
      case 'api':
        return <Zap className="w-4 h-4 text-primary" />;
      case 'auth':
        return <Lock className="w-4 h-4 text-amber-400" />;
      case 'resilience':
        return <Activity className="w-4 h-4 text-rose-400" />;
      case 'infra':
        return <Layers className="w-4 h-4 text-indigo-400" />;
    }
  };

  const estimatedDurationSec = steps.filter((s) => s.enabled).length * 8;

  return (
    <div className="flex flex-col h-full bg-card/60 border border-border/80 rounded-2xl overflow-hidden shadow-sm">
      {/* Timeline Header */}
      <div className="p-4 border-b border-border/60 bg-accent/20 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <div className="p-1.5 rounded-lg bg-primary/20 text-primary">
            <Layers className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground">
              Sequential Execution Pipeline ({steps.filter((s) => s.enabled).length} Active Stages)
            </h3>
            <span className="text-[11px] text-muted-foreground">
              Stages execute in top-down sequential order; outputs cascade downstream.
            </span>
          </div>
        </div>

        <div className="flex items-center space-x-3 text-xs">
          <div className="flex items-center space-x-1.5 text-muted-foreground font-mono text-[11px]">
            <Clock className="w-3.5 h-3.5 text-blue-400" />
            <span>Est. Runtime: ~{estimatedDurationSec}s</span>
          </div>

          <button
            type="button"
            onClick={resetPlan}
            className="text-[11px] text-muted-foreground hover:text-foreground underline transition-colors"
          >
            Reset
          </button>
        </div>
      </div>

      {/* Step Sequence List */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3 max-h-[500px]">
        {steps.length === 0 ? (
          <div className="py-12 text-center space-y-2 border border-dashed border-border rounded-xl">
            <Layers className="w-8 h-8 text-muted-foreground mx-auto stroke-1" />
            <p className="text-xs text-muted-foreground">
              No engines in this test pipeline yet.
            </p>
            <p className="text-[11px] text-muted-foreground/80">
              Select a curated preset above or click <strong>+ Add Step</strong> from the Engine Catalog.
            </p>
          </div>
        ) : (
          steps.map((step: PlanStep, index: number) => {
            const isFirst = index === 0;
            const isLast = index === steps.length - 1;
            const isConfiguring = activeConfigStepId === step.id;
            const optionKeys = Object.keys(step.options || {});

            return (
              <React.Fragment key={step.id}>
                {/* Stage Step Card */}
                <div
                  className={`p-3.5 rounded-xl border transition-all duration-150 space-y-2.5 ${
                    !step.enabled
                      ? 'bg-muted/20 border-border/40 opacity-60'
                      : isConfiguring
                      ? 'bg-primary/10 border-primary shadow-sm ring-1 ring-primary/40'
                      : 'bg-card border-border/80 hover:border-border'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center space-x-3">
                      {/* Stage Index Badge */}
                      <span className="w-6 h-6 rounded-full bg-accent flex items-center justify-center font-mono text-xs font-bold text-foreground shrink-0 border border-border">
                        {index + 1}
                      </span>

                      <div className="space-y-0.5">
                        <div className="flex items-center space-x-2">
                          {getCategoryIcon(step.category)}
                          <h4 className="text-xs font-semibold text-foreground">
                            {step.name}
                          </h4>
                          {step.disruptive && (
                            <span className="flex items-center gap-0.5 text-[9px] font-mono px-1.5 py-0.5 rounded bg-rose-950/40 text-rose-400 border border-rose-800/40">
                              <AlertTriangle className="w-2.5 h-2.5" />
                              <span>Disruptive</span>
                            </span>
                          )}
                        </div>
                        <span className="font-mono text-[10px] text-muted-foreground block">
                          {step.engineId}
                        </span>
                      </div>
                    </div>

                    {/* Step Actions */}
                    <div className="flex items-center space-x-1 shrink-0">
                      {/* Configure Button */}
                      <button
                        type="button"
                        onClick={() =>
                          setActiveConfigStepId(isConfiguring ? null : step.id)
                        }
                        title="Configure Engine Parameters"
                        className={`p-1.5 rounded-lg text-xs transition-colors ${
                          isConfiguring
                            ? 'bg-primary text-white'
                            : 'text-muted-foreground hover:text-foreground hover:bg-accent'
                        }`}
                      >
                        <Sliders className="w-3.5 h-3.5" />
                      </button>

                      {/* Move Up */}
                      <button
                        type="button"
                        onClick={() => reorderStep(index, index - 1)}
                        disabled={isFirst}
                        title="Move Up in Execution Sequence"
                        className="p-1 rounded text-muted-foreground hover:text-foreground disabled:opacity-30 disabled:cursor-not-allowed hover:bg-accent"
                      >
                        <ChevronUp className="w-3.5 h-3.5" />
                      </button>

                      {/* Move Down */}
                      <button
                        type="button"
                        onClick={() => reorderStep(index, index + 1)}
                        disabled={isLast}
                        title="Move Down in Execution Sequence"
                        className="p-1 rounded text-muted-foreground hover:text-foreground disabled:opacity-30 disabled:cursor-not-allowed hover:bg-accent"
                      >
                        <ChevronDown className="w-3.5 h-3.5" />
                      </button>

                      {/* Remove Step */}
                      <button
                        type="button"
                        onClick={() => removeStep(step.id)}
                        title="Remove Step"
                        className="p-1 rounded text-rose-400 hover:text-rose-300 hover:bg-rose-950/30 transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>

                  {/* Config Snapshot */}
                  <div className="flex flex-wrap items-center justify-between gap-2 pt-1.5 border-t border-border/40 text-[11px]">
                    <div className="flex flex-wrap items-center gap-1.5 text-muted-foreground font-mono text-[10px]">
                      {optionKeys.slice(0, 3).map((k) => (
                        <span
                          key={k}
                          className="px-1.5 py-0.5 rounded bg-accent/60 border border-border/50 text-foreground"
                        >
                          {k}: {String(step.options[k])}
                        </span>
                      ))}
                      {optionKeys.length > 3 && (
                        <span className="text-muted-foreground">
                          +{optionKeys.length - 3} more
                        </span>
                      )}
                    </div>

                    <label className="flex items-center space-x-1.5 cursor-pointer text-[10px] font-mono text-muted-foreground">
                      <input
                        type="checkbox"
                        checked={step.enabled}
                        onChange={() => toggleStep(step.id)}
                        className="rounded border-border text-primary focus:ring-0"
                      />
                      <span>{step.enabled ? 'Active' : 'Skipped'}</span>
                    </label>
                  </div>
                </div>

                {/* Downward Connector Arrow */}
                {!isLast && (
                  <div className="flex items-center justify-center py-0.5">
                    <ArrowDown className="w-3.5 h-3.5 text-border animate-pulse" />
                  </div>
                )}
              </React.Fragment>
            );
          })
        )}
      </div>
    </div>
  );
};
