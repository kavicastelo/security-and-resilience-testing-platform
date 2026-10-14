import React from 'react';
import {
  ShieldCheck,
  Zap,
  Activity,
  Layers,
  Sparkles,
  AlertTriangle,
} from 'lucide-react';
import {
  CURATED_PRESETS,
  usePlanStudioStore,
  EngineCategory,
} from '../../store/usePlanStudioStore.js';

export const PresetSelector: React.FC = () => {
  const { activePresetId, applyPreset } = usePlanStudioStore();

  const getCategoryIcon = (category: EngineCategory) => {
    switch (category) {
      case 'web':
        return <ShieldCheck className="w-4 h-4 text-emerald-400" />;
      case 'api':
        return <Zap className="w-4 h-4 text-primary" />;
      case 'resilience':
        return <Activity className="w-4 h-4 text-rose-400" />;
      case 'infra':
        return <Layers className="w-4 h-4 text-indigo-400" />;
      default:
        return <Sparkles className="w-4 h-4 text-amber-400" />;
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs uppercase font-mono tracking-wider text-muted-foreground flex items-center gap-1.5">
          <Sparkles className="w-3.5 h-3.5 text-primary" />
          <span>Curated Pipeline Presets</span>
        </span>
        <span className="text-[11px] text-muted-foreground">
          Click any preset to load a pre-configured multi-engine scenario
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5">
        {CURATED_PRESETS.map((preset) => {
          const isSelected = activePresetId === preset.id;

          return (
            <button
              key={preset.id}
              type="button"
              onClick={() => applyPreset(preset.id)}
              className={`p-3 rounded-xl border text-left flex flex-col justify-between transition-all duration-150 ${
                isSelected
                  ? 'bg-primary/10 border-primary shadow-sm ring-1 ring-primary/40'
                  : 'bg-card/70 border-border/80 hover:border-primary/40 hover:bg-accent/40'
              }`}
            >
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <div className="p-1 rounded-lg bg-accent/60">
                    {getCategoryIcon(preset.category)}
                  </div>
                  {preset.disruptive && (
                    <span
                      title="Disruptive: Contains fuzzing, load or chaos tests"
                      className="flex items-center gap-0.5 text-[9px] font-mono px-1.5 py-0.5 rounded bg-rose-950/40 text-rose-400 border border-rose-800/40 font-semibold"
                    >
                      <AlertTriangle className="w-2.5 h-2.5" />
                      <span>HAZARD</span>
                    </span>
                  )}
                </div>
                <h4 className="text-xs font-semibold text-foreground leading-tight">
                  {preset.name}
                </h4>
                <p className="text-[11px] text-muted-foreground line-clamp-2 leading-relaxed">
                  {preset.description}
                </p>
              </div>

              <div className="pt-2 mt-2 border-t border-border/40 flex items-center justify-between text-[10px] font-mono text-muted-foreground">
                <span className="capitalize">{preset.category}</span>
                <span>{preset.engineIds.length} Engines</span>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
};
