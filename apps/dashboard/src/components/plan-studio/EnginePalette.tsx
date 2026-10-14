import React, { useState } from 'react';
import {
  Search,
  Plus,
  ShieldCheck,
  Zap,
  Activity,
  Layers,
  AlertTriangle,
  Lock,
  Filter,
  Check,
} from 'lucide-react';
import {
  REGISTERED_ENGINES,
  usePlanStudioStore,
  EngineCategory,
} from '../../store/usePlanStudioStore.js';

export const EnginePalette: React.FC = () => {
  const { steps, addStep } = usePlanStudioStore();
  const [search, setSearch] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');

  const filteredEngines = REGISTERED_ENGINES.filter((engine) => {
    if (selectedCategory !== 'all' && engine.category !== selectedCategory) {
      return false;
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      const matchName = engine.name.toLowerCase().includes(q);
      const matchDesc = engine.description.toLowerCase().includes(q);
      const matchId = engine.id.toLowerCase().includes(q);
      if (!matchName && !matchDesc && !matchId) return false;
    }
    return true;
  });

  const getCategoryIcon = (category: EngineCategory) => {
    switch (category) {
      case 'web':
        return <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />;
      case 'api':
        return <Zap className="w-3.5 h-3.5 text-primary" />;
      case 'auth':
        return <Lock className="w-3.5 h-3.5 text-amber-400" />;
      case 'resilience':
        return <Activity className="w-3.5 h-3.5 text-rose-400" />;
      case 'infra':
        return <Layers className="w-3.5 h-3.5 text-indigo-400" />;
    }
  };

  return (
    <div className="flex flex-col h-full bg-card/60 border border-border/80 rounded-2xl overflow-hidden shadow-sm">
      {/* Palette Header */}
      <div className="p-4 border-b border-border/60 bg-accent/20 space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground flex items-center gap-1.5">
            <Filter className="w-3.5 h-3.5 text-primary" />
            <span>Engine Catalog ({REGISTERED_ENGINES.length})</span>
          </h3>
          <span className="text-[10px] font-mono text-muted-foreground">
            Click to append step
          </span>
        </div>

        {/* Search */}
        <div className="relative">
          <Search className="w-3.5 h-3.5 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search engines (e.g. BOLA, k6, SQLi)..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-accent border border-border text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>

        {/* Category Pills */}
        <div className="flex flex-wrap gap-1 text-[11px]">
          {['all', 'web', 'api', 'auth', 'resilience', 'infra'].map((cat) => (
            <button
              key={cat}
              type="button"
              onClick={() => setSelectedCategory(cat)}
              className={`px-2 py-0.5 rounded-md font-mono capitalize transition-colors ${
                selectedCategory === cat
                  ? 'bg-primary text-white font-medium'
                  : 'bg-accent/60 text-muted-foreground hover:text-foreground'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Engine List */}
      <div className="flex-1 overflow-y-auto p-3 space-y-2 max-h-[500px]">
        {filteredEngines.map((engine) => {
          const inPipeline = steps.some((s) => s.engineId === engine.id);

          return (
            <div
              key={engine.id}
              className={`p-3 rounded-xl border text-left flex flex-col justify-between transition-all duration-150 space-y-2 ${
                inPipeline
                  ? 'bg-primary/5 border-primary/40'
                  : 'bg-card border-border/70 hover:border-border hover:bg-accent/30'
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="space-y-0.5">
                  <div className="flex items-center space-x-1.5">
                    {getCategoryIcon(engine.category)}
                    <h4 className="text-xs font-semibold text-foreground">
                      {engine.name}
                    </h4>
                  </div>
                  <span className="font-mono text-[10px] text-muted-foreground block">
                    {engine.id}
                  </span>
                </div>

                <div className="flex items-center space-x-1">
                  {engine.disruptive && (
                    <span
                      title="Disruptive Engine: active fuzzing or capacity stress"
                      className="p-1 rounded bg-rose-950/40 text-rose-400 border border-rose-800/40"
                    >
                      <AlertTriangle className="w-3 h-3" />
                    </span>
                  )}
                  <span
                    className={`text-[9px] font-mono uppercase px-1.5 py-0.5 rounded border font-semibold ${
                      engine.complexity === 'high'
                        ? 'bg-purple-950/40 text-purple-300 border-purple-800/40'
                        : engine.complexity === 'medium'
                        ? 'bg-blue-950/40 text-blue-300 border-blue-800/40'
                        : 'bg-emerald-950/40 text-emerald-300 border-emerald-800/40'
                    }`}
                  >
                    {engine.complexity}
                  </span>
                </div>
              </div>

              <p className="text-[11px] text-muted-foreground leading-relaxed line-clamp-2">
                {engine.description}
              </p>

              <div className="flex items-center justify-between pt-1 border-t border-border/40">
                <span className="text-[10px] font-mono text-muted-foreground capitalize">
                  {engine.category}
                </span>

                <button
                  type="button"
                  onClick={() => addStep(engine.id)}
                  className={`flex items-center space-x-1 px-2.5 py-1 rounded-lg text-xs font-medium transition-colors ${
                    inPipeline
                      ? 'bg-accent text-primary hover:bg-accent/80'
                      : 'bg-primary hover:bg-primary/90 text-white'
                  }`}
                >
                  {inPipeline ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span>Added (+1)</span>
                    </>
                  ) : (
                    <>
                      <Plus className="w-3 h-3" />
                      <span>Add Step</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
