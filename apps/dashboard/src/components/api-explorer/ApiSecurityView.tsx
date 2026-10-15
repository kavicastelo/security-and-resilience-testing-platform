import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  FileCode2,
  FileCode,
  Flame,
  FileSearch,
  Target as TargetIcon,
  Sliders,
} from 'lucide-react';
import { targetsApi, Target } from '../../api/targets.js';
import { OpenApiCatalog } from './OpenApiCatalog.js';
import { GraphQLIntrospectionViewer } from './GraphQLIntrospectionViewer.js';
import { GraphQLDepthSimulator } from './GraphQLDepthSimulator.js';
import { FieldSuggestionCard } from './FieldSuggestionCard.js';
import { useAppStore } from '../../store/useAppStore.js';

export const ApiSecurityView: React.FC = () => {
  const { setActiveTab } = useAppStore();

  const [activeSubTab, setActiveSubTab] = useState<'openapi' | 'graphql' | 'depth' | 'suggestions'>('openapi');
  const [selectedTargetId, setSelectedTargetId] = useState<string>('');
  const [depthPreset, setDepthPreset] = useState<{ rootField: string; nestedField: string }>({
    rootField: 'user',
    nestedField: 'friends',
  });

  // Fetch targets
  const { data: targets = [] } = useQuery<Target[]>({
    queryKey: ['targets'],
    queryFn: () => targetsApi.listTargets(),
  });

  const activeTarget = targets.find((t) => t.id === selectedTargetId) || targets[0];
  const targetUrl = activeTarget?.baseUrl || 'http://localhost:4000';
  const targetName = activeTarget?.name || 'Local Environment';
  const isProduction =
    activeTarget?.name?.toLowerCase().includes('prod') ||
    activeTarget?.baseUrl?.toLowerCase().includes('prod') ||
    activeTarget?.verificationStatus === 'VERIFIED';

  const handleSelectQueryForDepth = (rootField: string, nestedField: string) => {
    setDepthPreset({ rootField, nestedField });
    setActiveSubTab('depth');
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Workbench Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-border/80 pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-cyan-500/15 border border-cyan-500/30 text-cyan-400">
              <FileCode2 className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold text-foreground">
                  API Security &amp; GraphQL Introspection Explorer
                </h1>
                <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 font-semibold">
                  Phase UI-06
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-0.5">
                Inspect OpenAPI specifications, map GraphQL schema types, audit circular query recursion, and test information disclosure leaks.
              </p>
            </div>
          </div>
        </div>

        {/* Target Selector Bar */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 p-1.5 rounded-xl bg-card border border-border">
            <TargetIcon className="w-4 h-4 text-cyan-400 ml-1" />
            <select
              value={activeTarget?.id || ''}
              onChange={(e) => setSelectedTargetId(e.target.value)}
              className="bg-transparent text-xs text-foreground font-medium focus:outline-none pr-3"
            >
              {targets.map((t) => (
                <option key={t.id} value={t.id} className="bg-background text-foreground">
                  {t.name} ({t.baseUrl})
                </option>
              ))}
              {targets.length === 0 && (
                <option value="" className="bg-background text-foreground">
                  Default Target (http://localhost:4000)
                </option>
              )}
            </select>
          </div>

          <button
            type="button"
            onClick={() => setActiveTab('runs')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-accent hover:bg-accent/80 text-foreground text-xs font-medium border border-border transition-colors shadow-sm"
          >
            <Sliders className="w-3.5 h-3.5 text-cyan-400" />
            <span>Open Test Plan Studio</span>
          </button>
        </div>
      </div>

      {/* Tab Switcher */}
      <div className="flex flex-wrap items-center gap-2 border-b border-border/70 pb-3">
        <button
          type="button"
          onClick={() => setActiveSubTab('openapi')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition-all ${
            activeSubTab === 'openapi'
              ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
              : 'text-muted-foreground hover:text-foreground hover:bg-accent/50 border border-transparent'
          }`}
        >
          <FileCode2 className="w-4 h-4 text-cyan-400" />
          <span>OpenAPI 3.0 Catalog &amp; Fuzzer</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveSubTab('graphql')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition-all ${
            activeSubTab === 'graphql'
              ? 'bg-purple-500/15 text-purple-300 border border-purple-500/30 shadow-sm'
              : 'text-muted-foreground hover:text-foreground hover:bg-accent/50 border border-transparent'
          }`}
        >
          <FileCode className="w-4 h-4 text-purple-400" />
          <span>GraphQL Introspection &amp; Schema</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveSubTab('depth')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition-all ${
            activeSubTab === 'depth'
              ? 'bg-rose-500/15 text-rose-300 border border-rose-500/30 shadow-sm'
              : 'text-muted-foreground hover:text-foreground hover:bg-accent/50 border border-transparent'
          }`}
        >
          <Flame className="w-4 h-4 text-rose-400" />
          <span>Circular Query Depth Simulator</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveSubTab('suggestions')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition-all ${
            activeSubTab === 'suggestions'
              ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30 shadow-sm'
              : 'text-muted-foreground hover:text-foreground hover:bg-accent/50 border border-transparent'
          }`}
        >
          <FileSearch className="w-4 h-4 text-amber-400" />
          <span>Field Suggestion Leak Auditor</span>
        </button>
      </div>

      {/* Active Tab View Rendering */}
      <div>
        {activeSubTab === 'openapi' && (
          <OpenApiCatalog targetId={activeTarget?.id} targetUrl={targetUrl} targetName={targetName} />
        )}

        {activeSubTab === 'graphql' && (
          <GraphQLIntrospectionViewer
            targetId={activeTarget?.id}
            targetUrl={targetUrl}
            targetName={targetName}
            onSelectQueryForDepth={handleSelectQueryForDepth}
          />
        )}

        {activeSubTab === 'depth' && (
          <GraphQLDepthSimulator
            targetUrl={targetUrl}
            targetName={targetName}
            isProduction={Boolean(isProduction)}
            initialRootField={depthPreset.rootField}
            initialNestedField={depthPreset.nestedField}
          />
        )}

        {activeSubTab === 'suggestions' && <FieldSuggestionCard targetUrl={targetUrl} />}
      </div>
    </div>
  );
};
