import React, { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import {
  X,
  Play,
  Layers,
  FileCode,
  Download,
  Copy,
  Check,
  RotateCw,
  Terminal,
} from 'lucide-react';
import { usePlanStudioStore } from '../../store/usePlanStudioStore.js';
import { Target } from '../../api/targets.js';
import { PresetSelector } from './PresetSelector.js';
import { EnginePalette } from './EnginePalette.js';
import { PipelineSequenceTimeline } from './PipelineSequenceTimeline.js';
import { PreflightValidatorCard } from './PreflightValidatorCard.js';
import { EngineConfigDrawer } from './EngineConfigDrawer.js';
import { useAppStore } from '../../store/useAppStore.js';
import { authFetch } from '../../api/client.js';

interface PlanStudioModalProps {
  targets: Target[];
  isOpen: boolean;
  onClose: () => void;
  onRunLaunched?: (runId: string) => void;
}

export const PlanStudioModal: React.FC<PlanStudioModalProps> = ({
  targets,
  isOpen,
  onClose,
  onRunLaunched,
}) => {
  const queryClient = useQueryClient();
  const { showToast } = useAppStore();
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000';

  const {
    planName,
    setPlanName,
    planDescription,
    selectedTargetId,
    setSelectedTargetId,
    targetEndpoint,
    setTargetEndpoint,
    steps,
    hazardAcknowledged,
    viewMode,
    setViewMode,
    exportToYaml,
  } = usePlanStudioStore();

  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Sync default target if none selected
  React.useEffect(() => {
    if (!selectedTargetId && targets.length > 0) {
      setSelectedTargetId(targets[0].id);
    }
  }, [selectedTargetId, targets, setSelectedTargetId]);

  if (!isOpen) return null;

  const activeTarget = targets.find((t) => t.id === selectedTargetId) || null;
  const activeSteps = steps.filter((s) => s.enabled);
  const disruptiveSteps = activeSteps.filter((s) => s.disruptive);
  const hasDisruptive = disruptiveSteps.length > 0;

  const copyToClipboard = (text: string, key: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    showToast(`Copied ${label} to clipboard`, 'info');
    setTimeout(() => {
      setCopiedKey((curr) => (curr === key ? null : curr));
    }, 2000);
  };

  const handleDownloadYaml = () => {
    const yaml = exportToYaml();
    const blob = new Blob([yaml], { type: 'text/yaml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-lab-plan-${Date.now()}.yaml`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('Downloaded plan YAML file', 'success');
  };

  // Execution Mutation
  const executePlanMutation = useMutation({
    mutationFn: async () => {
      if (!selectedTargetId) throw new Error('Please select a target');
      if (activeSteps.length === 0) throw new Error('Add at least one active engine to the pipeline');
      if (hasDisruptive && !hazardAcknowledged) {
        throw new Error('Please acknowledge the disruptive test hazard before executing this plan.');
      }

      const yamlContent = exportToYaml();
      const engineIds = activeSteps.map((s) => s.engineId);

      // Step 1: Create TestRun
      const createRes = await authFetch(`${apiUrl}/api/v1/test-runs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId: activeTarget?.projectId || selectedTargetId,
          targetId: selectedTargetId,
          profileId: 'plan-studio-custom',
          metadata: {
            planName,
            planDescription,
            endpoint: targetEndpoint.trim() || undefined,
            definitionYaml: yamlContent,
          },
        }),
      });

      const createJson = await createRes.json();
      if (!createJson.success) {
        throw new Error(createJson.error?.message || 'Failed to create TestRun');
      }

      const runId = createJson.data.id;

      // Step 2: Trigger Execution
      const execRes = await authFetch(`${apiUrl}/api/v1/test-runs/${runId}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          engineIds,
          definitionYaml: yamlContent,
          options: {
            endpoint: targetEndpoint.trim() || undefined,
          },
        }),
      });

      const execJson = await execRes.json();
      if (!execJson.success && execRes.status !== 202) {
        throw new Error(execJson.error?.message || 'Execution failed to start');
      }

      return runId;
    },
    onSuccess: (runId) => {
      queryClient.invalidateQueries({ queryKey: ['test-runs'] });
      showToast(`Test Run "${planName}" dispatched successfully!`, 'success');
      onClose();
      if (onRunLaunched) onRunLaunched(runId);
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      showToast(msg, 'error');
    },
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-2 sm:p-4 bg-background/80 backdrop-blur-md animate-fade-in">
      <div className="relative w-full max-w-7xl bg-card border border-border/80 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[95vh]">
        {/* Modal Header */}
        <div className="p-5 border-b border-border/60 bg-gradient-to-r from-card via-accent/20 to-card flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-primary/20 border border-primary/30 text-primary">
              <Layers className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-foreground flex items-center gap-2">
                <span>Test Plan Studio & Scenario Composer</span>
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-primary/20 text-primary border border-primary/30">
                  DSL V2
                </span>
              </h2>
              <p className="text-xs text-muted-foreground">
                Compose, customize, validate, and sequence multi-engine security & resilience pipelines.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 self-end sm:self-auto">
            {/* View Mode Toggle */}
            <div className="flex bg-accent/60 p-0.5 rounded-lg border border-border text-xs">
              <button
                type="button"
                onClick={() => setViewMode('visual')}
                className={`flex items-center space-x-1.5 px-3 py-1 rounded-md transition-colors ${
                  viewMode === 'visual'
                    ? 'bg-primary text-white font-medium shadow-sm'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                <Layers className="w-3.5 h-3.5" />
                <span>Visual Composer</span>
              </button>
              <button
                type="button"
                onClick={() => setViewMode('yaml')}
                className={`flex items-center space-x-1.5 px-3 py-1 rounded-md transition-colors ${
                  viewMode === 'yaml'
                    ? 'bg-primary text-white font-medium shadow-sm'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                <FileCode className="w-3.5 h-3.5" />
                <span>YAML / DSL V2</span>
              </button>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent/60 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Plan Configuration Subheader */}
        <div className="p-4 border-b border-border/60 bg-accent/10 grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
          <div className="md:col-span-2 space-y-1">
            <label className="block text-[11px] text-muted-foreground font-mono uppercase">
              Pipeline Plan Name
            </label>
            <input
              type="text"
              value={planName}
              onChange={(e) => setPlanName(e.target.value)}
              placeholder="e.g. Production Readiness & Chaos Assessment"
              className="w-full px-3 py-1.5 rounded-lg bg-accent/60 border border-border text-foreground font-semibold focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>

          <div className="space-y-1">
            <label className="block text-[11px] text-muted-foreground font-mono uppercase">
              Target Scope
            </label>
            <select
              value={selectedTargetId}
              onChange={(e) => setSelectedTargetId(e.target.value)}
              className="w-full px-3 py-1.5 rounded-lg bg-accent/60 border border-border text-foreground cursor-pointer focus:outline-none focus:ring-1 focus:ring-primary"
            >
              <option value="">Select target...</option>
              {targets.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name} ({t.baseUrl})
                </option>
              ))}
            </select>
          </div>

          <div className="space-y-1">
            <label className="block text-[11px] text-muted-foreground font-mono uppercase">
              Target Endpoint / Base Path
            </label>
            <input
              type="text"
              value={targetEndpoint}
              onChange={(e) => setTargetEndpoint(e.target.value)}
              placeholder="/ (root endpoint)"
              className="w-full px-3 py-1.5 rounded-lg bg-accent/60 border border-border text-foreground font-mono focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
        </div>

        {/* Modal Main Content */}
        <div className="p-5 overflow-y-auto flex-1 space-y-6">
          {viewMode === 'visual' ? (
            <div className="space-y-6">
              {/* Presets Row */}
              <PresetSelector />

              {/* 3-Column Studio Grid: Palette | Timeline | Preflight */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
                {/* Left 4 Cols: Engine Palette */}
                <div className="lg:col-span-4">
                  <EnginePalette />
                </div>

                {/* Center 5 Cols: Sequence Timeline */}
                <div className="lg:col-span-5">
                  <PipelineSequenceTimeline />
                </div>

                {/* Right 3 Cols: Pre-flight Safety Validation */}
                <div className="lg:col-span-3">
                  <PreflightValidatorCard selectedTarget={activeTarget} />
                </div>
              </div>
            </div>
          ) : (
            /* YAML View */
            <div className="space-y-4 animate-fade-in">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-muted-foreground">
                  Generated TestPlan DSL V2 Specification
                </span>
                <div className="flex items-center space-x-2">
                  <button
                    type="button"
                    onClick={() => copyToClipboard(exportToYaml(), 'yaml', 'Plan YAML')}
                    className="flex items-center space-x-1.5 px-3 py-1 rounded-lg bg-accent text-xs text-foreground hover:bg-accent/80 transition-colors"
                  >
                    {copiedKey === 'yaml' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey === 'yaml' ? 'Copied' : 'Copy YAML'}</span>
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      copyToClipboard(
                        `security-lab run --plan plan.yaml --target ${selectedTargetId || 'TARGET_ID'}`,
                        'cli',
                        'CLI Command',
                      )
                    }
                    className="flex items-center space-x-1.5 px-3 py-1 rounded-lg bg-accent text-xs text-primary hover:bg-accent/80 transition-colors font-mono"
                  >
                    <Terminal className="w-3.5 h-3.5" />
                    <span>Copy CLI Command</span>
                  </button>
                </div>
              </div>

              <pre className="p-4 rounded-xl bg-black/60 border border-border font-mono text-xs text-emerald-300 overflow-x-auto leading-relaxed max-h-[550px]">
                {exportToYaml()}
              </pre>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-border/60 bg-accent/20 flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-center space-x-2">
            <button
              type="button"
              onClick={handleDownloadYaml}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg border border-border text-foreground hover:bg-accent transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download YAML</span>
            </button>
          </div>

          <div className="flex items-center space-x-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
            >
              Cancel
            </button>

            <button
              type="button"
              onClick={() => executePlanMutation.mutate()}
              disabled={executePlanMutation.isPending || activeSteps.length === 0 || !selectedTargetId}
              className="flex items-center space-x-2 px-5 py-2 rounded-xl bg-primary hover:bg-primary/90 disabled:opacity-50 text-white font-semibold shadow-md transition-all hover:glow-blue"
            >
              {executePlanMutation.isPending ? (
                <>
                  <RotateCw className="w-4 h-4 animate-spin" />
                  <span>Dispatching Pipeline...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  <span>Execute Test Plan ({activeSteps.length} Stages)</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Engine Parameter Configuration Drawer */}
        <EngineConfigDrawer />
      </div>
    </div>
  );
};
