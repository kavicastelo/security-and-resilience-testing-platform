import React, { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import {
  X,
  AlertOctagon,
  Copy,
  Check,
  Globe,
  Radio,
  Clock,
} from 'lucide-react';
import { useRunEventStream } from '../../hooks/useRunEventStream.js';
import { StreamingTerminal } from './StreamingTerminal.js';
import { StageWaterfall } from './StageWaterfall.js';
import { LiveMetricsRow } from './LiveMetricsRow.js';
import { useAppStore } from '../../store/useAppStore.js';
import { authFetch } from '../../api/client.js';

interface LiveRunDrawerProps {
  runId: string | null;
  targetUrl?: string;
  targetName?: string;
  isOpen: boolean;
  onClose: () => void;
}

export const LiveRunDrawer: React.FC<LiveRunDrawerProps> = ({
  runId,
  targetUrl,
  targetName,
  isOpen,
  onClose,
}) => {
  const queryClient = useQueryClient();
  const { showToast } = useAppStore();
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000';

  const [selectedEngineFilter, setSelectedEngineFilter] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Hook connecting to SSE stream
  const {
    runStatus,
    progress,
    activeEngine,
    logs,
    metrics,
    engineStates,
    isPaused,
    togglePause,
    clearLogs,
  } = useRunEventStream({
    runId,
    enabled: isOpen && Boolean(runId),
  });

  // Cancel Run Mutation
  const cancelMutation = useMutation({
    mutationFn: async () => {
      if (!runId) return;
      const res = await authFetch(`${apiUrl}/api/v1/test-runs/${runId}/cancel`, {
        method: 'POST',
      });
      const json = await res.json();
      if (!res.ok) {
        throw new Error(json.error?.message || 'Failed to cancel test run');
      }
      return json.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['test-runs'] });
      showToast('Emergency Stop Triggered: Test run execution aborted', 'info');
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      showToast(msg, 'error');
    },
  });

  if (!isOpen || !runId) return null;

  const copyRunId = () => {
    navigator.clipboard.writeText(runId);
    setCopied(true);
    showToast('Copied Run ID to clipboard', 'info');
    setTimeout(() => setCopied(false), 2000);
  };

  const isRunning = runStatus === 'running' || runStatus === 'queued';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-2 sm:p-4 bg-background/85 backdrop-blur-md animate-fade-in">
      <div className="relative w-full max-w-7xl bg-card border border-border/80 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[95vh]">
        {/* Header Bar */}
        <div className="p-4 sm:p-5 border-b border-border/60 bg-gradient-to-r from-card via-accent/20 to-card flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-primary/20 border border-primary/30 text-primary">
              <Radio className="w-5 h-5 animate-pulse" />
            </div>

            <div className="space-y-0.5">
              <div className="flex items-center space-x-2">
                <h2 className="text-sm font-bold text-foreground">
                  Live Execution Telemetry & Runner
                </h2>
                <span
                  className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded-full border flex items-center gap-1 font-bold ${
                    runStatus === 'completed'
                      ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60'
                      : runStatus === 'failed'
                      ? 'bg-rose-950/60 text-rose-400 border-rose-800/60'
                      : runStatus === 'cancelled'
                      ? 'bg-amber-950/60 text-amber-400 border-amber-800/60'
                      : 'bg-blue-950/60 text-blue-400 border-blue-800/60 animate-pulse'
                  }`}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-current" />
                  <span>{runStatus}</span>
                </span>
              </div>

              <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground font-mono">
                {targetName && <span className="text-foreground font-semibold">{targetName}</span>}
                {targetUrl && (
                  <span className="flex items-center gap-1 text-primary">
                    <Globe className="w-3 h-3" />
                    <span>{targetUrl}</span>
                  </span>
                )}
                <span>•</span>
                <button
                  type="button"
                  onClick={copyRunId}
                  className="hover:text-foreground flex items-center gap-1"
                >
                  <span>ID: {runId.slice(0, 8)}...</span>
                  {copied ? <Check className="w-2.5 h-2.5 text-emerald-400" /> : <Copy className="w-2.5 h-2.5" />}
                </button>
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center space-x-2.5 self-end sm:self-auto">
            {isRunning && (
              <button
                type="button"
                onClick={() => {
                  if (window.confirm('Are you sure you want to abort this in-flight test run? Active engine workers will be terminated immediately.')) {
                    cancelMutation.mutate();
                  }
                }}
                disabled={cancelMutation.isPending}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white text-xs font-semibold shadow-md transition-colors"
              >
                <AlertOctagon className="w-3.5 h-3.5" />
                <span>{cancelMutation.isPending ? 'Aborting...' : 'Emergency Stop'}</span>
              </button>
            )}

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent/60 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Top Metric Strip */}
        <div className="p-4 border-b border-border/40 bg-accent/10">
          <LiveMetricsRow
            progress={progress}
            runStatus={runStatus}
            activeEngine={activeEngine}
            metrics={metrics}
          />
        </div>

        {/* 2-Column Telemetry Split: Waterfall | Terminal */}
        <div className="p-4 overflow-y-auto flex-1 grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
          {/* Left 4 Cols: Stage Waterfall */}
          <div className="lg:col-span-4 h-full">
            <StageWaterfall
              engineStates={engineStates}
              activeEngine={activeEngine}
              selectedEngineFilter={selectedEngineFilter}
              onSelectEngineFilter={setSelectedEngineFilter}
            />
          </div>

          {/* Right 8 Cols: Streaming Terminal Console */}
          <div className="lg:col-span-8 h-full">
            <StreamingTerminal
              logs={logs}
              isPaused={isPaused}
              onTogglePause={togglePause}
              onClear={clearLogs}
              selectedEngineFilter={selectedEngineFilter}
            />
          </div>
        </div>

        {/* Footer Bar */}
        <div className="p-3 border-t border-border/60 bg-accent/20 flex items-center justify-between text-xs">
          <div className="flex items-center space-x-2 text-[11px] text-muted-foreground font-mono">
            <Clock className="w-3.5 h-3.5 text-blue-400" />
            <span>EventSource Protocol: SSE v1.0 • TLS Pinning Active</span>
          </div>

          <div className="flex items-center space-x-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-1.5 rounded-lg bg-accent text-foreground hover:bg-accent/80 text-xs transition-colors"
            >
              Close Console
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
