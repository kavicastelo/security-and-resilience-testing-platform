import React, { useEffect, useState, useRef } from 'react';
import {
  Terminal,
  Activity,
  CheckCircle2,
  XCircle,
  Clock,
  Loader2,
  Copy,
  Pause,
  Play,
  Trash2,
  Wifi,
  WifiOff,
} from 'lucide-react';
import { useAppStore } from '../store/useAppStore.js';

export interface LiveLogEntry {
  id: string;
  timestamp: string;
  engineId?: string;
  message: string;
  type: 'info' | 'progress' | 'error' | 'success';
}

export interface EngineExecutionState {
  status: 'running' | 'completed' | 'failed' | 'cancelled';
  durationMs?: number;
  findingsCount?: number;
  error?: string;
}

export interface LiveRunMonitorProps {
  runId: string;
  onComplete?: () => void;
  initialStatus?: string;
  targetUrl?: string;
  className?: string;
}

export const LiveRunMonitor: React.FC<LiveRunMonitorProps> = ({
  runId,
  onComplete,
  initialStatus = 'running',
  targetUrl,
  className = '',
}) => {
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000';
  const { showToast } = useAppStore();

  const [connectionStatus, setConnectionStatus] = useState<
    'connecting' | 'connected' | 'completed' | 'error' | 'closed'
  >('connecting');
  const [progress, setProgress] = useState<number>(initialStatus === 'completed' ? 100 : 5);
  const [activeEngine, setActiveEngine] = useState<string | null>(null);
  const [engineStates, setEngineStates] = useState<Record<string, EngineExecutionState>>({});
  const [logs, setLogs] = useState<LiveLogEntry[]>([]);
  const [isAutoScroll, setIsAutoScroll] = useState<boolean>(true);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll terminal logs
  useEffect(() => {
    if (isAutoScroll && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, isAutoScroll]);

  // Connect to SSE stream
  useEffect(() => {
    if (!runId) return;

    let isSubscribed = true;
    const streamUrl = `${apiUrl}/api/v1/test-runs/${runId}/stream`;
    const eventSource = new EventSource(streamUrl);

    setConnectionStatus('connecting');

    const addLog = (entry: Omit<LiveLogEntry, 'id'>) => {
      if (!isSubscribed) return;
      setLogs((prev) => [
        ...prev.slice(-300), // maintain maximum 300 log entries
        {
          id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
          ...entry,
        },
      ]);
    };

    eventSource.onopen = () => {
      if (!isSubscribed) return;
      setConnectionStatus('connected');
      addLog({
        timestamp: new Date().toLocaleTimeString(),
        message: `Connected to real-time telemetry stream for test run ${runId.slice(0, 8)}...`,
        type: 'info',
      });
    };

    eventSource.onerror = () => {
      if (!isSubscribed) return;
      // If already completed or closed, don't trigger error state
      if (eventSource.readyState === EventSource.CLOSED) {
        setConnectionStatus('completed');
      } else {
        setConnectionStatus('error');
        addLog({
          timestamp: new Date().toLocaleTimeString(),
          message: 'Connection dropped. Attempting automated reconnection...',
          type: 'error',
        });
      }
    };

    // Event: init
    eventSource.addEventListener('init', (e) => {
      if (!isSubscribed) return;
      try {
        const data = JSON.parse(e.data);
        if (data.status === 'completed' || data.status === 'failed' || data.status === 'cancelled') {
          setProgress(100);
          setConnectionStatus('completed');
        }
        addLog({
          timestamp: new Date().toLocaleTimeString(),
          message: `Stream initialized (Status: ${data.status.toUpperCase()})`,
          type: 'info',
        });
      } catch (parseErr) {
        console.error('Failed to parse init event', parseErr);
      }
    });

    // Event: engine
    eventSource.addEventListener('engine', (e) => {
      if (!isSubscribed) return;
      try {
        const data = JSON.parse(e.data);
        const { engineId, status, durationMs, findingsCount, error } = data;

        setEngineStates((prev) => ({
          ...prev,
          [engineId]: { status, durationMs, findingsCount, error },
        }));

        if (status === 'running') {
          setActiveEngine(engineId);
          setProgress((prev) => Math.min(Math.max(prev, 25), 85));
          addLog({
            timestamp: new Date().toLocaleTimeString(),
            engineId,
            message: `Engine [${engineId}] dispatched and running...`,
            type: 'info',
          });
        } else if (status === 'completed') {
          addLog({
            timestamp: new Date().toLocaleTimeString(),
            engineId,
            message: `Engine [${engineId}] completed in ${durationMs ?? 0}ms (${findingsCount ?? 0} findings detected)`,
            type: 'success',
          });
        } else if (status === 'failed') {
          addLog({
            timestamp: new Date().toLocaleTimeString(),
            engineId,
            message: `Engine [${engineId}] failed: ${error || 'Unknown error'}`,
            type: 'error',
          });
        }
      } catch (parseErr) {
        console.error('Failed to parse engine event', parseErr);
      }
    });

    // Event: progress
    eventSource.addEventListener('progress', (e) => {
      if (!isSubscribed) return;
      try {
        const data = JSON.parse(e.data);
        const { engineId, percent, message } = data;
        if (typeof percent === 'number') {
          setProgress((prev) => Math.max(prev, Math.min(percent, 98)));
        }
        addLog({
          timestamp: new Date().toLocaleTimeString(),
          engineId,
          message: `[${percent}%] ${message}`,
          type: 'progress',
        });
      } catch (parseErr) {
        console.error('Failed to parse progress event', parseErr);
      }
    });

    // Event: run
    eventSource.addEventListener('run', (e) => {
      if (!isSubscribed) return;
      try {
        const data = JSON.parse(e.data);
        if (data.status === 'running') {
          setProgress((prev) => Math.max(prev, 15));
        } else if (['completed', 'failed', 'cancelled'].includes(data.status)) {
          setProgress(100);
          setConnectionStatus('completed');
        }
      } catch (parseErr) {
        console.error('Failed to parse run event', parseErr);
      }
    });

    // Event: run_completed
    eventSource.addEventListener('run_completed', (e) => {
      if (!isSubscribed) return;
      try {
        const data = JSON.parse(e.data);
        setProgress(100);
        setActiveEngine(null);
        setConnectionStatus('completed');
        addLog({
          timestamp: new Date().toLocaleTimeString(),
          message: `Test run finished with final status: ${data.status?.toUpperCase() || 'COMPLETED'}`,
          type: data.status === 'failed' ? 'error' : 'success',
        });

        eventSource.close();
        if (onComplete) onComplete();
      } catch (parseErr) {
        console.error('Failed to parse run_completed event', parseErr);
      }
    });

    // Clean up EventSource connection on unmount
    return () => {
      isSubscribed = false;
      eventSource.close();
      setConnectionStatus('closed');
    };
  }, [runId, apiUrl, onComplete]);

  const copyLogs = () => {
    const text = logs
      .map((l) => `[${l.timestamp}] ${l.engineId ? `[${l.engineId}] ` : ''}${l.message}`)
      .join('\n');
    navigator.clipboard.writeText(text);
    showToast('Terminal logs copied to clipboard', 'info');
  };

  const clearLogs = () => {
    setLogs([]);
  };

  const engineList = Object.entries(engineStates);

  return (
    <div className={`p-4 rounded-xl bg-card border border-border shadow-md space-y-4 ${className}`}>
      {/* Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/70 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="relative">
            <Activity className="w-5 h-5 text-blue-400 animate-pulse" />
            {connectionStatus === 'connected' && (
              <span className="absolute -top-1 -right-1 flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
              </span>
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-foreground">
                Real-Time Execution Telemetry Stream
              </span>
              <span className="font-mono text-xs px-2 py-0.5 rounded bg-accent text-blue-400">
                {runId.slice(0, 8)}
              </span>
            </div>
            {targetUrl && (
              <span className="text-xs text-muted-foreground font-mono truncate max-w-sm block">
                Target: {targetUrl}
              </span>
            )}
          </div>
        </div>

        {/* Connection status indicator badge */}
        <div className="flex items-center gap-2">
          {connectionStatus === 'connected' ? (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
              <Wifi className="w-3 h-3" /> Live SSE Active
            </span>
          ) : connectionStatus === 'connecting' ? (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-500/15 text-amber-400 border border-amber-500/30">
              <Loader2 className="w-3 h-3 animate-spin" /> Connecting Stream...
            </span>
          ) : connectionStatus === 'completed' ? (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-500/15 text-blue-400 border border-blue-500/30">
              <CheckCircle2 className="w-3 h-3" /> Execution Concluded
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-zinc-500/15 text-zinc-400 border border-zinc-500/30">
              <WifiOff className="w-3 h-3" /> Stream Disconnected
            </span>
          )}
        </div>
      </div>

      {/* Progress Bar & Percentage */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between text-xs font-mono">
          <span className="text-muted-foreground flex items-center gap-1.5">
            {progress < 100 ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin text-blue-400" />
                <span>
                  {activeEngine ? `Executing [${activeEngine}]...` : 'Orchestrating test engines...'}
                </span>
              </>
            ) : (
              <>
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>All verification engines completed</span>
              </>
            )}
          </span>
          <span className="font-bold text-foreground">{progress}%</span>
        </div>

        <div className="w-full h-2.5 rounded-full bg-secondary/80 overflow-hidden relative border border-border/40">
          <div
            className="h-full rounded-full transition-all duration-500 ease-out bg-gradient-to-r from-blue-500 via-indigo-500 to-emerald-400"
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      {/* Active Engine Badges */}
      {engineList.length > 0 && (
        <div className="space-y-1.5">
          <span className="text-[11px] text-muted-foreground uppercase font-sans tracking-wide block">
            Engine Dispatches:
          </span>
          <div className="flex flex-wrap gap-2">
            {engineList.map(([engineId, st]) => {
              const isRunning = st.status === 'running';
              const isCompleted = st.status === 'completed';
              const isFailed = st.status === 'failed';

              return (
                <div
                  key={engineId}
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono border transition-all ${
                    isRunning
                      ? 'bg-blue-500/15 border-blue-500/40 text-blue-300 shadow-sm animate-pulse'
                      : isCompleted
                        ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                        : isFailed
                          ? 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                          : 'bg-zinc-800/40 border-border text-muted-foreground'
                  }`}
                >
                  {isRunning ? (
                    <Loader2 className="w-3 h-3 animate-spin text-blue-400" />
                  ) : isCompleted ? (
                    <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                  ) : isFailed ? (
                    <XCircle className="w-3 h-3 text-rose-400" />
                  ) : (
                    <Clock className="w-3 h-3 text-muted-foreground" />
                  )}
                  <span>{engineId}</span>
                  {st.durationMs !== undefined && (
                    <span className="text-[10px] opacity-75">({st.durationMs}ms)</span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Streaming Terminal Log Box */}
      <div className="rounded-xl border border-border/80 bg-zinc-950 overflow-hidden font-mono text-xs">
        {/* Terminal Titlebar with Controls */}
        <div className="flex items-center justify-between px-3 py-2 bg-zinc-900 border-b border-border/60 text-muted-foreground text-[11px]">
          <div className="flex items-center gap-2">
            <Terminal className="w-3.5 h-3.5 text-blue-400" />
            <span className="text-zinc-300 font-semibold">Live Execution Output Console</span>
            <span className="text-[10px] text-zinc-500">({logs.length} messages)</span>
          </div>

          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setIsAutoScroll(!isAutoScroll)}
              title={isAutoScroll ? 'Pause Auto-scroll' : 'Resume Auto-scroll'}
              className={`p-1 rounded hover:bg-zinc-800 transition-colors ${
                isAutoScroll ? 'text-blue-400' : 'text-zinc-500'
              }`}
            >
              {isAutoScroll ? <Pause className="w-3 h-3" /> : <Play className="w-3 h-3" />}
            </button>
            <button
              onClick={copyLogs}
              title="Copy Console Output"
              className="p-1 rounded hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 transition-colors"
            >
              <Copy className="w-3 h-3" />
            </button>
            <button
              onClick={clearLogs}
              title="Clear Console Output"
              className="p-1 rounded hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 transition-colors"
            >
              <Trash2 className="w-3 h-3" />
            </button>
          </div>
        </div>

        {/* Log Messages Output */}
        <div className="p-3 max-h-56 overflow-y-auto space-y-1 scrollbar-thin scrollbar-thumb-zinc-700">
          {logs.length === 0 ? (
            <div className="text-zinc-500 py-3 text-center italic">
              Listening for execution telemetry events...
            </div>
          ) : (
            logs.map((log) => {
              const textClass =
                log.type === 'error'
                  ? 'text-rose-400'
                  : log.type === 'success'
                    ? 'text-emerald-400'
                    : log.type === 'progress'
                      ? 'text-cyan-400'
                      : 'text-zinc-300';

              return (
                <div key={log.id} className="flex items-start gap-2 leading-relaxed">
                  <span className="text-zinc-500 select-none shrink-0 text-[10px] pt-0.5">
                    [{log.timestamp}]
                  </span>
                  {log.engineId && (
                    <span className="text-blue-400 font-semibold shrink-0">
                      [{log.engineId}]
                    </span>
                  )}
                  <span className={`break-all ${textClass}`}>{log.message}</span>
                </div>
              );
            })
          )}
          <div ref={terminalEndRef} />
        </div>
      </div>
    </div>
  );
};
