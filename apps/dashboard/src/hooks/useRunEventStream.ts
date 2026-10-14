import { useEffect, useState, useRef, useCallback } from 'react';
import { getStoredApiKey } from '../api/client.js';

export type LogLevel = 'INFO' | 'WARN' | 'ERROR' | 'PAYLOAD';

export interface StreamLogEntry {
  id: string;
  timestamp: string;
  level: LogLevel;
  engineId?: string;
  message: string;
  raw?: unknown;
}

export interface StreamMetrics {
  rps: number;
  p95LatencyMs: number;
  totalRequests: number;
  activeWorkers: number;
  findingsCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export interface EngineStageState {
  engineId: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  durationMs?: number;
  findingsCount?: number;
  error?: string;
  startedAt?: string;
  completedAt?: string;
}

export type ConnectionState = 'idle' | 'connecting' | 'connected' | 'reconnecting' | 'completed' | 'error' | 'closed';

const MAX_LOG_BUFFER = 2000;

export interface UseRunEventStreamOptions {
  runId: string | null;
  enabled?: boolean;
  onRunCompleted?: (run: { testRunId: string; status: string; summary?: any }) => void;
}

export function useRunEventStream({
  runId,
  enabled = true,
  onRunCompleted,
}: UseRunEventStreamOptions) {
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000';
  const [connectionStatus, setConnectionStatus] = useState<ConnectionState>('idle');
  const [runStatus, setRunStatus] = useState<string>('pending');
  const [progress, setProgress] = useState<number>(0);
  const [activeEngine, setActiveEngine] = useState<string | null>(null);
  const [logs, setLogs] = useState<StreamLogEntry[]>([]);
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [engineStates, setEngineStates] = useState<Record<string, EngineStageState>>({});
  const [metrics, setMetrics] = useState<StreamMetrics>({
    rps: 0,
    p95LatencyMs: 0,
    totalRequests: 0,
    activeWorkers: 1,
    findingsCount: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  });

  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttemptsRef = useRef<number>(0);
  const pausedBufferRef = useRef<StreamLogEntry[]>([]);
  const isPausedRef = useRef<boolean>(false);
  isPausedRef.current = isPaused;

  const pushLog = useCallback((entry: Omit<StreamLogEntry, 'id'>) => {
    const newEntry: StreamLogEntry = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      ...entry,
    };

    if (isPausedRef.current) {
      pausedBufferRef.current.push(newEntry);
      if (pausedBufferRef.current.length > MAX_LOG_BUFFER) {
        pausedBufferRef.current.shift();
      }
      return;
    }

    setLogs((prev) => {
      const next = [...prev, newEntry];
      return next.length > MAX_LOG_BUFFER ? next.slice(-MAX_LOG_BUFFER) : next;
    });
  }, []);

  const clearLogs = useCallback(() => {
    setLogs([]);
    pausedBufferRef.current = [];
  }, []);

  const togglePause = useCallback(() => {
    setIsPaused((prev) => {
      const next = !prev;
      if (!next && pausedBufferRef.current.length > 0) {
        // Unpausing: flush buffered logs
        setLogs((curr) => {
          const combined = [...curr, ...pausedBufferRef.current];
          return combined.length > MAX_LOG_BUFFER ? combined.slice(-MAX_LOG_BUFFER) : combined;
        });
        pausedBufferRef.current = [];
      }
      return next;
    });
  }, []);

  useEffect(() => {
    if (!runId || !enabled) {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
      setConnectionStatus('idle');
      return;
    }

    let isMounted = true;

    const connectStream = () => {
      if (!isMounted) return;
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }

      setConnectionStatus(reconnectAttemptsRef.current > 0 ? 'reconnecting' : 'connecting');

      const apiKey = getStoredApiKey();
      const authParam = apiKey ? `?token=${encodeURIComponent(apiKey)}` : '';
      const streamUrl = `${apiUrl}/api/v1/test-runs/${runId}/stream${authParam}`;

      const es = new EventSource(streamUrl);
      eventSourceRef.current = es;

      es.onopen = () => {
        if (!isMounted) return;
        setConnectionStatus('connected');
        reconnectAttemptsRef.current = 0;
        pushLog({
          timestamp: new Date().toLocaleTimeString(),
          level: 'INFO',
          message: `Connected to live telemetry stream for run ${runId.slice(0, 8)}...`,
        });
      };

      es.addEventListener('init', (e: MessageEvent) => {
        if (!isMounted) return;
        try {
          const data = JSON.parse(e.data);
          setRunStatus(data.status || 'running');
          if (data.status === 'completed') setProgress(100);
          pushLog({
            timestamp: new Date().toLocaleTimeString(),
            level: 'INFO',
            message: `Stream snapshot initialized (status: ${data.status || 'unknown'})`,
          });
        } catch {
          // ignore parsing error
        }
      });

      es.addEventListener('progress', (e: MessageEvent) => {
        if (!isMounted) return;
        try {
          const data = JSON.parse(e.data);
          if (data.percent !== undefined) setProgress(data.percent);
          if (data.engineId) setActiveEngine(data.engineId);
          if (data.message) {
            pushLog({
              timestamp: new Date().toLocaleTimeString(),
              level: 'INFO',
              engineId: data.engineId,
              message: data.message,
            });
          }
        } catch {
          // ignore
        }
      });

      es.addEventListener('engine', (e: MessageEvent) => {
        if (!isMounted) return;
        try {
          const data = JSON.parse(e.data);
          if (data.engineId) {
            setEngineStates((prev) => ({
              ...prev,
              [data.engineId]: {
                engineId: data.engineId,
                status: data.status,
                durationMs: data.durationMs,
                findingsCount: data.findingsCount,
                error: data.error,
              },
            }));

            if (data.status === 'running') {
              setActiveEngine(data.engineId);
              pushLog({
                timestamp: new Date().toLocaleTimeString(),
                level: 'INFO',
                engineId: data.engineId,
                message: `Engine "${data.engineId}" dispatched to sandbox worker thread`,
              });
            } else if (data.status === 'completed') {
              pushLog({
                timestamp: new Date().toLocaleTimeString(),
                level: 'INFO',
                engineId: data.engineId,
                message: `Engine "${data.engineId}" finished successfully in ${data.durationMs ?? 0}ms (${data.findingsCount ?? 0} findings)`,
              });
            } else if (data.status === 'failed') {
              pushLog({
                timestamp: new Date().toLocaleTimeString(),
                level: 'ERROR',
                engineId: data.engineId,
                message: `Engine "${data.engineId}" failed: ${data.error || 'Unknown execution failure'}`,
              });
            }
          }
        } catch {
          // ignore
        }
      });

      es.addEventListener('run', (e: MessageEvent) => {
        if (!isMounted) return;
        try {
          const data = JSON.parse(e.data);
          setRunStatus(data.status);
          pushLog({
            timestamp: new Date().toLocaleTimeString(),
            level: data.status === 'failed' ? 'ERROR' : 'INFO',
            message: `Test run transition: status is now "${data.status}"`,
          });
        } catch {
          // ignore
        }
      });

      es.addEventListener('run_completed', (e: MessageEvent) => {
        if (!isMounted) return;
        try {
          const data = JSON.parse(e.data);
          setRunStatus(data.status || 'completed');
          setProgress(100);
          setConnectionStatus('completed');
          pushLog({
            timestamp: new Date().toLocaleTimeString(),
            level: 'INFO',
            message: `Execution complete. Final status: ${data.status}`,
          });
          if (onRunCompleted) onRunCompleted(data);
        } catch {
          // ignore
        }
      });

      es.onerror = () => {
        if (!isMounted) return;
        es.close();

        // If completed or failed, do not reconnect
        if (runStatus === 'completed' || runStatus === 'failed' || runStatus === 'cancelled') {
          setConnectionStatus('closed');
          return;
        }

        reconnectAttemptsRef.current += 1;
        setConnectionStatus('reconnecting');

        const delay = Math.min(1000 * Math.pow(1.5, reconnectAttemptsRef.current), 10000);
        pushLog({
          timestamp: new Date().toLocaleTimeString(),
          level: 'WARN',
          message: `Telemetry stream disconnected. Reconnecting in ${(delay / 1000).toFixed(1)}s (attempt ${reconnectAttemptsRef.current})...`,
        });

        reconnectTimeoutRef.current = setTimeout(() => {
          if (isMounted) connectStream();
        }, delay);
      };
    };

    connectStream();

    return () => {
      isMounted = false;
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    };
  }, [runId, enabled, apiUrl, pushLog, runStatus, onRunCompleted]);

  return {
    connectionStatus,
    runStatus,
    progress,
    activeEngine,
    logs,
    metrics,
    setMetrics,
    engineStates,
    isPaused,
    togglePause,
    clearLogs,
  };
}
