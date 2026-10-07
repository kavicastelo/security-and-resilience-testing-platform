export interface ExecutionProgressEvent {
  testRunId: string;
  engineId: string;
  executionId: string;
  percent: number;
  message: string;
  timestamp: string;
}

export interface EngineLifecycleEvent {
  testRunId: string;
  engineId: string;
  executionId: string;
  status: 'running' | 'completed' | 'failed' | 'cancelled';
  durationMs?: number;
  findingsCount?: number;
  error?: string;
  timestamp: string;
}

export interface RunLifecycleEvent {
  testRunId: string;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  summary?: unknown;
  timestamp: string;
}
