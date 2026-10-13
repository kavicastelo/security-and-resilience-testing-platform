import {
  LoadProfile,
  LoadThresholds,
  LoadStage,
  LoadProfileType,
  LatencyPercentiles,
  LoadExecutionSummary,
} from '@security-lab/contracts';

export type {
  LoadProfile,
  LoadThresholds,
  LoadStage,
  LoadProfileType,
  LatencyPercentiles,
  LoadExecutionSummary,
};

export interface LiveLoadTick {
  timestamp: number;
  elapsedSec: number;
  intervalRequests: number;
  intervalRps: number;
  totalRequests: number;
  totalErrors: number;
  currentP95Ms: number;
  currentAvgMs: number;
}

export interface NativeLoadEngineOptions extends LoadProfile {
  autoEvaluatePolicy?: boolean;
}
