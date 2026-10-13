import { TargetScope } from '@security-lab/domain';
import {
  TestInput,
  TestResult,
  RawEngineFinding,
  RawEngineMetric,
} from './types.js';

export interface SerializableTargetContext {
  readonly id: string;
  readonly name: string;
  readonly baseUrl: string;
  readonly scope: TargetScope;
}

export interface SerializableExecutionContext {
  readonly correlationId: string;
  readonly testRunId: string;
  readonly executionId: string;
  readonly target: SerializableTargetContext;
  readonly timeoutMs?: number;
}

export type WorkerMessageType =
  | 'EXECUTE'
  | 'CANCEL'
  | 'LOG'
  | 'PROGRESS'
  | 'FINDING'
  | 'METRIC'
  | 'RESULT'
  | 'ERROR'
  | 'READY';

export interface WorkerExecuteMessage {
  type: 'EXECUTE';
  id: string;
  engineId: string;
  input: TestInput;
  context: SerializableExecutionContext;
  executeFunctionSource?: string;
  engineModulePath?: string;
}

export interface WorkerCancelMessage {
  type: 'CANCEL';
  id: string;
  reason: string;
}

export interface WorkerLogMessage {
  type: 'LOG';
  id: string;
  level: 'debug' | 'info' | 'warn' | 'error';
  message: string;
  meta?: Record<string, unknown>;
}

export interface WorkerProgressMessage {
  type: 'PROGRESS';
  id: string;
  percentage: number;
  stepMessage: string;
}

export interface WorkerFindingMessage {
  type: 'FINDING';
  id: string;
  finding: RawEngineFinding;
}

export interface WorkerMetricMessage {
  type: 'METRIC';
  id: string;
  metric: RawEngineMetric;
}

export interface WorkerResultMessage {
  type: 'RESULT';
  id: string;
  result: TestResult;
  memoryUsageMb?: number;
}

export interface WorkerErrorMessage {
  type: 'ERROR';
  id: string;
  error: string;
  stack?: string;
}

export interface WorkerReadyMessage {
  type: 'READY';
  threadId: number;
}

export type WorkerInboundMessage = WorkerExecuteMessage | WorkerCancelMessage;
export type WorkerOutboundMessage =
  | WorkerReadyMessage
  | WorkerLogMessage
  | WorkerProgressMessage
  | WorkerFindingMessage
  | WorkerMetricMessage
  | WorkerResultMessage
  | WorkerErrorMessage;
