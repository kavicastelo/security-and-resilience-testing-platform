export {
  TestEngine,
  TestCapability,
  ExecutionContext,
  TargetExecutionContext,
  TestInput,
  TestResult,
  RawEngineFinding,
  RawEngineMetric,
  ValidationResult,
  ValidationIssue,
  EngineExecutionClass,
  TestEngineError,
  EngineExecutionError,
  safeFetch,
} from '@security-lab/test-sdk';

/**
 * Sandboxing configuration options for isolated worker thread engine execution.
 */
export interface EngineSandboxingOptions {
  /**
   * Whether worker sandboxing is enabled. Defaults to true.
   */
  enabled?: boolean;

  /**
   * Maximum execution timeout in milliseconds.
   * If exceeded, the worker is forcibly terminated with worker.terminate().
   * Defaults to 30,000ms.
   */
  timeoutMs?: number;

  /**
   * Memory ceiling: max V8 old generation heap size in megabytes.
   * Enforced via Node.js worker_threads resourceLimits.
   * Defaults to 512MB.
   */
  maxOldGenerationSizeMb?: number;

  /**
   * Memory ceiling: max V8 young generation heap size in megabytes.
   * Defaults to 128MB.
   */
  maxYoungGenerationSizeMb?: number;

  /**
   * Graceful fallback to main-thread execution if worker_threads cannot be initialized.
   * Defaults to true.
   */
  fallbackToInProcess?: boolean;

  /**
   * Custom worker entrypoint script path if overriding default.
   */
  workerEntryPath?: string;
}

/**
 * Execution telemetry and resource metrics collected from the worker thread harness.
 */
export interface WorkerRunnerTelemetry {
  readonly sandboxed: boolean;
  readonly threadId?: number;
  readonly durationMs: number;
  readonly timedOut: boolean;
  readonly memoryCeilingExceeded: boolean;
  readonly peakMemoryMb?: number;
}
