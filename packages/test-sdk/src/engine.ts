import { TestCapability } from './capability.js';
import { ExecutionContext } from './context.js';
import { TestInput, TestResult, ValidationResult } from './result.js';

export type EngineExecutionClass = 'class_a_native' | 'class_b_container' | 'class_c_worker';

export class TestEngineError extends Error {
  constructor(message: string, public readonly engineId?: string, public readonly cause?: unknown) {
    super(message);
    this.name = 'TestEngineError';
  }
}

/**
 * Fundamental test engine contract.
 * Every testing capability (Class A native, Class B scanner wrapper, Class C heavy worker)
 * implements or interfaces through this contract.
 */
export interface TestEngine {
  readonly id: string;
  readonly version: string;
  readonly executionClass?: EngineExecutionClass;

  capabilities(): TestCapability[];

  validate(input: TestInput): ValidationResult;

  execute(input: TestInput, context: ExecutionContext): Promise<TestResult>;

  /** Optional lifecycle initialization hook */
  init?(): Promise<void>;

  /** Optional health/readiness check hook */
  healthCheck?(): Promise<boolean>;

  /** Optional graceful teardown/cleanup hook */
  cleanup?(): Promise<void>;
}
