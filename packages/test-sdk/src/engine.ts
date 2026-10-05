import { TestCapability } from './capability.js';
import { ExecutionContext } from './context.js';
import { TestInput, TestResult, ValidationResult } from './result.js';

/**
 * Fundamental test engine contract.
 * Every testing capability (Class A native, Class B scanner wrapper, Class C heavy worker)
 * implements or interfaces through this contract.
 */
export interface TestEngine {
  readonly id: string;
  readonly version: string;

  capabilities(): TestCapability[];

  validate(input: TestInput): ValidationResult;

  execute(input: TestInput, context: ExecutionContext): Promise<TestResult>;
}
