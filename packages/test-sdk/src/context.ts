import { TargetScope } from '@security-lab/domain';
import { Logger } from '@security-lab/logger';

export interface TargetExecutionContext {
  readonly id: string;
  readonly name: string;
  readonly baseUrl: string;
  readonly scope: TargetScope;
}

export interface ExecutionContext {
  readonly correlationId: string;
  readonly testRunId: string;
  readonly executionId: string;
  readonly target: TargetExecutionContext;
  readonly logger: Logger;
  readonly abortSignal: AbortSignal;
  readonly reportProgress: (percentage: number, stepMessage: string) => void;
}
