import { Evidence, FindingSeverity } from '@security-lab/domain';

export interface TestInput {
  readonly targetUrl: string;
  readonly options?: Record<string, unknown>;
  readonly customHeaders?: Record<string, string>;
  readonly timeoutMs?: number;
}

export interface ValidationIssue {
  readonly path: string;
  readonly message: string;
}

export interface ValidationResult {
  readonly valid: boolean;
  readonly errors?: ValidationIssue[];
}

export interface RawEngineFinding {
  readonly title: string;
  readonly description: string;
  readonly severity: FindingSeverity;
  readonly category: string;
  readonly recommendation?: string;
  readonly evidence?: Partial<Evidence>;
  readonly metadata?: Record<string, unknown>;
}

export interface RawEngineMetric {
  readonly name: string;
  readonly value: number;
  readonly unit: string;
  readonly tags?: Record<string, string>;
}

export interface TestResult {
  readonly engineId: string;
  readonly durationMs: number;
  readonly success: boolean;
  readonly findings: RawEngineFinding[];
  readonly metrics: RawEngineMetric[];
  readonly rawOutput?: unknown;
  readonly error?: string;
}
