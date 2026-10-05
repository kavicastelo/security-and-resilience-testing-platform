import { Finding, Metric, TestRun, Target, Evidence } from '@security-lab/domain';
import { PostureScoreResult } from '@security-lab/scoring';
import { PolicyEvaluationResult } from '@security-lab/policy-engine';

export interface TestExecutionRecord {
  id: string;
  engineId: string;
  executionClass: string;
  status: string;
  durationMs?: number;
  errorMessage?: string;
}

export interface ReportInput {
  testRun: TestRun;
  target?: Target | { id: string; name: string; baseUrl: string };
  executions: TestExecutionRecord[];
  findings: Finding[];
  metrics?: Metric[];
  evidence?: Evidence[];
  posture?: PostureScoreResult;
  releaseGate?: PolicyEvaluationResult;
}
