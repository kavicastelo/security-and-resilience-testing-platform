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

export type FindingDiffStatus = 'NEW' | 'RECURRING' | 'FIXED';

export interface FindingDiffItem {
  fingerprint: string;
  title: string;
  severity: string;
  category: string;
  diffStatus: FindingDiffStatus;
  findingId?: string;
}

export interface FindingDiffSummary {
  newCount: number;
  recurringCount: number;
  fixedCount: number;
  previousTestRunId?: string;
  details?: FindingDiffItem[];
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
  findingDiff?: FindingDiffSummary;
}

