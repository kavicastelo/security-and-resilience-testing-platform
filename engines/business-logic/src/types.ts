import {
  WorkflowStep,
  WorkflowDefinition,
  StateTransition,
  RaceConditionTest,
  ParameterTamperTest,
  TamperTestParameter,
  BusinessLogicOptions,
} from '@security-lab/contracts';

export type {
  WorkflowStep,
  WorkflowDefinition,
  StateTransition,
  RaceConditionTest,
  ParameterTamperTest,
  TamperTestParameter,
  BusinessLogicOptions,
};

export interface BurstSocketResult {
  index: number;
  statusCode: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  latencyMs: number;
  arrivalTimestamp: number;
  error?: string;
}

export interface BurstTestSummary {
  testId: string;
  name: string;
  endpoint: string;
  method: string;
  concurrency: number;
  successfulResponses: number;
  failedResponses: number;
  statusCodes: number[];
  jitterSpreadMs: number;
  isVulnerable: boolean;
  details: string;
  results: BurstSocketResult[];
}

export interface StateTransitionViolation {
  workflowId: string;
  workflowName: string;
  fromStep: WorkflowStep;
  toStep: WorkflowStep;
  skippedSteps: WorkflowStep[];
  actualStatusCode: number;
  responseBody: string;
  responseHeaders: Record<string, string>;
  requestUrl: string;
  requestMethod: string;
  isViolation: boolean;
  reason: string;
}

export interface TamperViolation {
  testId: string;
  testName: string;
  endpoint: string;
  method: string;
  parameterName: string;
  tamperedValue: any;
  actualStatusCode: number;
  responseBody: string;
  responseHeaders: Record<string, string>;
  requestPayload: any;
  isViolation: boolean;
  reason: string;
}
