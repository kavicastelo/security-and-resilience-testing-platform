import {
  FaultAction,
  FaultRuleMatch,
  FaultRule,
  ClientScenarioStep,
  ChaosPlan,
  InjectedFaultRecord,
  ResilienceExecutionSummary,
} from '@security-lab/contracts';

export type {
  FaultAction,
  FaultRuleMatch,
  FaultRule,
  ClientScenarioStep,
  ChaosPlan,
  InjectedFaultRecord,
  ResilienceExecutionSummary,
};

export interface ChaosEngineOptions extends ChaosPlan {
  autoRunScenario?: boolean;
}
