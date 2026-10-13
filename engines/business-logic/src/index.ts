import {
  TestEngine,
  TestCapability,
  ExecutionContext,
  TestInput,
  TestResult,
  ValidationResult,
  RawEngineFinding,
  RawEngineMetric,
  dynamicWorkerEngineRegistry,
} from '@security-lab/engine-sdk';
import { validateUrlAgainstScope } from '@security-lab/domain';
import { redactHeaders } from '@security-lab/crypto';
import { createLogger } from '@security-lab/logger';
import {
  BusinessLogicOptions,
  WorkflowDefinition,
  RaceConditionTest,
  ParameterTamperTest,
} from './types.js';
import {
  evaluateWorkflowStateBypass,
  DEFAULT_CHECKOUT_WORKFLOW,
} from './state-graph.js';
import { executeSynchronizedBurst } from './burst-synchro.js';
import {
  evaluateParameterTampering,
  DEFAULT_TAMPER_TESTS,
} from './tamperer.js';

export * from './types.js';
export * from './state-graph.js';
export * from './burst-synchro.js';
export * from './tamperer.js';

const logger = createLogger({ name: 'engine-business-logic' });

export class BusinessLogicEngine implements TestEngine {
  readonly id = 'engine-business-logic';
  readonly version = '1.0.0';
  readonly executionClass = 'class_a_native' as const;

  capabilities(): TestCapability[] {
    return [
      {
        id: 'business_logic_state_bypass',
        name: 'Workflow State Machine Step-Skipping & Invariant Validation',
        category: 'protocol_audit',
        description: 'Models multi-step workflows to detect unauthorized state jumps, payment step skipping, and transition invariant violations.',
        isDisruptive: false,
      },
      {
        id: 'race_condition_burst',
        name: 'Synchronized Socket Burst & TOCTOU Concurrency Engine',
        category: 'protocol_audit',
        description: 'Executes synchronized single-packet TCP/HTTP burst requests against pre-warmed sockets to detect double-spending, coupon reuse, and limit bypasses.',
        isDisruptive: false,
      },
      {
        id: 'parameter_tampering',
        name: 'Financial Parameter Tampering & Negative Value Fuzzing',
        category: 'active_fuzzing',
        description: 'Fuzzes quantities, prices, discounts, and fee fields with negative values, zero, and integer overflows to detect business logic accounting bypasses.',
        isDisruptive: false,
      },
    ];
  }

  validate(input: TestInput): ValidationResult {
    try {
      const url = new URL(input.targetUrl);
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        return {
          valid: false,
          errors: [{ path: 'targetUrl', message: 'Target URL must use http or https protocol' }],
        };
      }
      return { valid: true };
    } catch {
      return {
        valid: false,
        errors: [{ path: 'targetUrl', message: `Invalid target URL: "${input.targetUrl}"` }],
      };
    }
  }

  async execute(input: TestInput, context: ExecutionContext): Promise<TestResult> {
    const startTime = Date.now();
    const options = (input.options || {}) as BusinessLogicOptions;
    const scope = context.target?.scope;

    // 1. Target Scope Boundary Enforcement (Rule 2)
    if (scope) {
      const scopeCheck = validateUrlAgainstScope(input.targetUrl, scope);
      if (!scopeCheck.valid) {
        return {
          engineId: this.id,
          durationMs: Date.now() - startTime,
          success: false,
          findings: [],
          metrics: [],
          error: `Target URL "${input.targetUrl}" violates security scope: ${scopeCheck.violations.join('; ')}`,
        };
      }
    }

    logger.info({ targetUrl: input.targetUrl }, 'Initiating business logic state machine & concurrency evaluation');

    const findings: RawEngineFinding[] = [];
    const timeoutMs = options.timeoutMs ?? 15000;

    let workflowsEvaluated = 0;
    let stateBypassViolations = 0;
    let raceTestsRun = 0;
    let raceViolations = 0;
    let tamperTestsRun = 0;
    let tamperViolations = 0;

    // 2. Workflow State Graph & Step-Skipping Evaluation
    const workflows: WorkflowDefinition[] =
      options.workflows && options.workflows.length > 0
        ? options.workflows
        : options.autoDiscoverCommonPatterns !== false
        ? [DEFAULT_CHECKOUT_WORKFLOW]
        : [];

    for (const wf of workflows) {
      workflowsEvaluated++;
      const stepViolations = await evaluateWorkflowStateBypass(input.targetUrl, wf, scope, timeoutMs);
      for (const v of stepViolations) {
        stateBypassViolations++;
        const isCritical = v.skippedSteps.some((s) => s.isPaymentOrTerminal);
        const severity = isCritical ? 'critical' : 'high';

        findings.push({
          title: `Workflow State Machine Bypass: Step-Skipping on ${v.toStep.method} ${v.toStep.path}`,
          description: v.reason,
          severity,
          category: 'business_logic',
          recommendation: `Enforce server-side state machine invariants verifying that prior required steps [${v.skippedSteps.map((s) => s.name).join(', ')}] are completed before processing "${v.toStep.name}".`,
          evidence: {
            request: {
              url: v.requestUrl,
              method: v.requestMethod,
              headers: redactHeaders(v.toStep.headers || {}),
              body: v.toStep.body ? JSON.stringify(v.toStep.body) : undefined,
            },
            response: {
              statusCode: v.actualStatusCode,
              headers: redactHeaders(v.responseHeaders),
              body: v.responseBody.slice(0, 500),
            },
            metadata: {
              workflowId: v.workflowId,
              fromStep: v.fromStep.name,
              toStep: v.toStep.name,
              skippedSteps: v.skippedSteps.map((s) => s.name),
            },
          },
          metadata: {
            ruleId: 'business-logic-state-bypass',
            workflowId: v.workflowId,
            skippedStepIds: v.skippedSteps.map((s) => s.id),
          },
        });
      }
    }

    // 3. Synchronized Socket Burst Race Condition Evaluation
    const raceTests: RaceConditionTest[] = options.raceConditions || [];
    for (const rt of raceTests) {
      raceTestsRun++;
      const burstSummary = await executeSynchronizedBurst(input.targetUrl, rt, {
        timeoutMs,
        concurrency: options.burstConcurrency ?? rt.concurrency,
      });

      if (burstSummary.isVulnerable) {
        raceViolations++;
        const fullEndpointUrl = new URL(rt.endpointPath, input.targetUrl).toString();

        findings.push({
          title: `Concurrency Race Condition (TOCTOU) on ${burstSummary.method} ${burstSummary.endpoint}`,
          description: burstSummary.details,
          severity: 'critical',
          category: 'business_logic',
          recommendation:
            'Implement atomic database transactions with row-level locking (SELECT FOR UPDATE) or distributed mutexes (e.g. Redis Redlock) to prevent concurrent state mutation.',
          evidence: {
            request: {
              url: fullEndpointUrl,
              method: burstSummary.method,
              headers: redactHeaders(rt.headers || {}),
              body: rt.body ? (typeof rt.body === 'string' ? rt.body : JSON.stringify(rt.body)) : undefined,
            },
            response: {
              statusCode: 200,
              headers: {},
              body: burstSummary.details,
            },
            metadata: {
              concurrency: burstSummary.concurrency,
              successfulResponses: burstSummary.successfulResponses,
              failedResponses: burstSummary.failedResponses,
              jitterSpreadMs: burstSummary.jitterSpreadMs,
              statusCodes: burstSummary.statusCodes,
            },
          },
          metadata: {
            ruleId: 'business-logic-race-condition',
            testId: rt.id,
            concurrency: burstSummary.concurrency,
            successfulResponses: burstSummary.successfulResponses,
            jitterSpreadMs: burstSummary.jitterSpreadMs,
          },
        });
      }
    }

    // 4. Parameter Tampering & Negative Value Fuzzing
    const tamperTests: ParameterTamperTest[] =
      options.tamperTests && options.tamperTests.length > 0
        ? options.tamperTests
        : options.autoDiscoverCommonPatterns !== false
        ? DEFAULT_TAMPER_TESTS
        : [];

    for (const tt of tamperTests) {
      tamperTestsRun++;
      const paramViolations = await evaluateParameterTampering(input.targetUrl, tt, scope, timeoutMs);
      for (const pv of paramViolations) {
        tamperViolations++;
        const fullEndpointUrl = new URL(tt.endpointPath, input.targetUrl).toString();

        findings.push({
          title: `Parameter Tampering & Negative Value Flaw on ${pv.method} ${pv.endpoint}`,
          description: pv.reason,
          severity: 'high',
          category: 'business_logic',
          recommendation:
            'Enforce strict server-side bounds checking and input validation rejecting zero, negative, or overflow values (e.g. quantity > 0, price >= 0).',
          evidence: {
            request: {
              url: fullEndpointUrl,
              method: pv.method,
              headers: {},
              body: JSON.stringify(pv.requestPayload),
            },
            response: {
              statusCode: pv.actualStatusCode,
              headers: redactHeaders(pv.responseHeaders),
              body: pv.responseBody.slice(0, 500),
            },
            metadata: {
              parameterName: pv.parameterName,
              tamperedValue: pv.tamperedValue,
            },
          },
          metadata: {
            ruleId: 'business-logic-parameter-tampering',
            testId: tt.id,
            parameter: pv.parameterName,
            tamperedValue: pv.tamperedValue,
          },
        });
      }
    }

    const metrics: RawEngineMetric[] = [
      { name: 'business_logic_workflows_evaluated', value: workflowsEvaluated, unit: 'count' },
      { name: 'business_logic_state_bypass_count', value: stateBypassViolations, unit: 'count' },
      { name: 'business_logic_race_tests_run', value: raceTestsRun, unit: 'count' },
      { name: 'business_logic_race_violations', value: raceViolations, unit: 'count' },
      { name: 'business_logic_tamper_tests_run', value: tamperTestsRun, unit: 'count' },
      { name: 'business_logic_tamper_violations', value: tamperViolations, unit: 'count' },
      { name: 'business_logic_total_violations', value: findings.length, unit: 'count' },
    ];

    logger.info(
      {
        workflowsEvaluated,
        stateBypassViolations,
        raceTestsRun,
        raceViolations,
        tamperTestsRun,
        tamperViolations,
        totalFindings: findings.length,
      },
      'Business logic evaluation completed',
    );

    return {
      engineId: this.id,
      durationMs: Date.now() - startTime,
      success: true,
      findings,
      metrics,
    };
  }
}

export const businessLogicEngine = new BusinessLogicEngine();
try {
  dynamicWorkerEngineRegistry.register(businessLogicEngine);
} catch {
  // Ignore if already registered
}
export default businessLogicEngine;
