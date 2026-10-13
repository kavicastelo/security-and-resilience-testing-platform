import {
  TestEngine,
  TestCapability,
  ExecutionContext,
  TestInput,
  TestResult,
  ValidationResult,
  RawEngineFinding,
  RawEngineMetric,
  safeFetch,
  dynamicWorkerEngineRegistry,
} from '@security-lab/engine-sdk';
import { validateUrlAgainstScope } from '@security-lab/domain';
import { redactHeaders } from '@security-lab/crypto';
import { createLogger } from '@security-lab/logger';
import {
  ChaosEngineOptions,
  FaultRule,
  ClientScenarioStep,
  ResilienceExecutionSummary,
} from './types.js';
import { ChaosMitmProxy } from './proxy.js';

export * from './types.js';
export * from './fault-rules.js';
export * from './proxy.js';

const logger = createLogger({ name: 'engine-chaos-mitm' });

export const DEFAULT_CHAOS_RULES: FaultRule[] = [
  {
    id: 'default-latency-rule',
    name: 'Default Upstream Latency Injection',
    match: { path: '/api/*', method: '*' },
    action: 'LATENCY',
    percentage: 50,
    latencyMs: 300,
    jitterMs: 50,
  },
  {
    id: 'default-503-rule',
    name: 'Default Transient 503 Gateway Error',
    match: { path: '/api/*', method: '*' },
    action: 'STATUS_CODE',
    percentage: 30,
    statusCode: 503,
  },
];

export class ChaosMitmEngine implements TestEngine {
  readonly id = 'engine-chaos-mitm';
  readonly version = '1.0.0';
  readonly executionClass = 'class_a_native' as const;

  capabilities(): TestCapability[] {
    return [
      {
        id: 'chaos_latency_injection',
        name: 'Controlled Upstream Latency & Jitter Fault Injection',
        category: 'protocol_audit',
        description: 'Injects configurable millisecond delays and jitter into matching HTTP routes to test client timeouts and degradation behavior.',
        isDisruptive: true,
      },
      {
        id: 'chaos_error_injection',
        name: 'Upstream Gateway Error Injection (HTTP 500, 502, 503, 504)',
        category: 'protocol_audit',
        description: 'Synthesizes server and gateway failure responses with configurable probabilities to verify client retry loops and fallback policies.',
        isDisruptive: true,
      },
      {
        id: 'chaos_connection_drop',
        name: 'TCP Socket Reset & Immediate Connection Drop Simulation',
        category: 'protocol_audit',
        description: 'Forcibly resets TCP connections upon request arrival to evaluate application network failure resilience.',
        isDisruptive: true,
      },
      {
        id: 'chaos_payload_truncation',
        name: 'Mid-Stream Response Payload Truncation Simulation',
        category: 'protocol_audit',
        description: 'Truncates response streams midway through transmission to test client JSON stream parser error handling.',
        isDisruptive: true,
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
    const options = (input.options || {}) as unknown as ChaosEngineOptions;
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

      // Check chaosTesting authorization in scope
      if (scope.testing && scope.testing.chaosTesting === false) {
        return {
          engineId: this.id,
          durationMs: Date.now() - startTime,
          success: false,
          findings: [],
          metrics: [],
          error: 'Chaos testing capability is strictly disabled in target security scope',
        };
      }
    }

    logger.info({ targetUrl: input.targetUrl }, 'Initializing ephemeral Chaos MITM fault-injection proxy');

    const faultRules = options.faultRules && options.faultRules.length > 0
      ? options.faultRules
      : DEFAULT_CHAOS_RULES;

    const proxy = new ChaosMitmProxy({
      upstreamBaseUrl: input.targetUrl,
      faultRules,
      scope,
      timeoutMs: options.proxyTimeoutMs || 15000,
    });

    let proxyPort = 0;
    const findings: RawEngineFinding[] = [];
    const failures: string[] = [];

    let totalClientRetries = 0;
    let recoveredRequests = 0;
    let unrecoveredRequests = 0;
    let recoveryLatencyTotal = 0;

    try {
      // 2. Start Ephemeral Proxy
      proxyPort = await proxy.start();
      const proxyBaseUrl = proxy.proxyUrl;

      // 3. Execute Client Scenarios through Chaos Proxy
      const scenarioSteps: ClientScenarioStep[] = options.scenarioSteps && options.scenarioSteps.length > 0
        ? options.scenarioSteps
        : [
            {
              name: 'Default Chaos Smoke Verification',
              method: 'GET',
              path: '/',
              maxRetries: 3,
              retryBackoffMs: 50,
              expectedFinalStatus: 200,
            },
          ];

      for (const step of scenarioSteps) {
        const stepUrl = new URL(step.path, proxyBaseUrl).toString();
        let stepSucceeded = false;
        let attempt = 0;
        let lastError = '';
        let lastStatus = 0;
        const stepStart = Date.now();

        while (attempt <= step.maxRetries && !stepSucceeded) {
          if (attempt > 0) {
            totalClientRetries++;
            const backoff = step.retryBackoffMs * Math.pow(2, attempt - 1);
            await new Promise((r) => setTimeout(r, backoff));
          }

          attempt++;

          try {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 10000);

            const res = await safeFetch(stepUrl, {
              method: step.method,
              headers: step.headers || {},
              body: step.body ? JSON.stringify(step.body) : undefined,
              signal: controller.signal,
            });
            clearTimeout(timer);

            lastStatus = res.status;
            if (res.status === step.expectedFinalStatus) {
              stepSucceeded = true;
              recoveredRequests++;
              recoveryLatencyTotal += Date.now() - stepStart;
            } else {
              lastError = `Received HTTP ${res.status} (expected ${step.expectedFinalStatus})`;
            }
          } catch (err: any) {
            lastError = err?.message || 'Network error';
          }
        }

        if (!stepSucceeded) {
          unrecoveredRequests++;
          const failMsg = `Step "${step.name}" (${step.method} ${step.path}) failed to recover after ${step.maxRetries} retries: ${lastError}`;
          failures.push(failMsg);

          findings.push({
            title: `Resilience Recovery Failure on ${step.method} ${step.path}`,
            description: failMsg,
            severity: 'high',
            category: 'reliability',
            recommendation:
              'Implement exponential retry backoff, circuit breaking, and fallback responses to prevent cascading service degradation during upstream network or gateway failures.',
            evidence: {
              request: {
                url: new URL(step.path, input.targetUrl).toString(),
                method: step.method,
                headers: redactHeaders(step.headers || {}),
                body: step.body ? JSON.stringify(step.body) : undefined,
              },
              response: {
                statusCode: lastStatus,
                headers: {},
                body: lastError,
              },
              metadata: {
                stepName: step.name,
                maxRetries: step.maxRetries,
                attemptsExecuted: attempt,
                lastError,
              },
            },
            metadata: {
              ruleId: 'resilience-recovery-failure',
              path: step.path,
              method: step.method,
              attempts: attempt,
            },
          });
        }
      }
    } finally {
      // 4. Always Stop Ephemeral Proxy (Failure/Rollback Requirement 20)
      await proxy.stop();
    }

    const proxyStats = proxy.stats;
    const avgRecoveryLatencyMs =
      recoveredRequests > 0 ? Math.round(recoveryLatencyTotal / recoveredRequests) : 0;
    const recoveryRate =
      recoveredRequests + unrecoveredRequests > 0
        ? Math.round((recoveredRequests / (recoveredRequests + unrecoveredRequests)) * 100)
        : 100;

    const summary: ResilienceExecutionSummary = {
      proxyPort,
      totalRequestsReceived: proxyStats.totalRequests,
      faultsInjected: proxyStats.faultsInjected,
      faultsByType: proxyStats.faultsByType,
      recoveredRequests,
      unrecoveredRequests,
      avgRecoveryLatencyMs,
      clientRetries: totalClientRetries,
      passed: failures.length === 0,
      failures,
      faultLog: proxyStats.faultLog,
    };

    logger.info(
      {
        totalRequests: proxyStats.totalRequests,
        faultsInjected: proxyStats.faultsInjected,
        clientRetries: totalClientRetries,
        recoveredRequests,
        unrecoveredRequests,
        passed: summary.passed,
      },
      'Chaos MITM resilience testing completed',
    );

    const metrics: RawEngineMetric[] = [
      { name: 'chaos_proxy_port', value: proxyPort, unit: 'count' },
      { name: 'chaos_total_requests', value: proxyStats.totalRequests, unit: 'count' },
      { name: 'chaos_faults_injected', value: proxyStats.faultsInjected, unit: 'count' },
      { name: 'chaos_faults_latency_count', value: proxyStats.faultsByType['LATENCY'] || 0, unit: 'count' },
      { name: 'chaos_faults_error_count', value: proxyStats.faultsByType['STATUS_CODE'] || 0, unit: 'count' },
      { name: 'chaos_faults_drop_count', value: proxyStats.faultsByType['DROP'] || 0, unit: 'count' },
      { name: 'chaos_faults_truncate_count', value: proxyStats.faultsByType['TRUNCATE'] || 0, unit: 'count' },
      { name: 'chaos_client_retries', value: totalClientRetries, unit: 'count' },
      { name: 'chaos_recovered_requests', value: recoveredRequests, unit: 'count' },
      { name: 'chaos_unrecovered_requests', value: unrecoveredRequests, unit: 'count' },
      { name: 'chaos_recovery_rate_percent', value: recoveryRate, unit: 'percent' },
      { name: 'chaos_avg_recovery_latency_ms', value: avgRecoveryLatencyMs, unit: 'ms' },
    ];

    return {
      engineId: this.id,
      durationMs: Date.now() - startTime,
      success: true,
      findings,
      metrics,
    };
  }
}

export const chaosMitmEngine = new ChaosMitmEngine();
try {
  dynamicWorkerEngineRegistry.register(chaosMitmEngine);
} catch {
  // Ignore if already registered
}
export default chaosMitmEngine;
