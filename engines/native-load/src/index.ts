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
  NativeLoadEngineOptions,
} from './types.js';
import { executeLoadProfile } from './load-generator.js';

export * from './types.js';
export * from './histogram.js';
export * from './load-generator.js';

const logger = createLogger({ name: 'engine-native-load' });

export class NativeLoadEngine implements TestEngine {
  readonly id = 'engine-native-load';
  readonly version = '1.0.0';
  readonly executionClass = 'class_a_native' as const;

  capabilities(): TestCapability[] {
    return [
      {
        id: 'native_capacity_benchmarking',
        name: 'In-Memory High-Throughput HTTP Load Generation & Capacity Benchmarking',
        category: 'protocol_audit',
        description: 'Generates up to 5,000+ requests per second in-memory without Docker to measure throughput, saturation points, and capacity boundaries.',
        isDisruptive: true,
      },
      {
        id: 'latency_percentiles_hdr',
        name: 'HDR Latency Percentile Distribution Analysis (P50, P90, P95, P99, P99.9)',
        category: 'protocol_audit',
        description: 'Calculates high-dynamic-range latency percentiles and statistical dispersion across thousands of concurrent requests.',
        isDisruptive: false,
      },
      {
        id: 'performance_slo_enforcement',
        name: 'Latency & Error Rate Performance SLO Policy Evaluation',
        category: 'passive_analysis',
        description: 'Enforces quantitative service level objectives (P95/P99 latency thresholds and error rates) to guard against performance regressions.',
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
    const options = ((input.options || {}) as unknown) as NativeLoadEngineOptions;
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

      // Check loadTesting permission in scope
      if (scope.testing && scope.testing.loadTesting === false) {
        return {
          engineId: this.id,
          durationMs: Date.now() - startTime,
          success: false,
          findings: [],
          metrics: [],
          error: 'Load testing capability is strictly disabled in target security scope',
        };
      }

      // Check concurrency ceiling in scope
      if (scope.limits?.maxConcurrency && options.connections) {
        if (options.connections > scope.limits.maxConcurrency) {
          return {
            engineId: this.id,
            durationMs: Date.now() - startTime,
            success: false,
            findings: [],
            metrics: [],
            error: `Requested concurrency (${options.connections} connections) exceeds target scope safety limit of ${scope.limits.maxConcurrency} connections`,
          };
        }
      }
    }

    logger.info({ targetUrl: input.targetUrl }, 'Initiating native in-memory performance benchmarking');

    const totalDurationSec = options.durationSec || 10;

    // 2. Execute Load Profile
    const summary = await executeLoadProfile(input.targetUrl, options, {
      onTick: (tick) => {
        if (context.reportProgress) {
          const pct = Math.min(99, Math.round((tick.elapsedSec / totalDurationSec) * 100));
          context.reportProgress(
            pct,
            `Running native load test: ${tick.intervalRps} RPS (P95: ${tick.currentP95Ms}ms)`,
          );
        }
      },
      shouldAbort: () => {
        return context.abortSignal ? context.abortSignal.aborted : false;
      },
    });

    const findings: RawEngineFinding[] = [];

    // 3. Emit SLO Breach Findings
    if (!summary.sloPassed) {
      const baseUrlObj = new URL(input.targetUrl);
      let finalPath = baseUrlObj.pathname;
      if (options.path && options.path !== '/') {
        finalPath = options.path.startsWith('/') ? options.path : `/${options.path}`;
      }
      const fullEndpointUrl = new URL(finalPath, baseUrlObj.origin).toString();

      findings.push({
        title: `Performance SLO Breach: Latency or Error Rate Threshold Exceeded`,
        description: `Service Level Objective (SLO) failed during capacity benchmarking: ${summary.sloViolations.join('; ')}.`,
        severity: 'high',
        category: 'performance',
        recommendation:
          'Investigate application profiling traces, optimize database query execution plans, configure connection pooling, or increase horizontal pod replica counts.',
        evidence: {
          request: {
            url: fullEndpointUrl,
            method: (options.method || 'GET').toUpperCase(),
            headers: redactHeaders(options.headers || {}),
          },
          response: {
            statusCode: 200,
            headers: {},
            body: JSON.stringify({
              latency: summary.latency,
              rps: summary.rps,
              errorRate: summary.errorRate,
              violations: summary.sloViolations,
            }),
          },
          metadata: {
            durationSec: summary.durationSec,
            rps: summary.rps,
            p50: summary.latency.p50,
            p90: summary.latency.p90,
            p95: summary.latency.p95,
            p99: summary.latency.p99,
            p999: summary.latency.p999,
            errorRatePercent: summary.errorRate * 100,
            violations: summary.sloViolations,
          },
        },
        metadata: {
          ruleId: 'performance-slo-breach',
          p95: summary.latency.p95,
          p99: summary.latency.p99,
          rps: summary.rps,
          violations: summary.sloViolations,
        },
      });
    }

    // 4. Output Quantitative Platform Metrics
    const metrics: RawEngineMetric[] = [
      { name: 'http_req_duration_p50', value: summary.latency.p50, unit: 'ms' },
      { name: 'http_req_duration_p90', value: summary.latency.p90, unit: 'ms' },
      { name: 'http_req_duration_p95', value: summary.latency.p95, unit: 'ms' },
      { name: 'http_req_duration_p99', value: summary.latency.p99, unit: 'ms' },
      { name: 'http_req_duration_p999', value: summary.latency.p999, unit: 'ms' },
      { name: 'http_req_duration_avg', value: summary.latency.avg, unit: 'ms' },
      { name: 'http_req_duration_min', value: summary.latency.min, unit: 'ms' },
      { name: 'http_req_duration_max', value: summary.latency.max, unit: 'ms' },
      { name: 'http_req_duration_stddev', value: summary.latency.stdDev, unit: 'ms' },
      { name: 'http_reqs_total', value: summary.totalRequests, unit: 'count' },
      { name: 'http_rps', value: summary.rps, unit: 'req/s' },
      { name: 'http_req_failed_ratio', value: Math.round(summary.errorRate * 10000) / 100, unit: 'percent' },
      { name: 'bytes_transferred', value: summary.bytesTransferred, unit: 'bytes' },
      { name: 'slo_violations_count', value: summary.sloViolations.length, unit: 'count' },
    ];

    logger.info(
      {
        totalRequests: summary.totalRequests,
        rps: summary.rps,
        p95: summary.latency.p95,
        p99: summary.latency.p99,
        findingsCount: findings.length,
      },
      'Native load engine execution completed',
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

export const nativeLoadEngine = new NativeLoadEngine();
try {
  dynamicWorkerEngineRegistry.register(nativeLoadEngine);
} catch {
  // Ignore if already registered
}
export default nativeLoadEngine;
