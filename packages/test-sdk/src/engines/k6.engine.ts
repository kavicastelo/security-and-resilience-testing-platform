import fs from 'node:fs';
import path from 'node:path';
import { TestEngine, TestEngineError, EngineExecutionError } from '../engine.js';
import { TestCapability } from '../capability.js';
import { ExecutionContext } from '../context.js';
import { TestInput, TestResult, ValidationResult, RawEngineFinding, RawEngineMetric } from '../result.js';
import { dockerRunner, IDockerRunner } from '../runners/docker.runner.js';
import { createScratchDirectory } from '../runners/scratch-dir.js';
import { buildK6Script, K6Stage } from './k6-script-builder.js';

export interface K6EngineOptions {
  vus?: number;
  duration?: string;
  durationSec?: number;
  stages?: K6Stage[];
  thresholds?: Record<string, string[]>;
  maxP95Ms?: number;
  maxFailedRatio?: number;
  dockerImage?: string;
  simulated?: boolean;
  mockSummary?: Record<string, unknown>;
  mockP95Ms?: number;
  throwOnError?: boolean;
  scenarioType?: 'load_sla' | 'concurrency_soak' | 'burst_resilience';
}

export interface K6SummaryMetrics {
  durationAvg: number;
  durationMin: number;
  durationMed: number;
  durationMax: number;
  durationP90: number;
  durationP95: number;
  durationP99: number;
  reqsTotal: number;
  rps: number;
  failedRate: number;
  failedCount: number;
  iterations: number;
}

/**
 * Calculates percentile from a sorted array of numbers.
 */
export function calculatePercentile(sortedValues: number[], percentile: number): number {
  if (sortedValues.length === 0) return 0;
  const index = Math.ceil((percentile / 100) * sortedValues.length) - 1;
  return sortedValues[Math.max(0, Math.min(index, sortedValues.length - 1))] ?? 0;
}

/**
 * Parses k6 native summary export JSON into canonical metrics structure.
 */
export function parseK6Summary(raw: unknown): K6SummaryMetrics {
  const root = (raw || {}) as {
    metrics?: Record<string, Record<string, unknown>>;
  };
  const metrics = root.metrics || {};

  const getMetricVals = (name: string): Record<string, number> => {
    const m = metrics[name];
    if (!m) return {};
    if (typeof m.values === 'object' && m.values !== null) {
      return m.values as Record<string, number>;
    }
    return m as Record<string, number>;
  };

  const durVals = getMetricVals('http_req_duration');
  const failVals = getMetricVals('http_req_failed');
  const reqVals = getMetricVals('http_reqs');
  const iterVals = getMetricVals('iterations');

  const failedRate =
    failVals['rate'] ??
    failVals['value'] ??
    (typeof failVals['passes'] === 'number' &&
    typeof failVals['fails'] === 'number' &&
    failVals['passes'] + failVals['fails'] > 0
      ? failVals['passes'] / (failVals['passes'] + failVals['fails'])
      : 0);

  return {
    durationAvg: durVals['avg'] ?? 0,
    durationMin: durVals['min'] ?? 0,
    durationMed: durVals['med'] ?? 0,
    durationMax: durVals['max'] ?? 0,
    durationP90: durVals['p(90)'] ?? durVals['p90'] ?? 0,
    durationP95: durVals['p(95)'] ?? durVals['p95'] ?? 0,
    durationP99: durVals['p(99)'] ?? durVals['p99'] ?? 0,
    reqsTotal: reqVals['count'] ?? 0,
    rps: reqVals['rate'] ?? 0,
    failedRate,
    failedCount: failVals['passes'] ?? 0,
    iterations: iterVals['count'] ?? 0,
  };
}

export const SAMPLE_K6_SUMMARY = {
  metrics: {
    http_req_duration: {
      type: 'trend',
      contains: 'time',
      values: {
        avg: 18.5,
        min: 5.2,
        med: 15.0,
        max: 65.4,
        'p(90)': 28.0,
        'p(95)': 38.5,
        'p(99)': 55.2,
      },
    },
    http_req_failed: {
      type: 'rate',
      contains: 'default',
      values: {
        rate: 0.0,
        passes: 0,
        fails: 150,
      },
    },
    http_reqs: {
      type: 'counter',
      contains: 'default',
      values: {
        count: 150,
        rate: 50.0,
      },
    },
    iterations: {
      type: 'counter',
      contains: 'default',
      values: {
        count: 150,
        rate: 50.0,
      },
    },
    vus: {
      type: 'gauge',
      contains: 'default',
      values: {
        value: 5,
        min: 5,
        max: 5,
      },
    },
  },
};

export function generateMockK6Summary(options: {
  targetUrl: string;
  vus: number;
  durationSec: number;
  mockP95Ms?: number;
  customSummary?: Record<string, unknown>;
}): Record<string, unknown> {
  if (options.customSummary) {
    return options.customSummary;
  }

  const isSlow = options.targetUrl.includes('/slow');
  const p95 = options.mockP95Ms ?? (isSlow ? 65.0 : 25.0);
  const med = isSlow ? 55.0 : 15.0;
  const avg = isSlow ? 58.0 : 18.0;
  const max = isSlow ? 85.0 : 45.0;
  const p99 = isSlow ? 78.0 : 38.0;
  const p90 = isSlow ? 62.0 : 22.0;

  const totalReqs = Math.max(options.vus * options.durationSec * 25, 10);
  const rps = totalReqs / Math.max(options.durationSec, 1);
  const isRateLimited = options.targetUrl.includes('/rate-limited');
  const failedRatio = isRateLimited ? 1.0 : 0.0;
  const failedCount = Math.round(totalReqs * failedRatio);

  return {
    metrics: {
      http_req_duration: {
        type: 'trend',
        contains: 'time',
        values: {
          avg,
          min: Math.max(med - 10, 1),
          med,
          max,
          'p(90)': p90,
          'p(95)': p95,
          'p(99)': p99,
        },
      },
      http_req_failed: {
        type: 'rate',
        contains: 'default',
        values: {
          rate: failedRatio,
          passes: failedCount,
          fails: totalReqs - failedCount,
        },
      },
      http_reqs: {
        type: 'counter',
        contains: 'default',
        values: {
          count: totalReqs,
          rate: rps,
        },
      },
      iterations: {
        type: 'counter',
        contains: 'default',
        values: {
          count: totalReqs,
          rate: rps,
        },
      },
      vus: {
        type: 'gauge',
        contains: 'default',
        values: {
          value: options.vus,
          min: options.vus,
          max: options.vus,
        },
      },
    },
  };
}

export class K6ResilienceEngine implements TestEngine {
  readonly id = 'engine-worker-k6';
  readonly version = '1.0.0';
  readonly executionClass = 'class_c_worker' as const;

  constructor(private readonly runner: IDockerRunner = dockerRunner) {}

  capabilities(): TestCapability[] {
    return [
      {
        id: 'k6_load_sla',
        name: 'Grafana k6 Concurrency & Latency SLA Audit',
        category: 'resilience_stress',
        description: 'Evaluates p95/p99 response latency SLAs and request failure ratios under concurrent load',
        isDisruptive: true,
        requiredScopeFlags: ['loadTesting'],
      },
      {
        id: 'k6_stress_soak',
        name: 'Grafana k6 Concurrency Soak Test',
        category: 'resilience_stress',
        description: 'Runs sustained concurrency soak test up to target scope limits to detect performance degradation',
        isDisruptive: true,
        requiredScopeFlags: ['loadTesting'],
      },
    ];
  }

  validate(input: TestInput): ValidationResult {
    try {
      new URL(input.targetUrl);
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
    const opts = (input.options || {}) as K6EngineOptions;

    // 1. Enforce Target Scope Security Boundary (loadTesting authorization)
    if (!context.target.scope.testing.loadTesting) {
      return {
        engineId: this.id,
        durationMs: Date.now() - startTime,
        success: false,
        findings: [],
        metrics: [],
        error: 'Load testing capability is strictly disabled in target security scope. Explicit authorization required.',
      };
    }

    // 2. Enforce Concurrency and Rate Clamps
    const maxAllowedVUs = context.target.scope.limits.maxConcurrency || 20;
    const requestedVUs = opts.vus || 5;
    if (requestedVUs > maxAllowedVUs) {
      return {
        engineId: this.id,
        durationMs: Date.now() - startTime,
        success: false,
        findings: [],
        metrics: [],
        error: `Requested concurrency (${requestedVUs} VUs) exceeds target scope safety limit of ${maxAllowedVUs} VUs`,
      };
    }

    const durationSec = Math.min(opts.durationSec || 3, 30);
    const maxP95Ms = opts.maxP95Ms ?? 500;
    const maxFailedRatio = opts.maxFailedRatio ?? 0.05;

    context.reportProgress(
      15,
      `Initializing Grafana k6 runner: ${requestedVUs} concurrent VUs for ${durationSec}s...`,
    );

    // 3. Ephemeral Scratch Directory for Script and Summary Transport
    const scratch = await createScratchDirectory('k6');
    const scriptPath = path.join(scratch.path, 'script.js');
    const summaryPath = path.join(scratch.path, 'summary.json');

    // Reject simulation outside test environment
    const isSimulatedRequested = opts.simulated === true;
    if (isSimulatedRequested && process.env.NODE_ENV !== 'test') {
      throw new EngineExecutionError(
        'Simulated scanner execution is disabled in production',
        this.id,
      );
    }

    const image = (opts.dockerImage as string) || process.env.K6_IMAGE || 'grafana/k6:latest';
    const isSimulated =
      process.env.NODE_ENV === 'test' &&
      (isSimulatedRequested || process.env.SECURITY_LAB_MOCK_CONTAINERS === 'true');

    let rawJson: unknown;

    try {
      // 4. Generate executable k6 ES module script
      const scriptCode = buildK6Script({
        targetUrl: input.targetUrl,
        vus: requestedVUs,
        durationSec,
        stages: opts.stages,
        thresholds: opts.thresholds,
        maxP95Ms,
        maxFailedRatio,
        headers: input.customHeaders,
        scenarioType: opts.scenarioType,
      });

      await fs.promises.writeFile(scriptPath, scriptCode, 'utf-8');

      const mockSummary = generateMockK6Summary({
        targetUrl: input.targetUrl,
        vus: requestedVUs,
        durationSec,
        mockP95Ms: opts.mockP95Ms,
        customSummary: opts.mockSummary,
      });

      if (isSimulated) {
        await fs.promises.writeFile(summaryPath, JSON.stringify(mockSummary), 'utf-8');
      }

      context.reportProgress(30, 'Dispatching container runner for Grafana k6 load test...');

      // 5. Execute container runner enforcing Rule 8 resource limits (512m memory, 1.0 CPU)
      const runResult = await this.runner.execute({
        image,
        args: ['run', '--summary-export=/scripts/summary.json', '/scripts/script.js'],
        volumes: [
          {
            hostPath: scratch.path,
            containerPath: '/scripts',
            mode: 'rw',
          },
        ],
        memoryLimit: '512m',
        cpuLimit: '1.0',
        user: '12345:12345',
        timeoutMs: Math.max((durationSec + 15) * 1000, input.timeoutMs || 60000),
        abortSignal: context.abortSignal,
        simulated: isSimulated,
        mockStdout: JSON.stringify(mockSummary),
      });

      // 6. Transport & Parse Summary JSON
      if (fs.existsSync(summaryPath)) {
        try {
          const reportRaw = await fs.promises.readFile(summaryPath, 'utf-8');
          rawJson = JSON.parse(reportRaw);
        } catch (parseErr: unknown) {
          if (runResult.simulated) {
            rawJson = mockSummary;
          } else {
            const parseMsg = parseErr instanceof Error ? parseErr.message : String(parseErr);
            throw new TestEngineError(`Failed to parse Grafana k6 summary.json: ${parseMsg}`, this.id, parseErr);
          }
        }
      } else {
        if (runResult.simulated) {
          rawJson = mockSummary;
        } else {
          throw new TestEngineError(
            `Grafana k6 container finished (exit code ${runResult.exitCode}) but failed to produce summary.json at /scripts/summary.json. Output: ${runResult.stderr || runResult.stdout || 'None'}`,
            this.id,
          );
        }
      }
    } catch (err: unknown) {
      if (opts.throwOnError) {
        throw err;
      }
      const msg = err instanceof Error ? err.message : String(err);
      return {
        engineId: this.id,
        durationMs: Date.now() - startTime,
        success: false,
        findings: [],
        metrics: [],
        error: `Load test execution failed: ${msg}`,
      };
    } finally {
      // 7. Clean up ephemeral scratch directory
      await scratch.destroy();
    }

    context.reportProgress(80, 'Analyzing k6 latency percentiles against SLA thresholds...');

    // 8. Canonical Metrics Mapping
    const stats = parseK6Summary(rawJson);

    const findings: RawEngineFinding[] = [];
    const metrics: RawEngineMetric[] = [
      { name: 'http_req_duration_p95', value: Math.round(stats.durationP95), unit: 'ms' },
      { name: 'http_req_duration_p99', value: Math.round(stats.durationP99), unit: 'ms' },
      { name: 'http_req_duration_med', value: Math.round(stats.durationMed), unit: 'ms' },
      { name: 'http_req_duration_avg', value: Math.round(stats.durationAvg), unit: 'ms' },
      { name: 'http_req_duration_max', value: Math.round(stats.durationMax), unit: 'ms' },
      { name: 'http_reqs_total', value: stats.reqsTotal, unit: 'count' },
      { name: 'http_req_failed_ratio', value: parseFloat((stats.failedRate * 100).toFixed(2)), unit: '%' },
      { name: 'http_rps', value: parseFloat(stats.rps.toFixed(1)), unit: 'rps' },
    ];

    // 9. Evaluate Latency SLA (P95)
    if (stats.reqsTotal > 0 && stats.durationP95 > maxP95Ms) {
      const isSevere = stats.durationP95 > maxP95Ms * 2;
      findings.push({
        title: `Latency SLA Breach: P95 Response Time (${Math.round(stats.durationP95)}ms > ${maxP95Ms}ms)`,
        category: 'performance',
        severity: isSevere ? 'high' : 'medium',
        description: `Target endpoint exceeded the maximum allowable p95 response time threshold under load of ${requestedVUs} concurrent VUs. Actual p95 was ${Math.round(stats.durationP95)}ms (threshold: ${maxP95Ms}ms).`,
        recommendation: 'Optimize backend query efficiency, implement HTTP caching headers, or provision additional service replicas.',
        evidence: {
          request: { method: 'GET', url: input.targetUrl, headers: input.customHeaders || {} },
          expected: `P95 <= ${maxP95Ms}ms`,
          actual: `P95 = ${Math.round(stats.durationP95)}ms (median: ${Math.round(stats.durationMed)}ms, max: ${Math.round(stats.durationMax)}ms, throughput: ${stats.rps.toFixed(1)} req/s)`,
        },
        metadata: {
          vus: requestedVUs,
          p95Ms: stats.durationP95,
          slaThresholdMs: maxP95Ms,
        },
      });
    }

    // 10. Evaluate Error Rate SLA
    if (stats.reqsTotal > 0 && stats.failedRate > maxFailedRatio) {
      findings.push({
        title: `Excessive Request Failure Rate Under Load (${(stats.failedRate * 100).toFixed(1)}%)`,
        category: 'resilience',
        severity: 'high',
        description: `Target experienced high failure rates (${stats.failedCount} failed out of ${stats.reqsTotal} total requests, ${(stats.failedRate * 100).toFixed(1)}%) during concurrency testing.`,
        recommendation: 'Inspect backend error logs, check connection pool saturation, and implement circuit breakers.',
        evidence: {
          request: { method: 'GET', url: input.targetUrl, headers: input.customHeaders || {} },
          expected: `Failure rate <= ${(maxFailedRatio * 100).toFixed(1)}%`,
          actual: `Failure rate = ${(stats.failedRate * 100).toFixed(1)}% (${stats.failedCount}/${stats.reqsTotal} failed)`,
        },
      });
    }

    context.reportProgress(100, `k6 SLA audit complete: p95=${Math.round(stats.durationP95)}ms, ${findings.length} findings.`);

    return {
      engineId: this.id,
      durationMs: Date.now() - startTime,
      success: findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length === 0,
      findings,
      metrics,
      rawOutput: stats,
    };
  }
}
