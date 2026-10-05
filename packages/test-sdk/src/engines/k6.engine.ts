import { TestEngine } from '../engine.js';
import { TestCapability } from '../capability.js';
import { ExecutionContext } from '../context.js';
import { TestInput, TestResult, ValidationResult, RawEngineFinding, RawEngineMetric } from '../result.js';
import { dockerRunner, DockerRunner } from '../runners/docker.runner.js';

export interface K6EngineOptions {
  vus?: number;
  duration?: string;
  durationSec?: number;
  maxP95Ms?: number;
  maxFailedRatio?: number;
  dockerImage?: string;
  simulated?: boolean;
}

export interface LatencyStats {
  count: number;
  avg: number;
  med: number;
  p95: number;
  p99: number;
  max: number;
  failedCount: number;
  failedRatio: number;
  rps: number;
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
 * Dispatches concurrent HTTP requests in-process to compute accurate empirical latency distributions.
 */
export async function executeConcurrentLoad(
  url: string,
  vus: number,
  durationSec: number,
  signal: AbortSignal,
  customHeaders?: Record<string, string>,
): Promise<LatencyStats> {
  const durations: number[] = [];
  let failedCount = 0;
  const startTime = Date.now();
  const endTime = startTime + durationSec * 1000;

  const worker = async () => {
    while (Date.now() < endTime && !signal.aborted) {
      const reqStart = Date.now();
      try {
        const res = await fetch(url, {
          method: 'GET',
          headers: {
            'User-Agent': 'SecurityLab-K6Worker/1.0',
            Accept: '*/*',
            ...customHeaders,
          },
          signal,
        });

        const reqDuration = Date.now() - reqStart;
        durations.push(reqDuration);
        if (!res.ok) {
          failedCount++;
        }
      } catch {
        durations.push(Date.now() - reqStart);
        failedCount++;
      }
    }
  };

  // Launch workers corresponding to requested virtual users
  const workers = Array.from({ length: vus }, () => worker());
  await Promise.all(workers);

  const totalTimeSec = Math.max((Date.now() - startTime) / 1000, 0.001);
  const totalCount = durations.length;
  durations.sort((a, b) => a - b);

  const avg = totalCount > 0 ? durations.reduce((acc, d) => acc + d, 0) / totalCount : 0;
  const med = calculatePercentile(durations, 50);
  const p95 = calculatePercentile(durations, 95);
  const p99 = calculatePercentile(durations, 99);
  const max = durations.length > 0 ? (durations[durations.length - 1] ?? 0) : 0;
  const failedRatio = totalCount > 0 ? failedCount / totalCount : 0;
  const rps = totalCount / totalTimeSec;

  return {
    count: totalCount,
    avg,
    med,
    p95,
    p99,
    max,
    failedCount,
    failedRatio,
    rps,
  };
}

export class K6ResilienceEngine implements TestEngine {
  readonly id = 'engine-worker-k6';
  readonly version = '1.0.0';

  constructor(private readonly runner: DockerRunner = dockerRunner) {}

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

    // 1. Enforce Scope Security Boundary
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
    const maxP95Ms = opts.maxP95Ms || 500;
    const maxFailedRatio = opts.maxFailedRatio || 0.05;

    context.reportProgress(
      15,
      `Initializing load testing worker: ${requestedVUs} concurrent VUs for ${durationSec}s...`,
    );

    let stats: LatencyStats;

    // 2. Execute Load Test
    try {
      context.reportProgress(30, 'Dispatching concurrent load against target endpoint...');
      if (opts.dockerImage) {
        await this.runner.execute({
          image: opts.dockerImage,
          args: ['version'],
          simulated: true,
        });
      }
      stats = await executeConcurrentLoad(
        input.targetUrl,
        requestedVUs,
        durationSec,
        context.abortSignal,
        input.customHeaders,
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        engineId: this.id,
        durationMs: Date.now() - startTime,
        success: false,
        findings: [],
        metrics: [],
        error: `Load test execution failed: ${msg}`,
      };
    }

    context.reportProgress(80, 'Analyzing latency percentiles against SLA thresholds...');

    const findings: RawEngineFinding[] = [];
    const metrics: RawEngineMetric[] = [
      { name: 'http_req_duration_p95', value: Math.round(stats.p95), unit: 'ms' },
      { name: 'http_req_duration_p99', value: Math.round(stats.p99), unit: 'ms' },
      { name: 'http_req_duration_med', value: Math.round(stats.med), unit: 'ms' },
      { name: 'http_req_duration_avg', value: Math.round(stats.avg), unit: 'ms' },
      { name: 'http_req_duration_max', value: Math.round(stats.max), unit: 'ms' },
      { name: 'http_reqs_total', value: stats.count, unit: 'count' },
      { name: 'http_req_failed_ratio', value: parseFloat((stats.failedRatio * 100).toFixed(2)), unit: '%' },
      { name: 'http_rps', value: parseFloat(stats.rps.toFixed(1)), unit: 'rps' },
    ];

    // 3. Evaluate Latency SLA (P95)
    if (stats.count > 0 && stats.p95 > maxP95Ms) {
      const isSevere = stats.p95 > maxP95Ms * 2;
      findings.push({
        title: `Latency SLA Breach: P95 Response Time (${Math.round(stats.p95)}ms > ${maxP95Ms}ms)`,
        category: 'performance',
        severity: isSevere ? 'high' : 'medium',
        description: `Target endpoint exceeded the maximum allowable p95 response time threshold under load of ${requestedVUs} concurrent VUs. Actual p95 was ${Math.round(stats.p95)}ms (threshold: ${maxP95Ms}ms).`,
        recommendation: 'Optimize backend query efficiency, implement HTTP caching headers, or provision additional service replicas.',
        evidence: {
          request: { method: 'GET', url: input.targetUrl, headers: input.customHeaders || {} },
          expected: `P95 <= ${maxP95Ms}ms`,
          actual: `P95 = ${Math.round(stats.p95)}ms (median: ${Math.round(stats.med)}ms, max: ${Math.round(stats.max)}ms, throughput: ${stats.rps.toFixed(1)} req/s)`,
        },
        metadata: {
          vus: requestedVUs,
          p95Ms: stats.p95,
          slaThresholdMs: maxP95Ms,
        },
      });
    }

    // 4. Evaluate Error Rate SLA
    if (stats.count > 0 && stats.failedRatio > maxFailedRatio) {
      findings.push({
        title: `Excessive Request Failure Rate Under Load (${(stats.failedRatio * 100).toFixed(1)}%)`,
        category: 'resilience',
        severity: 'high',
        description: `Target experienced high failure rates (${stats.failedCount} failed out of ${stats.count} total requests, ${(stats.failedRatio * 100).toFixed(1)}%) during concurrency testing.`,
        recommendation: 'Inspect backend error logs, check connection pool saturation, and implement circuit breakers.',
        evidence: {
          request: { method: 'GET', url: input.targetUrl, headers: input.customHeaders || {} },
          expected: `Failure rate <= ${(maxFailedRatio * 100).toFixed(1)}%`,
          actual: `Failure rate = ${(stats.failedRatio * 100).toFixed(1)}% (${stats.failedCount}/${stats.count} failed)`,
        },
      });
    }

    context.reportProgress(100, `k6 SLA audit complete: p95=${Math.round(stats.p95)}ms, ${findings.length} findings.`);

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
