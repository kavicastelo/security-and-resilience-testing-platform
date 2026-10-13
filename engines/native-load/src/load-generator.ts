import http from 'http';
import https from 'https';
import { URL } from 'url';
import { performance } from 'perf_hooks';
import { createLogger } from '@security-lab/logger';
import { LatencyHistogram } from './histogram.js';
import {
  LoadProfile,
  LoadExecutionSummary,
  LiveLoadTick,
} from './types.js';

const logger = createLogger({ name: 'engine-native-load' });

const LOCALHOST_MAX_SAFETY_RPS = 5000; // Rule 13: Cap localhost load generation to 5,000 RPS
const CONSECUTIVE_5XX_BREAKER_THRESHOLD = 25; // Circuit breaker threshold

export interface LoadGeneratorCallbacks {
  onTick?: (tick: LiveLoadTick) => void;
  shouldAbort?: () => boolean;
}

export function isLocalhost(hostname: string): boolean {
  return (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '::1' ||
    hostname.startsWith('127.')
  );
}

/**
 * High-performance native HTTP load generation engine
 */
export async function executeLoadProfile(
  targetBaseUrl: string,
  profile: LoadProfile,
  callbacks: LoadGeneratorCallbacks = {},
): Promise<LoadExecutionSummary> {
  const baseUrlObj = new URL(targetBaseUrl);
  let finalPath = baseUrlObj.pathname;
  if (profile.path && profile.path !== '/') {
    finalPath = profile.path.startsWith('/') ? profile.path : `/${profile.path}`;
  }
  const parsedUrl = new URL(finalPath, baseUrlObj.origin);
  if (baseUrlObj.search && !parsedUrl.search) {
    parsedUrl.search = baseUrlObj.search;
  }
  const isHttps = parsedUrl.protocol === 'https:';
  const isLocal = isLocalhost(parsedUrl.hostname);

  // Enforce Rule 13 localhost safety ceiling
  let effectiveMaxRps = profile.rateLimit;
  if (isLocal) {
    if (!effectiveMaxRps || effectiveMaxRps > LOCALHOST_MAX_SAFETY_RPS) {
      effectiveMaxRps = LOCALHOST_MAX_SAFETY_RPS;
      logger.info(
        { effectiveMaxRps: LOCALHOST_MAX_SAFETY_RPS },
        'Applied localhost safety cap (maximum 5,000 RPS)',
      );
    }
  }

  const durationMs = (profile.durationSec || 10) * 1000;
  const targetConnections = Math.max(1, Math.min(200, profile.connections || 10));

  const histogram = new LatencyHistogram();
  const statusCodes: Record<string, number> = {};

  let totalRequests = 0;
  let successfulRequests = 0;
  let failedRequests = 0;
  let bytesTransferred = 0;
  let consecutive5xxErrors = 0;
  let circuitBroken = false;

  const agent = isHttps
    ? new https.Agent({
        keepAlive: true,
        maxSockets: targetConnections,
        maxFreeSockets: targetConnections,
        rejectUnauthorized: false,
        timeout: profile.timeoutMs || 10000,
      })
    : new http.Agent({
        keepAlive: true,
        maxSockets: targetConnections,
        maxFreeSockets: targetConnections,
        timeout: profile.timeoutMs || 10000,
      });

  const method = (profile.method || 'GET').toUpperCase();
  const headers: Record<string, string> = {
    Accept: 'application/json, text/plain, */*',
    'User-Agent': 'SecurityLab-NativeLoad/1.0',
    ...(profile.headers || {}),
  };

  let bodyBuffer: Buffer | undefined = undefined;
  if (profile.body !== undefined) {
    const rawBody = typeof profile.body === 'string' ? profile.body : JSON.stringify(profile.body);
    bodyBuffer = Buffer.from(rawBody, 'utf-8');
    if (!headers['Content-Type'] && !headers['content-type']) {
      headers['Content-Type'] = 'application/json';
    }
    headers['Content-Length'] = String(bodyBuffer.length);
  }

  const requestOptions: http.RequestOptions = {
    protocol: parsedUrl.protocol,
    hostname: parsedUrl.hostname,
    port: parsedUrl.port || (isHttps ? 443 : 80),
    path: parsedUrl.pathname + parsedUrl.search,
    method,
    headers,
    agent,
    timeout: profile.timeoutMs || 10000,
  };

  logger.info(
    {
      target: parsedUrl.origin,
      path: requestOptions.path,
      connections: targetConnections,
      durationSec: profile.durationSec,
      rateLimit: effectiveMaxRps,
    },
    'Starting native load generation worker',
  );

  const startTime = performance.now();
  const endTime = startTime + durationMs;

  let lastTickTime = startTime;
  let lastTickRequests = 0;
  let isRunning = true;

  // Live telemetry timer (emits stats every 1 second)
  const statsInterval = setInterval(() => {
    if (!isRunning) return;
    const now = performance.now();
    const intervalSec = (now - lastTickTime) / 1000;
    const intervalReqs = totalRequests - lastTickRequests;
    const intervalRps = intervalSec > 0 ? Math.round(intervalReqs / intervalSec) : 0;
    const elapsedSec = Math.round((now - startTime) / 1000);

    const tick: LiveLoadTick = {
      timestamp: Date.now(),
      elapsedSec,
      intervalRequests: intervalReqs,
      intervalRps,
      totalRequests,
      totalErrors: failedRequests,
      currentP95Ms: histogram.getPercentile(95),
      currentAvgMs: histogram.avg,
    };

    logger.info(
      `[Live Load] ${elapsedSec}s: ${intervalRps} req/s (Total: ${totalRequests}, Errors: ${failedRequests}, Avg: ${tick.currentAvgMs}ms, P95: ${tick.currentP95Ms}ms)`,
    );

    if (callbacks.onTick) {
      callbacks.onTick(tick);
    }

    lastTickTime = now;
    lastTickRequests = totalRequests;
  }, 1000);

  // Rate Limiting Token Bucket
  let tokens = effectiveMaxRps ? effectiveMaxRps : Infinity;
  let lastTokenRefill = performance.now();

  function acquireToken(): boolean {
    if (!effectiveMaxRps) return true;
    const now = performance.now();
    const elapsed = (now - lastTokenRefill) / 1000;
    if (elapsed >= 0.1) {
      tokens = effectiveMaxRps * elapsed;
      lastTokenRefill = now;
    }
    if (tokens >= 1) {
      tokens -= 1;
      return true;
    }
    return false;
  }

  // Determine active concurrency based on profile type & stages
  function getActiveConcurrency(now: number): number {
    const elapsedSec = (now - startTime) / 1000;

    // 1. Stage-based ramping
    if (profile.stages && profile.stages.length > 0) {
      let cumulative = 0;
      for (const stage of profile.stages) {
        cumulative += stage.durationSec;
        if (elapsedSec <= cumulative) {
          return stage.targetConnections;
        }
      }
      const lastStage = profile.stages[profile.stages.length - 1];
      return lastStage ? lastStage.targetConnections : targetConnections;
    }

    // 2. Linear ramping profile
    if (profile.type === 'ramping') {
      const progress = Math.min(1, elapsedSec / (profile.durationSec || 10));
      const startConns = Math.max(1, Math.floor(targetConnections * 0.2));
      return Math.round(startConns + (targetConnections - startConns) * progress);
    }

    // 3. Constant or Spike
    return targetConnections;
  }

  // Single request executor
  const client = isHttps ? https : http;

  const dispatchSingleRequest = (): Promise<void> => {
    return new Promise<void>((resolve) => {
      const reqStart = performance.now();

      const req = client.request(requestOptions, (res) => {
        let bytes = 0;
        res.on('data', (chunk: Buffer) => {
          bytes += chunk.length;
        });

        res.on('end', () => {
          const reqEnd = performance.now();
          const latencyMs = reqEnd - reqStart;
          histogram.record(latencyMs);

          totalRequests++;
          bytesTransferred += bytes;

          const code = String(res.statusCode || 0);
          statusCodes[code] = (statusCodes[code] || 0) + 1;

          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 400) {
            successfulRequests++;
            consecutive5xxErrors = 0;
          } else {
            failedRequests++;
            if (res.statusCode && res.statusCode >= 500) {
              consecutive5xxErrors++;
              if (consecutive5xxErrors >= CONSECUTIVE_5XX_BREAKER_THRESHOLD) {
                circuitBroken = true;
                isRunning = false;
                logger.warn(
                  { consecutive5xxErrors },
                  'Circuit breaker tripped: Target returned continuous 500 errors. Halting load.',
                );
              }
            }
          }
          resolve();
        });
      });

      req.on('error', () => {
        const reqEnd = performance.now();
        histogram.record(reqEnd - reqStart);
        totalRequests++;
        failedRequests++;
        consecutive5xxErrors++;
        statusCodes['error'] = (statusCodes['error'] || 0) + 1;
        if (consecutive5xxErrors >= CONSECUTIVE_5XX_BREAKER_THRESHOLD) {
          circuitBroken = true;
          isRunning = false;
        }
        resolve();
      });

      req.on('timeout', () => {
        req.destroy(new Error('Request timeout'));
      });

      if (bodyBuffer) {
        req.write(bodyBuffer);
      }
      req.end();
    });
  };

  // Connection worker loop
  const runWorkerConnection = async (workerId: number) => {
    while (isRunning) {
      const now = performance.now();
      if (now >= endTime || circuitBroken) {
        break;
      }

      if (callbacks.shouldAbort && callbacks.shouldAbort()) {
        logger.info('Load generation aborted by execution context');
        break;
      }

      const activeConns = getActiveConcurrency(now);
      if (workerId >= activeConns) {
        // This connection is inactive in the current stage, wait briefly
        await new Promise((resolve) => setTimeout(resolve, 50));
        continue;
      }

      if (effectiveMaxRps && !acquireToken()) {
        await new Promise((resolve) => setTimeout(resolve, 5));
        continue;
      }

      await dispatchSingleRequest();
    }
  };

  // Launch initial concurrency pool
  try {
    const workers = Array.from({ length: targetConnections }, (_, i) => runWorkerConnection(i));
    await Promise.all(workers);
  } finally {
    isRunning = false;
    clearInterval(statsInterval);
    agent.destroy();
  }

  const finalDurationSec = Math.max(0.001, (performance.now() - startTime) / 1000);
  const rps = Math.round((totalRequests / finalDurationSec) * 100) / 100;
  const errorRate = totalRequests > 0 ? Math.round((failedRequests / totalRequests) * 10000) / 10000 : 0;
  const latencySummary = histogram.getSummary();

  // Evaluate SLO Thresholds
  const sloViolations: string[] = [];
  const th = profile.thresholds;
  if (th) {
    if (th.maxP50Ms !== undefined && latencySummary.p50 > th.maxP50Ms) {
      sloViolations.push(`P50 latency of ${latencySummary.p50}ms exceeded threshold of ${th.maxP50Ms}ms`);
    }
    if (th.maxP90Ms !== undefined && latencySummary.p90 > th.maxP90Ms) {
      sloViolations.push(`P90 latency of ${latencySummary.p90}ms exceeded threshold of ${th.maxP90Ms}ms`);
    }
    if (th.maxP95Ms !== undefined && latencySummary.p95 > th.maxP95Ms) {
      sloViolations.push(`P95 latency of ${latencySummary.p95}ms exceeded threshold of ${th.maxP95Ms}ms`);
    }
    if (th.maxP99Ms !== undefined && latencySummary.p99 > th.maxP99Ms) {
      sloViolations.push(`P99 latency of ${latencySummary.p99}ms exceeded threshold of ${th.maxP99Ms}ms`);
    }
    if (th.maxP999Ms !== undefined && latencySummary.p999 > th.maxP999Ms) {
      sloViolations.push(`P99.9 latency of ${latencySummary.p999}ms exceeded threshold of ${th.maxP999Ms}ms`);
    }
    if (th.minRps !== undefined && rps < th.minRps) {
      sloViolations.push(`Throughput of ${rps} RPS was below required threshold of ${th.minRps} RPS`);
    }
    if (th.maxErrorRate !== undefined && errorRate > th.maxErrorRate) {
      sloViolations.push(`Error rate of ${(errorRate * 100).toFixed(2)}% exceeded maximum allowable threshold of ${(th.maxErrorRate * 100).toFixed(2)}%`);
    }
  }

  const sloPassed = sloViolations.length === 0;

  logger.info(
    {
      totalRequests,
      successfulRequests,
      failedRequests,
      rps,
      p50: latencySummary.p50,
      p95: latencySummary.p95,
      p99: latencySummary.p99,
      sloPassed,
      violationsCount: sloViolations.length,
    },
    'Native load generation execution completed',
  );

  return {
    totalRequests,
    successfulRequests,
    failedRequests,
    errorRate,
    durationSec: Math.round(finalDurationSec * 100) / 100,
    rps,
    bytesTransferred,
    statusCodes,
    latency: latencySummary,
    sloPassed,
    sloViolations,
  };
}
