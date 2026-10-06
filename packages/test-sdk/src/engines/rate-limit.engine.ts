import { TestEngine } from '../engine.js';
import { TestCapability } from '../capability.js';
import { ExecutionContext } from '../context.js';
import { TestInput, TestResult, ValidationResult, RawEngineFinding } from '../result.js';
import { safeFetch } from '../http/index.js';

export class RateLimitResilienceEngine implements TestEngine {
  readonly id = 'engine-native-resilience';
  readonly version = '1.0.0';
  readonly executionClass = 'class_a_native' as const;

  capabilities(): TestCapability[] {
    return [
      {
        id: 'rate_limit_audit',
        name: 'API Rate Limiting & Throttling Audit',
        category: 'protocol_audit',
        description: 'Audits endpoint resilience against rapid burst requests and verifies HTTP 429 rate limiting defenses',
        isDisruptive: false,
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
    const burstCount = Math.min(context.target.scope.limits.maxRps || 30, 15);

    context.reportProgress(20, `Dispatching rapid burst check (${burstCount} requests) for rate limiting audit...`);

    const findings: RawEngineFinding[] = [];
    const responses: { status: number; headers: Record<string, string> }[] = [];

    // Send burst of requests concurrently
    const promises = Array.from({ length: burstCount }, async () => {
      try {
        const res = await safeFetch(input.targetUrl, {
          method: 'GET',
          headers: {
            'User-Agent': 'SecurityLab-ResilienceQA/1.0',
            Accept: '*/*',
            ...input.customHeaders,
          },
          signal: context.abortSignal,
          scope: context.target?.scope,
        });

        const headerMap: Record<string, string> = {};
        res.headers.forEach((val, key) => {
          headerMap[key.toLowerCase()] = val;
        });

        return { status: res.status, headers: headerMap };
      } catch {
        return null;
      }
    });

    const results = await Promise.all(promises);
    for (const r of results) {
      if (r) responses.push(r);
    }

    context.reportProgress(70, 'Analyzing rate limiting response headers and throttling status codes...');

    const rateLimitHeaders = ['x-ratelimit-limit', 'x-ratelimit-remaining', 'ratelimit-limit', 'retry-after'];
    const hasRateLimitHeader = responses.some((r) =>
      rateLimitHeaders.some((h) => r.headers[h] !== undefined),
    );
    const hasThrottledResponse = responses.some((r) => r.status === 429);

    if (!hasRateLimitHeader && !hasThrottledResponse) {
      findings.push({
        title: 'Missing API Rate Limiting / Abuse Protection',
        category: 'rate_limiting',
        severity: 'medium',
        description: `Target processed all ${responses.length} concurrent burst requests without emitting rate limiting headers (X-RateLimit-Limit) or HTTP 429 Too Many Requests responses.`,
        recommendation: 'Implement rate limiting middleware (e.g. sliding window algorithm) and return HTTP 429 with Retry-After header.',
        evidence: {
          request: { method: 'GET', url: input.targetUrl, headers: input.customHeaders || {} },
          expected: 'HTTP 429 or X-RateLimit headers present during request burst',
          actual: `All ${responses.length} requests returned HTTP 200 without rate-limit headers`,
        },
      });
    }

    context.reportProgress(100, `Rate limit audit completed: ${findings.length} findings.`);

    return {
      engineId: this.id,
      durationMs: Date.now() - startTime,
      success: true,
      findings,
      metrics: [
        {
          name: 'rate_limiting_enforced',
          value: hasRateLimitHeader || hasThrottledResponse ? 1 : 0,
          unit: 'boolean',
        },
        {
          name: 'burst_requests_evaluated',
          value: responses.length,
          unit: 'count',
        },
      ],
      rawOutput: {
        totalBurst: burstCount,
        successfulResponses: responses.length,
        hasRateLimitHeader,
        hasThrottledResponse,
      },
    };
  }
}
