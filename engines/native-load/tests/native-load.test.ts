import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import {
  nativeLoadEngine,
  LatencyHistogram,
  executeLoadProfile,
} from '../src/index.js';
import { executeSandboxedEngine } from '@security-lab/test-runner';
import { evaluatePolicy } from '@security-lab/policy-engine';
import { Policy } from '@security-lab/domain';

describe('Phase 09: Native Performance Engineering & Capacity Benchmarking', () => {
  let server: http.Server;
  let serverPort: number;
  let serverBaseUrl: string;

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      const url = new URL(req.url || '/', `http://127.0.0.1`);

      // 1. Slow endpoint for SLO breach testing
      if (url.pathname === '/api/slow') {
        setTimeout(() => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'ok', delayMs: 30 }));
        }, 30);
        return;
      }

      // 2. Continuous 500 endpoint for circuit breaker testing
      if (url.pathname === '/api/failing') {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal Server Error' }));
        return;
      }

      // 3. Fast baseline endpoint
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', timestamp: Date.now() }));
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address() as any;
        serverPort = addr.port;
        serverBaseUrl = `http://127.0.0.1:${serverPort}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  describe('1. LatencyHistogram Distribution & Statistical Math', () => {
    it('computes exact empirical percentiles, min, max, avg, and standard deviation', () => {
      const hist = new LatencyHistogram();

      // Feed known dataset: 1 to 100
      for (let i = 1; i <= 100; i++) {
        hist.record(i);
      }

      expect(hist.count).toBe(100);
      expect(hist.min).toBe(1);
      expect(hist.max).toBe(100);
      expect(hist.avg).toBe(50.5);
      expect(hist.getPercentile(50)).toBe(50.5);
      expect(hist.getPercentile(90)).toBe(90.1);
      expect(hist.getPercentile(95)).toBe(95.05);
      expect(hist.getPercentile(99)).toBe(99.01);
      expect(hist.getPercentile(99.9)).toBe(99.9);
      expect(hist.stdDev).toBeGreaterThan(28);
    });

    it('handles empty histogram gracefully', () => {
      const hist = new LatencyHistogram();
      expect(hist.count).toBe(0);
      expect(hist.min).toBe(0);
      expect(hist.max).toBe(0);
      expect(hist.avg).toBe(0);
      expect(hist.getPercentile(99)).toBe(0);
    });
  });

  describe('2. Engine Metadata & Protocol Validation', () => {
    it('declares valid engine metadata and native capabilities', () => {
      expect(nativeLoadEngine.id).toBe('engine-native-load');
      expect(nativeLoadEngine.version).toBe('1.0.0');
      expect(nativeLoadEngine.executionClass).toBe('class_a_native');

      const capabilities = nativeLoadEngine.capabilities();
      expect(capabilities.length).toBe(3);
      expect(capabilities.map((c) => c.id)).toContain('native_capacity_benchmarking');
      expect(capabilities.map((c) => c.id)).toContain('latency_percentiles_hdr');
      expect(capabilities.map((c) => c.id)).toContain('performance_slo_enforcement');
    });

    it('validates target URL format', () => {
      expect(nativeLoadEngine.validate({ targetUrl: serverBaseUrl, options: {} }).valid).toBe(true);
      expect(nativeLoadEngine.validate({ targetUrl: 'ws://invalid', options: {} }).valid).toBe(false);
    });
  });

  describe('3. High-Throughput Load Generation & Benchmarking', () => {
    it('achieves >= 2,000 RPS on localhost without Docker', async () => {
      const summary = await executeLoadProfile(serverBaseUrl, {
        type: 'constant',
        durationSec: 1.5,
        connections: 25,
      });

      expect(summary.totalRequests).toBeGreaterThanOrEqual(1500);
      expect(summary.rps).toBeGreaterThanOrEqual(2000); // Acceptance criteria: >= 2,000 RPS
      expect(summary.errorRate).toBe(0);
      expect(summary.successfulRequests).toBe(summary.totalRequests);
      expect(summary.latency.p50).toBeGreaterThanOrEqual(0);
      expect(summary.latency.p95).toBeGreaterThanOrEqual(summary.latency.p50);
      expect(summary.latency.p99).toBeGreaterThanOrEqual(summary.latency.p95);
    });

    it('supports stepped ramping profile with stages', async () => {
      const summary = await executeLoadProfile(serverBaseUrl, {
        type: 'ramping',
        durationSec: 2,
        connections: 20,
        stages: [
          { durationSec: 1, targetConnections: 5 },
          { durationSec: 1, targetConnections: 20 },
        ],
      });

      expect(summary.totalRequests).toBeGreaterThan(500);
      expect(summary.rps).toBeGreaterThan(500);
    });
  });

  describe('4. Performance SLO Enforcement & Finding Generation', () => {
    it('emits a Performance SLO Breach finding when p99 latency threshold is exceeded', async () => {
      const result = await nativeLoadEngine.execute(
        {
          targetUrl: `${serverBaseUrl}/api/slow`,
          options: {
            durationSec: 1,
            connections: 5,
            thresholds: {
              maxP99Ms: 15, // Server takes 30ms, so threshold will breach!
            },
          },
        },
        {
          runId: 'run-slo-breach',
          engineId: 'engine-native-load',
          target: { id: 'target-1', url: serverBaseUrl },
        },
      );

      expect(result.success).toBe(true);
      const sloFinding = result.findings.find((f) => f.title.includes('Performance SLO Breach'));
      expect(sloFinding).toBeDefined();
      expect(sloFinding?.severity).toBe('high');
      expect(sloFinding?.category).toBe('performance');
      expect(sloFinding?.description).toContain('P99 latency');

      // Verify quantitative metrics
      const p99Metric = result.metrics.find((m) => m.name === 'http_req_duration_p99');
      expect(p99Metric).toBeDefined();
      expect(p99Metric!.value).toBeGreaterThanOrEqual(25);
    });

    it('passes with zero findings when latency satisfies SLO thresholds', async () => {
      const result = await nativeLoadEngine.execute(
        {
          targetUrl: serverBaseUrl,
          options: {
            durationSec: 1,
            connections: 10,
            thresholds: {
              maxP99Ms: 250, // Generous threshold for fast endpoint
              maxErrorRate: 0.05,
            },
          },
        },
        {
          runId: 'run-slo-pass',
          engineId: 'engine-native-load',
          target: { id: 'target-1', url: serverBaseUrl },
        },
      );

      expect(result.success).toBe(true);
      expect(result.findings.length).toBe(0);
    });
  });

  describe('5. Target Scope Invariants & Circuit Breaker', () => {
    it('strictly prohibits execution when loadTesting is false in target scope', async () => {
      const result = await nativeLoadEngine.execute(
        { targetUrl: serverBaseUrl, options: { durationSec: 1, connections: 5 } },
        {
          runId: 'run-scope-forbidden',
          engineId: 'engine-native-load',
          target: {
            id: 'target-scope',
            url: serverBaseUrl,
            scope: {
              allowedHosts: ['127.0.0.1'],
              allowedPorts: [serverPort],
              excludedPaths: [],
              testing: {
                activeScanning: true,
                loadTesting: false, // Prohibited!
                chaosTesting: false,
              },
              limits: { maxRps: 50, maxConcurrency: 10, maxDuration: '1m' },
            },
          },
        },
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Load testing capability is strictly disabled in target security scope');
    });

    it('rejects workloads exceeding target scope maxConcurrency limits', async () => {
      const result = await nativeLoadEngine.execute(
        { targetUrl: serverBaseUrl, options: { durationSec: 1, connections: 25 } },
        {
          runId: 'run-concurrency-exceeded',
          engineId: 'engine-native-load',
          target: {
            id: 'target-concurrency',
            url: serverBaseUrl,
            scope: {
              allowedHosts: ['127.0.0.1'],
              allowedPorts: [serverPort],
              excludedPaths: [],
              testing: { activeScanning: true, loadTesting: true, chaosTesting: false },
              limits: { maxRps: 50, maxConcurrency: 10, maxDuration: '1m' },
            },
          },
        },
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('exceeds target scope safety limit of 10 connections');
    });

    it('trips circuit breaker on continuous 500 errors and halts load generation', async () => {
      const summary = await executeLoadProfile(`${serverBaseUrl}/api/failing`, {
        durationSec: 5,
        connections: 10,
      });

      // Breaker threshold is 25 consecutive errors; should halt well before 5 seconds
      expect(summary.failedRequests).toBeGreaterThanOrEqual(25);
      expect(summary.errorRate).toBe(1);
    });
  });

  describe('6. Policy Engine Release Gate Integration', () => {
    it('evaluates policy engine gate and blocks release when P99 latency threshold fails', async () => {
      const result = await nativeLoadEngine.execute(
        {
          targetUrl: `${serverBaseUrl}/api/slow`,
          options: {
            durationSec: 1,
            connections: 5,
          },
        },
        {
          runId: 'run-policy-eval',
          engineId: 'engine-native-load',
          target: { id: 'target-1', url: serverBaseUrl },
        },
      );

      const policy: Policy = {
        id: 'policy-latency-gate',
        name: 'Strict Latency Policy',
        rules: [
          {
            id: 'rule-p99-latency',
            name: 'P99 Latency Gate',
            condition: {
              maxP99LatencyMs: 10, // Max 10ms P99 SLA
            },
            action: 'block_release',
          },
        ],
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const domainMetrics = result.metrics.map((m) => ({
        id: 'metric-' + m.name,
        testRunId: 'test-run-1',
        name: m.name,
        value: m.value,
        unit: m.unit,
        timestamp: new Date(),
        tags: {},
      }));

      const policyResult = evaluatePolicy(policy, [], domainMetrics);

      expect(policyResult.passed).toBe(false);
      expect(policyResult.decision).toBe('failed');
      expect(policyResult.violations.length).toBeGreaterThan(0);
      expect(policyResult.violations[0]?.reason).toContain('P99 latency');
    });
  });

  describe('7. Worker Thread Sandboxed Execution', () => {
    it('executes native load engine in isolated V8 worker thread via executeSandboxedEngine', async () => {
      const workerResult = await executeSandboxedEngine(
        'engine-native-load',
        {
          targetUrl: serverBaseUrl,
          options: {
            durationSec: 1,
            connections: 10,
          },
        },
        {
          runId: 'run-worker-load',
          engineId: 'engine-native-load',
          target: {
            id: 'target-worker-load',
            url: serverBaseUrl,
          },
        },
        {
          timeoutMs: 15000,
        },
      );

      expect(workerResult.success).toBe(true);
      expect(workerResult.engineId).toBe('engine-native-load');
      expect(workerResult.metrics.length).toBeGreaterThan(0);

      const rpsMetric = workerResult.metrics.find((m) => m.name === 'http_rps');
      expect(rpsMetric).toBeDefined();
      expect(rpsMetric!.value).toBeGreaterThan(500);
    });
  });
});
