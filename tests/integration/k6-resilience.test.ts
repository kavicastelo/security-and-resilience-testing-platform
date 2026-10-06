import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth } from '../../apps/controller/src/services/db.js';
import { FastifyInstance } from 'fastify';
import { logger } from '@security-lab/logger';
import {
  K6ResilienceEngine,
  RateLimitResilienceEngine,
  calculatePercentile,
  buildK6Script,
  parseK6Summary,
  DockerRunner,
  TestEngineError,
  validateVolumePath,
  ExecutionContext,
} from '@security-lab/test-sdk';

describe('Phase 4: Class C Resilience & Load Testing (Grafana k6 & Rate Limiting)', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;
  let server: http.Server;
  let serverPort: number;
  let serverUrl: string;

  beforeAll(async () => {
    app = buildApp({ disableLogging: true });
    const health = await checkDatabaseHealth();
    isDbAvailable = health === 'up';

    // Mock HTTP target endpoint
    server = http.createServer((req, res) => {
      if (req.url === '/slow') {
        setTimeout(() => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'ok', slow: true }));
        }, 60);
        return;
      }

      if (req.url === '/rate-limited') {
        res.writeHead(429, {
          'Content-Type': 'application/json',
          'Retry-After': '60',
          'X-RateLimit-Limit': '100',
          'X-RateLimit-Remaining': '0',
        });
        res.end(JSON.stringify({ error: 'Too Many Requests' }));
        return;
      }

      // Fast normal endpoint (no rate limiting headers)
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok' }));
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        if (addr && typeof addr === 'object') {
          serverPort = addr.port;
          serverUrl = `http://127.0.0.1:${serverPort}`;
        }
        resolve();
      });
    });
  });

  afterAll(async () => {
    await app.close();
    await closeDatabase();
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  it('confirms database connectivity', () => {
    expect(isDbAvailable).toBe(true);
  });

  describe('1. Percentile and Statistical Distribution Calculations', () => {
    it('accurately calculates empirical percentiles', () => {
      expect(calculatePercentile([], 50)).toBe(0);
      expect(calculatePercentile([100], 95)).toBe(100);

      // Array: [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
      const values = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
      const p50 = calculatePercentile(values, 50);
      const p95 = calculatePercentile(values, 95);
      const p99 = calculatePercentile(values, 99);

      expect(p50).toBe(50);
      expect(p95).toBe(100);
      expect(p99).toBe(100);
    });
  });

  describe('2. K6ResilienceEngine Safety Gates & Latency SLA Audits', () => {
    const k6Engine = new K6ResilienceEngine();

    it('strictly prohibits load testing if loadTesting capability is false in target scope', async () => {
      const mockContext: ExecutionContext = {
        correlationId: 'test-corr-1',
        testRunId: 'test-run-1',
        executionId: 'test-exec-1',
        target: {
          id: 'target-1',
          name: 'Restricted Target',
          baseUrl: serverUrl,
          scope: {
            allowedHosts: ['127.0.0.1'],
            allowedPorts: [serverPort],
            excludedPaths: [],
            testing: {
              activeScanning: false,
              loadTesting: false, // Prohibited!
              chaosTesting: false,
            },
            limits: {
              maxRps: 10,
              maxConcurrency: 5,
              maxDuration: '1m',
            },
          },
        },
        abortSignal: new AbortController().signal,
        reportProgress: () => {},
        logger: logger.child({ test: true }),
      };

      const result = await k6Engine.execute(
        { targetUrl: serverUrl, options: { vus: 2, durationSec: 1 } },
        mockContext,
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Load testing capability is strictly disabled in target security scope');
    });

    it('rejects workloads exceeding target scope maxConcurrency limits', async () => {
      const mockContext: ExecutionContext = {
        correlationId: 'test-corr-2',
        testRunId: 'test-run-2',
        executionId: 'test-exec-2',
        target: {
          id: 'target-2',
          name: 'Bounded Target',
          baseUrl: serverUrl,
          scope: {
            allowedHosts: ['127.0.0.1'],
            allowedPorts: [serverPort],
            excludedPaths: [],
            testing: {
              activeScanning: true,
              loadTesting: true, // Authorized
              chaosTesting: false,
            },
            limits: {
              maxRps: 50,
              maxConcurrency: 4, // Max 4 VUs
              maxDuration: '1m',
            },
          },
        },
        abortSignal: new AbortController().signal,
        reportProgress: () => {},
        logger: logger.child({ test: true }),
      };

      const result = await k6Engine.execute(
        { targetUrl: serverUrl, options: { vus: 10, durationSec: 1 } },
        mockContext,
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Requested concurrency (10 VUs) exceeds target scope safety limit of 4 VUs');
    });

    it('executes authorized load test and produces quantitative latency percentiles', async () => {
      const mockContext: ExecutionContext = {
        correlationId: 'test-corr-3',
        testRunId: 'test-run-3',
        executionId: 'test-exec-3',
        target: {
          id: 'target-3',
          name: 'Authorized Target',
          baseUrl: serverUrl,
          scope: {
            allowedHosts: ['127.0.0.1'],
            allowedPorts: [serverPort],
            excludedPaths: [],
            testing: {
              activeScanning: true,
              loadTesting: true,
              chaosTesting: false,
            },
            limits: {
              maxRps: 100,
              maxConcurrency: 10,
              maxDuration: '1m',
            },
          },
        },
        abortSignal: new AbortController().signal,
        reportProgress: () => {},
        logger: logger.child({ test: true }),
      };

      const result = await k6Engine.execute(
        { targetUrl: serverUrl, options: { vus: 2, durationSec: 1, maxP95Ms: 1000, simulated: true } },
        mockContext,
      );

      expect(result.success).toBe(true);
      expect(result.metrics.length).toBeGreaterThan(0);

      const metricNames = result.metrics.map((m) => m.name);
      expect(metricNames).toContain('http_req_duration_p95');
      expect(metricNames).toContain('http_req_duration_p99');
      expect(metricNames).toContain('http_req_duration_med');
      expect(metricNames).toContain('http_req_duration_avg');
      expect(metricNames).toContain('http_req_duration_max');
      expect(metricNames).toContain('http_reqs_total');
      expect(metricNames).toContain('http_rps');

      const totalReqs = result.metrics.find((m) => m.name === 'http_reqs_total')?.value;
      expect(totalReqs).toBeGreaterThan(0);
    });

    it('flags Latency SLA Breach finding when p95 exceeds threshold', async () => {
      const mockContext: ExecutionContext = {
        correlationId: 'test-corr-4',
        testRunId: 'test-run-4',
        executionId: 'test-exec-4',
        target: {
          id: 'target-4',
          name: 'Slow Endpoint Target',
          baseUrl: `${serverUrl}/slow`,
          scope: {
            allowedHosts: ['127.0.0.1'],
            allowedPorts: [serverPort],
            excludedPaths: [],
            testing: {
              activeScanning: true,
              loadTesting: true,
              chaosTesting: false,
            },
            limits: {
              maxRps: 100,
              maxConcurrency: 10,
              maxDuration: '1m',
            },
          },
        },
        abortSignal: new AbortController().signal,
        reportProgress: () => {},
        logger: logger.child({ test: true }),
      };

      // Server takes ~60ms, set maxP95Ms to 20ms to trigger SLA breach finding
      const result = await k6Engine.execute(
        { targetUrl: `${serverUrl}/slow`, options: { vus: 2, durationSec: 1, maxP95Ms: 20, simulated: true } },
        mockContext,
      );

      const slaFinding = result.findings.find((f) => f.title.includes('Latency SLA Breach'));
      expect(slaFinding).toBeDefined();
      expect(slaFinding?.category).toBe('performance');
    });
  });

  describe('3. RateLimitResilienceEngine Burst Audits', () => {
    const rateLimitEngine = new RateLimitResilienceEngine();

    it('identifies missing rate limiting defenses when endpoint processes rapid bursts', async () => {
      const mockContext: ExecutionContext = {
        correlationId: 'test-corr-5',
        testRunId: 'test-run-5',
        executionId: 'test-exec-5',
        target: {
          id: 'target-5',
          name: 'Unprotected Target',
          baseUrl: serverUrl,
          scope: {
            allowedHosts: ['127.0.0.1'],
            allowedPorts: [serverPort],
            excludedPaths: [],
            testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
            limits: { maxRps: 15, maxConcurrency: 5, maxDuration: '1m' },
          },
        },
        abortSignal: new AbortController().signal,
        reportProgress: () => {},
        logger: logger.child({ test: true }),
      };

      const result = await rateLimitEngine.execute({ targetUrl: serverUrl }, mockContext);
      expect(result.success).toBe(true);
      expect(result.findings.some((f) => f.title.includes('Missing API Rate Limiting'))).toBe(true);

      const enforcedMetric = result.metrics.find((m) => m.name === 'rate_limiting_enforced');
      expect(enforcedMetric?.value).toBe(0);
    });

    it('confirms rate limiting enforcement when HTTP 429 is returned', async () => {
      const mockContext: ExecutionContext = {
        correlationId: 'test-corr-6',
        testRunId: 'test-run-6',
        executionId: 'test-exec-6',
        target: {
          id: 'target-6',
          name: 'Protected Target',
          baseUrl: `${serverUrl}/rate-limited`,
          scope: {
            allowedHosts: ['127.0.0.1'],
            allowedPorts: [serverPort],
            excludedPaths: [],
            testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
            limits: { maxRps: 15, maxConcurrency: 5, maxDuration: '1m' },
          },
        },
        abortSignal: new AbortController().signal,
        reportProgress: () => {},
        logger: logger.child({ test: true }),
      };

      const result = await rateLimitEngine.execute(
        { targetUrl: `${serverUrl}/rate-limited` },
        mockContext,
      );

      expect(result.success).toBe(true);
      expect(result.findings.some((f) => f.title.includes('Missing API Rate Limiting'))).toBe(false);

      const enforcedMetric = result.metrics.find((m) => m.name === 'rate_limiting_enforced');
      expect(enforcedMetric?.value).toBe(1);
    });
  });

  describe('4. End-to-End Controller Execution Pipeline & Metrics Persistence', () => {
    let projectId: string;
    let targetId: string;
    let testRunId: string;

    it('sets up project and authorized load testing target', async () => {
      const randomSuffix = Math.floor(Math.random() * 100000);

      // Create project
      const pRes = await app.inject({
        method: 'POST',
        url: '/api/v1/projects',
        payload: {
          name: `Class C Resilience Project ${randomSuffix}`,
          description: 'Validating k6 workers and quantitative metrics',
        },
      });
      expect(pRes.statusCode).toBe(201);
      projectId = JSON.parse(pRes.payload).data.id;

      // Create target with loadTesting: true
      const tRes = await app.inject({
        method: 'POST',
        url: `/api/v1/projects/${projectId}/targets`,
        payload: {
          name: `Resilience Target ${randomSuffix}`,
          baseUrl: serverUrl,
          allowedHosts: ['127.0.0.1'],
          allowedPorts: [serverPort],
          excludedPaths: [],
          testing: {
            activeScanning: true,
            loadTesting: true, // Explicit opt-in
            chaosTesting: false,
          },
          limits: {
            maxRps: 50,
            maxConcurrency: 10,
            maxDuration: '2m',
          },
        },
      });
      expect(tRes.statusCode).toBe(201);
      targetId = JSON.parse(tRes.payload).data.id;
    });

    it('queues and executes a Class C resilience test run', async () => {
      // 1. Create TestRun with profileId: 'class-c-resilience'
      const runRes = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        payload: {
          projectId,
          targetId,
          profileId: 'class-c-resilience',
          triggeredBy: 'manual',
          metadata: {
            vus: 3,
            durationSec: 1,
            maxP95Ms: 500,
            simulated: true,
          },
        },
      });
      expect(runRes.statusCode).toBe(201);
      testRunId = JSON.parse(runRes.payload).data.id;

      // 2. Execute TestRun
      const execRes = await app.inject({
        method: 'POST',
        url: `/api/v1/test-runs/${testRunId}/execute?wait=true`,
        payload: {
          options: {
            vus: 3,
            durationSec: 1,
            maxP95Ms: 500,
            simulated: true,
          },
        },
      });
      expect(execRes.statusCode).toBe(200);

      const execPayload = JSON.parse(execRes.payload);
      expect(execPayload.success).toBe(true);
      expect(execPayload.data.testRun.status).toBe('completed');

      // Verify that engine-worker-k6 and engine-native-resilience ran
      const enginesExecuted = execPayload.data.executions.map((e: { engineId: string }) => e.engineId);
      expect(enginesExecuted).toContain('engine-worker-k6');
      expect(enginesExecuted).toContain('engine-native-resilience');
    });

    it('persists and serves quantitative latency metrics via GET /api/v1/test-runs/:id/metrics', async () => {
      const metricsRes = await app.inject({
        method: 'GET',
        url: `/api/v1/test-runs/${testRunId}/metrics`,
      });
      expect(metricsRes.statusCode).toBe(200);

      const json = JSON.parse(metricsRes.payload);
      expect(json.success).toBe(true);
      expect(Array.isArray(json.data)).toBe(true);
      expect(json.data.length).toBeGreaterThan(0);

      const metricNames = json.data.map((m: { name: string }) => m.name);
      expect(metricNames).toContain('http_req_duration_p95');
      expect(metricNames).toContain('http_req_duration_p99');
      expect(metricNames).toContain('http_rps');
      expect(metricNames).toContain('rate_limiting_enforced');

      // Validate metric record structure
      const p95Record = json.data.find((m: { name: string }) => m.name === 'http_req_duration_p95');
      expect(p95Record).toBeDefined();
      expect(p95Record.testRunId).toBe(testRunId);
      expect(typeof p95Record.value).toBe('number');
      expect(p95Record.unit).toBe('ms');
    });
  });

  describe('5. Grafana k6 Script Builder & Real Summary Parsing', () => {
    it('buildK6Script generates valid ES-module k6 script with thresholds and headers', () => {
      const script = buildK6Script({
        targetUrl: 'http://127.0.0.1:8080/api/orders',
        vus: 8,
        durationSec: 5,
        maxP95Ms: 250,
        maxFailedRatio: 0.02,
        headers: {
          Authorization: 'Bearer test-token-123',
          'X-Custom-Header': 'security-audit',
        },
      });

      expect(script).toContain("import http from 'k6/http';");
      expect(script).toContain("import { check } from 'k6';");
      expect(script).toContain('"vus": 8');
      expect(script).toContain('"duration": "5s"');
      expect(script).toContain('"http_req_duration"');
      expect(script).toContain('"p(95)<250"');
      expect(script).toContain('"http_req_failed"');
      expect(script).toContain('"rate<0.02"');
      expect(script).toContain('"Authorization": "Bearer test-token-123"');
      expect(script).toContain('"X-Custom-Header": "security-audit"');
      expect(script).toContain('http.get(url, params)');
      expect(script).toContain('handleSummary(data)');
      expect(script).toContain('export default function ()');
    });

    it('buildK6Script supports stages and POST JSON payload', () => {
      const script = buildK6Script({
        targetUrl: 'http://127.0.0.1:8080/api/checkout',
        method: 'POST',
        stages: [
          { duration: '2s', target: 5 },
          { duration: '4s', target: 20 },
        ],
        body: { cartId: 'cart-999', currency: 'USD' },
      });

      expect(script).toContain('"stages": [');
      expect(script).toContain('http.post(url, payload, params)');
      expect(script).toContain('cartId');
      expect(script).toContain('cart-999');
    });

    it('parseK6Summary accurately extracts percentiles, error rates, and throughput', () => {
      const fixture = {
        metrics: {
          http_req_duration: {
            type: 'trend',
            contains: 'time',
            values: {
              avg: 45.2,
              min: 10.0,
              med: 42.1,
              max: 120.0,
              'p(90)': 75.0,
              'p(95)': 92.5,
              'p(99)': 110.0,
            },
          },
          http_req_failed: {
            type: 'rate',
            contains: 'default',
            values: {
              rate: 0.03,
              passes: 3,
              fails: 97,
            },
          },
          http_reqs: {
            type: 'counter',
            contains: 'default',
            values: {
              count: 100,
              rate: 50.0,
            },
          },
          iterations: {
            type: 'counter',
            contains: 'default',
            values: {
              count: 100,
              rate: 50.0,
            },
          },
        },
      };

      const metrics = parseK6Summary(fixture);
      expect(metrics.durationAvg).toBe(45.2);
      expect(metrics.durationMin).toBe(10.0);
      expect(metrics.durationMed).toBe(42.1);
      expect(metrics.durationMax).toBe(120.0);
      expect(metrics.durationP90).toBe(75.0);
      expect(metrics.durationP95).toBe(92.5);
      expect(metrics.durationP99).toBe(110.0);
      expect(metrics.reqsTotal).toBe(100);
      expect(metrics.rps).toBe(50.0);
      expect(metrics.failedRate).toBe(0.03);
      expect(metrics.failedCount).toBe(3);
    });

    it('volume exchange: writes script, executes runner, parses real summary.json, and destroys scratch dir', async () => {
      let capturedHostPath = '';
      const customK6Summary = {
        metrics: {
          http_req_duration: {
            values: {
              avg: 40.0,
              min: 8.0,
              med: 35.0,
              max: 110.0,
              'p(90)': 70.0,
              'p(95)': 88.0,
              'p(99)': 105.0,
            },
          },
          http_req_failed: {
            values: {
              rate: 0.0,
              passes: 0,
              fails: 200,
            },
          },
          http_reqs: {
            values: {
              count: 200,
              rate: 66.7,
            },
          },
          iterations: {
            values: {
              count: 200,
            },
          },
        },
      };

      const mockRunner = {
        execute: async (options: {
          image: string;
          args?: string[];
          volumes?: { hostPath: string; containerPath: string; mode?: string }[];
        }) => {
          expect(options.args).toEqual([
            'run',
            '--summary-export=/scripts/summary.json',
            '/scripts/script.js',
          ]);

          const scriptsVol = options.volumes?.find((v) => v.containerPath === '/scripts');
          expect(scriptsVol).toBeDefined();
          expect(scriptsVol?.mode).toBe('rw');
          expect(validateVolumePath(scriptsVol!.hostPath).valid).toBe(true);

          capturedHostPath = scriptsVol!.hostPath;

          // Verify script.js was generated in scratch directory before execution
          const scriptFile = path.join(capturedHostPath, 'script.js');
          expect(fs.existsSync(scriptFile)).toBe(true);
          const scriptContent = await fs.promises.readFile(scriptFile, 'utf-8');
          expect(scriptContent).toContain('export default function ()');

          // Simulate k6 container writing real summary.json
          const summaryFile = path.join(capturedHostPath, 'summary.json');
          await fs.promises.writeFile(summaryFile, JSON.stringify(customK6Summary), 'utf-8');

          return {
            exitCode: 0,
            stdout: 'k6 test execution completed',
            stderr: '',
            durationMs: 30,
            simulated: false,
          };
        },
      } as unknown as DockerRunner;

      const engine = new K6ResilienceEngine(mockRunner);
      const mockContext: ExecutionContext = {
        correlationId: 'test-corr-custom',
        testRunId: 'test-run-custom',
        executionId: 'test-exec-custom',
        target: {
          id: 'target-custom',
          name: 'Custom Target',
          baseUrl: serverUrl,
          scope: {
            allowedHosts: ['127.0.0.1'],
            allowedPorts: [serverPort],
            excludedPaths: [],
            testing: { activeScanning: true, loadTesting: true, chaosTesting: false },
            limits: { maxRps: 100, maxConcurrency: 10, maxDuration: '1m' },
          },
        },
        abortSignal: new AbortController().signal,
        reportProgress: () => {},
        logger: logger.child({ test: true }),
      };

      const result = await engine.execute(
        { targetUrl: serverUrl, options: { vus: 4, durationSec: 3, simulated: false } },
        mockContext,
      );

      expect(result.success).toBe(true);
      expect(result.metrics.find((m) => m.name === 'http_req_duration_p95')?.value).toBe(88);
      expect(result.metrics.find((m) => m.name === 'http_req_duration_p99')?.value).toBe(105);
      expect(result.metrics.find((m) => m.name === 'http_reqs_total')?.value).toBe(200);

      // Verify scratch directory was cleanly destroyed post-run
      expect(fs.existsSync(capturedHostPath)).toBe(false);
    });

    it('fails fast when summary.json is missing and simulated: false', async () => {
      const mockRunner = {
        execute: async () => ({
          exitCode: 1,
          stdout: '',
          stderr: 'k6 process crashed unexpectedly',
          durationMs: 10,
          simulated: false,
        }),
      } as unknown as DockerRunner;

      const engine = new K6ResilienceEngine(mockRunner);
      const mockContext: ExecutionContext = {
        correlationId: 'test-corr-fail',
        testRunId: 'test-run-fail',
        executionId: 'test-exec-fail',
        target: {
          id: 'target-fail',
          name: 'Failing Target',
          baseUrl: serverUrl,
          scope: {
            allowedHosts: ['127.0.0.1'],
            allowedPorts: [serverPort],
            excludedPaths: [],
            testing: { activeScanning: true, loadTesting: true, chaosTesting: false },
            limits: { maxRps: 100, maxConcurrency: 10, maxDuration: '1m' },
          },
        },
        abortSignal: new AbortController().signal,
        reportProgress: () => {},
        logger: logger.child({ test: true }),
      };

      // 1. With throwOnError: true, throws TestEngineError
      await expect(
        engine.execute(
          { targetUrl: serverUrl, options: { vus: 2, durationSec: 1, simulated: false, throwOnError: true } },
          mockContext,
        ),
      ).rejects.toThrowError(TestEngineError);

      // 2. Without throwOnError, returns success: false with clear error message
      const result = await engine.execute(
        { targetUrl: serverUrl, options: { vus: 2, durationSec: 1, simulated: false } },
        mockContext,
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('failed to produce summary.json at /scripts/summary.json');
    });
  });
});
