import http from 'node:http';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth } from '../../apps/controller/src/services/db.js';
import { FastifyInstance } from 'fastify';
import { logger } from '@security-lab/logger';
import {
  K6ResilienceEngine,
  RateLimitResilienceEngine,
  calculatePercentile,
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
        { targetUrl: serverUrl, options: { vus: 2, durationSec: 1, maxP95Ms: 1000 } },
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
        { targetUrl: `${serverUrl}/slow`, options: { vus: 2, durationSec: 1, maxP95Ms: 20 } },
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
          },
        },
      });
      expect(runRes.statusCode).toBe(201);
      testRunId = JSON.parse(runRes.payload).data.id;

      // 2. Execute TestRun
      const execRes = await app.inject({
        method: 'POST',
        url: `/api/v1/test-runs/${testRunId}/execute`,
        payload: {
          options: {
            vus: 3,
            durationSec: 1,
            maxP95Ms: 500,
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
});
