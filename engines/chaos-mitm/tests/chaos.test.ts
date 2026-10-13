import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import {
  chaosMitmEngine,
  ChaosMitmProxy,
  matchFaultRule,
} from '../src/index.js';
import { executeSandboxedEngine } from '@security-lab/test-runner';
import { safeFetch } from '@security-lab/engine-sdk';

describe('Phase 10: Resilience & Controlled Fault Injection (Chaos MITM)', () => {
  let upstreamServer: http.Server;
  let upstreamPort: number;
  let upstreamBaseUrl: string;

  beforeAll(async () => {
    upstreamServer = http.createServer((req, res) => {
      const url = new URL(req.url || '/', 'http://127.0.0.1');

      if (url.pathname === '/api/large-data') {
        const largeObj = {
          message: 'This is a large data payload designed to test streaming truncation and partial responses',
          data: Array.from({ length: 50 }, (_, i) => ({ id: i, name: `Record_${i}` })),
        };
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(largeObj));
        return;
      }

      if (url.pathname === '/api/always-500') {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Upstream Permanent Failure' }));
        return;
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'healthy', path: url.pathname }));
    });

    await new Promise<void>((resolve) => {
      upstreamServer.listen(0, '127.0.0.1', () => {
        const addr = upstreamServer.address() as any;
        upstreamPort = addr.port;
        upstreamBaseUrl = `http://127.0.0.1:${upstreamPort}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => upstreamServer.close(() => resolve()));
  });

  describe('1. Fault Rule Matcher & Parameter Evaluation', () => {
    it('matches exact and wildcard paths with method filters', () => {
      const rules = [
        {
          id: 'rule-exact',
          name: 'Exact Match',
          match: { path: '/api/checkout', method: 'POST' as const },
          action: 'STATUS_CODE' as const,
          statusCode: 503,
        },
        {
          id: 'rule-wildcard',
          name: 'Wildcard Match',
          match: { path: '/api/*', method: '*' as const },
          action: 'LATENCY' as const,
          latencyMs: 200,
          jitterMs: 20,
        },
      ];

      // Exact match
      const m1 = matchFaultRule(rules, '/api/checkout', 'POST');
      expect(m1).toBeDefined();
      expect(m1?.action).toBe('STATUS_CODE');
      expect(m1?.statusCode).toBe(503);

      // Method mismatch on exact rule falls back to wildcard
      const m2 = matchFaultRule(rules, '/api/checkout', 'GET');
      expect(m2).toBeDefined();
      expect(m2?.action).toBe('LATENCY');
      expect(m2?.delayMs).toBeGreaterThanOrEqual(180);
      expect(m2?.delayMs).toBeLessThanOrEqual(220);

      // Unmatched path
      const m3 = matchFaultRule(rules, '/health', 'GET');
      expect(m3).toBeNull();
    });
  });

  describe('2. Ephemeral Proxy Fault Injection Primitives', () => {
    it('injects artificial latency accurately via ephemeral proxy', async () => {
      const proxy = new ChaosMitmProxy({
        upstreamBaseUrl,
        faultRules: [
          {
            id: 'rule-latency',
            name: 'Latency Test',
            match: { path: '/api/slow-route', method: '*' },
            action: 'LATENCY',
            latencyMs: 150,
            jitterMs: 0,
          },
        ],
      });

      const port = await proxy.start();
      expect(port).toBeGreaterThan(0);

      try {
        const start = Date.now();
        const res = await safeFetch(`http://127.0.0.1:${port}/api/slow-route`);
        const duration = Date.now() - start;

        expect(res.status).toBe(200);
        expect(duration).toBeGreaterThanOrEqual(140);
        expect(proxy.stats.faultsInjected).toBe(1);
        expect(proxy.stats.faultsByType['LATENCY']).toBe(1);
      } finally {
        await proxy.stop();
      }
    });

    it('injects synthetic 503 status code and custom body', async () => {
      const proxy = new ChaosMitmProxy({
        upstreamBaseUrl,
        faultRules: [
          {
            id: 'rule-503',
            name: 'Synthetic 503',
            match: { path: '/api/flake', method: 'GET' },
            action: 'STATUS_CODE',
            statusCode: 503,
            statusBody: JSON.stringify({ error: 'Gateway Overloaded', retryAfter: 5 }),
          },
        ],
      });

      const port = await proxy.start();

      try {
        const res = await safeFetch(`http://127.0.0.1:${port}/api/flake`);
        expect(res.status).toBe(503);
        expect(res.headers.get('x-chaos-fault')).toBe('STATUS_CODE');

        const body = await res.json();
        expect(body.error).toBe('Gateway Overloaded');
        expect(proxy.stats.faultsByType['STATUS_CODE']).toBe(1);
      } finally {
        await proxy.stop();
      }
    });

    it('injects connection drop (DROP) causing network reset', async () => {
      const proxy = new ChaosMitmProxy({
        upstreamBaseUrl,
        faultRules: [
          {
            id: 'rule-drop',
            name: 'Drop Test',
            match: { path: '/api/cut-cable', method: '*' },
            action: 'DROP',
          },
        ],
      });

      const port = await proxy.start();

      try {
        let threw = false;
        try {
          await safeFetch(`http://127.0.0.1:${port}/api/cut-cable`);
        } catch {
          threw = true;
        }
        expect(threw).toBe(true);
        expect(proxy.stats.faultsByType['DROP']).toBe(1);
      } finally {
        await proxy.stop();
      }
    });

    it('injects mid-stream payload truncation (TRUNCATE)', async () => {
      const proxy = new ChaosMitmProxy({
        upstreamBaseUrl,
        faultRules: [
          {
            id: 'rule-truncate',
            name: 'Truncation Test',
            match: { path: '/api/large-data', method: '*' },
            action: 'TRUNCATE',
            truncateBytes: 32,
          },
        ],
      });

      const port = await proxy.start();

      try {
        let truncatedOrThrew = false;
        try {
          const res = await safeFetch(`http://127.0.0.1:${port}/api/large-data`);
          const text = await res.text();
          if (text.length < 100) {
            truncatedOrThrew = true;
          }
        } catch {
          // Socket was severed midway as expected during payload truncation
          truncatedOrThrew = true;
        }

        expect(truncatedOrThrew).toBe(true);
        expect(proxy.stats.faultsByType['TRUNCATE']).toBe(1);
      } finally {
        await proxy.stop();
      }
    });
  });

  describe('3. Target Scope Enforcement Invariants', () => {
    it('strictly prohibits execution when chaosTesting is false in target scope', async () => {
      const result = await chaosMitmEngine.execute(
        { targetUrl: upstreamBaseUrl, options: {} },
        {
          runId: 'run-chaos-forbidden',
          engineId: 'engine-chaos-mitm',
          target: {
            id: 'target-scope-1',
            url: upstreamBaseUrl,
            scope: {
              allowedHosts: ['127.0.0.1'],
              allowedPorts: [upstreamPort],
              excludedPaths: [],
              testing: {
                activeScanning: true,
                loadTesting: true,
                chaosTesting: false, // Prohibited!
              },
              limits: { maxRps: 50, maxConcurrency: 10, maxDuration: '1m' },
            },
          },
        },
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Chaos testing capability is strictly disabled in target security scope');
    });

    it('enforces target scope and blocks unauthorized destinations with 403 Forbidden', async () => {
      const proxy = new ChaosMitmProxy({
        upstreamBaseUrl,
        faultRules: [],
        scope: {
          allowedHosts: ['127.0.0.1'],
          allowedPorts: [upstreamPort],
          excludedPaths: ['/api/restricted-admin'],
          testing: { activeScanning: true, loadTesting: true, chaosTesting: true },
          limits: { maxRps: 50, maxConcurrency: 10, maxDuration: '1m' },
        },
      });

      const port = await proxy.start();

      try {
        const res = await safeFetch(`http://127.0.0.1:${port}/api/restricted-admin`);
        expect(res.status).toBe(403);
        const data = await res.json();
        expect(data.error).toContain('Forbidden');
      } finally {
        await proxy.stop();
      }
    });
  });

  describe('4. Client Resilience Scenario Execution & Recovery Finding', () => {
    it('verifies client retry loop recovers from transient 503 errors with zero findings', async () => {
      const result = await chaosMitmEngine.execute(
        {
          targetUrl: upstreamBaseUrl,
          options: {
            faultRules: [
              {
                id: 'transient-503',
                name: 'Transient Flake',
                match: { path: '/api/order', method: 'GET' },
                action: 'STATUS_CODE',
                statusCode: 503,
                percentage: 50, // 50% flake
              },
            ],
            scenarioSteps: [
              {
                name: 'Place Order with Exponential Backoff',
                method: 'GET',
                path: '/api/order',
                maxRetries: 5,
                retryBackoffMs: 25,
                expectedFinalStatus: 200,
              },
            ],
          },
        },
        {
          runId: 'run-resilience-recovery',
          engineId: 'engine-chaos-mitm',
          target: { id: 'target-1', url: upstreamBaseUrl },
        },
      );

      expect(result.success).toBe(true);
      expect(result.findings.length).toBe(0); // Successfully recovered!

      const totalRequests = result.metrics.find((m) => m.name === 'chaos_total_requests')?.value;
      expect(totalRequests).toBeGreaterThanOrEqual(1);

      const recoveredCount = result.metrics.find((m) => m.name === 'chaos_recovered_requests')?.value;
      expect(recoveredCount).toBe(1);
    });

    it('emits Resilience Recovery Failure finding when client fails to recover', async () => {
      const result = await chaosMitmEngine.execute(
        {
          targetUrl: upstreamBaseUrl,
          options: {
            faultRules: [
              {
                id: 'permanent-500',
                name: 'Total Outage',
                match: { path: '/api/critical-service', method: 'GET' },
                action: 'STATUS_CODE',
                statusCode: 500,
                percentage: 100, // 100% failure
              },
            ],
            scenarioSteps: [
              {
                name: 'Critical Service Check',
                method: 'GET',
                path: '/api/critical-service',
                maxRetries: 1, // Limited retries
                retryBackoffMs: 10,
                expectedFinalStatus: 200,
              },
            ],
          },
        },
        {
          runId: 'run-resilience-failure',
          engineId: 'engine-chaos-mitm',
          target: { id: 'target-1', url: upstreamBaseUrl },
        },
      );

      expect(result.success).toBe(true);
      expect(result.findings.length).toBe(1);

      const finding = result.findings[0]!;
      expect(finding.title).toContain('Resilience Recovery Failure');
      expect(finding.severity).toBe('high');
      expect(finding.category).toBe('reliability');
      expect(finding.description).toContain('failed to recover after 1 retries');

      const unrecoveredMetric = result.metrics.find((m) => m.name === 'chaos_unrecovered_requests')?.value;
      expect(unrecoveredMetric).toBe(1);
    });
  });

  describe('5. Worker Thread Sandboxed Execution', () => {
    it('executes chaos-mitm engine in isolated V8 worker thread via executeSandboxedEngine', async () => {
      const workerResult = await executeSandboxedEngine(
        'engine-chaos-mitm',
        {
          targetUrl: upstreamBaseUrl,
          options: {
            faultRules: [
              {
                id: 'worker-latency',
                name: 'Worker Latency Rule',
                match: { path: '/api/*', method: '*' },
                action: 'LATENCY',
                latencyMs: 50,
              },
            ],
            scenarioSteps: [
              {
                name: 'Worker Canary Check',
                method: 'GET',
                path: '/api/status',
                maxRetries: 2,
                expectedFinalStatus: 200,
              },
            ],
          },
        },
        {
          runId: 'run-worker-chaos',
          engineId: 'engine-chaos-mitm',
          target: {
            id: 'target-worker-chaos',
            url: upstreamBaseUrl,
          },
        },
        {
          timeoutMs: 15000,
        },
      );

      expect(workerResult.success).toBe(true);
      expect(workerResult.engineId).toBe('engine-chaos-mitm');
      expect(workerResult.metrics.length).toBeGreaterThan(0);

      const faultsInjected = workerResult.metrics.find((m) => m.name === 'chaos_faults_injected')?.value;
      expect(faultsInjected).toBeGreaterThanOrEqual(1);
    });
  });
});
