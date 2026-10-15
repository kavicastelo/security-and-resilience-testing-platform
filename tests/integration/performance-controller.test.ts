import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { FastifyInstance } from 'fastify';

// Mock DB before loading app to avoid requiring live PostgreSQL in unit/integration test runner
const mockTestRun = {
  id: 'test-run-mock-123',
  targetId: 'test-target-id',
  status: 'completed',
  summary: {
    totalTests: 1,
    passedTests: 1,
    failedTests: 0,
    errorTests: 0,
    findingsCount: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  },
  metadata: {
    durationSec: 5,
    concurrency: 10,
    rps: 100,
  },
};

const mockTarget = {
  id: 'test-target-id',
  projectId: 'proj-1',
  name: 'Performance Test Target',
  baseUrl: 'https://perf.staging.internal',
  scope: {
    allowedHosts: ['perf.staging.internal'],
    allowedPorts: [443],
    testing: { loadTesting: true },
    limits: { maxConcurrency: 50, maxRps: 500, maxDuration: '60s' },
  },
};

vi.mock('../../apps/controller/src/services/db.js', () => {
  const db = {
    insert: vi.fn(() => ({
      values: vi.fn(() => ({
        returning: vi.fn().mockResolvedValue([mockTestRun]),
      })),
    })),
    select: vi.fn(() => ({
      from: vi.fn((table: any) => {
        const queryResult =
          table && table._ && table._.name === 'targets' ? [mockTarget] : [mockTestRun];
        const resultPromise = Promise.resolve(queryResult);
        const whereObj = {
          limit: vi.fn().mockResolvedValue(queryResult),
          then: (resolve: any, reject: any) => resultPromise.then(resolve, reject),
        };
        return {
          where: vi.fn().mockReturnValue(whereObj),
          limit: vi.fn().mockResolvedValue(queryResult),
          then: (resolve: any, reject: any) => resultPromise.then(resolve, reject),
        };
      }),
    })),
  };
  return {
    getDatabase: () => ({ db }),
    closeDatabase: vi.fn(),
  };
});

import { buildApp } from '../../apps/controller/src/app/index.js';
import { webhookQueueService } from '../../apps/controller/src/services/webhook-queue.js';
import { signJwt, DEFAULT_WORKSPACE_ID } from '../../apps/controller/src/services/auth-token.service.js';
import { targetsService } from '../../apps/controller/src/services/targets.service.js';
import { metricsService } from '../../apps/controller/src/services/metrics.service.js';

describe('PR-06 Integration: Performance Studio Real-Time Metrics & Historical Baselines API', () => {
  let app: FastifyInstance;
  let authToken: string;

  beforeAll(async () => {
    app = buildApp({
      disableLogging: true,
      enableReaper: false,
      bypassAuth: false,
    });
    await app.ready();

    authToken = signJwt({
      userId: 'test-performance-architect',
      workspaceId: DEFAULT_WORKSPACE_ID,
      role: 'engineer',
    });

    vi.spyOn(targetsService, 'getTargetById').mockImplementation(async (id: string) => {
      if (id === 'strict-target-id') {
        return {
          id: 'strict-target-id',
          projectId: 'proj-1',
          name: 'Strict Target No Load',
          baseUrl: 'https://strict.perf.internal',
          scope: {
            allowedHosts: ['strict.perf.internal'],
            allowedPorts: [443],
            testing: {
              activeScanning: true,
              loadTesting: false,
            },
            limits: {
              maxRps: 10,
              maxConcurrency: 5,
            },
          },
        } as any;
      }
      if (id === 'test-target-id') {
        return mockTarget as any;
      }
      return null;
    });

    vi.spyOn(metricsService, 'saveMetric').mockResolvedValue({ id: 'm-saved' } as any);
    vi.spyOn(metricsService, 'listMetricsByTestRunId').mockResolvedValue([
      { id: 'm1', name: 'http_req_duration_p50', value: 45, unit: 'ms' },
      { id: 'm2', name: 'http_req_duration_p90', value: 85, unit: 'ms' },
      { id: 'm3', name: 'http_req_duration_p95', value: 110, unit: 'ms' },
      { id: 'm4', name: 'http_req_duration_p99', value: 160, unit: 'ms' },
      { id: 'm5', name: 'http_req_duration_avg', value: 50, unit: 'ms' },
      { id: 'm6', name: 'http_rps', value: 1200, unit: 'req/s' },
      { id: 'm7', name: 'http_reqs_total', value: 10000, unit: 'count' },
      { id: 'm8', name: 'http_req_failed_ratio', value: 0.002, unit: 'ratio' },
    ] as any);
  });

  afterAll(async () => {
    webhookQueueService.stopWorker();
    await app.close();
  });

  describe('Native Load Execution API (/api/v1/performance/load/execute)', () => {
    it('rejects load execution on targets where loadTesting capability is disabled', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/performance/load/execute',
        headers: {
          authorization: `Bearer ${authToken}`,
        },
        payload: {
          targetId: 'strict-target-id',
          concurrency: 5,
        },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.message).toContain('Load testing is strictly disabled');
    });

    it('rejects load execution when requested concurrency exceeds target scope limits', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/performance/load/execute',
        headers: {
          authorization: `Bearer ${authToken}`,
        },
        payload: {
          targetId: 'test-target-id',
          concurrency: 100, // Target max is 50
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error.message).toContain('exceeds target scope maximum');
    });

    it('executes native load test within scope limits and returns real telemetry execution', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/performance/load/execute',
        headers: {
          authorization: `Bearer ${authToken}`,
        },
        payload: {
          targetId: 'test-target-id',
          concurrency: 10,
          durationSec: 2,
          rps: 100,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.success).toBe(true);
      expect(body.testRunId).toBe('test-run-mock-123');
      expect(body.summary).toBeDefined();
      expect(body.summary.concurrency).toBe(10);
      expect(Array.isArray(body.metrics)).toBe(true);
    });
  });

  describe('Performance Run Timeseries & Histogram API (/api/v1/performance/runs/:id/timeseries)', () => {
    it('computes real percentile histograms and SLO analysis for executed test run', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/performance/runs/test-run-mock-123/timeseries',
        headers: {
          authorization: `Bearer ${authToken}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.success).toBe(true);
      expect(body.data.runId).toBe('test-run-mock-123');
      expect(body.data.percentiles).toBeDefined();
      expect(body.data.percentiles.p50).toBe(45);
      expect(body.data.percentiles.p90).toBe(85);
      expect(body.data.percentiles.p95).toBe(110);
      expect(body.data.percentiles.p99).toBe(160);
      expect(Array.isArray(body.data.histogramBins)).toBe(true);
      expect(body.data.histogramBins.length).toBeGreaterThan(0);
      expect(body.data.saturation).toBeDefined();
      expect(body.data.sloPassed).toBe(true);
      expect(body.data.statusDistribution).toBeDefined();
    });
  });

  describe('Historical Baselines & Golden Promotion API (/api/v1/performance/baselines)', () => {
    it('promotes a test run to a golden performance baseline', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/performance/baselines',
        headers: {
          authorization: `Bearer ${authToken}`,
        },
        payload: {
          targetId: 'test-target-id',
          testRunId: 'test-run-mock-123',
          name: 'v1.0.0 Production Golden Baseline',
          isGolden: true,
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.success).toBe(true);
      expect(body.data.name).toBe('v1.0.0 Production Golden Baseline');
      expect(body.data.isGolden).toBe(true);
      expect(body.data.p95).toBe(110);
      expect(body.data.peakRps).toBe(1200);
      expect(body.data.errorRate).toBe(0.002);
    });

    it('queries historical baselines filtered by targetId', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/performance/baselines?targetId=test-target-id',
        headers: {
          authorization: `Bearer ${authToken}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.success).toBe(true);
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.data.length).toBeGreaterThanOrEqual(1);

      const golden = body.data.find((b: any) => b.isGolden);
      expect(golden).toBeDefined();
      expect(golden.name).toBe('v1.0.0 Production Golden Baseline');
    });
  });
});
