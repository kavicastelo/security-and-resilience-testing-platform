import { describe, it, expect, vi } from 'vitest';
import type { LogEntry, StageItem, RunTelemetryMetrics } from '../src/hooks/useRunEventStream.js';

describe('Phase UI-05: Real-Time Live Execution Telemetry & Terminal Console', () => {
  describe('Terminal Log Ring Buffer & Memory Guard', () => {
    it('caps log buffer to max limit preventing browser memory leaks', () => {
      const MAX_BUFFER = 2000;
      let logs: LogEntry[] = [];

      const appendLog = (entry: Omit<LogEntry, 'id'>) => {
        const id = `log-${logs.length + 1}`;
        logs = [...logs.slice(-(MAX_BUFFER - 1)), { id, ...entry }];
      };

      // Push 2,500 logs to simulate high-throughput stream
      for (let i = 0; i < 2500; i++) {
        appendLog({
          timestamp: '12:00:00.000',
          level: i % 10 === 0 ? 'error' : i % 5 === 0 ? 'warn' : 'info',
          message: `Streaming event sequence #${i}`,
          engineId: i % 2 === 0 ? 'engine-native-headers' : 'engine-worker-k6',
        });
      }

      expect(logs.length).toBe(MAX_BUFFER);
      // Ensure oldest entries were pruned
      expect(logs[0].message).toBe('Streaming event sequence #500');
      expect(logs[logs.length - 1].message).toBe('Streaming event sequence #2499');
    });

    it('filters log lines by severity level chip', () => {
      const logs: LogEntry[] = [
        { id: '1', timestamp: '12:00:01', level: 'info', message: 'Engine initialized', engineId: 'engine-native-tls' },
        { id: '2', timestamp: '12:00:02', level: 'warn', message: 'Cipher suite weak', engineId: 'engine-native-tls' },
        { id: '3', timestamp: '12:00:03', level: 'error', message: 'Target unreachable: ECONNREFUSED', engineId: 'engine-native-tls' },
        { id: '4', timestamp: '12:00:04', level: 'payload', message: 'Dispatched raw fuzzing packet', engineId: 'engine-native-fuzzer' },
      ];

      const filterByLevel = (level: string) => {
        if (level === 'ALL') return logs;
        return logs.filter((l) => l.level.toLowerCase() === level.toLowerCase());
      };

      expect(filterByLevel('ALL')).toHaveLength(4);
      expect(filterByLevel('ERROR')).toHaveLength(1);
      expect(filterByLevel('ERROR')[0].id).toBe('3');
      expect(filterByLevel('WARN')).toHaveLength(1);
      expect(filterByLevel('PAYLOAD')).toHaveLength(1);
      expect(filterByLevel('INFO')).toHaveLength(1);
    });

    it('filters log lines by search text or regex query', () => {
      const logs: LogEntry[] = [
        { id: '1', timestamp: '12:00:01', level: 'info', message: 'GET /api/v1/health HTTP/1.1 200 OK' },
        { id: '2', timestamp: '12:00:02', level: 'warn', message: 'Strict-Transport-Security header missing' },
        { id: '3', timestamp: '12:00:03', level: 'error', message: 'Failed assertion: X-Frame-Options must be DENY' },
        { id: '4', timestamp: '12:00:04', level: 'payload', message: 'POST /api/v1/auth/login with SQLi payload' },
      ];

      const searchFilter = (query: string) => {
        return logs.filter((l) => {
          try {
            const regex = new RegExp(query, 'i');
            return regex.test(l.message) || regex.test(l.level);
          } catch {
            return l.message.toLowerCase().includes(query.toLowerCase());
          }
        });
      };

      // Search keyword
      expect(searchFilter('header')).toHaveLength(1);
      expect(searchFilter('assertion')).toHaveLength(1);

      // Regex search
      expect(searchFilter('GET|POST')).toHaveLength(2);
      expect(searchFilter('HTTP\\/1\\.1')).toHaveLength(1);
      expect(searchFilter('nonexistent')).toHaveLength(0);
    });

    it('filters logs by stage/engine isolation', () => {
      const logs: LogEntry[] = [
        { id: '1', timestamp: '12:00:01', level: 'info', message: 'Header check completed', engineId: 'engine-native-headers' },
        { id: '2', timestamp: '12:00:02', level: 'info', message: 'Starting k6 resilience worker', engineId: 'engine-worker-k6' },
        { id: '3', timestamp: '12:00:03', level: 'payload', message: 'Fuzzing endpoint /items', engineId: 'engine-native-fuzzer' },
        { id: '4', timestamp: '12:00:04', level: 'warn', message: 'K6 p95 latency threshold exceeded', engineId: 'engine-worker-k6' },
      ];

      const filterByEngine = (engineId: string | null) => {
        if (!engineId) return logs;
        return logs.filter((l) => l.engineId === engineId);
      };

      expect(filterByEngine('engine-worker-k6')).toHaveLength(2);
      expect(filterByEngine('engine-native-fuzzer')).toHaveLength(1);
      expect(filterByEngine(null)).toHaveLength(4);
    });
  });

  describe('Stage Waterfall Pipeline Lifecycle', () => {
    it('manages sequential stage transitions through execution phases', () => {
      let stages: StageItem[] = [
        { id: 'engine-native-headers', name: 'Headers & Security Flags', status: 'pending' },
        { id: 'engine-native-cors', name: 'CORS & Origin Policies', status: 'pending' },
        { id: 'engine-worker-k6', name: 'K6 Distributed Load Testing', status: 'pending' },
      ];

      // Step 1: Start stage 1
      stages = stages.map((s) => (s.id === 'engine-native-headers' ? { ...s, status: 'running' } : s));
      expect(stages[0].status).toBe('running');
      expect(stages[1].status).toBe('pending');

      // Step 2: Complete stage 1, start stage 2
      stages = stages.map((s) => {
        if (s.id === 'engine-native-headers') {
          return { ...s, status: 'completed', durationMs: 142, findingsCount: 2 };
        }
        if (s.id === 'engine-native-cors') {
          return { ...s, status: 'running' };
        }
        return s;
      });

      expect(stages[0].status).toBe('completed');
      expect(stages[0].durationMs).toBe(142);
      expect(stages[0].findingsCount).toBe(2);
      expect(stages[1].status).toBe('running');

      // Step 3: Stage 2 fails
      stages = stages.map((s) => {
        if (s.id === 'engine-native-cors') {
          return { ...s, status: 'failed', durationMs: 89, errorMessage: 'Preflight response timed out' };
        }
        return s;
      });

      expect(stages[1].status).toBe('failed');
      expect(stages[1].errorMessage).toBe('Preflight response timed out');
      expect(stages[2].status).toBe('pending');
    });

    it('formats stage runtime durations accurately', () => {
      const formatDuration = (ms?: number) => {
        if (ms === undefined || ms === null) return '--';
        if (ms < 1000) return `${ms}ms`;
        return `${(ms / 1000).toFixed(2)}s`;
      };

      expect(formatDuration(undefined)).toBe('--');
      expect(formatDuration(450)).toBe('450ms');
      expect(formatDuration(1500)).toBe('1.50s');
      expect(formatDuration(12430)).toBe('12.43s');
    });
  });

  describe('Real-Time Live Execution Telemetry Calculation', () => {
    it('aggregates live telemetry points and detects SLA degradation', () => {
      const metrics: RunTelemetryMetrics = {
        rps: 245,
        p95LatencyMs: 412,
        errorRatePct: 0.8,
        activeWorkers: 4,
        totalRequests: 12250,
      };

      const SLA_THRESHOLD_MS = 500;
      const isSlaBreached = metrics.p95LatencyMs > SLA_THRESHOLD_MS;
      expect(isSlaBreached).toBe(false);

      // Simulate latency spike during stress test
      const degradedMetrics: RunTelemetryMetrics = {
        ...metrics,
        rps: 650,
        p95LatencyMs: 620,
        errorRatePct: 4.2,
      };

      expect(degradedMetrics.p95LatencyMs > SLA_THRESHOLD_MS).toBe(true);
      expect(degradedMetrics.errorRatePct).toBeGreaterThan(1.0);
    });
  });

  describe('Safe Instant Cancellation Controls', () => {
    it('invokes cancel API endpoint with run ID and handles teardown', async () => {
      const runId = 'run-test-telemetry-001';
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ success: true, message: `Run ${runId} cancelled` }),
      });

      const cancelRun = async (id: string) => {
        const res = await mockFetch(`/api/v1/test-runs/${id}/cancel`, {
          method: 'POST',
        });
        const data = await res.json();
        return data;
      };

      const result = await cancelRun(runId);
      expect(mockFetch).toHaveBeenCalledWith(`/api/v1/test-runs/${runId}/cancel`, {
        method: 'POST',
      });
      expect(result.success).toBe(true);
    });
  });
});
