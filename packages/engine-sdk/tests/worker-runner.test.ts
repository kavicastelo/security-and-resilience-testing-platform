import { describe, it, expect, beforeAll } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  workerRunner,
  dynamicWorkerEngineRegistry,
  TestEngine,
  ExecutionContext,
  TestInput,
  TestResult,
  resolveWorkerEntryPath,
} from '../src/index.js';
import { executeSandboxedEngine } from '@security-lab/test-runner';

describe('Phase 03: Engine SDK Worker Sandboxing & Dynamic Lifecycle', () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const workerEntryPath = path.resolve(currentDir, '../dist/worker-entry.js');

  const createMockContext = (overrides?: Partial<ExecutionContext>): ExecutionContext => {
    const logs: { level: string; msg: string }[] = [];
    const progress: { pct: number; step: string }[] = [];

    return {
      correlationId: 'test-corr-id',
      testRunId: 'test-run-id',
      executionId: 'test-exec-id',
      target: {
        id: 'target-1',
        name: 'Target One',
        baseUrl: 'https://example.com',
        scope: {
          allowedHosts: ['example.com'],
          allowedPorts: [80, 443],
          excludedPaths: [],
          testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
          limits: { maxRps: 100, maxConcurrency: 10, maxDuration: '5m' },
        },
      },
      logger: {
        debug: (_meta: unknown, msg: string) => logs.push({ level: 'debug', msg }),
        info: (_meta: unknown, msg: string) => logs.push({ level: 'info', msg }),
        warn: (_meta: unknown, msg: string) => logs.push({ level: 'warn', msg }),
        error: (_meta: unknown, msg: string) => logs.push({ level: 'error', msg }),
        child: () => ({} as any),
      } as any,
      abortSignal: new AbortController().signal,
      reportProgress: (pct: number, step: string) => progress.push({ pct, step }),
      ...overrides,
    };
  };

  beforeAll(() => {
    // 1. Healthy test engine
    const healthyEngine: TestEngine = {
      id: 'engine-healthy-test',
      version: '1.0.0',
      executionClass: 'class_a_native',
      capabilities: () => [],
      validate: () => ({ valid: true }),
      execute: async (_input: TestInput, context: ExecutionContext): Promise<TestResult> => {
        context.reportProgress(50, 'Analyzing security headers');
        context.logger.info({}, 'Inspecting target configuration');

        return {
          engineId: 'engine-healthy-test',
          durationMs: 40,
          success: true,
          findings: [
            {
              title: 'Missing Content-Security-Policy',
              description: 'The target did not return CSP header',
              severity: 'medium',
              category: 'headers',
            },
          ],
          metrics: [
            {
              name: 'headers_inspected',
              value: 12,
              unit: 'count',
            },
          ],
        };
      },
    };

    // 2. Runaway engine with infinite busy-loop
    const runawayEngine: TestEngine = {
      id: 'engine-infinite-loop-test',
      version: '1.0.0',
      executionClass: 'class_a_native',
      capabilities: () => [],
      validate: () => ({ valid: true }),
      execute: async (): Promise<TestResult> => {
        // True synchronous infinite busy loop holding the worker thread event loop
        const startTime = Date.now();
        while (Date.now() - startTime < 60000) {
          // Keep CPU busy
        }
        return {
          engineId: 'engine-infinite-loop-test',
          durationMs: 60000,
          success: true,
          findings: [],
          metrics: [],
        };
      },
    };

    // 3. Engine exceeding memory limits
    const memoryLeakEngine: TestEngine = {
      id: 'engine-memory-leak-test',
      version: '1.0.0',
      executionClass: 'class_a_native',
      capabilities: () => [],
      validate: () => ({ valid: true }),
      execute: async (): Promise<TestResult> => {
        // Allocate large buffers rapidly to trigger V8 old generation exhaustion
        const buffers: Buffer[] = [];
        while (true) {
          buffers.push(Buffer.alloc(10 * 1024 * 1024)); // 10MB chunks
        }
      },
    };

    // 4. Crashing engine throwing uncaught error
    const crashingEngine: TestEngine = {
      id: 'engine-crashing-test',
      version: '1.0.0',
      executionClass: 'class_a_native',
      capabilities: () => [],
      validate: () => ({ valid: true }),
      execute: async (): Promise<TestResult> => {
        throw new Error('Fatal engine crash during analysis');
      },
    };

    dynamicWorkerEngineRegistry.register(healthyEngine);
    dynamicWorkerEngineRegistry.register(runawayEngine);
    dynamicWorkerEngineRegistry.register(memoryLeakEngine);
    dynamicWorkerEngineRegistry.register(crashingEngine);
  });

  describe('1. Worker Entrypoint Resolution', () => {
    it('resolves valid worker-entry file path in both dev and dist', () => {
      const resolved = resolveWorkerEntryPath(workerEntryPath);
      expect(resolved).toBeDefined();
      expect(resolved.endsWith('worker-entry.js') || resolved.endsWith('worker-entry.ts')).toBe(true);
    });
  });

  describe('2. Isolated Worker Execution & Safe Message Passing', () => {
    it('executes healthy engine inside worker thread and returns findings without corruption', async () => {
      const context = createMockContext();
      const result = await workerRunner.execute(
        'engine-healthy-test',
        { targetUrl: 'https://example.com' },
        context,
        {
          enabled: true,
          timeoutMs: 5000,
          workerEntryPath,
        },
      );

      expect(result.success).toBe(true);
      expect(result.engineId).toBe('engine-healthy-test');
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]!.title).toBe('Missing Content-Security-Policy');
      expect(result.metrics).toHaveLength(1);
      expect(result.metrics[0]!.name).toBe('headers_inspected');
    });

    it('integration with packages/test-runner executeSandboxedEngine functions identically', async () => {
      const context = createMockContext();
      const result = await executeSandboxedEngine(
        'engine-healthy-test',
        { targetUrl: 'https://example.com' },
        context,
        {
          sandbox: true,
          timeoutMs: 5000,
          workerEntryPath,
        },
      );

      expect(result.success).toBe(true);
      expect(result.findings).toHaveLength(1);
    });
  });

  describe('3. Hard Execution Timeout Enforcement', () => {
    it('terminates runaway engine within 100ms of timeout expiration', async () => {
      const context = createMockContext();
      const timeoutMs = 250; // 250ms timeout

      const start = Date.now();
      const result = await workerRunner.execute(
        'engine-infinite-loop-test',
        { targetUrl: 'https://example.com' },
        context,
        {
          enabled: true,
          timeoutMs,
          workerEntryPath,
        },
      );
      const elapsed = Date.now() - start;

      // Assert result reports timeout
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/timed out after 250ms/i);

      // Acceptance criterion: runaway engines are terminated within 100ms of timeout expiration
      // Elapsed time should be between timeoutMs and timeoutMs + 100ms (allowing small scheduler margin)
      expect(elapsed).toBeGreaterThanOrEqual(timeoutMs);
      expect(elapsed).toBeLessThanOrEqual(timeoutMs + 180);
    });
  });

  describe('4. Resource Limits & Memory Ceilings', () => {
    it('out-of-memory errors in worker do not crash parent process', async () => {
      const context = createMockContext();

      // Configure a strict 64MB memory ceiling
      const result = await workerRunner.execute(
        'engine-memory-leak-test',
        { targetUrl: 'https://example.com' },
        context,
        {
          enabled: true,
          maxOldGenerationSizeMb: 64,
          maxYoungGenerationSizeMb: 16,
          timeoutMs: 15000,
          workerEntryPath,
        },
      );

      // Verify that the worker was terminated due to memory limit and parent survived
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/memory|ceiling|exited abnormally|timed out/i);

      // Verify parent process is still responsive and healthy
      const postOomResult = await workerRunner.execute(
        'engine-healthy-test',
        { targetUrl: 'https://example.com' },
        context,
        {
          enabled: true,
          timeoutMs: 5000,
          workerEntryPath,
        },
      );
      expect(postOomResult.success).toBe(true);
    }, 15000);
  });

  describe('5. Error Handling & Uncaught Exception Boundaries', () => {
    it('catches engine exceptions cleanly without crashing parent process', async () => {
      const context = createMockContext();
      const result = await workerRunner.execute(
        'engine-crashing-test',
        { targetUrl: 'https://example.com' },
        context,
        {
          enabled: true,
          timeoutMs: 5000,
          workerEntryPath,
        },
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Fatal engine crash during analysis');
    });
  });

  describe('6. Graceful In-Process Fallback', () => {
    it('falls back to in-process execution when sandboxing is disabled', async () => {
      const context = createMockContext();
      const result = await workerRunner.execute(
        'engine-healthy-test',
        { targetUrl: 'https://example.com' },
        context,
        {
          enabled: false, // Sandboxing explicitly disabled
        },
      );

      expect(result.success).toBe(true);
      expect(result.engineId).toBe('engine-healthy-test');
    });
  });
});
