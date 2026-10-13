import { Worker } from 'node:worker_threads';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import { logger } from '@security-lab/logger';
import {
  ExecutionContext,
  TestEngine,
  TestInput,
  TestResult,
  EngineSandboxingOptions,
} from './types.js';
import {
  WorkerExecuteMessage,
  WorkerOutboundMessage,
  SerializableExecutionContext,
} from './worker-protocol.js';
import { dynamicWorkerEngineRegistry } from './registry.js';

export class WorkerExecutionTimeoutError extends Error {
  constructor(message: string, public readonly engineId: string, public readonly timeoutMs: number) {
    super(message);
    this.name = 'WorkerExecutionTimeoutError';
  }
}

export class WorkerMemoryLimitError extends Error {
  constructor(message: string, public readonly engineId: string, public readonly memoryLimitMb: number) {
    super(message);
    this.name = 'WorkerMemoryLimitError';
  }
}

/**
 * Resolves the path to the worker entrypoint script across development (TypeScript) and production (bundled/dist).
 */
export function resolveWorkerEntryPath(customPath?: string): string {
  if (customPath && fs.existsSync(customPath)) {
    return customPath;
  }

  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    path.resolve(currentDir, 'worker-entry.js'),
    path.resolve(currentDir, '../dist/worker-entry.js'),
    path.resolve(currentDir, '../../dist/packages/engine-sdk/src/worker-entry.js'),
    path.resolve(currentDir, 'worker-entry.ts'),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  return path.resolve(currentDir, 'worker-entry.js');
}

/**
 * Worker thread execution harness.
 * Isolates native engine execution within Node.js worker threads with hard CPU, memory,
 * and timeout limits to safeguard the runner and agent daemon processes.
 */
export class WorkerRunner {
  /**
   * Executes a native test engine inside an isolated worker thread with memory and timeout boundaries.
   */
  async execute(
    engineId: string,
    input: TestInput,
    context: ExecutionContext,
    options: EngineSandboxingOptions = {},
  ): Promise<TestResult> {
    const isSandboxed = options.enabled !== false;

    // Graceful fallback to in-process execution if sandboxing is explicitly disabled
    if (!isSandboxed) {
      return this.executeInProcess(engineId, input, context);
    }

    try {
      return await this.executeInWorkerThread(engineId, input, context, options);
    } catch (err: unknown) {
      if (options.fallbackToInProcess !== false) {
        logger.warn(
          {
            event: 'worker.fallback_in_process',
            engineId,
            error: err instanceof Error ? err.message : String(err),
          },
          `Worker thread execution failed to initialize; falling back to in-process execution for engine "${engineId}".`,
        );
        return this.executeInProcess(engineId, input, context);
      }
      throw err;
    }
  }

  /**
   * Fallback in-process execution when worker_threads are disabled or unavailable.
   */
  async executeInProcess(
    engineId: string,
    input: TestInput,
    context: ExecutionContext,
  ): Promise<TestResult> {
    const engine: TestEngine | undefined = dynamicWorkerEngineRegistry.get(engineId);
    if (!engine) {
      return {
        engineId,
        durationMs: 0,
        success: false,
        findings: [],
        metrics: [],
        error: `Engine "${engineId}" not found in registry`,
      };
    }

    const startTime = Date.now();
    try {
      const result = await engine.execute(input, context);
      return {
        ...result,
        durationMs: result.durationMs || Date.now() - startTime,
      };
    } catch (err: unknown) {
      return {
        engineId,
        durationMs: Date.now() - startTime,
        success: false,
        findings: [],
        metrics: [],
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  private executeInWorkerThread(
    engineId: string,
    input: TestInput,
    context: ExecutionContext,
    options: EngineSandboxingOptions,
  ): Promise<TestResult> {
    return new Promise<TestResult>((resolve) => {
      const startTime = Date.now();
      const executionId = context.executionId || crypto.randomUUID();
      const timeoutMs = options.timeoutMs ?? input.timeoutMs ?? 30000;
      const maxOldGenerationSizeMb = options.maxOldGenerationSizeMb ?? 512;
      const maxYoungGenerationSizeMb = options.maxYoungGenerationSizeMb ?? 128;

      const entryPath = resolveWorkerEntryPath(options.workerEntryPath);
      let worker: Worker | null = null;
      let timeoutTimer: NodeJS.Timeout | null = null;
      let isResolved = false;

      const cleanup = async () => {
        if (timeoutTimer) {
          clearTimeout(timeoutTimer);
          timeoutTimer = null;
        }
        if (worker) {
          try {
            await worker.terminate();
          } catch {
            // Ignore termination errors during cleanup
          }
          worker = null;
        }
      };

      const safeResolve = async (result: TestResult) => {
        if (isResolved) return;
        isResolved = true;
        await cleanup();
        resolve(result);
      };

      // Prepare serializable execution context across IPC boundary
      const serializableContext: SerializableExecutionContext = {
        correlationId: context.correlationId,
        testRunId: context.testRunId,
        executionId,
        target: {
          id: context.target.id,
          name: context.target.name,
          baseUrl: context.target.baseUrl,
          scope: context.target.scope,
        },
        timeoutMs,
      };

      // Initialize Worker with hard memory ceilings via resourceLimits
      try {
        const isTs = entryPath.endsWith('.ts');
        const execArgv = [...process.execArgv];
        if (isTs && !execArgv.some((arg) => arg.includes('tsx') || arg.includes('ts-node'))) {
          execArgv.push('--import', 'tsx');
        }

        worker = new Worker(entryPath, {
          resourceLimits: {
            maxOldGenerationSizeMb,
            maxYoungGenerationSizeMb,
          },
          execArgv,
        });
      } catch (err: unknown) {
        logger.error(
          { event: 'worker.spawn_failed', engineId, error: String(err) },
          `Failed to spawn worker thread for engine "${engineId}"`,
        );
        safeResolve({
          engineId,
          durationMs: Date.now() - startTime,
          success: false,
          findings: [],
          metrics: [],
          error: `Failed to spawn worker thread: ${err instanceof Error ? err.message : String(err)}`,
        });
        return;
      }

      // Hard timeout enforcement via worker.terminate()
      timeoutTimer = setTimeout(() => {
        const durationMs = Date.now() - startTime;
        logger.warn(
          {
            event: 'worker.timeout',
            engineId,
            durationMs,
            timeoutMs,
            targetUrl: input.targetUrl,
          },
          `Worker thread execution TIMED OUT for engine "${engineId}" after ${durationMs}ms (limit: ${timeoutMs}ms). Terminating worker forcibly.`,
        );

        safeResolve({
          engineId,
          durationMs,
          success: false,
          findings: [],
          metrics: [],
          error: `Engine execution timed out after ${timeoutMs}ms (terminated by worker harness)`,
        });
      }, timeoutMs);

      // Listen for parent abortSignal to terminate worker immediately on run cancellation
      if (context.abortSignal) {
        context.abortSignal.addEventListener(
          'abort',
          () => {
            const durationMs = Date.now() - startTime;
            logger.info(
              { event: 'worker.aborted', engineId, durationMs },
              `Worker thread for engine "${engineId}" cancelled via abort signal.`,
            );
            safeResolve({
              engineId,
              durationMs,
              success: false,
              findings: [],
              metrics: [],
              error: 'Engine execution was cancelled by parent signal',
            });
          },
          { once: true },
        );
      }

      // Message passing handler
      worker.on('message', (msg: WorkerOutboundMessage) => {
        if (!msg || typeof msg !== 'object') return;

        switch (msg.type) {
          case 'READY': {
            // Worker thread initialized; dispatch the EXECUTE payload
            if (worker) {
              const localEngine = dynamicWorkerEngineRegistry.get(engineId);
              let engineModulePath: string | undefined;
              if (engineId === 'engine-web-crawler') {
                engineModulePath = '@security-lab/web-crawler';
              } else if (engineId === 'engine-injection-fuzzer') {
                engineModulePath = '@security-lab/injection-fuzzer';
              } else if (engineId === 'engine-graphql-security') {
                engineModulePath = '@security-lab/graphql-security';
              }

              const executeFunctionSource =
                !engineModulePath && localEngine && typeof localEngine.execute === 'function'
                  ? localEngine.execute.toString()
                  : undefined;

              const execMsg: WorkerExecuteMessage = {
                type: 'EXECUTE',
                id: executionId,
                engineId,
                input,
                context: serializableContext,
                executeFunctionSource,
                engineModulePath,
              };
              worker.postMessage(execMsg);
            }
            break;
          }

          case 'PROGRESS': {
            if (context.reportProgress) {
              context.reportProgress(msg.percentage, msg.stepMessage);
            }
            break;
          }

          case 'LOG': {
            const { level, message, meta } = msg;
            if (context.logger && typeof (context.logger as any)[level] === 'function') {
              (context.logger as any)[level](meta || {}, `[Worker:${engineId}] ${message}`);
            }
            break;
          }

          case 'RESULT': {
            const durationMs = Date.now() - startTime;
            logger.info(
              {
                event: 'worker.success',
                engineId,
                durationMs,
                memoryUsageMb: msg.memoryUsageMb,
                findingsCount: msg.result.findings?.length ?? 0,
              },
              `Engine "${engineId}" completed successfully in worker thread (${durationMs}ms).`,
            );
            safeResolve({
              ...msg.result,
              durationMs: msg.result.durationMs || durationMs,
            });
            break;
          }

          case 'ERROR': {
            const durationMs = Date.now() - startTime;
            logger.warn(
              {
                event: 'worker.engine_error',
                engineId,
                durationMs,
                error: msg.error,
              },
              `Engine "${engineId}" emitted execution error in worker thread: ${msg.error}`,
            );
            safeResolve({
              engineId,
              durationMs,
              success: false,
              findings: [],
              metrics: [],
              error: msg.error,
            });
            break;
          }
        }
      });

      // Handle worker error event (uncaught exceptions or OOM crashes)
      worker.on('error', (err: Error) => {
        const durationMs = Date.now() - startTime;
        const isOom =
          err.message.includes('out of memory') ||
          (err as any).code === 'ERR_WORKER_OUT_OF_MEMORY' ||
          err.message.includes('allocation failure');

        if (isOom) {
          logger.warn(
            {
              event: 'worker.out_of_memory',
              engineId,
              durationMs,
              maxOldGenerationSizeMb,
            },
            `Engine "${engineId}" exceeded memory ceiling of ${maxOldGenerationSizeMb}MB and was terminated. Parent process intact.`,
          );
          safeResolve({
            engineId,
            durationMs,
            success: false,
            findings: [],
            metrics: [],
            error: `Engine exceeded memory ceiling of ${maxOldGenerationSizeMb}MB (terminated by worker harness)`,
          });
        } else {
          logger.warn(
            {
              event: 'worker.thread_error',
              engineId,
              durationMs,
              error: err.message,
            },
            `Worker thread for engine "${engineId}" encountered error: ${err.message}`,
          );
          safeResolve({
            engineId,
            durationMs,
            success: false,
            findings: [],
            metrics: [],
            error: err.message,
          });
        }
      });

      // Handle worker exit event
      worker.on('exit', (exitCode: number) => {
        if (isResolved) return;
        const durationMs = Date.now() - startTime;
        if (exitCode !== 0) {
          logger.warn(
            {
              event: 'worker.abnormal_exit',
              engineId,
              exitCode,
              durationMs,
            },
            `Worker thread for engine "${engineId}" terminated unexpectedly with exit code ${exitCode}.`,
          );
          safeResolve({
            engineId,
            durationMs,
            success: false,
            findings: [],
            metrics: [],
            error: `Worker thread exited abnormally with code ${exitCode} (possible memory exhaustion or segfault)`,
          });
        }
      });
    });
  }
}

export const workerRunner = new WorkerRunner();
