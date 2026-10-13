import { parentPort, threadId } from 'node:worker_threads';
import {
  WorkerInboundMessage,
  WorkerOutboundMessage,
  WorkerExecuteMessage,
} from './worker-protocol.js';
import { dynamicWorkerEngineRegistry } from './registry.js';
import {
  ExecutionContext,
  TargetExecutionContext,
  TestEngine,
  TestResult,
} from './types.js';

/**
 * Worker thread execution harness entrypoint.
 * Listens for EXECUTE instructions, runs the engine in isolation,
 * and streams progress, logs, metrics, findings, and results back to the parent process.
 */
function initializeWorker(): void {
  if (!parentPort) {
    throw new Error('Worker entrypoint must be executed within a Node.js worker_thread');
  }

  // Notify parent thread that worker is ready
  parentPort.postMessage({
    type: 'READY',
    threadId,
  } satisfies WorkerOutboundMessage);

  parentPort.on('message', async (message: WorkerInboundMessage) => {
    if (message.type === 'EXECUTE') {
      await handleExecute(message);
    }
  });

  // Global uncaught handlers inside worker to prevent silent thread crashes
  process.on('uncaughtException', (err: Error) => {
    if (parentPort) {
      parentPort.postMessage({
        type: 'ERROR',
        id: 'uncaught_exception',
        error: err.message,
        stack: err.stack,
      } satisfies WorkerOutboundMessage);
    }
  });

  process.on('unhandledRejection', (reason: unknown) => {
    if (parentPort) {
      const msg = reason instanceof Error ? reason.message : String(reason);
      parentPort.postMessage({
        type: 'ERROR',
        id: 'unhandled_rejection',
        error: msg,
      } satisfies WorkerOutboundMessage);
    }
  });
}

function deserializeFunction(source: string): (input: any, context: any) => Promise<any> {
  const trimmed = source.trim();
  try {
    return new Function(`return (${trimmed})`)();
  } catch {
    try {
      const obj = new Function(`return ({ ${trimmed} })`)();
      const keys = Object.keys(obj);
      if (keys.length > 0) {
        return obj[keys[0]!];
      }
    } catch {
      return new Function(`return async function ${trimmed.replace(/^async\s*/, '')}`)();
    }
  }
  throw new Error(`Failed to deserialize function source: ${source.substring(0, 100)}`);
}

async function handleExecute(msg: WorkerExecuteMessage): Promise<void> {
  const { id, engineId, input, context: serialContext, executeFunctionSource, engineModulePath } = msg;

  try {
    // 1. Resolve Engine
    let engine: TestEngine | undefined = dynamicWorkerEngineRegistry.get(engineId);

    if (!engine && engineModulePath) {
      try {
        const mod = await import(engineModulePath);
        const resolved =
          mod.default ||
          mod[engineId] ||
          mod.webCrawlerEngine ||
          mod.injectionFuzzerEngine ||
          mod.graphQLSecurityEngine ||
          mod.engine;
        if (resolved) engine = resolved;
      } catch {
        // Continue to fallback below
      }
    }

    if (!engine && executeFunctionSource) {
      try {
        const executeFn = deserializeFunction(executeFunctionSource);
        engine = {
          id: engineId,
          version: '1.0.0',
          capabilities: () => [],
          validate: () => ({ valid: true }),
          execute: executeFn,
        };
      } catch {
        // Continue to error check below
      }
    }

    if (!engine) {
      parentPort!.postMessage({
        type: 'ERROR',
        id,
        error: `Engine "${engineId}" not found in worker registry`,
      } satisfies WorkerOutboundMessage);
      return;
    }

    // 2. Reconstitute ExecutionContext with IPC callbacks
    const abortController = new AbortController();

    const targetContext: TargetExecutionContext = {
      id: serialContext.target.id,
      name: serialContext.target.name,
      baseUrl: serialContext.target.baseUrl,
      scope: serialContext.target.scope,
    };

    const bridgeContext: ExecutionContext = {
      correlationId: serialContext.correlationId,
      testRunId: serialContext.testRunId,
      executionId: serialContext.executionId,
      target: targetContext,
      abortSignal: abortController.signal,
      reportProgress: (percentage: number, stepMessage: string) => {
        parentPort!.postMessage({
          type: 'PROGRESS',
          id,
          percentage,
          stepMessage,
        } satisfies WorkerOutboundMessage);
      },
      logger: {
        debug: (objOrMsg: unknown, ...args: unknown[]) => postLog('debug', id, objOrMsg, args),
        info: (objOrMsg: unknown, ...args: unknown[]) => postLog('info', id, objOrMsg, args),
        warn: (objOrMsg: unknown, ...args: unknown[]) => postLog('warn', id, objOrMsg, args),
        error: (objOrMsg: unknown, ...args: unknown[]) => postLog('error', id, objOrMsg, args),
        child: () => bridgeContext.logger,
      } as any,
    };

    // 3. Execute Engine
    const startTime = Date.now();
    const result: TestResult = await engine.execute(input, bridgeContext);
    const durationMs = Date.now() - startTime;

    const memoryMb = Math.round((process.memoryUsage().heapUsed / (1024 * 1024)) * 10) / 10;

    parentPort!.postMessage({
      type: 'RESULT',
      id,
      result: {
        ...result,
        durationMs: result.durationMs || durationMs,
      },
      memoryUsageMb: memoryMb,
    } satisfies WorkerOutboundMessage);
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    const errorStack = err instanceof Error ? err.stack : undefined;
    parentPort!.postMessage({
      type: 'ERROR',
      id,
      error: errorMsg,
      stack: errorStack,
    } satisfies WorkerOutboundMessage);
  }
}

function postLog(level: 'debug' | 'info' | 'warn' | 'error', id: string, objOrMsg: unknown, args: unknown[]): void {
  if (!parentPort) return;
  let message = '';
  let meta: Record<string, unknown> | undefined;

  if (typeof objOrMsg === 'string') {
    message = objOrMsg;
    if (args.length > 0 && typeof args[0] === 'string') {
      message = `${message} ${args.join(' ')}`;
    }
  } else if (typeof objOrMsg === 'object' && objOrMsg !== null) {
    meta = objOrMsg as Record<string, unknown>;
    message = typeof args[0] === 'string' ? args[0] : JSON.stringify(objOrMsg);
  }

  parentPort.postMessage({
    type: 'LOG',
    id,
    level,
    message,
    meta,
  } satisfies WorkerOutboundMessage);
}

// Auto-initialize when loaded as worker entry
initializeWorker();
