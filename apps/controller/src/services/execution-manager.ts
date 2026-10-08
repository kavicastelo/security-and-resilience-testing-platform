import { EventEmitter } from 'node:events';
import { logger } from '@security-lab/logger';
import { TestRun, TestRunSummary } from '@security-lab/domain';
import { testRunsService } from './test-runs.service.js';
import { testRunnerService, ExecuteRunOptions, TestRunExecutionResult } from './runner.service.js';
import {
  RunLifecycleEvent,
  EngineLifecycleEvent,
  ExecutionProgressEvent,
} from './execution-events.js';
import { getDatabase } from './db.js';
import { testExecutions, agentJobs } from './db/schema.js';
import { eq, and, inArray } from 'drizzle-orm';

export interface QueuedExecutionJob {
  testRunId: string;
  options?: ExecuteRunOptions;
  enqueuedAt: Date;
  resolve?: (result: TestRunExecutionResult) => void;
  reject?: (err: Error) => void;
}

export interface ActiveExecutionEntry {
  testRunId: string;
  abortController: AbortController;
  startedAt: Date;
  options?: ExecuteRunOptions;
  promise?: Promise<TestRunExecutionResult>;
}

export interface CancelResult {
  cancelled: boolean;
  status: string;
  reason?: string;
}

/**
 * ExecutionManager provides an in-memory concurrency-limited worker queue,
 * centralized AbortController lifecycle tracking, and cancellation controls
 * for asynchronous test run execution.
 */
export class ExecutionManager extends EventEmitter {
  private readonly concurrency: number;
  private readonly queue: QueuedExecutionJob[] = [];
  private readonly activeRuns = new Map<string, ActiveExecutionEntry>();
  private runningCount = 0;

  constructor(concurrency = 2) {
    super();
    this.concurrency = concurrency;

    testRunnerService.on('run', (event: RunLifecycleEvent) => {
      this.emit('run', event);
      this.emit(`run:${event.testRunId}`, event);
    });

    testRunnerService.on('engine', (event: EngineLifecycleEvent) => {
      this.emit('engine', event);
      this.emit(`engine:${event.testRunId}`, event);
    });

    testRunnerService.on('progress', (event: ExecutionProgressEvent) => {
      this.emit('progress', event);
      this.emit(`progress:${event.testRunId}`, event);
    });
  }

  /**
   * Enqueues a test run for asynchronous processing and immediately returns status 202-compatible payload.
   */
  async enqueue(
    testRunId: string,
    options?: ExecuteRunOptions,
  ): Promise<{ status: 'queued'; testRunId: string; pollingUrl: string }> {
    const queueLogger = logger.child({ testRunId });

    // Validate that test run exists
    const run = await testRunsService.getTestRunById(testRunId);
    if (!run) {
      throw new Error(`TestRun "${testRunId}" not found`);
    }

    if (run.status === 'completed' || run.status === 'failed' || run.status === 'cancelled') {
      throw new Error(`TestRun "${testRunId}" is already in terminal state "${run.status}"`);
    }

    // Check if already in queue or running
    if (this.isRunActive(testRunId)) {
      queueLogger.info(`Test run ${testRunId} is already queued or executing.`);
      return {
        status: 'queued',
        testRunId,
        pollingUrl: `/api/v1/test-runs/${testRunId}`,
      };
    }

    // Update status in database to queued
    await testRunsService.updateTestRunStatus(testRunId, 'queued');

    const queuedEvent: RunLifecycleEvent = {
      testRunId,
      status: 'queued',
      timestamp: new Date().toISOString(),
    };
    this.emit('run', queuedEvent);
    this.emit(`run:${testRunId}`, queuedEvent);

    this.queue.push({
      testRunId,
      options,
      enqueuedAt: new Date(),
    });

    queueLogger.info(
      { queueDepth: this.queue.length, runningCount: this.runningCount },
      `[ExecutionQueue] Enqueued test run ${testRunId}`,
    );

    // Trigger queue scheduler
    this.schedule();

    return {
      status: 'queued',
      testRunId,
      pollingUrl: `/api/v1/test-runs/${testRunId}`,
    };
  }

  /**
   * Enqueues a test run and awaits its full completion (backward-compatible synchronous execution).
   */
  async executeAndWait(
    testRunId: string,
    options?: ExecuteRunOptions,
  ): Promise<TestRunExecutionResult> {
    const run = await testRunsService.getTestRunById(testRunId);
    if (!run) {
      throw new Error(`TestRun "${testRunId}" not found`);
    }

    return new Promise<TestRunExecutionResult>((resolve, reject) => {
      // Mark as queued in DB
      testRunsService.updateTestRunStatus(testRunId, 'queued').catch(reject);

      const queuedEvent: RunLifecycleEvent = {
        testRunId,
        status: 'queued',
        timestamp: new Date().toISOString(),
      };
      this.emit('run', queuedEvent);
      this.emit(`run:${testRunId}`, queuedEvent);

      this.queue.push({
        testRunId,
        options,
        enqueuedAt: new Date(),
        resolve,
        reject,
      });

      this.schedule();
    });
  }

  /**
   * Cancels a queued or in-flight test run, aborting active containers and child processes.
   */
  async cancel(testRunId: string): Promise<CancelResult> {
    const cancelLogger = logger.child({ testRunId });
    const { db } = getDatabase();

    // 1. Check if job is still waiting in queue
    const queuedIdx = this.queue.findIndex((job) => job.testRunId === testRunId);
    if (queuedIdx !== -1) {
      const [job] = this.queue.splice(queuedIdx, 1);
      cancelLogger.info(`[ExecutionQueue] Removed queued test run ${testRunId} from queue.`);

      const summary: TestRunSummary = {
        totalTests: 0,
        passedTests: 0,
        failedTests: 0,
        errorTests: 0,
        findingsCount: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      };

      await testRunsService.updateTestRunStatus(testRunId, 'cancelled', summary);

      const cancelEvent: RunLifecycleEvent = {
        testRunId,
        status: 'cancelled',
        summary,
        timestamp: new Date().toISOString(),
      };
      this.emit('run', cancelEvent);
      this.emit(`run:${testRunId}`, cancelEvent);

      if (job?.reject) {
        job.reject(new Error(`Test run ${testRunId} cancelled while queued.`));
      }

      return { cancelled: true, status: 'cancelled' };
    }

    // 2. Check if job is currently active
    const activeEntry = this.activeRuns.get(testRunId);
    if (activeEntry) {
      cancelLogger.warn(`[ExecutionQueue] Aborting in-flight test run ${testRunId}...`);

      // Trigger AbortSignal to propagate to engines and DockerRunner
      activeEntry.abortController.abort();

      // Wait briefly for execution loop to acknowledge cancellation
      if (activeEntry.promise) {
        await Promise.race([
          activeEntry.promise.catch(() => {}),
          new Promise((r) => setTimeout(r, 800)),
        ]);
      }

      // Update test run in database
      await testRunsService.updateTestRunStatus(testRunId, 'cancelled');

      const cancelEvent: RunLifecycleEvent = {
        testRunId,
        status: 'cancelled',
        timestamp: new Date().toISOString(),
      };
      this.emit('run', cancelEvent);
      this.emit(`run:${testRunId}`, cancelEvent);

      // Update any running executions and associated agent_jobs for this test run
      try {
        await db
          .update(testExecutions)
          .set({
            status: 'cancelled',
            completedAt: new Date(),
            errorMessage: 'Execution aborted by cancellation request',
          })
          .where(and(eq(testExecutions.testRunId, testRunId), eq(testExecutions.status, 'running')));

        await db
          .update(agentJobs)
          .set({
            status: 'cancelled',
            leaseExpiresAt: null,
            error: 'Execution cancelled by user',
            completedAt: new Date(),
            updatedAt: new Date(),
          })
          .where(
            and(
              eq(agentJobs.testRunId, testRunId),
              inArray(agentJobs.status, ['queued', 'leased', 'running']),
            ),
          );
      } catch (err) {
        cancelLogger.error({ err }, 'Failed to update running executions or agent_jobs to cancelled');
      }

      return { cancelled: true, status: 'cancelled' };
    }

    // 3. Fallback: check database directly (including remote agent executions)
    const run = await testRunsService.getTestRunById(testRunId);
    if (!run) {
      return { cancelled: false, status: 'not_found', reason: `Test run "${testRunId}" not found` };
    }

    if (run.status === 'pending' || run.status === 'queued' || run.status === 'running') {
      await testRunsService.updateTestRunStatus(testRunId, 'cancelled');

      try {
        await db
          .update(testExecutions)
          .set({
            status: 'cancelled',
            completedAt: new Date(),
            errorMessage: 'Execution aborted by cancellation request',
          })
          .where(and(eq(testExecutions.testRunId, testRunId), eq(testExecutions.status, 'running')));

        await db
          .update(agentJobs)
          .set({
            status: 'cancelled',
            leaseExpiresAt: null,
            error: 'Execution cancelled by user',
            completedAt: new Date(),
            updatedAt: new Date(),
          })
          .where(
            and(
              eq(agentJobs.testRunId, testRunId),
              inArray(agentJobs.status, ['queued', 'leased', 'running']),
            ),
          );
      } catch (err) {
        cancelLogger.error({ err }, 'Failed to update database records to cancelled');
      }

      const cancelEvent: RunLifecycleEvent = {
        testRunId,
        status: 'cancelled',
        timestamp: new Date().toISOString(),
      };
      this.emit('run', cancelEvent);
      this.emit(`run:${testRunId}`, cancelEvent);

      return { cancelled: true, status: 'cancelled' };
    }

    return {
      cancelled: false,
      status: run.status,
      reason: `Test run "${testRunId}" is already in terminal state "${run.status}"`,
    };
  }

  /**
   * Checks whether a run is either waiting in the queue or actively executing.
   */
  isRunActive(testRunId: string): boolean {
    return (
      this.activeRuns.has(testRunId) ||
      this.queue.some((job) => job.testRunId === testRunId)
    );
  }

  /**
   * Returns current concurrency metrics for observability.
   */
  getQueueMetrics(): { queued: number; running: number; concurrency: number } {
    return {
      queued: this.queue.length,
      running: this.runningCount,
      concurrency: this.concurrency,
    };
  }

  /**
   * Helper that polls the database until a run reaches terminal status or timeout occurs.
   */
  async waitForRun(testRunId: string, timeoutMs = 30000): Promise<TestRun> {
    const startTime = Date.now();
    while (Date.now() - startTime < timeoutMs) {
      const run = await testRunsService.getTestRunById(testRunId);
      if (run && ['completed', 'failed', 'cancelled'].includes(run.status)) {
        return run;
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(`Timed out waiting for test run "${testRunId}" after ${timeoutMs}ms`);
  }

  /**
   * Internal scheduler: dispatches queued jobs up to max concurrency.
   */
  private schedule(): void {
    while (this.runningCount < this.concurrency && this.queue.length > 0) {
      const job = this.queue.shift();
      if (!job) break;

      this.runningCount++;
      const abortController = new AbortController();

      const activeEntry: ActiveExecutionEntry = {
        testRunId: job.testRunId,
        abortController,
        startedAt: new Date(),
        options: job.options,
      };

      this.activeRuns.set(job.testRunId, activeEntry);

      logger.info(
        {
          testRunId: job.testRunId,
          activeCount: this.runningCount,
          concurrency: this.concurrency,
        },
        `[ExecutionQueue] Dispatching worker slot for test run ${job.testRunId}`,
      );

      const execPromise = testRunnerService.executeTestRunInternal(
        job.testRunId,
        job.options,
        abortController.signal,
      );
      activeEntry.promise = execPromise;

      execPromise
        .then((result) => {
          if (job.resolve) job.resolve(result);
        })
        .catch((err) => {
          if (job.reject) job.reject(err);
        })
        .finally(() => {
          this.activeRuns.delete(job.testRunId);
          this.runningCount--;
          logger.debug(
            {
              testRunId: job.testRunId,
              remainingRunning: this.runningCount,
              queueLength: this.queue.length,
            },
            `[ExecutionQueue] Completed worker slot for test run ${job.testRunId}`,
          );
          // Process next items in queue
          this.schedule();
        });
    }
  }
}

export const executionManager = new ExecutionManager(2);
