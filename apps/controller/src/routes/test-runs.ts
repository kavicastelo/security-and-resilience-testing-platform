import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { eq } from 'drizzle-orm';
import { CreateTestRunInputSchema, ExecuteTestRunInputSchema } from '@security-lab/domain';
import { getDatabase } from '../services/db.js';
import { testExecutions } from '../services/db/schema.js';
import { testRunsService } from '../services/test-runs.service.js';
import { ExecuteRunOptions } from '../services/runner.service.js';
import { executionManager } from '../services/execution-manager.js';
import { findingsService } from '../services/findings.service.js';
import { evidenceService } from '../services/evidence.service.js';
import { metricsService } from '../services/metrics.service.js';
import { extractTenantScope } from '../services/tenant-context.js';
import {
  RunLifecycleEvent,
  EngineLifecycleEvent,
  ExecutionProgressEvent,
} from '../services/execution-events.js';

export const testRunsRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  const defaultScanMax = process.env.NODE_ENV === 'production' ? 10 : 500;
  const scanMax = fastify.rateLimitOverrides?.scanMax ?? defaultScanMax;
  const scanRateLimitConfig = {
    max: scanMax,
    timeWindow: '1 minute',
    keyGenerator: (request: any) => {
      // Key rate limits by authenticated tenantId, keyId, or client IP.
      // Never key by raw client-supplied x-tenant-id header.
      const id = request.auth?.tenantId || request.auth?.keyId || request.ip;
      return `scan:${id}`;
    },
    errorResponseBuilder: (_request: any, context: any) => ({
      statusCode: 429,
      error: 'Too Many Requests',
      message: 'Rate limit exceeded for scan execution. Please wait before retrying.',
      retryAfter: Math.ceil(context.ttl / 1000) || 60,
    }),
  };

  // 1. Create & Queue TestRun
  fastify.post('/api/v1/test-runs', {
    config: {
      rateLimit: scanRateLimitConfig,
    },
  }, async (request, reply) => {
    const parseResult = CreateTestRunInputSchema.safeParse(request.body);
    if (!parseResult.success) {
      const isSimulationError = parseResult.error.issues.some((i) =>
        i.message.includes('Simulation options are not permitted via the public API'),
      );
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: isSimulationError
            ? 'Simulation options are not permitted via the public API'
            : 'Invalid TestRun input parameters',
          details: parseResult.error.format(),
        },
      });
    }

    try {
      const tenantId = extractTenantScope(request);
      const testRun = await testRunsService.createTestRun(parseResult.data, tenantId);
      return reply.status(201).send({
        success: true,
        data: testRun,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to create TestRun';
      return reply.status(400).send({
        success: false,
        error: {
          code: 'TESTRUN_CREATION_FAILED',
          message,
        },
      });
    }
  });

  // 2. List TestRuns
  fastify.get<{
    Querystring: { projectId?: string; targetId?: string };
  }>('/api/v1/test-runs', async (request, reply) => {
    const { projectId, targetId } = request.query;
    const tenantId = extractTenantScope(request);
    const runs = await testRunsService.listTestRuns({ projectId, targetId }, tenantId);
    return reply.send({
      success: true,
      data: runs,
    });
  });

  // 3. Get TestRun by ID
  fastify.get<{ Params: { id: string } }>('/api/v1/test-runs/:id', async (request, reply) => {
    const tenantId = extractTenantScope(request);
    const run = await testRunsService.getTestRunById(request.params.id, tenantId);
    if (!run) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'TESTRUN_NOT_FOUND',
          message: `TestRun with ID "${request.params.id}" not found`,
        },
      });
    }

    return reply.send({
      success: true,
      data: run,
    });
  });

  // 3b. Get TestRun Executions
  fastify.get<{ Params: { id: string } }>('/api/v1/test-runs/:id/executions', async (request, reply) => {
    const tenantId = extractTenantScope(request);
    const run = await testRunsService.getTestRunById(request.params.id, tenantId);
    if (!run) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'TESTRUN_NOT_FOUND',
          message: `TestRun with ID "${request.params.id}" not found`,
        },
      });
    }

    const { db } = getDatabase();
    const rows = await db
      .select()
      .from(testExecutions)
      .where(eq(testExecutions.testRunId, request.params.id))
      .orderBy(testExecutions.startedAt);

    return reply.send({
      success: true,
      data: rows.map((e) => ({
        id: e.id,
        engineId: e.engineId,
        executionClass: e.executionClass,
        status: e.status,
        durationMs: e.durationMs,
        errorMessage: e.errorMessage,
        startedAt: e.startedAt,
        completedAt: e.completedAt,
      })),
    });
  });

  // 3c. Real-Time Execution SSE Stream
  fastify.get<{ Params: { id: string } }>('/api/v1/test-runs/:id/stream', {
    config: {
      rateLimit: false,
    },
  }, async (request, reply) => {
    const { id } = request.params;
    const tenantId = extractTenantScope(request);
    const run = await testRunsService.getTestRunById(id, tenantId);
    if (!run) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'TESTRUN_NOT_FOUND',
          message: `TestRun with ID "${id}" not found`,
        },
      });
    }

    // Disable socket timeouts for long-lived SSE connections
    if (typeof request.raw?.setTimeout === 'function') {
      try {
        request.raw.setTimeout(0, () => {});
      } catch {
        // Ignore mock socket errors
      }
    }
    if (typeof reply.raw?.setTimeout === 'function') {
      try {
        reply.raw.setTimeout(0, () => {});
      } catch {
        // Ignore mock socket errors
      }
    }
    if (request.raw?.socket && typeof request.raw.socket.setTimeout === 'function') {
      try {
        request.raw.socket.setTimeout(0);
      } catch {
        // Ignore mock socket errors
      }
    }

    reply.hijack();

    reply.raw.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });

    const streamLogger = request.log.child({ testRunId: id, sse: true });
    streamLogger.info('SSE client connected for test-run stream');

    const sendEvent = (event: string, data: unknown) => {
      try {
        reply.raw.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
      } catch (err) {
        streamLogger.warn({ err }, 'Error writing SSE event to stream');
      }
    };

    // Initial snapshot
    sendEvent('init', {
      testRunId: run.id,
      status: run.status,
      summary: run.summary,
      timestamp: new Date().toISOString(),
    });

    if (
      (request.query as Record<string, unknown>)?.snapshot === 'true' ||
      request.headers['x-stream-snapshot'] === 'true' ||
      ['completed', 'failed', 'cancelled'].includes(run.status)
    ) {
      sendEvent('run_completed', {
        testRunId: run.id,
        status: run.status,
        summary: run.summary,
        timestamp: new Date().toISOString(),
      });
      reply.raw.end();
      return;
    }

    let cleanedUp = false;
    const cleanup = () => {
      if (cleanedUp) return;
      cleanedUp = true;
      clearInterval(heartbeat);
      executionManager.off(`run:${id}`, onRun);
      executionManager.off(`engine:${id}`, onEngine);
      executionManager.off(`progress:${id}`, onProgress);
      streamLogger.info('SSE client disconnected, listeners cleaned up');
    };

    const onRun = (event: RunLifecycleEvent) => {
      sendEvent('run', event);
      if (['completed', 'failed', 'cancelled'].includes(event.status)) {
        sendEvent('run_completed', event);
        cleanup();
        reply.raw.end();
      }
    };

    const onEngine = (event: EngineLifecycleEvent) => {
      sendEvent('engine', event);
    };

    const onProgress = (event: ExecutionProgressEvent) => {
      sendEvent('progress', event);
    };

    executionManager.on(`run:${id}`, onRun);
    executionManager.on(`engine:${id}`, onEngine);
    executionManager.on(`progress:${id}`, onProgress);

    const heartbeat = setInterval(() => {
      try {
        reply.raw.write(': heartbeat\n\n');
      } catch {
        clearInterval(heartbeat);
      }
    }, 15000);

    request.raw.on('close', cleanup);
    request.raw.on('error', cleanup);
  });

  // 4. Execute TestRun (Asynchronous Queue Decoupled from HTTP Response)
  fastify.post<{
    Params: { id: string };
    Body?: ExecuteRunOptions;
    Querystring: { wait?: string };
  }>('/api/v1/test-runs/:id/execute', {
    config: {
      rateLimit: scanRateLimitConfig,
    },
  }, async (request, reply) => {
    const shouldWait = request.query.wait === 'true' || request.body?.wait === true;
    const tenantId = extractTenantScope(request);

    const execParseResult = ExecuteTestRunInputSchema.safeParse(request.body ?? {});
    if (!execParseResult.success) {
      const isSimulationError = execParseResult.error.issues.some((i) =>
        i.message.includes('Simulation options are not permitted via the public API'),
      );
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: isSimulationError
            ? 'Simulation options are not permitted via the public API'
            : 'Invalid TestRun execution parameters',
          details: execParseResult.error.format(),
        },
      });
    }

    const run = await testRunsService.getTestRunById(request.params.id, tenantId);
    if (!run) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'TESTRUN_NOT_FOUND',
          message: `TestRun with ID "${request.params.id}" not found`,
        },
      });
    }

    try {
      if (shouldWait) {
        // Synchronous / wait mode: block and await complete execution
        const result = await executionManager.executeAndWait(request.params.id, request.body);
        return reply.status(200).send({
          success: true,
          data: result,
        });
      }

      // Asynchronous decoupled mode: enqueue job and immediately return 202 Accepted
      const queuedJob = await executionManager.enqueue(request.params.id, request.body);
      return reply.status(202).send({
        success: true,
        data: queuedJob,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Test run execution failed';
      return reply.status(500).send({
        success: false,
        error: {
          code: 'TESTRUN_EXECUTION_FAILED',
          message,
        },
      });
    }
  });

  // 4a. Execute TestRun Alias (without :id param, taking testRunId/id in body)
  fastify.post<{
    Body?: ExecuteRunOptions & { testRunId?: string; id?: string };
    Querystring: { wait?: string };
  }>('/api/v1/test-runs/execute', {
    config: {
      rateLimit: scanRateLimitConfig,
    },
  }, async (request, reply) => {
    const runId = request.body?.testRunId || request.body?.id;
    if (!runId) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'testRunId or id is required in request body for /api/v1/test-runs/execute',
        },
      });
    }

    const shouldWait = request.query.wait === 'true' || request.body?.wait === true;
    const tenantId = extractTenantScope(request);

    const execParseResult = ExecuteTestRunInputSchema.safeParse(request.body ?? {});
    if (!execParseResult.success) {
      const isSimulationError = execParseResult.error.issues.some((i) =>
        i.message.includes('Simulation options are not permitted via the public API'),
      );
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: isSimulationError
            ? 'Simulation options are not permitted via the public API'
            : 'Invalid TestRun execution parameters',
          details: execParseResult.error.format(),
        },
      });
    }

    const run = await testRunsService.getTestRunById(runId, tenantId);
    if (!run) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'TESTRUN_NOT_FOUND',
          message: `TestRun with ID "${runId}" not found`,
        },
      });
    }

    try {
      if (shouldWait) {
        const result = await executionManager.executeAndWait(runId, request.body);
        return reply.status(200).send({
          success: true,
          data: result,
        });
      }

      const queuedJob = await executionManager.enqueue(runId, request.body);
      return reply.status(202).send({
        success: true,
        data: queuedJob,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Test run execution failed';
      return reply.status(500).send({
        success: false,
        error: {
          code: 'TESTRUN_EXECUTION_FAILED',
          message,
        },
      });
    }
  });

  // 4b. Cancel In-Flight or Queued TestRun
  fastify.post<{
    Params: { id: string };
  }>('/api/v1/test-runs/:id/cancel', async (request, reply) => {
    const tenantId = extractTenantScope(request);
    const run = await testRunsService.getTestRunById(request.params.id, tenantId);
    if (!run) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'TESTRUN_NOT_FOUND',
          message: `TestRun with ID "${request.params.id}" not found`,
        },
      });
    }

    try {
      const cancelResult = await executionManager.cancel(request.params.id);
      if (cancelResult.status === 'not_found') {
        return reply.status(404).send({
          success: false,
          error: {
            code: 'TESTRUN_NOT_FOUND',
            message: cancelResult.reason || `TestRun with ID "${request.params.id}" not found`,
          },
        });
      }

      if (!cancelResult.cancelled) {
        return reply.status(400).send({
          success: false,
          error: {
            code: 'TESTRUN_NOT_CANCELLABLE',
            message: cancelResult.reason || `TestRun cannot be cancelled in state "${cancelResult.status}"`,
          },
        });
      }

      return reply.status(200).send({
        success: true,
        data: {
          status: 'cancelled',
          testRunId: request.params.id,
        },
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to cancel test run';
      return reply.status(500).send({
        success: false,
        error: {
          code: 'TESTRUN_CANCEL_FAILED',
          message,
        },
      });
    }
  });

  // 5. Get TestRun Findings
  fastify.get<{ Params: { id: string } }>('/api/v1/test-runs/:id/findings', async (request, reply) => {
    const tenantId = extractTenantScope(request);
    const run = await testRunsService.getTestRunById(request.params.id, tenantId);
    if (!run) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'TESTRUN_NOT_FOUND',
          message: `TestRun with ID "${request.params.id}" not found`,
        },
      });
    }

    const findingsList = await findingsService.listFindings({ testRunId: request.params.id, tenantId });
    return reply.send({
      success: true,
      data: findingsList,
    });
  });

  // 6. Get TestRun Forensic Evidence Records
  fastify.get<{ Params: { id: string } }>('/api/v1/test-runs/:id/evidence', async (request, reply) => {
    const tenantId = extractTenantScope(request);
    const run = await testRunsService.getTestRunById(request.params.id, tenantId);
    if (!run) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'TESTRUN_NOT_FOUND',
          message: `TestRun with ID "${request.params.id}" not found`,
        },
      });
    }

    const evidenceList = await evidenceService.listEvidenceByTestRunId(request.params.id);
    return reply.send({
      success: true,
      data: evidenceList,
    });
  });

  // 7. Get TestRun Quantitative Metrics
  fastify.get<{ Params: { id: string } }>('/api/v1/test-runs/:id/metrics', async (request, reply) => {
    const tenantId = extractTenantScope(request);
    const run = await testRunsService.getTestRunById(request.params.id, tenantId);
    if (!run) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'TESTRUN_NOT_FOUND',
          message: `TestRun with ID "${request.params.id}" not found`,
        },
      });
    }

    const metricsList = await metricsService.listMetricsByTestRunId(request.params.id);
    return reply.send({
      success: true,
      data: metricsList,
    });
  });

  // 8. Delete TestRun
  fastify.delete<{ Params: { id: string } }>('/api/v1/test-runs/:id', async (request, reply) => {
    const { id } = request.params;
    const tenantId = extractTenantScope(request);
    const deleted = await testRunsService.deleteTestRun(id, tenantId);
    if (!deleted) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'TESTRUN_NOT_FOUND',
          message: `TestRun with ID "${id}" not found`,
        },
      });
    }

    return reply.send({
      success: true,
      data: { id, deleted: true },
    });
  });
};
