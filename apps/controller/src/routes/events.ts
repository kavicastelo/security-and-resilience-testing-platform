import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { eq } from 'drizzle-orm';
import { getDatabase } from '../services/db.js';
import { testExecutions } from '../services/db/schema.js';
import { testRunsService } from '../services/test-runs.service.js';
import { executionManager } from '../services/execution-manager.js';
import { extractTenantScope } from '../services/tenant-context.js';
import { requireAuditor } from '../plugins/rbac.js';
import {
  RunLifecycleEvent,
  EngineLifecycleEvent,
  ExecutionProgressEvent,
} from '../services/execution-events.js';
import { logger } from '@security-lab/logger';

export const eventsRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // Real-Time Server-Sent Events (SSE) Stream for a TestRun
  fastify.get<{
    Params: { id: string };
  }>(
    '/api/v1/test-runs/:id/stream',
    { preHandler: [requireAuditor] },
    async (request, reply) => {
      const { id } = request.params;
      const tenantId = extractTenantScope(request);

      const testRun = await testRunsService.getTestRunById(id, tenantId);
      if (!testRun) {
        return reply.status(404).send({
          success: false,
          error: {
            code: 'TESTRUN_NOT_FOUND',
            message: `TestRun with ID "${id}" not found`,
          },
        });
      }

      // Hijack the underlying Node.js response socket for Server-Sent Events
      reply.raw.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no',
        'Access-Control-Allow-Origin': '*',
      });

      // Send initial state
      const { db } = getDatabase();
      const currentExecutions = await db
        .select()
        .from(testExecutions)
        .where(eq(testExecutions.testRunId, id));

      reply.raw.write(
        `event: init\ndata: ${JSON.stringify({
          status: testRun.status,
          testRun,
          executions: currentExecutions,
        })}\n\n`,
      );

      // If test run is already terminated, emit completed event and close stream
      if (['completed', 'failed', 'cancelled'].includes(testRun.status)) {
        reply.raw.write(
          `event: run_completed\ndata: ${JSON.stringify({
            status: testRun.status,
            testRunId: id,
          })}\n\n`,
        );
        reply.raw.end();
        return;
      }

      // Setup event listeners on executionManager for real-time dispatching
      const onRun = (event: RunLifecycleEvent) => {
        reply.raw.write(`event: run\ndata: ${JSON.stringify(event)}\n\n`);
        if (['completed', 'failed', 'cancelled'].includes(event.status)) {
          reply.raw.write(`event: run_completed\ndata: ${JSON.stringify(event)}\n\n`);
          cleanup();
          reply.raw.end();
        }
      };

      const onEngine = (event: EngineLifecycleEvent) => {
        reply.raw.write(`event: engine\ndata: ${JSON.stringify(event)}\n\n`);
      };

      const onProgress = (event: ExecutionProgressEvent) => {
        reply.raw.write(`event: progress\ndata: ${JSON.stringify(event)}\n\n`);
      };

      executionManager.on(`run:${id}`, onRun);
      executionManager.on(`engine:${id}`, onEngine);
      executionManager.on(`progress:${id}`, onProgress);

      // Periodic keep-alive ping comment (every 15s)
      const pingTimer = setInterval(() => {
        try {
          reply.raw.write(': keep-alive\n\n');
        } catch {
          cleanup();
        }
      }, 15000);

      const cleanup = () => {
        clearInterval(pingTimer);
        executionManager.off(`run:${id}`, onRun);
        executionManager.off(`engine:${id}`, onEngine);
        executionManager.off(`progress:${id}`, onProgress);
      };

      request.raw.on('close', () => {
        cleanup();
      });

      request.raw.on('error', (err) => {
        logger.debug({ err, testRunId: id }, 'SSE stream connection error');
        cleanup();
      });
    },
  );
};
