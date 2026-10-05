import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { CreateTestRunInputSchema } from '@security-lab/domain';
import { testRunsService } from '../services/test-runs.service.js';

export const testRunsRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // 1. Create & Queue TestRun
  fastify.post('/api/v1/test-runs', async (request, reply) => {
    const parseResult = CreateTestRunInputSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid TestRun input parameters',
          details: parseResult.error.format(),
        },
      });
    }

    try {
      const testRun = await testRunsService.createTestRun(parseResult.data);
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
    const runs = await testRunsService.listTestRuns({ projectId, targetId });
    return reply.send({
      success: true,
      data: runs,
    });
  });

  // 3. Get TestRun by ID
  fastify.get<{ Params: { id: string } }>('/api/v1/test-runs/:id', async (request, reply) => {
    const run = await testRunsService.getTestRunById(request.params.id);
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
};
