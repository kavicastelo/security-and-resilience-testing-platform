import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { releasesService, EvaluateReleaseGateInput } from '../services/releases.service.js';

export const releasesRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // 1. Evaluate Release Gate for a TestRun
  fastify.post<{ Body: EvaluateReleaseGateInput }>('/api/v1/releases/evaluate', async (request, reply) => {
    const { testRunId } = request.body || {};
    if (!testRunId) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'MISSING_PARAM',
          message: 'Parameter "testRunId" is required for release gate evaluation',
        },
      });
    }

    try {
      const evaluation = await releasesService.evaluateReleaseGate(request.body);
      return reply.send({
        success: true,
        data: evaluation,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Release gate evaluation failed';
      return reply.status(400).send({
        success: false,
        error: {
          code: 'EVALUATION_FAILED',
          message,
        },
      });
    }
  });

  // 2. List Releases
  fastify.get<{ Querystring: { projectId?: string } }>('/api/v1/releases', async (request, reply) => {
    const list = await releasesService.listReleases(request.query.projectId);
    return reply.send({
      success: true,
      data: list,
    });
  });

  // 3. Get Release by ID
  fastify.get<{ Params: { id: string } }>('/api/v1/releases/:id', async (request, reply) => {
    const item = await releasesService.getReleaseById(request.params.id);
    if (!item) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'RELEASE_NOT_FOUND',
          message: `Release "${request.params.id}" not found`,
        },
      });
    }

    return reply.send({
      success: true,
      data: item,
    });
  });
};
