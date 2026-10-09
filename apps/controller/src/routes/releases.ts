import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { releasesService, EvaluateReleaseGateInput } from '../services/releases.service.js';
import { extractTenantId } from '../services/tenant-context.js';

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
      const tenantId = extractTenantId(request);
      const evaluation = await releasesService.evaluateReleaseGate(request.body, tenantId);
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
    const tenantId = extractTenantId(request);
    const list = await releasesService.listReleases(request.query.projectId, tenantId);
    return reply.send({
      success: true,
      data: list,
    });
  });

  // 3. Get Release by ID
  fastify.get<{ Params: { id: string } }>('/api/v1/releases/:id', async (request, reply) => {
    const tenantId = extractTenantId(request);
    const item = await releasesService.getReleaseById(request.params.id, tenantId);
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

  // 4. Delete Release
  fastify.delete<{ Params: { id: string } }>('/api/v1/releases/:id', async (request, reply) => {
    const { id } = request.params;
    const tenantId = extractTenantId(request);
    const deleted = await releasesService.deleteRelease(id, tenantId);
    if (!deleted) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'RELEASE_NOT_FOUND',
          message: `Release "${id}" not found`,
        },
      });
    }

    return reply.send({
      success: true,
      data: { id, deleted: true },
    });
  });
};
