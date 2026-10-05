import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { FindingSeverity } from '@security-lab/domain';
import { findingsService } from '../services/findings.service.js';

export const findingsRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // 1. List findings with optional filters
  fastify.get<{
    Querystring: {
      testRunId?: string;
      targetId?: string;
      severity?: FindingSeverity;
    };
  }>('/api/v1/findings', async (request, reply) => {
    const { testRunId, targetId, severity } = request.query;
    const findingsList = await findingsService.listFindings({ testRunId, targetId, severity });
    return reply.send({
      success: true,
      data: findingsList,
    });
  });

  // 2. Get single finding by ID
  fastify.get<{ Params: { id: string } }>('/api/v1/findings/:id', async (request, reply) => {
    const finding = await findingsService.getFindingById(request.params.id);
    if (!finding) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'FINDING_NOT_FOUND',
          message: `Finding with ID "${request.params.id}" not found`,
        },
      });
    }

    return reply.send({
      success: true,
      data: finding,
    });
  });
};
