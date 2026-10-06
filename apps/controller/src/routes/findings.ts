import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { FindingSeverity, FindingStatus } from '@security-lab/domain';
import { findingsService } from '../services/findings.service.js';

export const findingsRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // 1. List findings with optional filters (testRunId, targetId, severity, status)
  fastify.get<{
    Querystring: {
      testRunId?: string;
      targetId?: string;
      severity?: FindingSeverity;
      status?: FindingStatus;
    };
  }>('/api/v1/findings', async (request, reply) => {
    const { testRunId, targetId, severity, status } = request.query;
    const findingsList = await findingsService.listFindings({ testRunId, targetId, severity, status });
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

  // 3. Update Finding Status (Triage: open, suppressed, resolved, false_positive, risk_accepted)
  fastify.patch<{
    Params: { id: string };
    Body: { status: FindingStatus; notes?: string };
  }>('/api/v1/findings/:id', async (request, reply) => {
    const { id } = request.params;
    const { status, notes } = request.body || {};

    if (!status) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'MISSING_PARAM',
          message: 'Parameter "status" is required to update finding triage state',
        },
      });
    }

    try {
      const updated = await findingsService.updateFindingStatus(id, status, notes);
      if (!updated) {
        return reply.status(404).send({
          success: false,
          error: {
            code: 'FINDING_NOT_FOUND',
            message: `Finding with ID "${id}" not found`,
          },
        });
      }

      return reply.send({
        success: true,
        data: updated,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to update finding';
      return reply.status(400).send({
        success: false,
        error: {
          code: 'FINDING_UPDATE_FAILED',
          message,
        },
      });
    }
  });

  // 4. Delete Finding
  fastify.delete<{ Params: { id: string } }>('/api/v1/findings/:id', async (request, reply) => {
    const { id } = request.params;
    const deleted = await findingsService.deleteFinding(id);
    if (!deleted) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'FINDING_NOT_FOUND',
          message: `Finding with ID "${id}" not found`,
        },
      });
    }

    return reply.send({
      success: true,
      data: { id, deleted: true },
    });
  });
};
