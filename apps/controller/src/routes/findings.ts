import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { FindingSeverity, FindingStatus } from '@security-lab/domain';
import { findingsService } from '../services/findings.service.js';
import { testRunsService } from '../services/test-runs.service.js';
import { executionManager } from '../services/execution-manager.js';
import { extractTenantScope } from '../services/tenant-context.js';

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
    const tenantId = extractTenantScope(request);
    const findingsList = await findingsService.listFindings({ testRunId, targetId, severity, status, tenantId });
    return reply.send({
      success: true,
      data: findingsList,
    });
  });

  // 2. Get single finding by ID
  fastify.get<{ Params: { id: string } }>('/api/v1/findings/:id', async (request, reply) => {
    const tenantId = extractTenantScope(request);
    const finding = await findingsService.getFindingById(request.params.id, tenantId);
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
    Body: { status: FindingStatus; notes?: string; triggerRetest?: boolean };
  }>('/api/v1/findings/:id', async (request, reply) => {
    const { id } = request.params;
    const { status, notes, triggerRetest } = request.body || {};

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
      const tenantId = extractTenantScope(request);
      const updated = await findingsService.updateFindingStatus(id, status, notes, tenantId);
      if (!updated) {
        return reply.status(404).send({
          success: false,
          error: {
            code: 'FINDING_NOT_FOUND',
            message: `Finding with ID "${id}" not found`,
          },
        });
      }

      let retestRunId: string | undefined;
      if (triggerRetest && updated.testRunId) {
        try {
          const originalRun = await testRunsService.getTestRunById(updated.testRunId, tenantId);
          if (originalRun) {
            const retestRun = await testRunsService.createTestRun({
              projectId: originalRun.projectId,
              targetId: originalRun.targetId,
              profileId: updated.testDefinitionId,
              triggeredBy: 'api',
              metadata: {
                isRetest: true,
                originalFindingId: updated.id,
                fingerprint: updated.fingerprint,
              },
            }, tenantId);
            await executionManager.enqueue(retestRun.id, {
              engineIds: [updated.testDefinitionId],
            });
            retestRunId = retestRun.id;
          }
        } catch (retestErr) {
          request.log.warn({ err: retestErr }, 'Failed to trigger automated retest for resolved finding');
        }
      }

      return reply.send({
        success: true,
        data: updated,
        retestRunId,
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
    const tenantId = extractTenantScope(request);
    const deleted = await findingsService.deleteFinding(id, tenantId);
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
