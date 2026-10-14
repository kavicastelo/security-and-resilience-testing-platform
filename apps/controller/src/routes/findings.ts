import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { FindingSeverity, FindingStatus } from '@security-lab/domain';
import { FindingTriageRequestSchema } from '@security-lab/contracts';
import { findingsService } from '../services/findings.service.js';
import { testRunsService } from '../services/test-runs.service.js';
import { executionManager } from '../services/execution-manager.js';
import { retesterService } from '../services/retester.js';
import { flappingService } from '../services/flapping.js';
import { extractTenantScope } from '../services/tenant-context.js';
import { requireAuditor, requireEngineer } from '../plugins/rbac.js';

export const findingsRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // 1. List findings with optional filters (testRunId, targetId, severity, status, isFlapping)
  fastify.get<{
    Querystring: {
      testRunId?: string;
      targetId?: string;
      severity?: FindingSeverity;
      status?: FindingStatus;
      isFlapping?: boolean;
    };
  }>('/api/v1/findings', { preHandler: [requireAuditor] }, async (request, reply) => {
    const { testRunId, targetId, severity, status, isFlapping } = request.query;
    const tenantId = extractTenantScope(request);
    const findingsList = await findingsService.listFindings({
      testRunId,
      targetId,
      severity,
      status,
      tenantId,
      isFlapping,
    });
    return reply.send({
      success: true,
      data: findingsList,
    });
  });

  // 2. Get single finding by ID
  fastify.get<{ Params: { id: string } }>('/api/v1/findings/:id', { preHandler: [requireAuditor] }, async (request, reply) => {
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

  // 3. Update Finding Status (Legacy PATCH: open, suppressed, resolved, false_positive, risk_accepted)
  fastify.patch<{
    Params: { id: string };
    Body: { status: FindingStatus | string; notes?: string; comment?: string; expiresAt?: string; triggerRetest?: boolean };
  }>('/api/v1/findings/:id', { preHandler: [requireEngineer] }, async (request, reply) => {
    const { id } = request.params;
    const { status, notes, comment, expiresAt, triggerRetest } = request.body || {};

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
      const actorId = (request as unknown as { user?: { sub?: string } }).user?.sub || 'api';
      const updated = await findingsService.updateFindingStatus(
        id,
        status,
        comment || notes,
        tenantId,
        actorId,
        expiresAt,
      );

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

  // 4. Targeted Single-Finding Retest (POST /api/v1/findings/:id/retest)
  fastify.post<{
    Params: { id: string };
    Body?: { timeoutMs?: number };
  }>('/api/v1/findings/:id/retest', { preHandler: [requireEngineer] }, async (request, reply) => {
    const { id } = request.params;
    const tenantId = extractTenantScope(request);
    const timeoutMs = request.body?.timeoutMs || 5000;

    try {
      const result = await retesterService.retestFinding(id, tenantId, timeoutMs);
      return reply.send({
        success: true,
        data: result,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Retest execution failed';
      const statusCode = message.includes('not found') ? 404 : 400;
      return reply.status(statusCode).send({
        success: false,
        error: {
          code: statusCode === 404 ? 'FINDING_NOT_FOUND' : 'RETEST_FAILED',
          message,
        },
      });
    }
  });

  // 5. Finding Triage State Machine Endpoint (POST /api/v1/findings/:id/triage)
  fastify.post<{
    Params: { id: string };
    Body: {
      status: string;
      comment?: string;
      notes?: string;
      expiresAt?: string;
      actorId?: string;
    };
  }>('/api/v1/findings/:id/triage', { preHandler: [requireEngineer] }, async (request, reply) => {
    const { id } = request.params;
    const tenantId = extractTenantScope(request);
    const actorId =
      request.body?.actorId ||
      (request as unknown as { user?: { sub?: string } }).user?.sub ||
      'api';

    const parseResult = FindingTriageRequestSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: parseResult.error.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join('; '),
          details: parseResult.error.flatten(),
        },
      });
    }

    try {
      const updated = await findingsService.triageFinding(
        id,
        parseResult.data,
        actorId,
        tenantId,
      );

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
      const message = err instanceof Error ? err.message : 'Triage transition failed';
      return reply.status(400).send({
        success: false,
        error: {
          code: 'TRIAGE_TRANSITION_FAILED',
          message,
        },
      });
    }
  });

  // 6. Flapping Analysis Endpoint (GET /api/v1/findings/:id/flapping)
  fastify.get<{
    Params: { id: string };
    Querystring: { maxRuns?: number };
  }>('/api/v1/findings/:id/flapping', { preHandler: [requireAuditor] }, async (request, reply) => {
    const { id } = request.params;
    const tenantId = extractTenantScope(request);
    const maxRuns = request.query.maxRuns || 10;

    const analysis = await flappingService.calculateFlappingScore(id, tenantId, maxRuns);
    if (!analysis) {
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
      data: analysis,
    });
  });

  // 7. Delete Finding
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
