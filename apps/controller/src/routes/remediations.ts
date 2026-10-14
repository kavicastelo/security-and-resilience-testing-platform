import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import {
  RemediateFindingRequestSchema,
  VerifyRemediationRequestSchema,
} from '@security-lab/contracts';
import { remediationService } from '../services/ai/remediation.service.js';
import { requireEngineer, requireAuditor } from '../plugins/rbac.js';
import { extractTenantScope } from '../services/tenant-context.js';

export const remediationsRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // 1. Generate an AI remediation proposal for a finding
  fastify.post<{ Params: { id: string } }>(
    '/api/v1/findings/:id/remediate',
    { preHandler: [requireEngineer] },
    async (request, reply) => {
      const { id: findingId } = request.params;
      const workspaceId =
        (request as unknown as { user?: { workspaceId?: string } }).user?.workspaceId ||
        extractTenantScope(request);

      const parseResult = RemediateFindingRequestSchema.safeParse(request.body || {});
      if (!parseResult.success) {
        return reply.status(400).send({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: parseResult.error.errors.map((e) => e.message).join(', '),
          },
        });
      }

      try {
        const proposal = await remediationService.generateRemediation(
          findingId,
          parseResult.data,
          workspaceId,
        );
        return reply.status(201).send({ success: true, data: proposal });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        const statusCode = message.includes('not found') ? 404 : 500;
        return reply.status(statusCode).send({
          success: false,
          error: {
            code: statusCode === 404 ? 'NOT_FOUND' : 'REMEDIATION_FAILED',
            message,
          },
        });
      }
    },
  );

  // 2. Fetch all remediation proposals for a finding
  fastify.get<{ Params: { id: string } }>(
    '/api/v1/findings/:id/remediation',
    { preHandler: [requireAuditor] },
    async (request, reply) => {
      const { id: findingId } = request.params;
      const list = await remediationService.getRemediationsForFinding(findingId);
      return reply.send({ success: true, data: list });
    },
  );

  // 3. Fetch single remediation proposal by ID
  fastify.get<{ Params: { id: string } }>(
    '/api/v1/remediations/:id',
    { preHandler: [requireAuditor] },
    async (request, reply) => {
      const { id } = request.params;
      const item = await remediationService.getRemediationById(id);
      if (!item) {
        return reply.status(404).send({
          success: false,
          error: { code: 'NOT_FOUND', message: `Remediation "${id}" not found` },
        });
      }
      return reply.send({ success: true, data: item });
    },
  );

  // 4. Verify remediation proposal via finding endpoint
  fastify.post<{ Params: { id: string } }>(
    '/api/v1/findings/:id/remediation/verify',
    { preHandler: [requireEngineer] },
    async (request, reply) => {
      const { id: findingId } = request.params;
      const parseResult = VerifyRemediationRequestSchema.safeParse(request.body || {});
      if (!parseResult.success) {
        return reply.status(400).send({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: parseResult.error.errors.map((e) => e.message).join(', '),
          },
        });
      }

      let remediationId = parseResult.data.remediationId;
      if (!remediationId) {
        // Fetch latest remediation proposal for finding
        const existing = await remediationService.getRemediationsForFinding(findingId);
        if (existing.length === 0) {
          return reply.status(404).send({
            success: false,
            error: {
              code: 'NOT_FOUND',
              message: `No remediation proposals found for finding "${findingId}". Generate one first.`,
            },
          });
        }
        remediationId = existing[0]!.id;
      }

      try {
        const verifyResult = await remediationService.verifyRemediation(
          remediationId,
          parseResult.data,
        );
        return reply.send({ success: true, data: verifyResult });
      } catch (err) {
        return reply.status(500).send({
          success: false,
          error: {
            code: 'VERIFICATION_FAILED',
            message: err instanceof Error ? err.message : String(err),
          },
        });
      }
    },
  );

  // 5. Verify remediation proposal directly by remediation ID
  fastify.post<{ Params: { id: string } }>(
    '/api/v1/remediations/:id/verify',
    { preHandler: [requireEngineer] },
    async (request, reply) => {
      const { id: remediationId } = request.params;
      const parseResult = VerifyRemediationRequestSchema.safeParse(request.body || {});
      if (!parseResult.success) {
        return reply.status(400).send({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: parseResult.error.errors.map((e) => e.message).join(', '),
          },
        });
      }

      try {
        const verifyResult = await remediationService.verifyRemediation(
          remediationId,
          parseResult.data,
        );
        return reply.send({ success: true, data: verifyResult });
      } catch (err) {
        return reply.status(500).send({
          success: false,
          error: {
            code: 'VERIFICATION_FAILED',
            message: err instanceof Error ? err.message : String(err),
          },
        });
      }
    },
  );
};
