import { FastifyInstance, FastifyPluginAsync, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { CreateTargetInputSchema } from '@security-lab/domain';
import { targetsService } from '../services/targets.service.js';
import { extractTenantScope } from '../services/tenant-context.js';

const ValidateScopeRequestSchema = z.object({
  candidateUrl: z.string().url(),
  capability: z.enum(['activeScanning', 'loadTesting', 'chaosTesting']).optional(),
  requestedRps: z.number().int().positive().optional(),
  requestedConcurrency: z.number().int().positive().optional(),
});

export const targetsRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // 1. Create Target in Project
  fastify.post<{ Params: { projectId: string } }>(
    '/api/v1/projects/:projectId/targets',
    async (request, reply) => {
      const payload = {
        ...(request.body as object),
        projectId: request.params.projectId,
      };

      const parseResult = CreateTargetInputSchema.safeParse(payload);
      if (!parseResult.success) {
        return reply.status(400).send({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid target scope payload',
            details: parseResult.error.format(),
          },
        });
      }

      try {
        const tenantId = extractTenantScope(request);
        const target = await targetsService.createTarget(parseResult.data, tenantId);
        return reply.status(201).send({
          success: true,
          data: target,
        });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'Failed to create target';
        return reply.status(400).send({
          success: false,
          error: {
            code: 'TARGET_SCOPE_VIOLATION',
            message,
          },
        });
      }
    },
  );

  // 2. List Targets by Project
  fastify.get<{ Params: { projectId: string } }>(
    '/api/v1/projects/:projectId/targets',
    async (request, reply) => {
      const tenantId = extractTenantScope(request);
      const targetList = await targetsService.listTargetsByProject(request.params.projectId, tenantId);
      return reply.send({
        success: true,
        data: targetList,
      });
    },
  );

  // 3. List All Targets
  fastify.get('/api/v1/targets', async (request, reply) => {
    const tenantId = extractTenantScope(request);
    const targetList = await targetsService.listAllTargets(tenantId);
    return reply.send({
      success: true,
      data: targetList,
    });
  });

  // 4. Get Target by ID
  fastify.get<{ Params: { id: string } }>('/api/v1/targets/:id', async (request, reply) => {
    const tenantId = extractTenantScope(request);
    const target = await targetsService.getTargetById(request.params.id, tenantId);
    if (!target) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'TARGET_NOT_FOUND',
          message: `Target with ID "${request.params.id}" not found`,
        },
      });
    }

    return reply.send({
      success: true,
      data: target,
    });
  });

  // 5. Pre-flight Scope Boundary Validation
  fastify.post<{ Params: { id: string } }>(
    '/api/v1/targets/:id/validate-scope',
    async (request, reply) => {
      const parseResult = ValidateScopeRequestSchema.safeParse(request.body);
      if (!parseResult.success) {
        return reply.status(400).send({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid scope check request parameters',
            details: parseResult.error.format(),
          },
        });
      }

      const { candidateUrl, capability, requestedRps, requestedConcurrency } = parseResult.data;
      const tenantId = extractTenantScope(request);
      const validation = await targetsService.validateCandidateUrl(
        request.params.id,
        candidateUrl,
        {
          requestedCapability: capability,
          requestedRps,
          requestedConcurrency,
        },
        tenantId,
      );

      if (!validation.target) {
        return reply.status(404).send({
          success: false,
          error: {
            code: 'TARGET_NOT_FOUND',
            message: `Target with ID "${request.params.id}" not found`,
          },
        });
      }

      return reply.send({
        success: true,
        data: {
          targetId: request.params.id,
          targetName: validation.target.name,
          candidateUrl,
          valid: validation.valid,
          violations: validation.violations,
          matchedHost: validation.matchedHost,
          normalizedUrl: validation.normalizedUrl,
          scope: validation.target.scope,
        },
      });
    },
  );

  // 6. Update Target (PUT / PATCH)
  const handleUpdateTarget = async (
    request: FastifyRequest<{ Params: { id: string }; Body: unknown }>,
    reply: { status: (code: number) => { send: (payload: unknown) => unknown }; send: (payload: unknown) => unknown },
  ) => {
    const { id } = request.params;
    const body = (request.body as {
      name?: string;
      baseUrl?: string;
      allowedHosts?: string[];
      allowedPorts?: number[];
      excludedPaths?: string[];
      testing?: Record<string, boolean>;
      limits?: Record<string, unknown>;
      scope?: Record<string, unknown>;
    }) || {};

    try {
      const tenantId = extractTenantScope(request);
      const updated = await targetsService.updateTarget(id, body, tenantId);
      if (!updated) {
        return reply.status(404).send({
          success: false,
          error: {
            code: 'TARGET_NOT_FOUND',
            message: `Target with ID "${id}" not found`,
          },
        });
      }

      return reply.send({
        success: true,
        data: updated,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to update target';
      return reply.status(400).send({
        success: false,
        error: {
          code: 'TARGET_UPDATE_FAILED',
          message,
        },
      });
    }
  };

  fastify.put<{ Params: { id: string }; Body: unknown }>('/api/v1/targets/:id', handleUpdateTarget);
  fastify.patch<{ Params: { id: string }; Body: unknown }>('/api/v1/targets/:id', handleUpdateTarget);

  // 7. Delete Target
  fastify.delete<{ Params: { id: string } }>('/api/v1/targets/:id', async (request, reply) => {
    const { id } = request.params;
    const tenantId = extractTenantScope(request);
    const deleted = await targetsService.deleteTarget(id, tenantId);
    if (!deleted) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'TARGET_NOT_FOUND',
          message: `Target with ID "${id}" not found`,
        },
      });
    }

    return reply.send({
      success: true,
      data: { id, deleted: true },
    });
  });
};
