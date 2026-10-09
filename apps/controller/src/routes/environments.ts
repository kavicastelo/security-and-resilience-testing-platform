import { FastifyInstance, FastifyPluginAsync, FastifyRequest } from 'fastify';
import { CreateEnvironmentInputSchema } from '@security-lab/domain';
import { environmentsService } from '../services/environments.service.js';
import { extractTenantId } from '../services/tenant-context.js';

export const environmentsRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // 1. Create Environment for Project
  fastify.post<{ Params: { projectId: string } }>(
    '/api/v1/projects/:projectId/environments',
    async (request, reply) => {
      const payload = {
        ...(request.body as object),
        projectId: request.params.projectId,
      };

      const parseResult = CreateEnvironmentInputSchema.safeParse(payload);
      if (!parseResult.success) {
        return reply.status(400).send({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid environment payload',
            details: parseResult.error.format(),
          },
        });
      }

      try {
        const tenantId = extractTenantId(request);
        const env = await environmentsService.createEnvironment(parseResult.data, tenantId);
        return reply.status(201).send({
          success: true,
          data: env,
        });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'Failed to create environment';
        return reply.status(409).send({
          success: false,
          error: {
            code: 'ENVIRONMENT_CREATION_FAILED',
            message,
          },
        });
      }
    },
  );

  // 2. List Environments for Project
  fastify.get<{ Params: { projectId: string } }>(
    '/api/v1/projects/:projectId/environments',
    async (request, reply) => {
      const tenantId = extractTenantId(request);
      const envList = await environmentsService.listEnvironmentsByProject(request.params.projectId, tenantId);
      return reply.send({
        success: true,
        data: envList,
      });
    },
  );

  // 3. Get Environment by ID
  fastify.get<{ Params: { id: string } }>('/api/v1/environments/:id', async (request, reply) => {
    const tenantId = extractTenantId(request);
    const env = await environmentsService.getEnvironmentById(request.params.id, tenantId);
    if (!env) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'ENVIRONMENT_NOT_FOUND',
          message: `Environment with ID "${request.params.id}" not found`,
        },
      });
    }

    return reply.send({
      success: true,
      data: env,
    });
  });

  // 4. Update Environment (PUT / PATCH)
  const handleUpdateEnv = async (
    request: FastifyRequest<{ Params: { id: string }; Body: unknown }>,
    reply: { status: (code: number) => { send: (payload: unknown) => unknown }; send: (payload: unknown) => unknown },
  ) => {
    const { id } = request.params;
    const body = (request.body as {
      name?: string;
      type?: 'development' | 'staging' | 'production';
      variables?: Record<string, string>;
      headers?: Record<string, string>;
    }) || {};

    try {
      const tenantId = extractTenantId(request);
      const updated = await environmentsService.updateEnvironment(id, body, tenantId);
      if (!updated) {
        return reply.status(404).send({
          success: false,
          error: {
            code: 'ENVIRONMENT_NOT_FOUND',
            message: `Environment with ID "${id}" not found`,
          },
        });
      }

      return reply.send({
        success: true,
        data: updated,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to update environment';
      return reply.status(400).send({
        success: false,
        error: {
          code: 'ENVIRONMENT_UPDATE_FAILED',
          message,
        },
      });
    }
  };

  fastify.put<{ Params: { id: string }; Body: unknown }>('/api/v1/environments/:id', handleUpdateEnv);
  fastify.patch<{ Params: { id: string }; Body: unknown }>('/api/v1/environments/:id', handleUpdateEnv);

  // 5. Delete Environment
  fastify.delete<{ Params: { id: string } }>('/api/v1/environments/:id', async (request, reply) => {
    const { id } = request.params;
    const tenantId = extractTenantId(request);
    const deleted = await environmentsService.deleteEnvironment(id, tenantId);
    if (!deleted) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'ENVIRONMENT_NOT_FOUND',
          message: `Environment with ID "${id}" not found`,
        },
      });
    }

    return reply.send({
      success: true,
      data: { id, deleted: true },
    });
  });
};
