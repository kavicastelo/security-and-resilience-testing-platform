import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { CreateEnvironmentInputSchema } from '@security-lab/domain';
import { environmentsService } from '../services/environments.service.js';

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
        const env = await environmentsService.createEnvironment(parseResult.data);
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
      const envList = await environmentsService.listEnvironmentsByProject(request.params.projectId);
      return reply.send({
        success: true,
        data: envList,
      });
    },
  );
};
