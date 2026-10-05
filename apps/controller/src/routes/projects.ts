import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { CreateProjectInputSchema } from '@security-lab/domain';
import { projectsService } from '../services/projects.service.js';

export const projectsRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // 1. Create Project
  fastify.post('/api/v1/projects', async (request, reply) => {
    const parseResult = CreateProjectInputSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid project payload',
          details: parseResult.error.format(),
        },
      });
    }

    try {
      const project = await projectsService.createProject(parseResult.data);
      return reply.status(201).send({
        success: true,
        data: project,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to create project';
      return reply.status(409).send({
        success: false,
        error: {
          code: 'PROJECT_CREATION_FAILED',
          message,
        },
      });
    }
  });

  // 2. List Projects
  fastify.get('/api/v1/projects', async (_request, reply) => {
    const projectsList = await projectsService.listProjects();
    return reply.send({
      success: true,
      data: projectsList,
    });
  });

  // 3. Get Project by ID
  fastify.get<{ Params: { id: string } }>('/api/v1/projects/:id', async (request, reply) => {
    const project = await projectsService.getProjectById(request.params.id);
    if (!project) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'PROJECT_NOT_FOUND',
          message: `Project with ID "${request.params.id}" not found`,
        },
      });
    }

    return reply.send({
      success: true,
      data: project,
    });
  });
};
