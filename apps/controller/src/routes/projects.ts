import { FastifyInstance, FastifyPluginAsync, FastifyRequest, FastifyReply } from 'fastify';
import { CreateProjectInputSchema } from '@security-lab/domain';
import { projectsService } from '../services/projects.service.js';
import { extractTenantId, extractTenantScope } from '../services/tenant-context.js';

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
      const tenantId = extractTenantId(request);
      const project = await projectsService.createProject(parseResult.data, tenantId);
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
  fastify.get('/api/v1/projects', async (request, reply) => {
    const tenantId = extractTenantScope(request);
    const projectsList = await projectsService.listProjects(tenantId);
    return reply.send({
      success: true,
      data: projectsList,
    });
  });

  // 3. Get Project by ID
  fastify.get<{ Params: { id: string } }>('/api/v1/projects/:id', async (request, reply) => {
    const tenantId = extractTenantScope(request);
    const project = await projectsService.getProjectById(request.params.id, tenantId);
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

  // 4. Update Project (PUT / PATCH)
  const handleUpdateProject = async (
    request: FastifyRequest<{ Params: { id: string } }>,
    reply: FastifyReply,
  ) => {
    const tenantId = extractTenantScope(request);
    const { id } = request.params;
    const body = (request.body as { name?: string; description?: string }) || {};

    try {
      const updated = await projectsService.updateProject(id, body, tenantId);
      if (!updated) {
        return reply.status(404).send({
          success: false,
          error: {
            code: 'PROJECT_NOT_FOUND',
            message: `Project with ID "${id}" not found`,
          },
        });
      }

      return reply.send({
        success: true,
        data: updated,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to update project';
      return reply.status(400).send({
        success: false,
        error: {
          code: 'PROJECT_UPDATE_FAILED',
          message,
        },
      });
    }
  };

  fastify.put<{ Params: { id: string } }>('/api/v1/projects/:id', handleUpdateProject);
  fastify.patch<{ Params: { id: string } }>('/api/v1/projects/:id', handleUpdateProject);

  // 5. Delete Project
  fastify.delete<{ Params: { id: string } }>('/api/v1/projects/:id', async (request, reply) => {
    const tenantId = extractTenantScope(request);
    const { id } = request.params;
    const deleted = await projectsService.deleteProject(id, tenantId);
    if (!deleted) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'PROJECT_NOT_FOUND',
          message: `Project with ID "${id}" not found`,
        },
      });
    }

    return reply.send({
      success: true,
      data: { id, deleted: true },
    });
  });
};
