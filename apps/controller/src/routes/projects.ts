import { FastifyInstance, FastifyPluginAsync, FastifyRequest, FastifyReply } from 'fastify';
import { CreateProjectInputSchema } from '@security-lab/domain';
import { projectsService } from '../services/projects.service.js';
import { extractTenantId, extractTenantScope } from '../services/tenant-context.js';
import { requireAdmin, requireEngineer, requireAuditor } from '../plugins/rbac.js';

export const projectsRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  const getWorkspaceScope = (req: FastifyRequest): string | undefined => {
    // ADMIN can access projects across all workspaces unless explicitly constrained by workspaceId header
    if (req.user?.role === 'ADMIN' && !req.headers['x-workspace-id']) {
      return undefined;
    }
    return req.workspaceId;
  };

  // 1. Create Project (ADMIN, ENGINEER)
  fastify.post('/api/v1/projects', { preHandler: [requireEngineer] }, async (request, reply) => {
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
      const workspaceId = request.workspaceId;
      const project = await projectsService.createProject(parseResult.data, tenantId, workspaceId);
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

  // 2. List Projects (ADMIN, ENGINEER, AUDITOR)
  fastify.get('/api/v1/projects', { preHandler: [requireAuditor] }, async (request, reply) => {
    const tenantId = extractTenantScope(request);
    const workspaceId = getWorkspaceScope(request);
    const projectsList = await projectsService.listProjects(tenantId, workspaceId);
    return reply.send({
      success: true,
      data: projectsList,
    });
  });

  // 3. Get Project by ID (ADMIN, ENGINEER, AUDITOR)
  fastify.get<{ Params: { id: string } }>('/api/v1/projects/:id', { preHandler: [requireAuditor] }, async (request, reply) => {
    const tenantId = extractTenantScope(request);
    const workspaceId = getWorkspaceScope(request);
    const project = await projectsService.getProjectById(request.params.id, tenantId, workspaceId);
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

  // 4. Update Project (ADMIN, ENGINEER)
  const handleUpdateProject = async (
    request: FastifyRequest<{ Params: { id: string } }>,
    reply: FastifyReply,
  ) => {
    const tenantId = extractTenantScope(request);
    const workspaceId = getWorkspaceScope(request);
    const { id } = request.params;
    const body = (request.body as { name?: string; description?: string }) || {};

    try {
      const updated = await projectsService.updateProject(id, body, tenantId, workspaceId);
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

  fastify.put<{ Params: { id: string } }>('/api/v1/projects/:id', { preHandler: [requireEngineer] }, handleUpdateProject);
  fastify.patch<{ Params: { id: string } }>('/api/v1/projects/:id', { preHandler: [requireEngineer] }, handleUpdateProject);

  // 5. Delete Project (ADMIN only)
  fastify.delete<{ Params: { id: string } }>('/api/v1/projects/:id', { preHandler: [requireAdmin] }, async (request, reply) => {
    const tenantId = extractTenantScope(request);
    const workspaceId = getWorkspaceScope(request);
    const { id } = request.params;
    const deleted = await projectsService.deleteProject(id, tenantId, workspaceId);
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
