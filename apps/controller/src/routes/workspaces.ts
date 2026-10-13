import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import {
  CreateWorkspaceSchema,
  UpdateWorkspaceSchema,
  CreateUserSchema,
  AddWorkspaceMemberSchema,
  CreateApiKeySchema,
  LoginRequestSchema,
} from '@security-lab/contracts';
import { workspacesService } from '../services/workspaces.service.js';
import { requireAdmin, requireAuditor } from '../plugins/rbac.js';
import { signJwt, verifyPassword, DEFAULT_WORKSPACE_ID } from '../services/auth-token.service.js';

export const workspacesRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // 1. Create Workspace (ADMIN only)
  fastify.post('/api/v1/workspaces', { preHandler: [requireAdmin] }, async (request, reply) => {
    const parseResult = CreateWorkspaceSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid workspace payload',
          details: parseResult.error.format(),
        },
      });
    }

    try {
      const workspace = await workspacesService.createWorkspace(parseResult.data, request.user?.id);
      return reply.status(201).send({
        success: true,
        data: workspace,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to create workspace';
      return reply.status(409).send({
        success: false,
        error: {
          code: 'WORKSPACE_CREATION_FAILED',
          message,
        },
      });
    }
  });

  // 2. List Workspaces (ADMIN, ENGINEER, AUDITOR)
  fastify.get('/api/v1/workspaces', { preHandler: [requireAuditor] }, async (request, reply) => {
    try {
      const list = await workspacesService.listWorkspaces(request.user?.id, request.user?.role);
      return reply.send({
        success: true,
        data: list,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to list workspaces';
      return reply.status(500).send({
        success: false,
        error: {
          code: 'WORKSPACES_LIST_FAILED',
          message,
        },
      });
    }
  });

  // 3. Get Workspace by ID (ADMIN, ENGINEER, AUDITOR)
  fastify.get<{ Params: { id: string } }>('/api/v1/workspaces/:id', { preHandler: [requireAuditor] }, async (request, reply) => {
    const { id } = request.params;
    // Cross-tenant check: non-admin cannot access another workspace
    if (request.user?.role !== 'ADMIN' && request.workspaceId && request.workspaceId !== id) {
      return reply.status(403).send({
        success: false,
        error: {
          code: 'FORBIDDEN',
          message: 'Cross-workspace access forbidden',
        },
      });
    }

    const workspace = await workspacesService.getWorkspaceById(id);
    if (!workspace) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'WORKSPACE_NOT_FOUND',
          message: `Workspace "${id}" not found`,
        },
      });
    }

    return reply.send({
      success: true,
      data: workspace,
    });
  });

  // 4. Update Workspace (ADMIN only)
  fastify.put<{ Params: { id: string } }>('/api/v1/workspaces/:id', { preHandler: [requireAdmin] }, async (request, reply) => {
    const { id } = request.params;
    const parseResult = UpdateWorkspaceSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid workspace update payload',
          details: parseResult.error.format(),
        },
      });
    }

    const updated = await workspacesService.updateWorkspace(id, parseResult.data, request.user?.id);
    if (!updated) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'WORKSPACE_NOT_FOUND',
          message: `Workspace "${id}" not found`,
        },
      });
    }

    return reply.send({
      success: true,
      data: updated,
    });
  });

  // 5. Delete Workspace (ADMIN only)
  fastify.delete<{ Params: { id: string } }>('/api/v1/workspaces/:id', { preHandler: [requireAdmin] }, async (request, reply) => {
    const { id } = request.params;
    try {
      const deleted = await workspacesService.deleteWorkspace(id, request.user?.id);
      if (!deleted) {
        return reply.status(404).send({
          success: false,
          error: {
            code: 'WORKSPACE_NOT_FOUND',
            message: `Workspace "${id}" not found`,
          },
        });
      }
      return reply.send({
        success: true,
        data: { id, deleted: true },
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to delete workspace';
      return reply.status(400).send({
        success: false,
        error: {
          code: 'WORKSPACE_DELETION_FAILED',
          message,
        },
      });
    }
  });

  // 6. Add Member to Workspace (ADMIN only)
  fastify.post<{ Params: { id: string } }>('/api/v1/workspaces/:id/members', { preHandler: [requireAdmin] }, async (request, reply) => {
    const { id } = request.params;
    const parseResult = AddWorkspaceMemberSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid member payload',
          details: parseResult.error.format(),
        },
      });
    }

    try {
      const member = await workspacesService.addMember(id, parseResult.data, request.user?.id);
      return reply.status(201).send({
        success: true,
        data: member,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to add member';
      return reply.status(400).send({
        success: false,
        error: {
          code: 'ADD_MEMBER_FAILED',
          message,
        },
      });
    }
  });

  // 7. List Workspace Members (ADMIN, ENGINEER, AUDITOR)
  fastify.get<{ Params: { id: string } }>('/api/v1/workspaces/:id/members', { preHandler: [requireAuditor] }, async (request, reply) => {
    const { id } = request.params;
    if (request.user?.role !== 'ADMIN' && request.workspaceId && request.workspaceId !== id) {
      return reply.status(403).send({
        success: false,
        error: {
          code: 'FORBIDDEN',
          message: 'Cross-workspace access forbidden',
        },
      });
    }

    const members = await workspacesService.listMembers(id);
    return reply.send({
      success: true,
      data: members,
    });
  });

  // 8. Remove Member from Workspace (ADMIN only)
  fastify.delete<{ Params: { id: string; userId: string } }>('/api/v1/workspaces/:id/members/:userId', { preHandler: [requireAdmin] }, async (request, reply) => {
    const { id, userId } = request.params;
    const removed = await workspacesService.removeMember(id, userId, request.user?.id);
    if (!removed) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'MEMBER_NOT_FOUND',
          message: `Member "${userId}" not found in workspace`,
        },
      });
    }
    return reply.send({
      success: true,
      data: { userId, removed: true },
    });
  });

  // 9. Create Scoped API Key (ADMIN only)
  fastify.post<{ Params: { id: string } }>('/api/v1/workspaces/:id/api-keys', { preHandler: [requireAdmin] }, async (request, reply) => {
    const { id } = request.params;
    const parseResult = CreateApiKeySchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid API key payload',
          details: parseResult.error.format(),
        },
      });
    }

    try {
      const result = await workspacesService.createApiKey(id, parseResult.data, request.user?.id);
      return reply.status(201).send({
        success: true,
        data: result,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to create API key';
      return reply.status(400).send({
        success: false,
        error: {
          code: 'API_KEY_CREATION_FAILED',
          message,
        },
      });
    }
  });

  // 10. List Workspace API Keys (ADMIN only)
  fastify.get<{ Params: { id: string } }>('/api/v1/workspaces/:id/api-keys', { preHandler: [requireAdmin] }, async (request, reply) => {
    const { id } = request.params;
    const keys = await workspacesService.listApiKeys(id);
    return reply.send({
      success: true,
      data: keys,
    });
  });

  // 11. Revoke API Key (ADMIN only)
  fastify.delete<{ Params: { id: string; keyId: string } }>('/api/v1/workspaces/:id/api-keys/:keyId', { preHandler: [requireAdmin] }, async (request, reply) => {
    const { id, keyId } = request.params;
    const revoked = await workspacesService.revokeApiKey(id, keyId, request.user?.id);
    if (!revoked) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'API_KEY_NOT_FOUND',
          message: `API key "${keyId}" not found in workspace`,
        },
      });
    }
    return reply.send({
      success: true,
      data: { keyId, revoked: true },
    });
  });

  // 12. User Registration (Public / Authenticated)
  fastify.post('/api/v1/auth/register', async (request, reply) => {
    const parseResult = CreateUserSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid user registration payload',
          details: parseResult.error.format(),
        },
      });
    }

    try {
      const user = await workspacesService.createUser(parseResult.data, request.user?.id);
      return reply.status(201).send({
        success: true,
        data: user,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Registration failed';
      return reply.status(409).send({
        success: false,
        error: {
          code: 'REGISTRATION_FAILED',
          message,
        },
      });
    }
  });

  // 13. User Session Login -> JWT Token
  fastify.post('/api/v1/auth/login', async (request, reply) => {
    const parseResult = LoginRequestSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid login payload',
          details: parseResult.error.format(),
        },
      });
    }

    const { email, password, workspaceId } = parseResult.data;
    const user = await workspacesService.findUserByEmail(email);
    if (!user || !user.passwordHash || !verifyPassword(password, user.passwordHash)) {
      return reply.status(401).send({
        success: false,
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password',
        },
      });
    }

    const targetWorkspaceId = workspaceId || DEFAULT_WORKSPACE_ID;
    const role = (await workspacesService.getUserRoleInWorkspace(targetWorkspaceId, user.id)) || 'ENGINEER';

    const token = signJwt({
      sub: user.id,
      email: user.email,
      name: user.name,
      workspaceId: targetWorkspaceId,
      role,
    });

    return reply.send({
      success: true,
      data: {
        token,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
        },
        workspaceId: targetWorkspaceId,
        role,
      },
    });
  });

  // 14. List Workspace Audit Events (ADMIN, AUDITOR)
  fastify.get<{ Params: { id: string } }>('/api/v1/workspaces/:id/audit-events', { preHandler: [requireAuditor] }, async (request, reply) => {
    const { id } = request.params;
    if (request.user?.role !== 'ADMIN' && request.workspaceId && request.workspaceId !== id) {
      return reply.status(403).send({
        success: false,
        error: { code: 'FORBIDDEN', message: 'Cross-workspace access forbidden' },
      });
    }
    const events = await workspacesService.listAuditEvents(id);
    return reply.send({ success: true, data: events });
  });
};
