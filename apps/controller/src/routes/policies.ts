import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { PolicyWaiver } from '@security-lab/domain';
import { policiesService, CreatePolicyInput } from '../services/policies.service.js';

export const policiesRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // 1. List Policies
  fastify.get('/api/v1/policies', async (request, reply) => {
    const tenantId = request.headers['x-tenant-id'] as string | undefined;
    const list = await policiesService.listPolicies(tenantId);
    return reply.send({
      success: true,
      data: list,
    });
  });

  // 2. Get Default Policy
  fastify.get('/api/v1/policies/default', async (_request, reply) => {
    const policy = await policiesService.getDefaultPolicy();
    return reply.send({
      success: true,
      data: policy,
    });
  });

  // 3. Get Policy by ID
  fastify.get<{ Params: { id: string } }>('/api/v1/policies/:id', async (request, reply) => {
    const policy = await policiesService.getPolicyById(request.params.id);
    if (!policy) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'POLICY_NOT_FOUND',
          message: `Policy "${request.params.id}" not found`,
        },
      });
    }

    return reply.send({
      success: true,
      data: policy,
    });
  });

  // 4. Create Policy
  fastify.post<{ Body: CreatePolicyInput }>('/api/v1/policies', async (request, reply) => {
    try {
      const tenantId = request.headers['x-tenant-id'] as string | undefined;
      const created = await policiesService.createPolicy(request.body, tenantId);
      return reply.status(201).send({
        success: true,
        data: created,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to create policy';
      return reply.status(400).send({
        success: false,
        error: {
          code: 'POLICY_CREATION_FAILED',
          message,
        },
      });
    }
  });

  // 5. Update Policy (PUT / PATCH)
  const handleUpdatePolicy = async (
    request: { params: { id: string }; body: unknown },
    reply: { status: (code: number) => { send: (payload: unknown) => unknown }; send: (payload: unknown) => unknown },
  ) => {
    const { id } = request.params;
    const body = (request.body as Partial<CreatePolicyInput>) || {};

    try {
      const updated = await policiesService.updatePolicy(id, body);
      if (!updated) {
        return reply.status(404).send({
          success: false,
          error: {
            code: 'POLICY_NOT_FOUND',
            message: `Policy "${id}" not found`,
          },
        });
      }

      return reply.send({
        success: true,
        data: updated,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to update policy';
      const status = /default|baseline/i.test(message) ? 403 : 400;
      return reply.status(status).send({
        success: false,
        error: {
          code: status === 403 ? 'POLICY_FORBIDDEN' : 'POLICY_UPDATE_FAILED',
          message,
        },
      });
    }
  };

  fastify.put<{ Params: { id: string } }>('/api/v1/policies/:id', handleUpdatePolicy);
  fastify.patch<{ Params: { id: string } }>('/api/v1/policies/:id', handleUpdatePolicy);

  // 5b. Add Waiver to Policy
  fastify.post<{
    Params: { id: string };
    Body: PolicyWaiver;
  }>('/api/v1/policies/:id/waivers', async (request, reply) => {
    try {
      const updated = await policiesService.addWaiver(request.params.id, request.body);
      return reply.status(200).send({
        success: true,
        data: updated,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to add waiver to policy';
      return reply.status(400).send({
        success: false,
        error: { code: 'WAIVER_CREATION_FAILED', message },
      });
    }
  });

  fastify.post<{
    Body: PolicyWaiver & { policyId?: string };
  }>('/api/v1/policies/waivers', async (request, reply) => {
    try {
      const { policyId, ...waiver } = request.body;
      const updated = await policiesService.addWaiver(policyId, waiver);
      return reply.status(200).send({
        success: true,
        data: updated,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to add waiver to policy';
      return reply.status(400).send({
        success: false,
        error: { code: 'WAIVER_CREATION_FAILED', message },
      });
    }
  });

  // 6. Delete Policy
  fastify.delete<{ Params: { id: string } }>('/api/v1/policies/:id', async (request, reply) => {
    const { id } = request.params;
    try {
      const deleted = await policiesService.deletePolicy(id);
      if (!deleted) {
        return reply.status(404).send({
          success: false,
          error: {
            code: 'POLICY_NOT_FOUND',
            message: `Policy "${id}" not found`,
          },
        });
      }

      return reply.send({
        success: true,
        data: { id, deleted: true },
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to delete policy';
      const status = /default|baseline/i.test(message) ? 403 : 400;
      return reply.status(status).send({
        success: false,
        error: {
          code: status === 403 ? 'POLICY_FORBIDDEN' : 'POLICY_DELETE_FAILED',
          message,
        },
      });
    }
  });
};
