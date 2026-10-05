import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { policiesService, CreatePolicyInput } from '../services/policies.service.js';

export const policiesRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // 1. List Policies
  fastify.get('/api/v1/policies', async (_request, reply) => {
    const list = await policiesService.listPolicies();
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
      const created = await policiesService.createPolicy(request.body);
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
};
