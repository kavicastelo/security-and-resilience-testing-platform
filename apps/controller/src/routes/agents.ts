import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import {
  AgentRegistrationRequestSchema,
  AgentHeartbeatRequestSchema,
  AgentPollRequestSchema,
  AgentJobProgressReportSchema,
  AgentJobCompletionReportSchema,
} from '@security-lab/contracts';
import { agentDispatcherService } from '../services/agent-dispatcher.service.js';
import { extractTenantId } from '../services/tenant-context.js';
import { z } from 'zod';

export async function agentsRoutes(fastify: FastifyInstance) {
  // 1. POST /api/v1/agents/register
  fastify.post('/register', async (request: FastifyRequest, reply: FastifyReply) => {
    const parseResult = AgentRegistrationRequestSchema.safeParse(request.body);
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
      const tenantId = extractTenantId(request);
      const registration = await agentDispatcherService.registerAgent(parseResult.data, tenantId);
      return reply.status(201).send({
        success: true,
        data: registration,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return reply.status(400).send({
        success: false,
        error: { code: 'AGENT_REGISTRATION_FAILED', message: msg },
      });
    }
  });

  // Helper to authenticate Bearer token for agent requests
  async function requireAgentAuth(request: FastifyRequest, reply: FastifyReply) {
    const authHeader = request.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      reply.status(401).send({
        success: false,
        error: { code: 'UNAUTHORIZED', message: 'Missing or invalid Bearer authorization token' },
      });
      return null;
    }

    const token = authHeader.replace('Bearer ', '').trim();
    const agent = await agentDispatcherService.authenticateAgent(token);
    if (!agent) {
      reply.status(401).send({
        success: false,
        error: { code: 'UNAUTHORIZED', message: 'Invalid or revoked agent token' },
      });
      return null;
    }

    return agent;
  }

  // 2. POST /api/v1/agents/heartbeat
  fastify.post('/heartbeat', async (request: FastifyRequest, reply: FastifyReply) => {
    const agent = await requireAgentAuth(request, reply);
    if (!agent) return;

    const parseResult = AgentHeartbeatRequestSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        success: false,
        error: { code: 'VALIDATION_ERROR', message: 'Invalid heartbeat payload' },
      });
    }

    await agentDispatcherService.recordHeartbeat(
      agent.id,
      parseResult.data.status,
      parseResult.data.metrics as Record<string, unknown> | undefined,
    );

    return reply.status(200).send({
      acknowledged: true,
      timestamp: new Date().toISOString(),
      command: 'continue',
    });
  });

  // 3. GET /api/v1/agents
  fastify.get('/', async (request: FastifyRequest, reply: FastifyReply) => {
    const tenantId = request.headers['x-tenant-id'] as string | undefined;
    const list = await agentDispatcherService.listAgents(tenantId);
    return reply.status(200).send({
      success: true,
      data: list,
    });
  });

  // 4. POST /api/v1/agents/poll
  fastify.post('/poll', async (request: FastifyRequest, reply: FastifyReply) => {
    const agent = await requireAgentAuth(request, reply);
    if (!agent) return;

    const parseResult = AgentPollRequestSchema.safeParse(request.body);
    const maxJobs = parseResult.success ? parseResult.data.maxJobs : 1;

    const jobs = await agentDispatcherService.pollJobs(
      agent.id,
      agent.tenantId,
      agent.capabilities as string[],
      agent.tags as string[],
      maxJobs,
    );

    return reply.status(200).send({
      jobs,
    });
  });

  // 5. POST /api/v1/agents/jobs/:jobId/progress
  fastify.post<{ Params: { jobId: string } }>('/jobs/:jobId/progress', async (request, reply) => {
    const agent = await requireAgentAuth(request, reply);
    if (!agent) return;

    const parseResult = AgentJobProgressReportSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        success: false,
        error: { code: 'VALIDATION_ERROR', message: 'Invalid progress report' },
      });
    }

    await agentDispatcherService.reportJobProgress(
      request.params.jobId,
      parseResult.data.percent,
      parseResult.data.message,
      parseResult.data.engineId,
    );

    return reply.status(200).send({ success: true });
  });

  // 6. POST /api/v1/agents/jobs/:jobId/complete
  fastify.post<{ Params: { jobId: string } }>('/jobs/:jobId/complete', async (request, reply) => {
    const agent = await requireAgentAuth(request, reply);
    if (!agent) return;

    const parseResult = AgentJobCompletionReportSchema.safeParse(request.body);
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
      await agentDispatcherService.completeJob(request.params.jobId, parseResult.data);
      return reply.status(200).send({ success: true });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return reply.status(500).send({
        success: false,
        error: { code: 'JOB_COMPLETION_ERROR', message: msg },
      });
    }
  });

  // 7. POST /api/v1/agents/jobs/:jobId/fail
  fastify.post<{ Params: { jobId: string }; Body: { error: string } }>(
    '/jobs/:jobId/fail',
    async (request, reply) => {
      const agent = await requireAgentAuth(request, reply);
      if (!agent) return;

      const errorMsg = request.body?.error || 'Unknown agent execution failure';
      await agentDispatcherService.failJob(request.params.jobId, errorMsg);
      return reply.status(200).send({ success: true });
    },
  );

  // 8. POST /api/v1/agents/dispatch
  const DispatchSchema = z.object({
    testRunId: z.string().uuid(),
    engineIds: z.array(z.string()).default([]),
    options: z.record(z.string(), z.unknown()).optional(),
  });

  fastify.post('/dispatch', async (request: FastifyRequest, reply: FastifyReply) => {
    const parseResult = DispatchSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        success: false,
        error: { code: 'VALIDATION_ERROR', message: 'Invalid dispatch payload' },
      });
    }

    try {
      const tenantId = extractTenantId(request);
      const jobId = await agentDispatcherService.enqueueAgentJob(
        parseResult.data.testRunId,
        tenantId,
        parseResult.data.engineIds,
        parseResult.data.options,
      );

      return reply.status(202).send({
        success: true,
        data: {
          jobId,
          testRunId: parseResult.data.testRunId,
          status: 'pending',
        },
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return reply.status(400).send({
        success: false,
        error: { code: 'DISPATCH_FAILED', message: msg },
      });
    }
  });
}
