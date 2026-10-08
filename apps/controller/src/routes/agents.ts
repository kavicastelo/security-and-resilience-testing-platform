import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import {
  AgentRegistrationRequestSchema,
  AgentHeartbeatRequestSchema,
  AgentPollRequestSchema,
  AgentJobProgressReportSchema,
  AgentJobCompletionReportSchema,
  RevokeAgentRequestSchema,
} from '@security-lab/contracts';
import { agentDispatcherService, AuthorizationError, NotFoundError } from '../services/agent-dispatcher.service.js';
import { enrollmentKeysService } from '../services/enrollment-keys.service.js';
import { extractTenantId } from '../services/tenant-context.js';
import { logger } from '@security-lab/logger';
import { z } from 'zod';

export async function agentsRoutes(fastify: FastifyInstance) {
  // 1. POST /api/v1/agents/register
  fastify.post('/register', async (request: FastifyRequest, reply: FastifyReply) => {
    // Phase 16.1: Require Master Tenant Enrollment Key (TEK)
    const authHeader = request.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return reply.status(401).send({
        success: false,
        error: {
          code: 'AGENT_UNAUTHORIZED',
          message: 'Missing or invalid Tenant Enrollment Key. Provide "Authorization: Bearer tek_<slug>_<hex>"',
        },
      });
    }

    const rawKey = authHeader.replace('Bearer ', '').trim();
    const validation = await enrollmentKeysService.validateAndConsumeEnrollmentKey(rawKey);
    if (!validation.valid || !validation.tek) {
      return reply.status(401).send({
        success: false,
        error: {
          code: validation.errorCode || 'INVALID_ENROLLMENT_KEY',
          message: validation.error || 'Invalid Tenant Enrollment Key',
        },
      });
    }

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
      // Tenant ID is strictly derived from the validated TEK (Rule 5: Never trust client header)
      const tenantId = validation.tek.tenantId;
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
    const authResult = await agentDispatcherService.authenticateAgent(token);
    if (!authResult.agent) {
      reply.status(401).send({
        success: false,
        error: {
          code: authResult.code || 'UNAUTHORIZED',
          message: authResult.error || 'Invalid or revoked agent token',
        },
      });
      return null;
    }

    // Rule 5: Tenant identity must NEVER be trusted from an arbitrary request header alone.
    // If client supplies an x-tenant-id header that conflicts with the authenticated agent's tenant,
    // this represents an active spoofing attempt. Reject with 403 Forbidden (TENANT_MISMATCH).
    const headerTenantId = request.headers['x-tenant-id'];
    if (headerTenantId && typeof headerTenantId === 'string' && headerTenantId.trim().length > 0) {
      if (headerTenantId.trim() !== authResult.agent.tenantId) {
        logger.warn(
          {
            event: 'security.tenant_spoof_attempt',
            callerAgentId: authResult.agent.id,
            tokenTenantId: authResult.agent.tenantId,
            headerTenantId: headerTenantId.trim(),
            url: request.url,
            method: request.method,
          },
          'Blocked active tenant spoofing attempt (header mismatch with agent token)',
        );
        reply.status(403).send({
          success: false,
          error: {
            code: 'TENANT_MISMATCH',
            message: 'Tenant header does not match authenticated agent tenant',
          },
        });
        return null;
      }
    }

    return authResult.agent;
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

    const heartbeatResult = await agentDispatcherService.recordHeartbeat(
      agent.id,
      parseResult.data.status,
      parseResult.data.metrics as Record<string, unknown> | undefined,
      parseResult.data.leaseId,
      parseResult.data.activeLeaseIds,
    );

    return reply.status(200).send({
      acknowledged: heartbeatResult.acknowledged,
      timestamp: new Date().toISOString(),
      command: 'continue',
      renewedLeases: heartbeatResult.renewedLeases,
    });
  });

  // 3. GET /api/v1/agents
  fastify.get('/', async (request: FastifyRequest, reply: FastifyReply) => {
    let tenantId: string | undefined;

    const authHeader = request.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.replace('Bearer ', '').trim();
      if (token.startsWith('agt_sec_')) {
        const authResult = await agentDispatcherService.authenticateAgent(token);
        if (authResult.agent) {
          tenantId = authResult.agent.tenantId;
          const headerTenant = request.headers['x-tenant-id'];
          if (headerTenant && typeof headerTenant === 'string' && headerTenant.trim().length > 0 && headerTenant.trim() !== tenantId) {
            logger.warn(
              {
                event: 'security.tenant_spoof_attempt',
                callerAgentId: authResult.agent.id,
                tokenTenantId: tenantId,
                headerTenantId: headerTenant.trim(),
                url: request.url,
              },
              'Blocked active tenant spoofing attempt on agent listing',
            );
            return reply.status(403).send({
              success: false,
              error: {
                code: 'TENANT_MISMATCH',
                message: 'Tenant header does not match authenticated agent tenant',
              },
            });
          }
        }
      } else if (token.startsWith('tek_')) {
        const tekResult = await enrollmentKeysService.validateAndConsumeEnrollmentKey(token);
        if (tekResult.valid && tekResult.tek) {
          tenantId = tekResult.tek.tenantId;
        }
      }
    }

    if (!tenantId) {
      tenantId = request.headers['x-tenant-id'] as string | undefined;
    }

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

    try {
      await agentDispatcherService.reportJobProgress(
        request.params.jobId,
        agent,
        parseResult.data.percent,
        parseResult.data.message,
        parseResult.data.engineId,
      );
      return reply.status(200).send({ success: true });
    } catch (err: unknown) {
      if (err instanceof AuthorizationError || err instanceof NotFoundError) {
        return reply.status(err.statusCode).send({
          success: false,
          error: { code: err.code, message: err.message },
        });
      }
      const msg = err instanceof Error ? err.message : String(err);
      return reply.status(500).send({
        success: false,
        error: { code: 'PROGRESS_REPORT_FAILED', message: msg },
      });
    }
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
      const result = await agentDispatcherService.completeJob(request.params.jobId, agent, parseResult.data);
      return reply.status(200).send({
        success: true,
        ...(result?.deduplicated ? { deduplicated: true } : {}),
      });
    } catch (err: unknown) {
      if (err instanceof AuthorizationError || err instanceof NotFoundError) {
        return reply.status(err.statusCode).send({
          success: false,
          error: { code: err.code, message: err.message },
        });
      }
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
      try {
        await agentDispatcherService.failJob(request.params.jobId, agent, errorMsg);
        return reply.status(200).send({ success: true });
      } catch (err: unknown) {
        if (err instanceof AuthorizationError || err instanceof NotFoundError) {
          return reply.status(err.statusCode).send({
            success: false,
            error: { code: err.code, message: err.message },
          });
        }
        const msg = err instanceof Error ? err.message : String(err);
        return reply.status(500).send({
          success: false,
          error: { code: 'JOB_FAIL_ERROR', message: msg },
        });
      }
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

  // 9. POST /api/v1/agents/rotate-token
  fastify.post('/rotate-token', async (request: FastifyRequest, reply: FastifyReply) => {
    const agent = await requireAgentAuth(request, reply);
    if (!agent) return;

    try {
      const rotation = await agentDispatcherService.rotateAgentToken(agent.id);
      return reply.status(200).send({
        success: true,
        data: rotation,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return reply.status(500).send({
        success: false,
        error: { code: 'ROTATION_FAILED', message: msg },
      });
    }
  });

  // 10. POST /api/v1/agents/:id/revoke
  fastify.post<{ Params: { id: string } }>('/:id/revoke', async (request, reply) => {
    const parseResult = RevokeAgentRequestSchema.safeParse(request.body || {});
    const reason = parseResult.success ? parseResult.data.reason : 'Administrative revocation';

    try {
      const revocation = await agentDispatcherService.revokeAgent(request.params.id, reason);
      return reply.status(200).send({
        success: true,
        data: revocation,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return reply.status(400).send({
        success: false,
        error: { code: 'REVOCATION_FAILED', message: msg },
      });
    }
  });
}
