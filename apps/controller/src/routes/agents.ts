import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import {
  AgentRegistrationRequestSchema,
  AgentHeartbeatRequestSchema,
  AgentPollRequestSchema,
  AgentJobProgressReportSchema,
  AgentJobCompletionReportSchema,
  RevokeAgentRequestSchema,
  CURRENT_PROTOCOL_VERSION,
  MIN_SUPPORTED_PROTOCOL_VERSION,
  CONTROLLER_VERSION,
  HEADER_PROTOCOL_VERSION,
  HEADER_CONTROLLER_VERSION,
  evaluateProtocolCompatibility,
} from '@security-lab/contracts';
import { agentDispatcherService, AuthorizationError, NotFoundError } from '../services/agent-dispatcher.service.js';
import { enrollmentKeysService } from '../services/enrollment-keys.service.js';
import { extractTenantId } from '../services/tenant-context.js';
import { DEFAULT_TENANT_ID } from '../services/tenants.service.js';
import { agentAuditService } from '../services/agent-audit.service.js';
import { logger } from '@security-lab/logger';
import { z } from 'zod';

export async function agentsRoutes(fastify: FastifyInstance) {
  // Protocol Handshake Response Headers (Phase 16.8)
  fastify.addHook('onSend', async (_request, reply) => {
    reply.header(HEADER_PROTOCOL_VERSION, CURRENT_PROTOCOL_VERSION);
    reply.header(HEADER_CONTROLLER_VERSION, CONTROLLER_VERSION);
  });

  // Helper to determine if a route is an agent-daemon-facing endpoint
  function isAgentDaemonRoute(url: string): boolean {
    const cleanUrl = (url || '').split('?')[0]!.replace(/\/$/, '');
    if (cleanUrl.endsWith('/register')) return true;
    if (cleanUrl.endsWith('/heartbeat')) return true;
    if (cleanUrl.endsWith('/poll')) return true;
    if (cleanUrl.includes('/jobs/') && !cleanUrl.endsWith('/dispatch')) return true;
    if (cleanUrl.endsWith('/rotate-token')) return true;
    return false;
  }

  // Protocol Negotiation PreHandler Hook (Phase 16.8)
  fastify.addHook('preHandler', async (request: FastifyRequest, reply: FastifyReply) => {
    const clientProtocolVersion = request.headers[HEADER_PROTOCOL_VERSION] as string | undefined;
    const isAgentRoute = isAgentDaemonRoute(request.url);

    if (isAgentRoute || clientProtocolVersion !== undefined) {
      const evaluation = evaluateProtocolCompatibility(clientProtocolVersion);
      if (!evaluation.compatible) {
        logger.warn(
          {
            event: 'protocol.negotiation_failed',
            url: request.url,
            method: request.method,
            clientProtocolVersion: clientProtocolVersion || 'MISSING',
            minSupportedVersion: MIN_SUPPORTED_PROTOCOL_VERSION,
            currentVersion: CURRENT_PROTOCOL_VERSION,
            ip: request.ip,
            statusCode: evaluation.statusCode,
            errorCode: evaluation.errorCode,
          },
          'Rejected agent request due to protocol incompatibility',
        );

        await agentAuditService.recordAuditEvent({
          tenantId: (request.headers['x-tenant-id'] as string) || DEFAULT_TENANT_ID,
          eventType: 'security.protocol_violation',
          actorType: 'agent',
          actorId: 'unverified_agent',
          metadata: {
            clientProtocolVersion: clientProtocolVersion || 'MISSING',
            minSupportedVersion: MIN_SUPPORTED_PROTOCOL_VERSION,
            currentVersion: CURRENT_PROTOCOL_VERSION,
            url: request.url,
            method: request.method,
            errorCode: evaluation.errorCode,
          },
          ipAddress: request.ip,
        });

        return reply.status(evaluation.statusCode || 426).send({
          success: false,
          code: evaluation.errorCode,
          error: {
            code: evaluation.errorCode,
            message: evaluation.message,
            minSupportedVersion: MIN_SUPPORTED_PROTOCOL_VERSION,
            currentVersion: CURRENT_PROTOCOL_VERSION,
          },
          minSupportedVersion: MIN_SUPPORTED_PROTOCOL_VERSION,
          currentVersion: CURRENT_PROTOCOL_VERSION,
        });
      }
    }
  });

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
        await agentAuditService.recordAuditEvent({
          tenantId: authResult.agent.tenantId,
          agentId: authResult.agent.id,
          eventType: 'security.tenant_mismatch',
          actorType: 'agent',
          actorId: authResult.agent.id,
          metadata: {
            action: 'header_spoof_attempt',
            headerTenantId: headerTenantId.trim(),
            agentTenantId: authResult.agent.tenantId,
            url: request.url,
            method: request.method,
          },
          ipAddress: request.ip,
        });
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

  // 2. POST /api/v1/agents/heartbeat (max 120 req/min per agent)
  fastify.post(
    '/heartbeat',
    {
      config: {
        rateLimit: {
          max: 120,
          timeWindow: '1 minute',
          keyGenerator: (request: FastifyRequest) => {
            const authHeader = request.headers.authorization;
            if (authHeader && authHeader.startsWith('Bearer ')) {
              return authHeader.replace('Bearer ', '').trim();
            }
            return request.ip;
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
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
        cancelledJobIds: heartbeatResult.cancelledJobIds,
      });
    },
  );

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

  // 4. POST /api/v1/agents/poll (max 60 req/min per agent)
  fastify.post(
    '/poll',
    {
      config: {
        rateLimit: {
          max: 60,
          timeWindow: '1 minute',
          keyGenerator: (request: FastifyRequest) => {
            const authHeader = request.headers.authorization;
            if (authHeader && authHeader.startsWith('Bearer ')) {
              return authHeader.replace('Bearer ', '').trim();
            }
            return request.ip;
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const agent = await requireAgentAuth(request, reply);
      if (!agent) return;

      const parseResult = AgentPollRequestSchema.safeParse(request.body);
      const maxJobs = parseResult.success ? parseResult.data.maxJobs : 1;
      const capabilities = (parseResult.success && parseResult.data.capabilities && parseResult.data.capabilities.length > 0)
        ? parseResult.data.capabilities
        : ((agent.capabilities as string[]) || []);
      const tags = (parseResult.success && parseResult.data.tags && parseResult.data.tags.length > 0)
        ? parseResult.data.tags
        : ((agent.tags as string[]) || []);

      const jobs = await agentDispatcherService.pollJobs(
        agent.id,
        agent.tenantId,
        capabilities,
        tags,
        maxJobs,
      );

      return reply.status(200).send({
        jobs,
      });
    },
  );

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

  // 6. POST /api/v1/agents/jobs/:jobId/complete (5MB body limit)
  fastify.post<{ Params: { jobId: string } }>(
    '/jobs/:jobId/complete',
    {
      bodyLimit: 5 * 1024 * 1024,
    },
    async (request, reply) => {
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
          ...(result?.ignored ? { ignored: true, status: result.status } : {}),
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
    },
  );

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

  // 7b. POST /api/v1/agents/jobs/:jobId/cancel-ack
  fastify.post<{ Params: { jobId: string } }>('/jobs/:jobId/cancel-ack', async (request, reply) => {
    const agent = await requireAgentAuth(request, reply);
    if (!agent) return;

    try {
      const ackResult = await agentDispatcherService.acknowledgeJobCancellation(request.params.jobId, agent);
      return reply.status(200).send(ackResult);
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
        error: { code: 'CANCEL_ACK_ERROR', message: msg },
      });
    }
  });

  // 8. POST /api/v1/agents/dispatch
  const DispatchSchema = z.object({
    testRunId: z.string().uuid(),
    engineIds: z.array(z.string()).default([]),
    options: z.record(z.string(), z.unknown()).optional(),
    requiredCapabilities: z.array(z.string()).default([]),
    requiredTags: z.array(z.string()).default([]),
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
        parseResult.data.requiredCapabilities,
        parseResult.data.requiredTags,
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

  // 11. GET /api/v1/agents/:id/audit-events
  fastify.get<{
    Params: { id: string };
    Querystring: { page?: string; limit?: string; eventType?: string };
  }>('/:id/audit-events', async (request, reply) => {
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
      tenantId = extractTenantId(request);
    }

    const agent = await agentDispatcherService.getAgentById(request.params.id);
    if (!agent) {
      return reply.status(404).send({
        success: false,
        error: { code: 'NOT_FOUND', message: `Agent "${request.params.id}" not found` },
      });
    }

    if (agent.tenantId !== tenantId) {
      await agentAuditService.recordAuditEvent({
        tenantId,
        agentId: request.params.id,
        eventType: 'security.tenant_mismatch',
        actorType: 'admin',
        actorId: 'admin',
        metadata: {
          action: 'query_audit_events',
          agentTenantId: agent.tenantId,
          requestedTenantId: tenantId,
        },
        ipAddress: request.ip,
      });

      return reply.status(403).send({
        success: false,
        error: { code: 'TENANT_MISMATCH', message: 'Agent belongs to another tenant' },
      });
    }

    const page = Math.max(1, parseInt(request.query.page || '1', 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(request.query.limit || '50', 10) || 50));
    const offset = (page - 1) * limit;

    const result = await agentAuditService.getAuditEvents({
      tenantId,
      agentId: request.params.id,
      eventType: request.query.eventType,
      limit,
      offset,
    });

    return reply.status(200).send({
      success: true,
      data: result.events,
      events: result.events,
      pagination: {
        total: result.total,
        page,
        limit,
        totalPages: Math.ceil(result.total / limit),
      },
    });
  });
}
