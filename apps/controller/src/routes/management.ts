import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import {
  PurgeDataRequestSchema,
  PurgeDataRequest,
  CreateBackupRequestSchema,
  CreateBackupRequest,
  RestoreBackupRequestSchema,
  RestoreBackupRequest,
} from '@security-lab/contracts';
import { managementService } from '../services/management.service.js';
import { extractTenantId } from '../services/tenant-context.js';
import { getDatabase } from '../services/db.js';
import { agentAuditEvents } from '../services/db/schema.js';
import { desc, eq } from 'drizzle-orm';

function requireAdminRole(request: FastifyRequest, reply: FastifyReply): boolean {
  if (request.auth?.role !== 'admin') {
    reply.status(403).send({
      success: false,
      error: {
        code: 'FORBIDDEN',
        message: 'Administrative authorization required for this operation',
      },
    });
    return false;
  }
  return true;
}

export async function managementRoutes(fastify: FastifyInstance) {
  // GET /api/v1/management/overview
  fastify.get('/overview', async (_request: FastifyRequest, reply: FastifyReply) => {
    try {
      const stats = await managementService.getSystemOverview();
      return reply.status(200).send({
        success: true,
        data: stats,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to retrieve system management metrics';
      return reply.status(500).send({
        success: false,
        error: {
          code: 'MANAGEMENT_STATS_ERROR',
          message,
        },
      });
    }
  });

  // POST /api/v1/management/purge
  const defaultPurgeMax = process.env.NODE_ENV === 'production' ? 3 : 50;
  const purgeMax = fastify.rateLimitOverrides?.purgeMax ?? defaultPurgeMax;
  fastify.post('/purge', {
    config: {
      rateLimit: {
        max: purgeMax,
        timeWindow: '5 minutes',
        keyGenerator: (request: FastifyRequest) => {
          const id = request.auth?.keyId || request.auth?.tenantId || request.ip;
          return `purge:${id}`;
        },
        errorResponseBuilder: (_request, context) => ({
          statusCode: 429,
          error: 'Too Many Requests',
          message: 'Rate limit exceeded for administrative purge operations. Please wait before retrying.',
          retryAfter: Math.ceil(context.ttl / 1000) || 300,
        }),
      },
    },
  }, async (request: FastifyRequest<{ Body: PurgeDataRequest }>, reply: FastifyReply) => {
    if (!requireAdminRole(request, reply)) return;

    const parseResult = PurgeDataRequestSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: parseResult.error.errors.map((e) => e.message).join(', '),
        },
      });
    }

    const { mode, confirmation } = parseResult.data;
    const tenantId = extractTenantId(request);

    try {
      const result = await managementService.purgeData(mode, confirmation, tenantId);
      return reply.status(200).send({
        success: true,
        data: result,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Data purge operation failed';
      return reply.status(400).send({
        success: false,
        error: {
          code: 'PURGE_FAILED',
          message,
        },
      });
    }
  });

  // POST /api/v1/management/seed
  fastify.post('/seed', async (request: FastifyRequest<{ Body?: { force?: boolean } }>, reply: FastifyReply) => {
    // 1. Production Environment Lockout: disabled entirely in production
    if (process.env.NODE_ENV === 'production') {
      return reply.status(403).send({
        error: 'Forbidden',
        message: 'Demo data seeding is disabled in production environments.',
      });
    }

    // 2. Administrative Authentication Guard: non-admin requests rejected
    if (!requireAdminRole(request, reply)) return;

    const tenantId = extractTenantId(request);
    const force = Boolean(request.body?.force);

    try {
      const result = await managementService.seedDemoData(tenantId, { force });
      return reply.status(201).send({
        success: true,
        data: result,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Demo data seed failed';
      const isConflict = message.includes('existing project(s) found');
      return reply.status(isConflict ? 409 : 500).send({
        success: false,
        error: {
          code: isConflict ? 'PROJECTS_EXIST' : 'SEED_FAILED',
          message,
        },
      });
    }
  });

  // POST /api/v1/management/reap-jobs
  fastify.post('/reap-jobs', async (request: FastifyRequest, reply: FastifyReply) => {
    if (!requireAdminRole(request, reply)) return;

    try {
      const result = await managementService.reapAgentJobsNow();
      return reply.status(200).send({
        success: true,
        data: result,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Job lease watchdog reap failed';
      return reply.status(500).send({
        success: false,
        error: {
          code: 'REAPER_FAILED',
          message,
        },
      });
    }
  });

  // GET /api/v1/management/audit-events
  fastify.get('/audit-events', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { db } = getDatabase();
      const tenantId = extractTenantId(request);
      const query = db.select().from(agentAuditEvents);
      const events = request.auth?.role === 'admin'
        ? await query.orderBy(desc(agentAuditEvents.createdAt)).limit(50)
        : await query.where(eq(agentAuditEvents.tenantId, tenantId)).orderBy(desc(agentAuditEvents.createdAt)).limit(50);

      return reply.status(200).send({
        success: true,
        data: events,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to retrieve audit events';
      return reply.status(500).send({
        success: false,
        error: {
          code: 'AUDIT_QUERY_FAILED',
          message,
        },
      });
    }
  });

  // GET /api/v1/management/backups
  fastify.get('/backups', async (_request: FastifyRequest, reply: FastifyReply) => {
    try {
      const backups = await managementService.listBackups();
      return reply.status(200).send({
        success: true,
        data: backups,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to list backups';
      return reply.status(500).send({
        success: false,
        error: {
          code: 'BACKUP_LIST_ERROR',
          message,
        },
      });
    }
  });

  // POST /api/v1/management/backups
  fastify.post('/backups', async (request: FastifyRequest<{ Body: CreateBackupRequest }>, reply: FastifyReply) => {
    const parseResult = CreateBackupRequestSchema.safeParse(request.body || {});
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
      const backup = await managementService.createBackup(parseResult.data);
      return reply.status(201).send({
        success: true,
        data: backup,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to create backup';
      return reply.status(500).send({
        success: false,
        error: {
          code: 'BACKUP_CREATE_ERROR',
          message,
        },
      });
    }
  });

  // GET /api/v1/management/backups/:id/download
  fastify.get('/backups/:id/download', async (request: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply) => {
    try {
      const { filename, content } = await managementService.getBackupFile(request.params.id);
      return reply
        .header('Content-Disposition', `attachment; filename="${filename}"`)
        .header('Content-Type', 'application/json')
        .send(content);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to download backup';
      return reply.status(404).send({
        success: false,
        error: {
          code: 'BACKUP_NOT_FOUND',
          message,
        },
      });
    }
  });

  // DELETE /api/v1/management/backups/:id
  fastify.delete('/backups/:id', async (request: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply) => {
    if (!requireAdminRole(request, reply)) return;

    try {
      const result = await managementService.deleteBackup(request.params.id);
      return reply.status(200).send({
        success: true,
        data: result,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to delete backup';
      return reply.status(404).send({
        success: false,
        error: {
          code: 'BACKUP_DELETE_ERROR',
          message,
        },
      });
    }
  });

  // POST /api/v1/management/backups/restore
  fastify.post('/backups/restore', async (request: FastifyRequest<{ Body: RestoreBackupRequest }>, reply: FastifyReply) => {
    if (!requireAdminRole(request, reply)) return;

    const parseResult = RestoreBackupRequestSchema.safeParse(request.body || {});
    if (!parseResult.success) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: parseResult.error.errors.map((e) => e.message).join(', '),
        },
      });
    }

    const tenantId = extractTenantId(request);

    try {
      const result = await managementService.restoreBackup(parseResult.data, tenantId);
      return reply.status(200).send({
        success: true,
        data: result,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to restore backup';
      return reply.status(400).send({
        success: false,
        error: {
          code: 'RESTORE_ERROR',
          message,
        },
      });
    }
  });
}

