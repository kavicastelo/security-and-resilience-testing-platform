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
import { desc } from 'drizzle-orm';

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
  fastify.post('/purge', async (request: FastifyRequest<{ Body: PurgeDataRequest }>, reply: FastifyReply) => {
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
  fastify.post('/seed', async (request: FastifyRequest, reply: FastifyReply) => {
    const tenantId = extractTenantId(request);
    try {
      const result = await managementService.seedDemoData(tenantId);
      return reply.status(201).send({
        success: true,
        data: result,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Demo data seed failed';
      return reply.status(500).send({
        success: false,
        error: {
          code: 'SEED_FAILED',
          message,
        },
      });
    }
  });

  // POST /api/v1/management/reap-jobs
  fastify.post('/reap-jobs', async (_request: FastifyRequest, reply: FastifyReply) => {
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
  fastify.get('/audit-events', async (_request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { db } = getDatabase();
      const events = await db
        .select()
        .from(agentAuditEvents)
        .orderBy(desc(agentAuditEvents.createdAt))
        .limit(50);

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

