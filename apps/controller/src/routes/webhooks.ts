import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { webhookQueueService } from '../services/webhook-queue.js';
import { gitHubSyncService } from '../services/integrations/github.js';
import { jiraSyncService } from '../services/integrations/jira.js';
import { requireEngineer, requireAuditor } from '../plugins/rbac.js';
import { extractTenantScope } from '../services/tenant-context.js';

const CreateWebhookSchema = z.object({
  url: z.string().url('Webhook URL must be a valid HTTP or HTTPS address'),
  description: z.string().optional(),
  secret: z.string().optional(),
  events: z.array(z.string()).optional(),
  headers: z.record(z.string()).optional(),
});

export const webhooksRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // 1. List configured webhooks
  fastify.get('/api/v1/webhooks', { preHandler: [requireAuditor] }, async (request, reply) => {
    const workspaceId =
      (request as unknown as { user?: { workspaceId?: string } }).user?.workspaceId ||
      extractTenantScope(request) ||
      '00000000-0000-0000-0000-000000000000';

    const list = await webhookQueueService.listWebhooks(workspaceId);
    return reply.send({ success: true, data: list });
  });

  // 2. Register a new webhook endpoint
  fastify.post('/api/v1/webhooks', { preHandler: [requireEngineer] }, async (request, reply) => {
    const workspaceId =
      (request as unknown as { user?: { workspaceId?: string } }).user?.workspaceId ||
      extractTenantScope(request) ||
      '00000000-0000-0000-0000-000000000000';

    const parseResult = CreateWebhookSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: parseResult.error.errors.map((e) => e.message).join(', '),
        },
      });
    }

    const created = await webhookQueueService.createWebhook({
      workspaceId,
      ...parseResult.data,
    });

    return reply.status(201).send({ success: true, data: created });
  });

  // 3. Delete webhook
  fastify.delete<{ Params: { id: string } }>(
    '/api/v1/webhooks/:id',
    { preHandler: [requireEngineer] },
    async (request, reply) => {
      const { id } = request.params;
      const workspaceId = (request as unknown as { user?: { workspaceId?: string } }).user?.workspaceId;

      const deleted = await webhookQueueService.deleteWebhook(id, workspaceId);
      if (!deleted) {
        return reply.status(404).send({
          success: false,
          error: { code: 'WEBHOOK_NOT_FOUND', message: `Webhook "${id}" not found` },
        });
      }

      return reply.send({ success: true, message: 'Webhook deleted successfully' });
    },
  );

  // 4. Test Webhook Ping
  fastify.post<{ Params: { id: string } }>(
    '/api/v1/webhooks/:id/test',
    { preHandler: [requireEngineer] },
    async (request, reply) => {
      const { id } = request.params;
      const wh = await webhookQueueService.getWebhookById(id);
      if (!wh) {
        return reply.status(404).send({
          success: false,
          error: { code: 'WEBHOOK_NOT_FOUND', message: `Webhook "${id}" not found` },
        });
      }

      const deliveries = await webhookQueueService.dispatchEvent(wh.workspaceId, 'ping', {
        message: 'Security Lab Webhook Connectivity Verification',
        timestamp: new Date().toISOString(),
      });

      return reply.send({
        success: true,
        message: 'Test ping enqueued for delivery',
        data: deliveries[0] || null,
      });
    },
  );

  // 5. List delivery logs for a specific webhook
  fastify.get<{ Params: { id: string }; Querystring: { limit?: number } }>(
    '/api/v1/webhooks/:id/deliveries',
    { preHandler: [requireAuditor] },
    async (request, reply) => {
      const { id } = request.params;
      const limit = Number(request.query.limit) || 50;
      const deliveries = await webhookQueueService.listDeliveries(id, limit);
      return reply.send({ success: true, data: deliveries });
    },
  );

  // 6. Inbound Issue Tracker Webhooks (GitHub / Jira issue closure triggers retest)
  fastify.post('/api/v1/integrations/github/webhook', async (request, reply) => {
    const event = (request.headers['x-github-event'] as string) || 'issues';
    const payload = (request.body as Record<string, unknown>) || {};
    const tenantId = extractTenantScope(request);

    const result = await gitHubSyncService.handleGitHubWebhook(event, payload, tenantId);
    return reply.send({ success: true, ...result });
  });

  fastify.post('/api/v1/integrations/jira/webhook', async (request, reply) => {
    const payload = (request.body as Record<string, unknown>) || {};
    const tenantId = extractTenantScope(request);

    const result = await jiraSyncService.handleJiraWebhook(payload, tenantId);
    return reply.send({ success: true, ...result });
  });
};
