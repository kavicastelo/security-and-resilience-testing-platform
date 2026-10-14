import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { SubscriptionTierSchema, QuotaLimitsSchema } from '@security-lab/contracts';
import { z } from 'zod';
import { billingService } from '../services/billing/billing.service.js';
import { verifyStripeSignature } from '../services/billing/stripe.js';
import { requireAdmin, requireAuditor } from '../plugins/rbac.js';

const UpdateTierRequestSchema = z.object({
  tier: SubscriptionTierSchema,
  stripeCustomerId: z.string().optional(),
  customQuotas: QuotaLimitsSchema.partial().optional(),
});

export const billingRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // 1. Stripe Inbound Webhook (Public POST with Stripe signature verification)
  fastify.post('/api/v1/billing/webhook', async (request, reply) => {
    const sigHeader = request.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    const rawBody = typeof request.body === 'string' ? request.body : JSON.stringify(request.body);

    if (webhookSecret && typeof sigHeader === 'string') {
      const isValid = verifyStripeSignature(rawBody, sigHeader, webhookSecret);
      if (!isValid) {
        return reply.status(400).send({
          success: false,
          error: {
            code: 'INVALID_STRIPE_SIGNATURE',
            message: 'Stripe webhook signature verification failed',
          },
        });
      }
    }

    try {
      const event = typeof request.body === 'string' ? JSON.parse(request.body) : request.body;
      const result = await billingService.handleStripeEvent(event);
      return reply.send({
        received: true,
        handled: result.handled,
        action: result.action,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to process Stripe webhook';
      return reply.status(400).send({
        success: false,
        error: { code: 'STRIPE_WEBHOOK_ERROR', message },
      });
    }
  });

  // 2. Get Workspace Billing & Quotas (ADMIN / AUDITOR)
  fastify.get<{ Params: { id: string } }>(
    '/api/v1/workspaces/:id/billing',
    { preHandler: [requireAuditor] },
    async (request, reply) => {
      const { id } = request.params;
      const billing = await billingService.getWorkspaceBilling(id);
      if (!billing) {
        return reply.status(404).send({
          success: false,
          error: { code: 'WORKSPACE_NOT_FOUND', message: `Workspace "${id}" not found` },
        });
      }
      return reply.send({
        success: true,
        data: billing,
      });
    },
  );

  // 3. Update Workspace Subscription Tier & Quotas (ADMIN only)
  fastify.put<{ Params: { id: string } }>(
    '/api/v1/workspaces/:id/billing/tier',
    { preHandler: [requireAdmin] },
    async (request, reply) => {
      const { id } = request.params;
      const parseResult = UpdateTierRequestSchema.safeParse(request.body);
      if (!parseResult.success) {
        return reply.status(400).send({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid tier update payload',
            details: parseResult.error.format(),
          },
        });
      }

      try {
        const updated = await billingService.updateSubscriptionTier(
          id,
          parseResult.data.tier,
          parseResult.data.stripeCustomerId,
          parseResult.data.customQuotas,
        );
        return reply.send({
          success: true,
          data: updated,
        });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'Failed to update billing tier';
        return reply.status(400).send({
          success: false,
          error: { code: 'BILLING_UPDATE_FAILED', message },
        });
      }
    },
  );
};
