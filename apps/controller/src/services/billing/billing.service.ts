import { eq, and, sql } from 'drizzle-orm';
import { getDatabase } from '../db.js';
import { workspaces, testRuns, projects } from '../db/schema.js';
import {
  SubscriptionTier,
  QuotaLimits,
  DEFAULT_TIER_QUOTAS,
  WorkspaceBilling,
} from '@security-lab/contracts';
import { telemetryRegistry } from '../../telemetry.js';
import { logger } from '@security-lab/logger';

export interface QuotaCheckResult {
  allowed: boolean;
  code?: 'QUOTA_EXCEEDED' | 'CONCURRENT_LIMIT_EXCEEDED';
  message?: string;
  details?: {
    tier: SubscriptionTier;
    usageMinutes: number;
    maxMinutes: number;
    activeRuns?: number;
    maxConcurrentRuns?: number;
  };
}

export class BillingService {
  /**
   * Retrieves billing, tier, and usage metrics for a workspace.
   */
  async getWorkspaceBilling(workspaceId: string): Promise<WorkspaceBilling | null> {
    const { db } = getDatabase();
    const [row] = await db
      .select({
        id: workspaces.id,
        subscriptionTier: workspaces.subscriptionTier,
        stripeCustomerId: workspaces.stripeCustomerId,
        quotaLimits: workspaces.quotaLimits,
        usageMinutes: workspaces.usageMinutes,
      })
      .from(workspaces)
      .where(eq(workspaces.id, workspaceId));

    if (!row) return null;

    const tier = (row.subscriptionTier || 'free') as SubscriptionTier;
    const quotaLimits = (row.quotaLimits as QuotaLimits) || DEFAULT_TIER_QUOTAS[tier] || DEFAULT_TIER_QUOTAS.free;
    const usageMinutes = row.usageMinutes || 0;
    const isQuotaExceeded = usageMinutes >= quotaLimits.maxExecutionMinutesPerMonth;

    return {
      workspaceId: row.id,
      subscriptionTier: tier,
      stripeCustomerId: row.stripeCustomerId,
      quotaLimits,
      usageMinutes,
      isQuotaExceeded,
    };
  }

  /**
   * Updates workspace subscription tier and corresponding quotas.
   */
  async updateSubscriptionTier(
    workspaceId: string,
    tier: SubscriptionTier,
    stripeCustomerId?: string,
    customQuotas?: Partial<QuotaLimits>,
  ): Promise<WorkspaceBilling> {
    const { db } = getDatabase();
    const baseQuotas = DEFAULT_TIER_QUOTAS[tier] || DEFAULT_TIER_QUOTAS.free;
    const quotaLimits: QuotaLimits = {
      ...baseQuotas,
      ...customQuotas,
    };

    const updateValues: Record<string, unknown> = {
      subscriptionTier: tier,
      quotaLimits,
      updatedAt: new Date(),
    };

    if (stripeCustomerId !== undefined) {
      updateValues.stripeCustomerId = stripeCustomerId;
    }

    const [updated] = await db
      .update(workspaces)
      .set(updateValues)
      .where(eq(workspaces.id, workspaceId))
      .returning();

    if (!updated) {
      throw new Error(`Workspace "${workspaceId}" not found`);
    }

    logger.info(
      { workspaceId, tier, quotaLimits },
      `Workspace subscription tier updated to "${tier}"`,
    );

    return {
      workspaceId: updated.id,
      subscriptionTier: updated.subscriptionTier as SubscriptionTier,
      stripeCustomerId: updated.stripeCustomerId,
      quotaLimits: updated.quotaLimits as QuotaLimits,
      usageMinutes: updated.usageMinutes,
      isQuotaExceeded: updated.usageMinutes >= (updated.quotaLimits as QuotaLimits).maxExecutionMinutesPerMonth,
    };
  }

  /**
   * Evaluates workspace quota before launching or queuing a test run.
   * Returns allowed: true if within limits, or allowed: false (402 Payment Required) if exceeded.
   */
  async checkRunQuota(workspaceId?: string): Promise<QuotaCheckResult> {
    if (!workspaceId) {
      return { allowed: true };
    }

    const billing = await this.getWorkspaceBilling(workspaceId);
    if (!billing) {
      return { allowed: true };
    }

    const { subscriptionTier, quotaLimits, usageMinutes } = billing;

    // 1. Check monthly execution minutes limit
    if (usageMinutes >= quotaLimits.maxExecutionMinutesPerMonth) {
      return {
        allowed: false,
        code: 'QUOTA_EXCEEDED',
        message: `Monthly execution quota exceeded for "${subscriptionTier}" tier (${usageMinutes}/${quotaLimits.maxExecutionMinutesPerMonth} minutes used). Please upgrade your subscription tier to continue.`,
        details: {
          tier: subscriptionTier,
          usageMinutes,
          maxMinutes: quotaLimits.maxExecutionMinutesPerMonth,
        },
      };
    }

    // 2. Check concurrent active test runs limit
    const { db } = getDatabase();
    const activeRuns = await db
      .select({ count: sql<number>`count(*)` })
      .from(testRuns)
      .innerJoin(projects, eq(testRuns.projectId, projects.id))
      .where(
        and(
          eq(projects.workspaceId, workspaceId),
          eq(testRuns.status, 'running'),
        ),
      );

    const runningCount = Number(activeRuns[0]?.count || 0);
    if (runningCount >= quotaLimits.maxConcurrentRuns) {
      return {
        allowed: false,
        code: 'CONCURRENT_LIMIT_EXCEEDED',
        message: `Concurrent execution quota reached for "${subscriptionTier}" tier (${runningCount}/${quotaLimits.maxConcurrentRuns} active runs). Wait for existing runs to finish or upgrade tier.`,
        details: {
          tier: subscriptionTier,
          usageMinutes,
          maxMinutes: quotaLimits.maxExecutionMinutesPerMonth,
          activeRuns: runningCount,
          maxConcurrentRuns: quotaLimits.maxConcurrentRuns,
        },
      };
    }

    return { allowed: true };
  }

  /**
   * Increments workspace usage upon test run execution completion.
   */
  async recordRunUsage(workspaceId: string, durationSeconds: number): Promise<{ usageMinutes: number }> {
    if (!workspaceId || durationSeconds <= 0) {
      return { usageMinutes: 0 };
    }

    // Convert seconds to whole minutes (minimum 1 minute per run)
    const minutes = Math.max(1, Math.ceil(durationSeconds / 60));

    const { db } = getDatabase();
    const [updated] = await db
      .update(workspaces)
      .set({
        usageMinutes: sql`${workspaces.usageMinutes} + ${minutes}`,
        updatedAt: new Date(),
      })
      .where(eq(workspaces.id, workspaceId))
      .returning({ usageMinutes: workspaces.usageMinutes });

    // Track Prometheus metric
    telemetryRegistry.recordTenantUsage(workspaceId, durationSeconds);

    return { usageMinutes: updated?.usageMinutes || 0 };
  }

  /**
   * Handles incoming Stripe subscription and invoice events.
   */
  async handleStripeEvent(event: any): Promise<{ handled: boolean; action?: string; workspaceId?: string }> {
    const eventType = event.type;
    const dataObj = event.data?.object || {};
    const { db } = getDatabase();

    if (eventType === 'customer.subscription.created' || eventType === 'customer.subscription.updated') {
      const customerId = dataObj.customer;
      const metadata = dataObj.metadata || {};
      const targetWorkspaceId = metadata.workspace_id || metadata.workspaceId;

      // Determine tier from price lookup key, plan nickname, or metadata
      let tier: SubscriptionTier = 'starter';
      const candidateTier = metadata.tier || dataObj.items?.data?.[0]?.price?.lookup_key || dataObj.plan?.nickname || '';
      if (candidateTier.includes('enterprise')) {
        tier = 'enterprise';
      } else if (candidateTier.includes('starter')) {
        tier = 'starter';
      } else if (candidateTier.includes('free')) {
        tier = 'free';
      }

      // Find workspace
      let workspaceToUpdate: string | undefined = targetWorkspaceId;
      if (!workspaceToUpdate && customerId) {
        const [ws] = await db
          .select({ id: workspaces.id })
          .from(workspaces)
          .where(eq(workspaces.stripeCustomerId, customerId));
        workspaceToUpdate = ws?.id;
      }

      if (workspaceToUpdate) {
        await this.updateSubscriptionTier(workspaceToUpdate, tier, customerId);
        return { handled: true, action: 'subscription_updated', workspaceId: workspaceToUpdate };
      }
    } else if (eventType === 'customer.subscription.deleted') {
      const customerId = dataObj.customer;
      const metadata = dataObj.metadata || {};
      const targetWorkspaceId = metadata.workspace_id || metadata.workspaceId;

      let workspaceToUpdate: string | undefined = targetWorkspaceId;
      if (!workspaceToUpdate && customerId) {
        const [ws] = await db
          .select({ id: workspaces.id })
          .from(workspaces)
          .where(eq(workspaces.stripeCustomerId, customerId));
        workspaceToUpdate = ws?.id;
      }

      if (workspaceToUpdate) {
        // Downgrade to free
        await this.updateSubscriptionTier(workspaceToUpdate, 'free');
        return { handled: true, action: 'subscription_canceled', workspaceId: workspaceToUpdate };
      }
    } else if (eventType === 'invoice.payment_succeeded') {
      // Monthly billing reset
      const customerId = dataObj.customer;
      if (customerId) {
        const [updated] = await db
          .update(workspaces)
          .set({ usageMinutes: 0, updatedAt: new Date() })
          .where(eq(workspaces.stripeCustomerId, customerId))
          .returning({ id: workspaces.id });
        if (updated) {
          return { handled: true, action: 'usage_reset', workspaceId: updated.id };
        }
      }
    }

    return { handled: false };
  }
}

export const billingService = new BillingService();
