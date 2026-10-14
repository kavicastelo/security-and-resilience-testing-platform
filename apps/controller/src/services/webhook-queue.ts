import crypto from 'node:crypto';
import { eq, and, lte, inArray } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { webhooks, webhookDeliveries } from './db/schema.js';
import { encryptObject, decryptObject, EncryptedPayload } from '@security-lab/crypto';
import { telemetryRegistry } from '../telemetry.js';
import { logger } from '@security-lab/logger';

export interface CreateWebhookInput {
  workspaceId: string;
  url: string;
  secret?: string;
  description?: string;
  events?: string[];
  headers?: Record<string, string>;
}

export interface WebhookRecord {
  id: string;
  workspaceId: string;
  url: string;
  description?: string | null;
  events: string[];
  isActive: boolean;
  headers: Record<string, string>;
  createdAt: Date;
  updatedAt: Date;
}

export interface WebhookDeliveryRecord {
  id: string;
  webhookId: string;
  workspaceId: string;
  eventType: string;
  payload: Record<string, unknown>;
  status: 'pending' | 'delivering' | 'succeeded' | 'failed' | 'dead_letter';
  attempts: number;
  maxAttempts: number;
  nextRetryAt: Date;
  lastAttemptAt?: Date | null;
  responseStatusCode?: number | null;
  responseBody?: string | null;
  lastError?: string | null;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Computes standard HMAC-SHA256 signature for webhook payload:
 * sha256=HEX(HMAC-SHA256(secret, payloadString))
 */
export function signWebhookPayload(payloadStr: string, secret: string): string {
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(payloadStr, 'utf8');
  return `sha256=${hmac.digest('hex')}`;
}

export class WebhookQueueService {
  private isWorkerRunning = false;
  private workerTimer: NodeJS.Timeout | null = null;

  /**
   * Encrypts and registers a new webhook endpoint.
   */
  async createWebhook(input: CreateWebhookInput): Promise<WebhookRecord> {
    const { db } = getDatabase();
    const rawSecret = input.secret || crypto.randomBytes(32).toString('hex');
    
    // Encrypt secret at rest via AES-256-GCM envelope
    const encryptedSecret = encryptObject({ secret: rawSecret });

    const [inserted] = await db
      .insert(webhooks)
      .values({
        workspaceId: input.workspaceId,
        url: input.url,
        description: input.description,
        secret: JSON.stringify(encryptedSecret),
        events: input.events && input.events.length > 0 ? input.events : ['*'],
        headers: input.headers || {},
        isActive: true,
      })
      .returning();

    if (!inserted) {
      throw new Error('Failed to create webhook');
    }

    return {
      id: inserted.id,
      workspaceId: inserted.workspaceId,
      url: inserted.url,
      description: inserted.description,
      events: inserted.events as string[],
      isActive: inserted.isActive,
      headers: inserted.headers as Record<string, string>,
      createdAt: inserted.createdAt,
      updatedAt: inserted.updatedAt,
    };
  }

  async getWebhookById(id: string, workspaceId?: string): Promise<WebhookRecord | null> {
    const { db } = getDatabase();
    const conditions = [eq(webhooks.id, id)];
    if (workspaceId) {
      conditions.push(eq(webhooks.workspaceId, workspaceId));
    }
    const [row] = await db.select().from(webhooks).where(and(...conditions));
    if (!row) return null;

    return {
      id: row.id,
      workspaceId: row.workspaceId,
      url: row.url,
      description: row.description,
      events: row.events as string[],
      isActive: row.isActive,
      headers: row.headers as Record<string, string>,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  }

  async listWebhooks(workspaceId: string): Promise<WebhookRecord[]> {
    const { db } = getDatabase();
    const rows = await db
      .select()
      .from(webhooks)
      .where(eq(webhooks.workspaceId, workspaceId));

    return rows.map((row) => ({
      id: row.id,
      workspaceId: row.workspaceId,
      url: row.url,
      description: row.description,
      events: row.events as string[],
      isActive: row.isActive,
      headers: row.headers as Record<string, string>,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    }));
  }

  async deleteWebhook(id: string, workspaceId?: string): Promise<boolean> {
    const { db } = getDatabase();
    const conditions = [eq(webhooks.id, id)];
    if (workspaceId) {
      conditions.push(eq(webhooks.workspaceId, workspaceId));
    }
    const deleted = await db.delete(webhooks).where(and(...conditions)).returning();
    return deleted.length > 0;
  }

  /**
   * Helper to retrieve and decrypt a webhook's signing secret.
   */
  async getWebhookSecret(id: string): Promise<string | null> {
    const { db } = getDatabase();
    const [row] = await db.select({ secret: webhooks.secret }).from(webhooks).where(eq(webhooks.id, id));
    if (!row) return null;

    try {
      const parsed = JSON.parse(row.secret) as EncryptedPayload;
      if (parsed.algorithm === 'aes-256-gcm') {
        const decrypted = decryptObject<{ secret: string }>(parsed);
        return decrypted.secret;
      }
    } catch {
      // Fallback if raw secret string was stored
    }
    return row.secret;
  }

  /**
   * Enqueues an event payload across all active webhooks subscribed to this event in the workspace.
   */
  async dispatchEvent(
    workspaceId: string,
    eventType: string,
    payload: Record<string, unknown>,
  ): Promise<WebhookDeliveryRecord[]> {
    const { db } = getDatabase();

    // Query active webhooks in workspace
    const targets = await db
      .select()
      .from(webhooks)
      .where(and(eq(webhooks.workspaceId, workspaceId), eq(webhooks.isActive, true)));

    const matchingWebhooks = targets.filter((wh) => {
      const events = wh.events as string[];
      return events.includes('*') || events.includes(eventType);
    });

    if (matchingWebhooks.length === 0) {
      return [];
    }

    const insertedDeliveries: WebhookDeliveryRecord[] = [];
    for (const wh of matchingWebhooks) {
      const [delivery] = await db
        .insert(webhookDeliveries)
        .values({
          webhookId: wh.id,
          workspaceId: wh.workspaceId,
          eventType,
          payload,
          status: 'pending',
          attempts: 0,
          maxAttempts: 5,
          nextRetryAt: new Date(),
        })
        .returning();

      if (delivery) {
        insertedDeliveries.push({
          id: delivery.id,
          webhookId: delivery.webhookId,
          workspaceId: delivery.workspaceId,
          eventType: delivery.eventType,
          payload: delivery.payload as Record<string, unknown>,
          status: delivery.status as WebhookDeliveryRecord['status'],
          attempts: delivery.attempts,
          maxAttempts: delivery.maxAttempts,
          nextRetryAt: delivery.nextRetryAt,
          lastAttemptAt: delivery.lastAttemptAt,
          responseStatusCode: delivery.responseStatusCode,
          responseBody: delivery.responseBody,
          lastError: delivery.lastError,
          createdAt: delivery.createdAt,
          updatedAt: delivery.updatedAt,
        });
      }
    }

    return insertedDeliveries;
  }

  /**
   * Executes a single delivery attempt for a queued item.
   */
  async processDelivery(deliveryId: string, customFetch?: typeof fetch): Promise<boolean> {
    const { db } = getDatabase();
    const fetchFn = customFetch || globalThis.fetch;

    const [delivery] = await db
      .select()
      .from(webhookDeliveries)
      .where(eq(webhookDeliveries.id, deliveryId));

    if (!delivery || delivery.status === 'succeeded' || delivery.status === 'dead_letter') {
      return false;
    }

    const [wh] = await db.select().from(webhooks).where(eq(webhooks.id, delivery.webhookId));
    if (!wh) {
      await db
        .update(webhookDeliveries)
        .set({ status: 'dead_letter', lastError: 'Webhook endpoint configuration not found' })
        .where(eq(webhookDeliveries.id, deliveryId));
      return false;
    }

    const secret = await this.getWebhookSecret(wh.id);
    const payloadStr = JSON.stringify({
      id: delivery.id,
      event: delivery.eventType,
      workspaceId: delivery.workspaceId,
      timestamp: new Date().toISOString(),
      data: delivery.payload,
    });

    const signature = secret ? signWebhookPayload(payloadStr, secret) : '';
    const attempt = delivery.attempts + 1;
    const now = new Date();

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'SecurityLab-Webhook-Dispatcher/1.0',
      'X-SecurityLab-Event': delivery.eventType,
      'X-SecurityLab-Delivery': delivery.id,
      'X-SecurityLab-Signature': signature,
      ...((wh.headers as Record<string, string>) || {}),
    };

    try {
      const response = await fetchFn(wh.url, {
        method: 'POST',
        headers,
        body: payloadStr,
        signal: AbortSignal.timeout(10000), // 10s timeout
      });

      const responseBody = await response.text().catch(() => '');

      if (response.ok) {
        // Success
        await db
          .update(webhookDeliveries)
          .set({
            status: 'succeeded',
            attempts: attempt,
            lastAttemptAt: now,
            responseStatusCode: response.status,
            responseBody: responseBody.slice(0, 2048),
            lastError: null,
            updatedAt: now,
          })
          .where(eq(webhookDeliveries.id, deliveryId));

        telemetryRegistry.recordWebhookDelivery('success', 1);
        logger.info(
          { deliveryId, webhookId: wh.id, status: response.status, attempts: attempt },
          'Webhook delivered successfully',
        );
        return true;
      }

      // HTTP Error (4xx or 5xx)
      const isRetryable = response.status >= 500 || response.status === 429;
      return await this.handleDeliveryFailure(
        delivery,
        attempt,
        now,
        `HTTP ${response.status}: ${responseBody.slice(0, 256)}`,
        response.status,
        responseBody.slice(0, 2048),
        isRetryable,
      );
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return await this.handleDeliveryFailure(delivery, attempt, now, message, null, null, true);
    }
  }

  private async handleDeliveryFailure(
    delivery: typeof webhookDeliveries.$inferSelect,
    attempt: number,
    attemptTime: Date,
    errorMessage: string,
    statusCode: number | null,
    responseBody: string | null,
    isRetryable: boolean,
  ): Promise<boolean> {
    const { db } = getDatabase();

    if (!isRetryable || attempt >= delivery.maxAttempts) {
      // Dead Letter Queue after max retries or permanent error (4xx)
      await db
        .update(webhookDeliveries)
        .set({
          status: 'dead_letter',
          attempts: attempt,
          lastAttemptAt: attemptTime,
          responseStatusCode: statusCode,
          responseBody,
          lastError: errorMessage,
          updatedAt: attemptTime,
        })
        .where(eq(webhookDeliveries.id, delivery.id));

      telemetryRegistry.recordWebhookDelivery('failure', 1);
      logger.warn(
        { deliveryId: delivery.id, attempts: attempt, error: errorMessage },
        'Webhook delivery permanently failed -> dead_letter',
      );
      return false;
    }

    // Exponential backoff: 2^attempt * 10 seconds (10s, 20s, 40s, 80s...)
    const backoffSeconds = Math.pow(2, attempt) * 10;
    const nextRetryAt = new Date(Date.now() + backoffSeconds * 1000);

    await db
      .update(webhookDeliveries)
      .set({
        status: 'failed',
        attempts: attempt,
        lastAttemptAt: attemptTime,
        nextRetryAt,
        responseStatusCode: statusCode,
        responseBody,
        lastError: errorMessage,
        updatedAt: attemptTime,
      })
      .where(eq(webhookDeliveries.id, delivery.id));

    telemetryRegistry.recordWebhookDelivery('failure', 1);
    logger.warn(
      { deliveryId: delivery.id, attempt, backoffSeconds, nextRetryAt, error: errorMessage },
      'Webhook delivery attempt failed. Scheduled exponential backoff retry.',
    );
    return false;
  }

  /**
   * Polls and processes pending or failed deliveries that are ready for retry.
   */
  async processQueueBatch(limit = 10, customFetch?: typeof fetch): Promise<number> {
    const { db } = getDatabase();
    const now = new Date();

    const readyDeliveries = await db
      .select({ id: webhookDeliveries.id })
      .from(webhookDeliveries)
      .where(
        and(
          inArray(webhookDeliveries.status, ['pending', 'failed']),
          lte(webhookDeliveries.nextRetryAt, now),
        ),
      )
      .limit(limit);

    let processedCount = 0;
    for (const item of readyDeliveries) {
      await this.processDelivery(item.id, customFetch);
      processedCount++;
    }

    return processedCount;
  }

  /**
   * Starts periodic background delivery worker.
   */
  startWorker(intervalMs = 5000): void {
    if (this.isWorkerRunning) return;
    this.isWorkerRunning = true;

    this.workerTimer = setInterval(async () => {
      try {
        await this.processQueueBatch(10);
      } catch (err) {
        logger.error({ err }, 'Error in webhook queue worker tick');
      }
    }, intervalMs);

    logger.info({ intervalMs }, 'Webhook delivery queue worker started');
  }

  /**
   * Stops background delivery worker.
   */
  stopWorker(): void {
    if (this.workerTimer) {
      clearInterval(this.workerTimer);
      this.workerTimer = null;
    }
    this.isWorkerRunning = false;
    logger.info('Webhook delivery queue worker stopped');
  }
}

export const webhookQueueService = new WebhookQueueService();
