import { eq, desc, and, sql } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { agentAuditEvents } from './db/schema.js';
import { AgentAuditEvent } from '@security-lab/contracts';
import { logger } from '@security-lab/logger';

export const REDACTED_PLACEHOLDER = '***REDACTED***';

export const agentAuditMetrics = {
  audit_events_written_total: 0,
  audit_events_by_type: {} as Record<string, number>,
  audit_scrubbed_fields_total: 0,
};

/**
 * Checks if a key name matches any known sensitive credential patterns (Rule 17).
 */
export function isSensitiveField(key: string): boolean {
  if (!key || typeof key !== 'string') return false;
  const lower = key.toLowerCase();

  // Exact matches
  if (['token', 'secret', 'password', 'key', 'authorization'].includes(lower)) {
    return true;
  }

  // Common substring matches
  if (
    lower.includes('token') ||
    lower.includes('secret') ||
    lower.includes('password') ||
    lower.includes('authorization') ||
    lower.includes('auth_header') ||
    lower.includes('bearer')
  ) {
    return true;
  }

  // Key-specific compound patterns
  if (
    lower.includes('api_key') ||
    lower.includes('apikey') ||
    lower.includes('private_key') ||
    lower.includes('secret_key') ||
    lower.includes('access_key') ||
    lower.endsWith('key') ||
    lower.startsWith('key_') ||
    lower.startsWith('key-')
  ) {
    return true;
  }

  return false;
}

/**
 * Checks if a string value appears to be a raw secret, credential, or Bearer token (Rule 17).
 */
export function isSensitiveValue(value: string): boolean {
  if (!value || typeof value !== 'string') return false;
  const trimmed = value.trim();
  if (trimmed.length < 8) return false;
  if (/^Bearer\s+[A-Za-z0-9._-]+$/i.test(trimmed)) return true;
  if (/^tek_[a-z0-9_-]+/i.test(trimmed)) return true;
  if (/^agt_sec_[a-z0-9_-]+/i.test(trimmed)) return true;
  return false;
}

/**
 * Recursively scrubs all sensitive fields and values from an object, array, or primitive.
 * Safe against circular references.
 */
export function scrubSecrets(data: unknown, seen = new WeakSet<object>()): unknown {
  if (data === null || data === undefined) return data;

  if (typeof data === 'string') {
    if (isSensitiveValue(data)) {
      agentAuditMetrics.audit_scrubbed_fields_total++;
      return REDACTED_PLACEHOLDER;
    }
    return data;
  }

  if (data instanceof Date) {
    return data.toISOString();
  }

  if (data instanceof Error) {
    return { name: data.name, message: data.message };
  }

  if (typeof data !== 'object') {
    return data;
  }

  if (seen.has(data)) {
    return '[CIRCULAR]';
  }
  seen.add(data);

  if (Array.isArray(data)) {
    return data.map((item) => scrubSecrets(item, seen));
  }

  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data)) {
    if (isSensitiveField(key)) {
      result[key] = REDACTED_PLACEHOLDER;
      agentAuditMetrics.audit_scrubbed_fields_total++;
    } else {
      result[key] = scrubSecrets(value, seen);
    }
  }

  return result;
}

export interface RecordAuditEventInput {
  tenantId: string;
  agentId?: string | null;
  eventType: string;
  actorType: 'agent' | 'admin' | 'system';
  actorId: string;
  metadata?: Record<string, unknown>;
  ipAddress?: string | null;
}

export interface GetAuditEventsOptions {
  tenantId: string;
  agentId?: string;
  eventType?: string;
  limit?: number;
  offset?: number;
}

export class AgentAuditService {
  /**
   * Sanitizes arbitrary metadata ensuring zero secret leakage (Rule 17).
   */
  sanitizeMetadata(metadata: unknown): Record<string, unknown> {
    const scrubbed = scrubSecrets(metadata || {});
    if (typeof scrubbed === 'object' && scrubbed !== null && !Array.isArray(scrubbed)) {
      return scrubbed as Record<string, unknown>;
    }
    return { data: scrubbed };
  }

  /**
   * Asynchronously records an immutable audit event (Rule 20).
   * Catches errors internally so callers are never blocked or crashed by audit logging failures.
   */
  async recordAuditEvent(input: RecordAuditEventInput): Promise<AgentAuditEvent | null> {
    try {
      const { db } = getDatabase();
      if (!db) {
        logger.warn('Database unavailable; skipping audit event persistence');
        return null;
      }

      const sanitizedMetadata = (scrubSecrets(input.metadata || {}) as Record<string, unknown>) || {};

      const [inserted] = await db
        .insert(agentAuditEvents)
        .values({
          tenantId: input.tenantId,
          agentId: input.agentId || null,
          eventType: input.eventType,
          actorType: input.actorType,
          actorId: input.actorId,
          metadata: sanitizedMetadata,
          ipAddress: input.ipAddress || null,
        })
        .returning();

      if (!inserted) return null;

      agentAuditMetrics.audit_events_written_total++;
      agentAuditMetrics.audit_events_by_type[input.eventType] =
        (agentAuditMetrics.audit_events_by_type[input.eventType] || 0) + 1;

      return this.mapToDto(inserted);
    } catch (err: unknown) {
      logger.error({ err, eventType: input.eventType, tenantId: input.tenantId, agentId: input.agentId }, 'Failed to record agent audit event');
      return null;
    }
  }

  /**
   * Overloaded helper for recording audit events with positional arguments.
   */
  async record(
    tenantId: string,
    eventType: string,
    actorType: 'agent' | 'admin' | 'system',
    actorId: string,
    metadata?: Record<string, unknown>,
    ipAddress?: string | null,
    agentId?: string | null,
  ): Promise<AgentAuditEvent | null> {
    return this.recordAuditEvent({
      tenantId,
      eventType,
      actorType,
      actorId,
      metadata,
      ipAddress,
      agentId,
    });
  }

  /**
   * Retrieves paginated audit events strictly scoped to a tenant and optionally an agent.
   */
  async getAuditEvents(options: GetAuditEventsOptions): Promise<{ events: AgentAuditEvent[]; total: number }> {
    const { db } = getDatabase();
    if (!db) return { events: [], total: 0 };

    const conditions = [eq(agentAuditEvents.tenantId, options.tenantId)];

    if (options.agentId) {
      conditions.push(eq(agentAuditEvents.agentId, options.agentId));
    }

    if (options.eventType) {
      conditions.push(eq(agentAuditEvents.eventType, options.eventType));
    }

    const whereClause = and(...conditions);

    const [countRow] = await db
      .select({ count: sql<number>`count(*)::int` })
      .from(agentAuditEvents)
      .where(whereClause);

    const total = countRow ? Number(countRow.count) : 0;

    const limit = options.limit ?? 50;
    const offset = options.offset ?? 0;

    const rows = await db
      .select()
      .from(agentAuditEvents)
      .where(whereClause)
      .orderBy(desc(agentAuditEvents.createdAt))
      .limit(limit)
      .offset(offset);

    return {
      events: rows.map((r) => this.mapToDto(r)),
      total,
    };
  }

  /**
   * Returns current telemetry and observability metrics for audit events.
   */
  getMetrics() {
    return {
      eventsWrittenTotal: agentAuditMetrics.audit_events_written_total,
      eventsByType: { ...agentAuditMetrics.audit_events_by_type },
      scrubbedFieldsTotal: agentAuditMetrics.audit_scrubbed_fields_total,
    };
  }

  /**
   * Maps database entity to contract DTO.
   */
  private mapToDto(row: typeof agentAuditEvents.$inferSelect): AgentAuditEvent {
    return {
      id: row.id,
      tenantId: row.tenantId,
      agentId: row.agentId,
      eventType: row.eventType,
      actorType: row.actorType as 'agent' | 'admin' | 'system',
      actorId: row.actorId,
      metadata: (row.metadata as Record<string, unknown>) || {},
      ipAddress: row.ipAddress,
      createdAt: row.createdAt.toISOString(),
    };
  }
}

export const agentAuditService = new AgentAuditService();
