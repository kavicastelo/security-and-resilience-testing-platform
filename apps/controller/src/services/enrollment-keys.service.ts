import crypto from 'node:crypto';
import { eq, and, desc } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { tenantEnrollmentKeys, tenants } from './db/schema.js';
import {
  CreateTenantEnrollmentKeyRequest,
  TenantEnrollmentKeyResponse,
} from '@security-lab/contracts';
import { logger } from '@security-lab/logger';

export function hashEnrollmentKey(rawKey: string): string {
  return crypto.createHash('sha256').update(rawKey.trim()).digest('hex');
}

export interface ValidateKeyResult {
  valid: boolean;
  error?: string;
  errorCode?: string;
  tek?: typeof tenantEnrollmentKeys.$inferSelect;
}

export class EnrollmentKeysService {
  /**
   * Generates a new Tenant Enrollment Key (TEK) for an organization/tenant.
   * Generates a plaintext key once and stores only its SHA-256 hash.
   */
  async createEnrollmentKey(
    tenantId: string,
    input: CreateTenantEnrollmentKeyRequest,
  ): Promise<TenantEnrollmentKeyResponse> {
    const { db } = getDatabase();
    if (!db) throw new Error('Database unavailable');

    // 1. Validate tenant exists
    const [tenant] = await db
      .select()
      .from(tenants)
      .where(eq(tenants.id, tenantId))
      .limit(1);

    if (!tenant) {
      throw new Error(`Tenant "${tenantId}" not found`);
    }

    // 2. Generate cryptographically strong random token
    const randomHex = crypto.randomBytes(32).toString('hex');
    const slug = tenant.slug || 'tenant';
    const rawKey = `tek_${slug}_${randomHex}`;
    const keyHash = hashEnrollmentKey(rawKey);
    const keyPrefix = `${rawKey.slice(0, 16)}...`;

    const days = input.expiresInDays !== undefined ? input.expiresInDays : 30;
    const expiresAt = days > 0 ? new Date(Date.now() + days * 86400000) : null;

    const [created] = await db
      .insert(tenantEnrollmentKeys)
      .values({
        tenantId,
        name: input.name.trim(),
        keyHash,
        keyPrefix,
        maxUses: input.maxUses || null,
        usesCount: 0,
        expiresAt,
      })
      .returning();

    if (!created) {
      throw new Error('Failed to create tenant enrollment key');
    }

    logger.info(
      { tekId: created.id, tenantId, name: created.name, keyPrefix },
      'Generated new Tenant Enrollment Key',
    );

    return {
      id: created.id,
      tenantId: created.tenantId,
      name: created.name,
      keyPrefix: created.keyPrefix,
      key: rawKey, // Plaintext returned only once at creation
      maxUses: created.maxUses,
      usesCount: created.usesCount,
      expiresAt: created.expiresAt ? created.expiresAt.toISOString() : null,
      revokedAt: created.revokedAt ? created.revokedAt.toISOString() : null,
      createdAt: created.createdAt.toISOString(),
    };
  }

  /**
   * Lists enrollment keys for a tenant without revealing plaintext keys.
   */
  async listEnrollmentKeys(tenantId: string): Promise<TenantEnrollmentKeyResponse[]> {
    const { db } = getDatabase();
    if (!db) return [];

    const rows = await db
      .select()
      .from(tenantEnrollmentKeys)
      .where(eq(tenantEnrollmentKeys.tenantId, tenantId))
      .orderBy(desc(tenantEnrollmentKeys.createdAt));

    return rows.map((r) => ({
      id: r.id,
      tenantId: r.tenantId,
      name: r.name,
      keyPrefix: r.keyPrefix,
      maxUses: r.maxUses,
      usesCount: r.usesCount,
      expiresAt: r.expiresAt ? r.expiresAt.toISOString() : null,
      revokedAt: r.revokedAt ? r.revokedAt.toISOString() : null,
      createdAt: r.createdAt.toISOString(),
    }));
  }

  /**
   * Revokes an existing enrollment key immediately.
   */
  async revokeEnrollmentKey(tenantId: string, keyId: string): Promise<boolean> {
    const { db } = getDatabase();
    if (!db) return false;

    const [updated] = await db
      .update(tenantEnrollmentKeys)
      .set({
        revokedAt: new Date(),
        updatedAt: new Date(),
      })
      .where(
        and(
          eq(tenantEnrollmentKeys.tenantId, tenantId),
          eq(tenantEnrollmentKeys.id, keyId),
        ),
      )
      .returning();

    if (updated) {
      logger.info({ tekId: keyId, tenantId }, 'Tenant Enrollment Key revoked');
      return true;
    }
    return false;
  }

  /**
   * Validates an enrollment key, checking revocation, expiration, and usage limits.
   * Atomically increments the usage counter on success.
   */
  async validateAndConsumeEnrollmentKey(rawKey: string): Promise<ValidateKeyResult> {
    const { db } = getDatabase();
    if (!db || !rawKey) {
      return {
        valid: false,
        errorCode: 'INVALID_ENROLLMENT_KEY',
        error: 'Provided Tenant Enrollment Key is missing or invalid.',
      };
    }

    const keyHash = hashEnrollmentKey(rawKey);
    const [tek] = await db
      .select()
      .from(tenantEnrollmentKeys)
      .where(eq(tenantEnrollmentKeys.keyHash, keyHash))
      .limit(1);

    if (!tek) {
      return {
        valid: false,
        errorCode: 'INVALID_ENROLLMENT_KEY',
        error: 'Provided Tenant Enrollment Key is invalid or not registered.',
      };
    }

    if (tek.revokedAt) {
      return {
        valid: false,
        errorCode: 'ENROLLMENT_KEY_REVOKED',
        error: 'Provided Tenant Enrollment Key has been administratively revoked.',
      };
    }

    if (tek.expiresAt && new Date(tek.expiresAt) <= new Date()) {
      return {
        valid: false,
        errorCode: 'ENROLLMENT_KEY_EXPIRED',
        error: 'Provided Tenant Enrollment Key has expired.',
      };
    }

    if (tek.maxUses !== null && tek.usesCount >= tek.maxUses) {
      return {
        valid: false,
        errorCode: 'ENROLLMENT_KEY_EXHAUSTED',
        error: 'Provided Tenant Enrollment Key has reached its maximum allowed enrollments.',
      };
    }

    // Atomically increment usage
    await db
      .update(tenantEnrollmentKeys)
      .set({
        usesCount: tek.usesCount + 1,
        updatedAt: new Date(),
      })
      .where(eq(tenantEnrollmentKeys.id, tek.id));

    return {
      valid: true,
      tek,
    };
  }
}

export const enrollmentKeysService = new EnrollmentKeysService();
