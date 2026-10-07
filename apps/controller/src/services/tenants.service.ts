import { eq } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { tenants } from './db/schema.js';
import { logger } from '@security-lab/logger';

export const DEFAULT_TENANT_ID = '00000000-0000-0000-0000-000000000000';

export interface CreateTenantInput {
  name: string;
  slug: string;
  plan?: string;
  settings?: Record<string, unknown>;
}

export interface TenantRecord {
  id: string;
  name: string;
  slug: string;
  plan: string;
  settings: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

export class TenantsService {
  async ensureDefaultTenant(): Promise<TenantRecord> {
    const { db } = getDatabase();
    if (!db) {
      return {
        id: DEFAULT_TENANT_ID,
        name: 'Default Organization',
        slug: 'default',
        plan: 'enterprise',
        settings: {},
        createdAt: new Date(),
        updatedAt: new Date(),
      };
    }

    const existing = await db
      .select()
      .from(tenants)
      .where(eq(tenants.id, DEFAULT_TENANT_ID))
      .limit(1);

    if (existing.length > 0) {
      return existing[0] as TenantRecord;
    }

    const [created] = await db
      .insert(tenants)
      .values({
        id: DEFAULT_TENANT_ID,
        name: 'Default Organization',
        slug: 'default',
        plan: 'enterprise',
        settings: {},
      })
      .returning();

    logger.info({ tenantId: DEFAULT_TENANT_ID }, 'Initialized default SaaS tenant');
    return created as TenantRecord;
  }

  async createTenant(input: CreateTenantInput): Promise<TenantRecord> {
    const { db } = getDatabase();
    if (!db) {
      throw new Error('Database connection not available');
    }

    const existing = await db
      .select()
      .from(tenants)
      .where(eq(tenants.slug, input.slug.toLowerCase().trim()))
      .limit(1);

    if (existing.length > 0) {
      throw new Error(`Tenant with slug "${input.slug}" already exists`);
    }

    const [created] = await db
      .insert(tenants)
      .values({
        name: input.name.trim(),
        slug: input.slug.toLowerCase().trim(),
        plan: input.plan || 'enterprise',
        settings: input.settings || {},
      })
      .returning();

    if (!created) {
      throw new Error('Failed to create tenant');
    }

    logger.info({ tenantId: created.id, slug: created.slug }, 'Created new SaaS tenant');
    return created as TenantRecord;
  }

  async getTenantById(id: string): Promise<TenantRecord | null> {
    const { db } = getDatabase();
    if (!db) return null;

    const [tenant] = await db
      .select()
      .from(tenants)
      .where(eq(tenants.id, id))
      .limit(1);

    return (tenant as TenantRecord) || null;
  }

  async getTenantBySlug(slug: string): Promise<TenantRecord | null> {
    const { db } = getDatabase();
    if (!db) return null;

    const [tenant] = await db
      .select()
      .from(tenants)
      .where(eq(tenants.slug, slug.toLowerCase().trim()))
      .limit(1);

    return (tenant as TenantRecord) || null;
  }

  async listTenants(): Promise<TenantRecord[]> {
    const { db } = getDatabase();
    if (!db) return [];

    const list = await db.select().from(tenants);
    return list as TenantRecord[];
  }
}

export const tenantsService = new TenantsService();
