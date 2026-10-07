import { eq } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { policies } from './db/schema.js';
import { Policy, PolicyRule, PolicyWaiver } from '@security-lab/domain';

export const ENTERPRISE_DEFAULT_POLICY: Policy = {
  id: '00000000-0000-0000-0000-000000000001',
  name: 'Enterprise Security Baseline Gate',
  description: 'Strict baseline policy enforcing zero critical vulnerabilities, limited high/medium findings, and P95 latency SLA compliance',
  requiredProfiles: [],
  waivers: [],
  rules: [
    {
      id: 'rule-zero-critical',
      name: 'Zero Critical Vulnerabilities',
      description: 'Releases are immediately blocked if any critical vulnerabilities are detected',
      condition: {
        maxAllowedSeverity: 'high',
      },
      action: 'block_release',
    },
    {
      id: 'rule-high-threshold',
      name: 'Maximum High Severity Limit',
      description: 'No more than 2 high-severity findings permitted without explicit approval',
      condition: {
        maxCountBySeverity: {
          high: 2,
        },
      },
      action: 'warn',
    },
    {
      id: 'rule-latency-sla',
      name: 'Production Response Latency SLA',
      description: 'P95 response latency under load must not exceed 500ms',
      condition: {
        maxP95LatencyMs: 500,
      },
      action: 'block_release',
    },
  ],
  createdAt: new Date(),
  updatedAt: new Date(),
};

export interface CreatePolicyInput {
  id?: string;
  name: string;
  description?: string;
  rules: PolicyRule[];
  requiredProfiles?: string[];
  waivers?: PolicyWaiver[];
  isDefault?: boolean;
}

import { DEFAULT_TENANT_ID } from './tenants.service.js';

export class PoliciesService {
  async createPolicy(input: CreatePolicyInput, tenantId?: string): Promise<Policy> {
    const { db } = getDatabase();

    const [row] = await db
      .insert(policies)
      .values({
        id: input.id,
        tenantId: tenantId || DEFAULT_TENANT_ID,
        name: input.name,
        description: input.description,
        rules: input.rules,
        requiredProfiles: input.requiredProfiles || [],
        waivers: input.waivers || [],
        isDefault: input.isDefault ?? false,
      })
      .returning();

    if (!row) {
      throw new Error('Failed to create policy');
    }

    return {
      id: row.id,
      name: row.name,
      description: row.description || undefined,
      rules: row.rules as PolicyRule[],
      requiredProfiles: (row.requiredProfiles as string[]) || [],
      waivers: (row.waivers as PolicyWaiver[]) || [],
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  }

  async listPolicies(tenantId?: string): Promise<Policy[]> {
    const { db } = getDatabase();
    const query = db.select().from(policies);
    const rows = tenantId
      ? await query.where(eq(policies.tenantId, tenantId)).orderBy(policies.createdAt)
      : await query.orderBy(policies.createdAt);

    if (rows.length === 0) {
      return [ENTERPRISE_DEFAULT_POLICY];
    }

    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      description: r.description || undefined,
      rules: r.rules as PolicyRule[],
      requiredProfiles: (r.requiredProfiles as string[]) || [],
      waivers: (r.waivers as PolicyWaiver[]) || [],
      createdAt: r.createdAt,
      updatedAt: r.updatedAt,
    }));
  }

  async getPolicyById(id: string): Promise<Policy | null> {
    const { db } = getDatabase();
    const [row] = await db.select().from(policies).where(eq(policies.id, id)).limit(1);

    if (row) {
      return {
        id: row.id,
        name: row.name,
        description: row.description || undefined,
        rules: row.rules as PolicyRule[],
        requiredProfiles: (row.requiredProfiles as string[]) || [],
        waivers: (row.waivers as PolicyWaiver[]) || [],
        createdAt: row.createdAt,
        updatedAt: row.updatedAt,
      };
    }

    if (id === ENTERPRISE_DEFAULT_POLICY.id) {
      return this.getDefaultPolicy();
    }

    return null;
  }

  async getDefaultPolicy(): Promise<Policy> {
    const { db } = getDatabase();
    const [row] = await db.select().from(policies).where(eq(policies.isDefault, true)).limit(1);

    if (row) {
      return {
        id: row.id,
        name: row.name,
        description: row.description || undefined,
        rules: row.rules as PolicyRule[],
        requiredProfiles: (row.requiredProfiles as string[]) || [],
        waivers: (row.waivers as PolicyWaiver[]) || [],
        createdAt: row.createdAt,
        updatedAt: row.updatedAt,
      };
    }

    // Seed default policy into database so foreign keys can safely reference it
    try {
      const [inserted] = await db
        .insert(policies)
        .values({
          id: ENTERPRISE_DEFAULT_POLICY.id,
          name: ENTERPRISE_DEFAULT_POLICY.name,
          description: ENTERPRISE_DEFAULT_POLICY.description,
          rules: ENTERPRISE_DEFAULT_POLICY.rules,
          requiredProfiles: ENTERPRISE_DEFAULT_POLICY.requiredProfiles || [],
          waivers: ENTERPRISE_DEFAULT_POLICY.waivers || [],
          isDefault: true,
        })
        .onConflictDoNothing()
        .returning();

      if (inserted) {
        return {
          id: inserted.id,
          name: inserted.name,
          description: inserted.description || undefined,
          rules: inserted.rules as PolicyRule[],
          requiredProfiles: (inserted.requiredProfiles as string[]) || [],
          waivers: (inserted.waivers as PolicyWaiver[]) || [],
          createdAt: inserted.createdAt,
          updatedAt: inserted.updatedAt,
        };
      }
    } catch {
      // Fallback if already inserted or transient error
    }

    const [seeded] = await db.select().from(policies).where(eq(policies.id, ENTERPRISE_DEFAULT_POLICY.id)).limit(1);
    if (seeded) {
      return {
        id: seeded.id,
        name: seeded.name,
        description: seeded.description || undefined,
        rules: seeded.rules as PolicyRule[],
        requiredProfiles: (seeded.requiredProfiles as string[]) || [],
        waivers: (seeded.waivers as PolicyWaiver[]) || [],
        createdAt: seeded.createdAt,
        updatedAt: seeded.updatedAt,
      };
    }

    return ENTERPRISE_DEFAULT_POLICY;
  }

  async updatePolicy(
    id: string,
    input: {
      name?: string;
      description?: string;
      rules?: PolicyRule[];
      requiredProfiles?: string[];
      waivers?: PolicyWaiver[];
    },
  ): Promise<Policy | null> {
    const { db } = getDatabase();
    if (id === ENTERPRISE_DEFAULT_POLICY.id) {
      throw new Error('Cannot modify the enterprise baseline default policy');
    }

    const updateValues: Record<string, unknown> = {
      updatedAt: new Date(),
    };
    if (input.name !== undefined) updateValues.name = input.name;
    if (input.description !== undefined) updateValues.description = input.description;
    if (input.rules !== undefined) updateValues.rules = input.rules;
    if (input.requiredProfiles !== undefined) updateValues.requiredProfiles = input.requiredProfiles;
    if (input.waivers !== undefined) updateValues.waivers = input.waivers;

    const [updated] = await db
      .update(policies)
      .set(updateValues)
      .where(eq(policies.id, id))
      .returning();

    if (!updated) return null;

    return {
      id: updated.id,
      name: updated.name,
      description: updated.description || undefined,
      rules: updated.rules as PolicyRule[],
      requiredProfiles: (updated.requiredProfiles as string[]) || [],
      waivers: (updated.waivers as PolicyWaiver[]) || [],
      createdAt: updated.createdAt,
      updatedAt: updated.updatedAt,
    };
  }

  async addWaiver(policyId: string | undefined, waiver: PolicyWaiver): Promise<Policy> {
    const targetPolicy = policyId ? await this.getPolicyById(policyId) : await this.getDefaultPolicy();
    if (!targetPolicy) {
      throw new Error(`Policy "${policyId}" not found`);
    }

    const existingWaivers = targetPolicy.waivers || [];
    const updatedWaivers = [
      ...existingWaivers.filter((w) => w.fingerprint !== waiver.fingerprint),
      waiver,
    ];

    if (targetPolicy.id === ENTERPRISE_DEFAULT_POLICY.id) {
      const cloned = await this.createPolicy({
        name: 'Enterprise Security Gate (Active Waivers)',
        description: 'Cloned from baseline policy with customized finding waivers',
        rules: targetPolicy.rules,
        requiredProfiles: targetPolicy.requiredProfiles,
        waivers: updatedWaivers,
        isDefault: true,
      });
      return cloned;
    }

    const updated = await this.updatePolicy(targetPolicy.id, { waivers: updatedWaivers });
    return updated!;
  }

  async deletePolicy(id: string): Promise<boolean> {
    const { db } = getDatabase();
    if (id === ENTERPRISE_DEFAULT_POLICY.id) {
      throw new Error('Cannot delete the enterprise baseline default policy');
    }

    const [existing] = await db.select().from(policies).where(eq(policies.id, id)).limit(1);
    if (!existing) return false;
    if (existing.isDefault) {
      throw new Error('Cannot delete a default policy');
    }

    const deleted = await db.delete(policies).where(eq(policies.id, id)).returning();
    return deleted.length > 0;
  }
}

export const policiesService = new PoliciesService();
