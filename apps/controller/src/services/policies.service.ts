import { eq } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { policies } from './db/schema.js';
import { Policy, PolicyRule } from '@security-lab/domain';

export const ENTERPRISE_DEFAULT_POLICY: Policy = {
  id: '00000000-0000-0000-0000-000000000001',
  name: 'Enterprise Security Baseline Gate',
  description: 'Strict baseline policy enforcing zero critical vulnerabilities, limited high/medium findings, and P95 latency SLA compliance',
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
  isDefault?: boolean;
}

export class PoliciesService {
  async createPolicy(input: CreatePolicyInput): Promise<Policy> {
    const { db } = getDatabase();

    const [row] = await db
      .insert(policies)
      .values({
        id: input.id,
        name: input.name,
        description: input.description,
        rules: input.rules,
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
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  }

  async listPolicies(): Promise<Policy[]> {
    const { db } = getDatabase();
    const rows = await db.select().from(policies).orderBy(policies.createdAt);

    if (rows.length === 0) {
      return [ENTERPRISE_DEFAULT_POLICY];
    }

    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      description: r.description || undefined,
      rules: r.rules as PolicyRule[],
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
        createdAt: seeded.createdAt,
        updatedAt: seeded.updatedAt,
      };
    }

    return ENTERPRISE_DEFAULT_POLICY;
  }
}

export const policiesService = new PoliciesService();
