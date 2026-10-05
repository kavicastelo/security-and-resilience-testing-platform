import { eq } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { targets } from './db/schema.js';
import {
  CreateTargetInput,
  Target,
  TargetScope,
  validateUrlAgainstScope,
  ScopeValidationResult,
  ScopeCheckOptions,
} from '@security-lab/domain';

export class TargetsService {
  async createTarget(input: CreateTargetInput): Promise<Target> {
    const { db } = getDatabase();

    const scope: TargetScope = {
      allowedHosts: input.allowedHosts,
      allowedPorts: input.allowedPorts || [80, 443],
      excludedPaths: input.excludedPaths || [],
      testing: {
        activeScanning: input.testing?.activeScanning ?? false,
        loadTesting: input.testing?.loadTesting ?? false,
        chaosTesting: input.testing?.chaosTesting ?? false,
      },
      limits: {
        maxRps: input.limits?.maxRps ?? 100,
        maxConcurrency: input.limits?.maxConcurrency ?? 20,
        maxDuration: input.limits?.maxDuration ?? '10m',
      },
    };

    // Pre-flight validation: base URL must conform to the declared allowed hosts and ports
    const baseUrlValidation = validateUrlAgainstScope(input.baseUrl, scope);
    if (!baseUrlValidation.valid) {
      throw new Error(
        `Target baseUrl "${input.baseUrl}" violates its own defined scope boundaries: ${baseUrlValidation.violations.join('; ')}`,
      );
    }

    const [inserted] = await db
      .insert(targets)
      .values({
        projectId: input.projectId,
        name: input.name,
        baseUrl: input.baseUrl,
        scope,
      })
      .returning();

    if (!inserted) {
      throw new Error('Failed to insert target');
    }

    return {
      id: inserted.id,
      projectId: inserted.projectId,
      name: inserted.name,
      baseUrl: inserted.baseUrl,
      scope: inserted.scope,
      createdAt: inserted.createdAt,
      updatedAt: inserted.updatedAt,
    };
  }

  async listTargetsByProject(projectId: string): Promise<Target[]> {
    const { db } = getDatabase();
    const rows = await db
      .select()
      .from(targets)
      .where(eq(targets.projectId, projectId))
      .orderBy(targets.name);

    return rows.map((r) => ({
      id: r.id,
      projectId: r.projectId,
      name: r.name,
      baseUrl: r.baseUrl,
      scope: r.scope,
      createdAt: r.createdAt,
      updatedAt: r.updatedAt,
    }));
  }

  async listAllTargets(): Promise<Target[]> {
    const { db } = getDatabase();
    const rows = await db.select().from(targets).orderBy(targets.name);
    return rows.map((r) => ({
      id: r.id,
      projectId: r.projectId,
      name: r.name,
      baseUrl: r.baseUrl,
      scope: r.scope,
      createdAt: r.createdAt,
      updatedAt: r.updatedAt,
    }));
  }

  async getTargetById(id: string): Promise<Target | null> {
    const { db } = getDatabase();
    const [row] = await db.select().from(targets).where(eq(targets.id, id));
    if (!row) return null;

    return {
      id: row.id,
      projectId: row.projectId,
      name: row.name,
      baseUrl: row.baseUrl,
      scope: row.scope,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  }

  async deleteTarget(id: string): Promise<boolean> {
    const { db } = getDatabase();
    const deleted = await db.delete(targets).where(eq(targets.id, id)).returning();
    return deleted.length > 0;
  }

  async validateCandidateUrl(
    targetId: string,
    candidateUrl: string,
    options: ScopeCheckOptions = {},
  ): Promise<ScopeValidationResult & { target?: Target }> {
    const target = await this.getTargetById(targetId);
    if (!target) {
      return {
        valid: false,
        violations: [`Target with ID "${targetId}" does not exist`],
      };
    }

    const validation = validateUrlAgainstScope(candidateUrl, target.scope, options);
    return {
      ...validation,
      target,
    };
  }
}

export const targetsService = new TargetsService();
