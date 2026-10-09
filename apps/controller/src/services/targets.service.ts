import { eq, and } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { targets, testRuns, projects } from './db/schema.js';
import {
  CreateTargetInput,
  Target,
  TargetScope,
  validateUrlAgainstScope,
  ScopeValidationResult,
  ScopeCheckOptions,
} from '@security-lab/domain';

import { DEFAULT_TENANT_ID } from './tenants.service.js';

export class TargetsService {
  async createTarget(input: CreateTargetInput, tenantId?: string): Promise<Target> {
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

    // Verify parent project exists and belongs to the caller's tenant
    if (tenantId) {
      const parentProject = await db
        .select()
        .from(projects)
        .where(and(eq(projects.id, input.projectId), eq(projects.tenantId, tenantId)))
        .limit(1);
      if (parentProject.length === 0) {
        throw new Error(`Project "${input.projectId}" not found or access denied`);
      }
    }

    const [inserted] = await db
      .insert(targets)
      .values({
        tenantId: tenantId || DEFAULT_TENANT_ID,
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

  async listTargetsByProject(projectId: string, tenantId?: string): Promise<Target[]> {
    const { db } = getDatabase();
    const conditions = [eq(targets.projectId, projectId)];
    if (tenantId) {
      conditions.push(eq(targets.tenantId, tenantId));
    }

    const rows = await db
      .select()
      .from(targets)
      .where(and(...conditions))
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

  async listAllTargets(tenantId?: string): Promise<Target[]> {
    const { db } = getDatabase();
    const query = db.select().from(targets);
    const rows = tenantId
      ? await query.where(eq(targets.tenantId, tenantId)).orderBy(targets.name)
      : await query.orderBy(targets.name);
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

  async getTargetById(id: string, tenantId?: string): Promise<Target | null> {
    const { db } = getDatabase();
    const conditions = [eq(targets.id, id)];
    if (tenantId) {
      conditions.push(eq(targets.tenantId, tenantId));
    }

    const [row] = await db
      .select()
      .from(targets)
      .where(and(...conditions))
      .limit(1);

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

  async updateTarget(
    id: string,
    input: {
      name?: string;
      baseUrl?: string;
      allowedHosts?: string[];
      allowedPorts?: number[];
      excludedPaths?: string[];
      testing?: Partial<TargetScope['testing']>;
      limits?: Partial<TargetScope['limits']>;
      scope?: Partial<TargetScope>;
    },
    tenantId?: string,
  ): Promise<Target | null> {
    const { db } = getDatabase();
    const existing = await this.getTargetById(id, tenantId);
    if (!existing) return null;

    const nestedScope = input.scope || {};

    const mergedScope: TargetScope = {
      allowedHosts: input.allowedHosts ?? nestedScope.allowedHosts ?? existing.scope.allowedHosts,
      allowedPorts: input.allowedPorts ?? nestedScope.allowedPorts ?? existing.scope.allowedPorts,
      excludedPaths: input.excludedPaths ?? nestedScope.excludedPaths ?? existing.scope.excludedPaths,
      testing: {
        activeScanning:
          input.testing?.activeScanning ??
          nestedScope.testing?.activeScanning ??
          existing.scope.testing.activeScanning,
        loadTesting:
          input.testing?.loadTesting ??
          nestedScope.testing?.loadTesting ??
          existing.scope.testing.loadTesting,
        chaosTesting:
          input.testing?.chaosTesting ??
          nestedScope.testing?.chaosTesting ??
          existing.scope.testing.chaosTesting,
      },
      limits: {
        maxRps: input.limits?.maxRps ?? nestedScope.limits?.maxRps ?? existing.scope.limits.maxRps,
        maxConcurrency:
          input.limits?.maxConcurrency ??
          nestedScope.limits?.maxConcurrency ??
          existing.scope.limits.maxConcurrency,
        maxDuration:
          input.limits?.maxDuration ??
          nestedScope.limits?.maxDuration ??
          existing.scope.limits.maxDuration,
      },
    };

    const targetUrl = input.baseUrl ?? existing.baseUrl;
    const baseUrlValidation = validateUrlAgainstScope(targetUrl, mergedScope);
    if (!baseUrlValidation.valid) {
      throw new Error(
        `Target baseUrl "${targetUrl}" violates defined scope boundaries: ${baseUrlValidation.violations.join('; ')}`,
      );
    }

    const updateValues: Record<string, unknown> = {
      scope: mergedScope,
      updatedAt: new Date(),
    };
    if (input.name !== undefined) updateValues.name = input.name;
    if (input.baseUrl !== undefined) updateValues.baseUrl = input.baseUrl;

    const updateConditions = [eq(targets.id, id)];
    if (tenantId) {
      updateConditions.push(eq(targets.tenantId, tenantId));
    }

    const [updated] = await db
      .update(targets)
      .set(updateValues)
      .where(and(...updateConditions))
      .returning();

    if (!updated) return null;

    return {
      id: updated.id,
      projectId: updated.projectId,
      name: updated.name,
      baseUrl: updated.baseUrl,
      scope: updated.scope,
      createdAt: updated.createdAt,
      updatedAt: updated.updatedAt,
    };
  }

  async deleteTarget(id: string, tenantId?: string): Promise<boolean> {
    const { db } = getDatabase();
    const existing = await this.getTargetById(id, tenantId);
    if (!existing) return false;

    // Cascade delete any associated test runs first to respect foreign key constraint
    await db.delete(testRuns).where(eq(testRuns.targetId, id));

    const deleteConditions = [eq(targets.id, id)];
    if (tenantId) {
      deleteConditions.push(eq(targets.tenantId, tenantId));
    }

    const deleted = await db.delete(targets).where(and(...deleteConditions)).returning();
    return deleted.length > 0;
  }

  async validateCandidateUrl(
    targetId: string,
    candidateUrl: string,
    options: ScopeCheckOptions = {},
    tenantId?: string,
  ): Promise<ScopeValidationResult & { target?: Target }> {
    const target = await this.getTargetById(targetId, tenantId);
    if (!target) {
      return {
        valid: false,
        violations: [`Target with ID "${targetId}" not found`],
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
