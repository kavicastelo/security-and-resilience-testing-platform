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

import { isLocalHost, generateChallengeToken } from './target-verification.js';
import { encryptObject, decryptObject } from '@security-lab/crypto';

export class TargetsService {
  private mapRowToTarget(r: any): Target {
    const rawAuth = r.encryptedAuthData ?? r.encrypted_auth_data;
    return {
      id: r.id,
      projectId: r.projectId,
      name: r.name,
      baseUrl: r.baseUrl,
      scope: r.scope,
      verificationToken: r.verificationToken ?? null,
      verificationStatus: (r.verificationStatus as any) || 'PENDING',
      verifiedAt: r.verifiedAt ?? null,
      verificationMethod: (r.verificationMethod as any) ?? null,
      authConfigured: Boolean(rawAuth),
      authType: rawAuth?.type || (rawAuth ? 'ENCRYPTED' : undefined),
      createdAt: r.createdAt,
      updatedAt: r.updatedAt,
    };
  }

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

    let isLocal = false;
    try {
      isLocal = isLocalHost(new URL(input.baseUrl).hostname);
    } catch {
      isLocal = false;
    }

    const verificationToken = generateChallengeToken();
    const verificationStatus = isLocal ? 'VERIFIED' : 'PENDING';
    const verificationMethod = isLocal ? 'LOCAL_OVERRIDE' : null;
    const verifiedAt = isLocal ? new Date() : null;

    const rawAuth = input.authFlow;
    const encryptedAuthData = rawAuth ? encryptObject(rawAuth) : null;

    const [inserted] = await db
      .insert(targets)
      .values({
        tenantId: tenantId || DEFAULT_TENANT_ID,
        projectId: input.projectId,
        name: input.name,
        baseUrl: input.baseUrl,
        scope,
        verificationToken,
        verificationStatus,
        verificationMethod,
        verifiedAt,
        encryptedAuthData,
      })
      .returning();

    if (!inserted) {
      throw new Error('Failed to insert target');
    }

    return this.mapRowToTarget(inserted);
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

    return rows.map((r) => this.mapRowToTarget(r));
  }

  async listAllTargets(tenantId?: string): Promise<Target[]> {
    const { db } = getDatabase();
    const query = db.select().from(targets);
    const rows = tenantId
      ? await query.where(eq(targets.tenantId, tenantId)).orderBy(targets.name)
      : await query.orderBy(targets.name);
    return rows.map((r) => this.mapRowToTarget(r));
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

    return this.mapRowToTarget(row);
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
    if ((input as any).authFlow !== undefined) {
      updateValues.encryptedAuthData = (input as any).authFlow ? encryptObject((input as any).authFlow) : null;
    }

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

    return this.mapRowToTarget(updated);
  }

  async getDecryptedAuthData<T = unknown>(targetId: string, tenantId?: string): Promise<T | null> {
    const { db } = getDatabase();
    const conditions = [eq(targets.id, targetId)];
    if (tenantId) {
      conditions.push(eq(targets.tenantId, tenantId));
    }

    const [row] = await db
      .select({ encryptedAuthData: targets.encryptedAuthData })
      .from(targets)
      .where(and(...conditions))
      .limit(1);

    if (!row?.encryptedAuthData) return null;
    try {
      return decryptObject<T>(row.encryptedAuthData as any);
    } catch {
      return null;
    }
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
