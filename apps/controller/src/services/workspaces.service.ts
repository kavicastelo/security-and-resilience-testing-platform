import { eq, and, desc } from 'drizzle-orm';
import { getDatabase } from './db.js';
import {
  workspaces,
  users,
  workspaceMemberships,
  apiKeys,
  auditEvents,
} from './db/schema.js';
import {
  Workspace,
  CreateWorkspaceInput,
  UpdateWorkspaceInput,
  User,
  CreateUserInput,
  WorkspaceMembership,
  AddWorkspaceMemberInput,
  ApiKey,
  CreateApiKeyInput,
  ApiKeyCreatedResponse,
  Role,
} from '@security-lab/contracts';
import {
  generateApiKey,
  hashPassword,
  DEFAULT_WORKSPACE_ID,
} from './auth-token.service.js';

export class WorkspacesService {
  async createWorkspace(input: CreateWorkspaceInput, actorId?: string): Promise<Workspace> {
    const { db } = getDatabase();
    const slug = input.slug || input.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');

    const [inserted] = await db
      .insert(workspaces)
      .values({
        name: input.name,
        slug,
        description: input.description,
      })
      .returning();

    if (!inserted) {
      throw new Error('Failed to create workspace');
    }

    // If an actorId is supplied, add them as workspace ADMIN
    if (actorId && actorId !== 'system' && actorId !== 'bypass-test-key') {
      try {
        await db.insert(workspaceMemberships).values({
          workspaceId: inserted.id,
          userId: actorId,
          role: 'ADMIN',
        });
      } catch {
        // User may be a system user not in users table
      }
    }

    await this.recordAuditEvent({
      workspaceId: inserted.id,
      actorId: actorId || 'system',
      eventType: 'workspace.created',
      details: { name: inserted.name, slug: inserted.slug },
    });

    return inserted;
  }

  async listWorkspaces(userId?: string, userRole?: Role): Promise<Workspace[]> {
    const { db } = getDatabase();

    // System admin sees all workspaces
    if (!userId || userRole === 'ADMIN') {
      return db.select().from(workspaces).orderBy(workspaces.name);
    }

    // Non-admin sees workspaces they are a member of
    const memberships = await db
      .select({ workspace: workspaces })
      .from(workspaceMemberships)
      .innerJoin(workspaces, eq(workspaceMemberships.workspaceId, workspaces.id))
      .where(eq(workspaceMemberships.userId, userId))
      .orderBy(workspaces.name);

    return memberships.map((m) => m.workspace);
  }

  async getWorkspaceById(id: string): Promise<Workspace | null> {
    const { db } = getDatabase();
    const [row] = await db.select().from(workspaces).where(eq(workspaces.id, id));
    return row || null;
  }

  async updateWorkspace(id: string, input: UpdateWorkspaceInput, actorId?: string): Promise<Workspace | null> {
    const { db } = getDatabase();
    const updateValues: Record<string, unknown> = {
      updatedAt: new Date(),
    };

    if (input.name !== undefined) updateValues.name = input.name;
    if (input.description !== undefined) updateValues.description = input.description;

    const [updated] = await db
      .update(workspaces)
      .set(updateValues)
      .where(eq(workspaces.id, id))
      .returning();

    if (updated) {
      await this.recordAuditEvent({
        workspaceId: id,
        actorId: actorId || 'system',
        eventType: 'workspace.updated',
        details: input,
      });
    }

    return updated || null;
  }

  async deleteWorkspace(id: string, actorId?: string): Promise<boolean> {
    const { db } = getDatabase();
    if (id === DEFAULT_WORKSPACE_ID) {
      throw new Error('Cannot delete default system workspace');
    }

    const deleted = await db.delete(workspaces).where(eq(workspaces.id, id)).returning();
    if (deleted.length > 0) {
      await this.recordAuditEvent({
        workspaceId: id,
        actorId: actorId || 'system',
        eventType: 'workspace.deleted',
        details: { workspaceId: id },
      });
      return true;
    }
    return false;
  }

  // --- Users & Memberships ---

  async createUser(input: CreateUserInput, actorId?: string): Promise<User> {
    const { db } = getDatabase();
    const passwordHash = input.password ? hashPassword(input.password) : null;

    const [user] = await db
      .insert(users)
      .values({
        email: input.email.toLowerCase(),
        name: input.name,
        passwordHash,
      })
      .returning();

    if (!user) {
      throw new Error('Failed to create user');
    }

    const targetWorkspaceId = input.workspaceId || DEFAULT_WORKSPACE_ID;
    await db.insert(workspaceMemberships).values({
      workspaceId: targetWorkspaceId,
      userId: user.id,
      role: input.role || 'ENGINEER',
    });

    await this.recordAuditEvent({
      workspaceId: targetWorkspaceId,
      actorId: actorId || 'system',
      eventType: 'user.created',
      details: { userId: user.id, email: user.email, role: input.role || 'ENGINEER' },
    });

    return {
      id: user.id,
      email: user.email,
      name: user.name,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }

  async findUserByEmail(email: string): Promise<(typeof users.$inferSelect) | null> {
    const { db } = getDatabase();
    const [user] = await db.select().from(users).where(eq(users.email, email.toLowerCase()));
    return user || null;
  }

  async findUserById(id: string): Promise<User | null> {
    const { db } = getDatabase();
    const [user] = await db.select().from(users).where(eq(users.id, id));
    if (!user) return null;
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }

  async addMember(workspaceId: string, input: AddWorkspaceMemberInput, actorId?: string): Promise<WorkspaceMembership> {
    const { db } = getDatabase();
    let targetUserId = input.userId;

    if (!targetUserId && input.email) {
      const existing = await this.findUserByEmail(input.email);
      if (existing) {
        targetUserId = existing.id;
      } else {
        const newUser = await this.createUser({
          email: input.email,
          name: input.email.split('@')[0] || 'User',
          role: input.role,
          workspaceId,
        });
        targetUserId = newUser.id;
      }
    }

    if (!targetUserId) {
      throw new Error('Either userId or email must be provided to add a member');
    }

    const [membership] = await db
      .insert(workspaceMemberships)
      .values({
        workspaceId,
        userId: targetUserId,
        role: input.role,
      })
      .onConflictDoUpdate({
        target: [workspaceMemberships.workspaceId, workspaceMemberships.userId],
        set: { role: input.role, updatedAt: new Date() },
      })
      .returning();

    await this.recordAuditEvent({
      workspaceId,
      actorId: actorId || 'system',
      eventType: 'workspace.member_added',
      details: { userId: targetUserId, role: input.role },
    });

    if (!membership) {
      throw new Error('Failed to create or update workspace membership');
    }

    return membership;
  }

  async listMembers(workspaceId: string): Promise<(WorkspaceMembership & { user: User })[]> {
    const { db } = getDatabase();
    const rows = await db
      .select({
        membership: workspaceMemberships,
        user: users,
      })
      .from(workspaceMemberships)
      .innerJoin(users, eq(workspaceMemberships.userId, users.id))
      .where(eq(workspaceMemberships.workspaceId, workspaceId));

    return rows.map((r) => ({
      ...r.membership,
      user: {
        id: r.user.id,
        email: r.user.email,
        name: r.user.name,
        createdAt: r.user.createdAt,
        updatedAt: r.user.updatedAt,
      },
    }));
  }

  async removeMember(workspaceId: string, userId: string, actorId?: string): Promise<boolean> {
    const { db } = getDatabase();
    const deleted = await db
      .delete(workspaceMemberships)
      .where(and(eq(workspaceMemberships.workspaceId, workspaceId), eq(workspaceMemberships.userId, userId)))
      .returning();

    if (deleted.length > 0) {
      await this.recordAuditEvent({
        workspaceId,
        actorId: actorId || 'system',
        eventType: 'workspace.member_removed',
        details: { userId },
      });
      return true;
    }
    return false;
  }

  async getUserRoleInWorkspace(workspaceId: string, userId: string): Promise<Role | null> {
    const { db } = getDatabase();
    const [row] = await db
      .select({ role: workspaceMemberships.role })
      .from(workspaceMemberships)
      .where(and(eq(workspaceMemberships.workspaceId, workspaceId), eq(workspaceMemberships.userId, userId)));
    return (row?.role as Role) || null;
  }

  // --- API Keys ---

  async createApiKey(workspaceId: string, input: CreateApiKeyInput, actorId?: string): Promise<ApiKeyCreatedResponse> {
    const { db } = getDatabase();
    const { secretKey, keyPrefix, keyHash } = generateApiKey();

    const expiresAt = input.expiresInDays
      ? new Date(Date.now() + input.expiresInDays * 24 * 3600 * 1000)
      : null;

    const [apiKey] = await db
      .insert(apiKeys)
      .values({
        workspaceId,
        userId: input.userId,
        name: input.name,
        keyHash,
        keyPrefix,
        role: input.role,
        expiresAt,
      })
      .returning();

    if (!apiKey) {
      throw new Error('Failed to create API key');
    }

    await this.recordAuditEvent({
      workspaceId,
      actorId: actorId || 'system',
      eventType: 'api_key.created',
      details: { keyId: apiKey.id, name: apiKey.name, role: apiKey.role },
    });

    return {
      apiKey,
      secretKey,
    };
  }

  async listApiKeys(workspaceId: string): Promise<ApiKey[]> {
    const { db } = getDatabase();
    return db
      .select()
      .from(apiKeys)
      .where(and(eq(apiKeys.workspaceId, workspaceId)))
      .orderBy(desc(apiKeys.createdAt));
  }

  async revokeApiKey(workspaceId: string, keyId: string, actorId?: string): Promise<boolean> {
    const { db } = getDatabase();
    const [revoked] = await db
      .update(apiKeys)
      .set({ revokedAt: new Date(), updatedAt: new Date() })
      .where(and(eq(apiKeys.workspaceId, workspaceId), eq(apiKeys.id, keyId)))
      .returning();

    if (revoked) {
      await this.recordAuditEvent({
        workspaceId,
        actorId: actorId || 'system',
        eventType: 'api_key.revoked',
        details: { keyId },
      });
      return true;
    }
    return false;
  }

  async findApiKeyByHash(keyHash: string): Promise<ApiKey | null> {
    const { db } = getDatabase();
    const [row] = await db
      .select()
      .from(apiKeys)
      .where(eq(apiKeys.keyHash, keyHash));

    if (!row) return null;
    if (row.revokedAt) return null;
    if (row.expiresAt && row.expiresAt < new Date()) return null;

    // Update lastUsedAt asynchronously
    db.update(apiKeys)
      .set({ lastUsedAt: new Date() })
      .where(eq(apiKeys.id, row.id))
      .catch(() => {});

    return row;
  }

  // --- Audit Events ---

  async recordAuditEvent(input: {
    workspaceId?: string;
    actorId: string;
    eventType: string;
    details?: Record<string, unknown>;
    ipAddress?: string;
  }): Promise<void> {
    try {
      const { db } = getDatabase();
      await db.insert(auditEvents).values({
        workspaceId: input.workspaceId || DEFAULT_WORKSPACE_ID,
        actorId: input.actorId,
        eventType: input.eventType,
        details: input.details || {},
        ipAddress: input.ipAddress,
      });
    } catch (_err) {
      // Non-blocking for primary flows
    }
  }

  async listAuditEvents(workspaceId?: string, limit = 50): Promise<(typeof auditEvents.$inferSelect)[]> {
    const { db } = getDatabase();
    const query = db.select().from(auditEvents);
    if (workspaceId && workspaceId !== DEFAULT_WORKSPACE_ID) {
      return query
        .where(eq(auditEvents.workspaceId, workspaceId))
        .orderBy(desc(auditEvents.createdAt))
        .limit(limit);
    }
    return query.orderBy(desc(auditEvents.createdAt)).limit(limit);
  }
}

export const workspacesService = new WorkspacesService();
