import { eq, and } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { projects } from './db/schema.js';
import { CreateProjectInput, Project } from '@security-lab/domain';
import { DEFAULT_TENANT_ID } from './tenants.service.js';
import { DEFAULT_WORKSPACE_ID } from './auth-token.service.js';

export class ProjectsService {
  async createProject(input: CreateProjectInput, tenantId?: string, workspaceId?: string): Promise<Project> {
    const { db } = getDatabase();
    const [inserted] = await db
      .insert(projects)
      .values({
        tenantId: tenantId || DEFAULT_TENANT_ID,
        workspaceId: workspaceId || DEFAULT_WORKSPACE_ID,
        name: input.name,
        description: input.description,
      })
      .returning();

    if (!inserted) {
      throw new Error('Failed to insert project');
    }

    return {
      id: inserted.id,
      name: inserted.name,
      description: inserted.description ?? undefined,
      createdAt: inserted.createdAt,
      updatedAt: inserted.updatedAt,
    };
  }

  async listProjects(tenantId?: string, workspaceId?: string): Promise<Project[]> {
    const { db } = getDatabase();
    const query = db.select().from(projects);
    const conditions = [];
    if (tenantId) conditions.push(eq(projects.tenantId, tenantId));
    if (workspaceId) conditions.push(eq(projects.workspaceId, workspaceId));

    const rows = conditions.length > 0
      ? await query.where(and(...conditions)).orderBy(projects.name)
      : await query.orderBy(projects.name);

    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      description: r.description ?? undefined,
      createdAt: r.createdAt,
      updatedAt: r.updatedAt,
    }));
  }

  async getProjectById(id: string, tenantId?: string, workspaceId?: string): Promise<Project | null> {
    const { db } = getDatabase();
    const conditions = [eq(projects.id, id)];
    if (tenantId) conditions.push(eq(projects.tenantId, tenantId));
    if (workspaceId) conditions.push(eq(projects.workspaceId, workspaceId));

    const [row] = await db.select().from(projects).where(and(...conditions));
    if (!row) return null;
    return {
      id: row.id,
      name: row.name,
      description: row.description ?? undefined,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  }

  async updateProject(id: string, input: Partial<CreateProjectInput>, tenantId?: string, workspaceId?: string): Promise<Project | null> {
    const { db } = getDatabase();
    const updateValues: Record<string, unknown> = {
      updatedAt: new Date(),
    };

    if (input.name !== undefined) updateValues.name = input.name;
    if (input.description !== undefined) updateValues.description = input.description;

    const conditions = [eq(projects.id, id)];
    if (tenantId) conditions.push(eq(projects.tenantId, tenantId));
    if (workspaceId) conditions.push(eq(projects.workspaceId, workspaceId));

    const [updated] = await db
      .update(projects)
      .set(updateValues)
      .where(and(...conditions))
      .returning();

    if (!updated) return null;

    return {
      id: updated.id,
      name: updated.name,
      description: updated.description ?? undefined,
      createdAt: updated.createdAt,
      updatedAt: updated.updatedAt,
    };
  }

  async deleteProject(id: string, tenantId?: string, workspaceId?: string): Promise<boolean> {
    const { db } = getDatabase();
    const conditions = [eq(projects.id, id)];
    if (tenantId) conditions.push(eq(projects.tenantId, tenantId));
    if (workspaceId) conditions.push(eq(projects.workspaceId, workspaceId));

    const deleted = await db.delete(projects).where(and(...conditions)).returning();
    return deleted.length > 0;
  }
}

export const projectsService = new ProjectsService();
