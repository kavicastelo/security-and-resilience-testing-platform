import { eq } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { projects } from './db/schema.js';
import { CreateProjectInput, Project } from '@security-lab/domain';

export class ProjectsService {
  async createProject(input: CreateProjectInput): Promise<Project> {
    const { db } = getDatabase();
    const [inserted] = await db
      .insert(projects)
      .values({
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

  async listProjects(): Promise<Project[]> {
    const { db } = getDatabase();
    const rows = await db.select().from(projects).orderBy(projects.name);
    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      description: r.description ?? undefined,
      createdAt: r.createdAt,
      updatedAt: r.updatedAt,
    }));
  }

  async getProjectById(id: string): Promise<Project | null> {
    const { db } = getDatabase();
    const [row] = await db.select().from(projects).where(eq(projects.id, id));
    if (!row) return null;
    return {
      id: row.id,
      name: row.name,
      description: row.description ?? undefined,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  }

  async updateProject(id: string, input: Partial<CreateProjectInput>): Promise<Project | null> {
    const { db } = getDatabase();
    const updateValues: Record<string, unknown> = {
      updatedAt: new Date(),
    };

    if (input.name !== undefined) updateValues.name = input.name;
    if (input.description !== undefined) updateValues.description = input.description;

    const [updated] = await db
      .update(projects)
      .set(updateValues)
      .where(eq(projects.id, id))
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

  async deleteProject(id: string): Promise<boolean> {
    const { db } = getDatabase();
    const deleted = await db.delete(projects).where(eq(projects.id, id)).returning();
    return deleted.length > 0;
  }
}

export const projectsService = new ProjectsService();
