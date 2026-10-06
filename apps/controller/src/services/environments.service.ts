import { eq } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { environments } from './db/schema.js';
import { CreateEnvironmentInput, Environment } from '@security-lab/domain';

export class EnvironmentsService {
  async createEnvironment(input: CreateEnvironmentInput): Promise<Environment> {
    const { db } = getDatabase();
    const [inserted] = await db
      .insert(environments)
      .values({
        projectId: input.projectId,
        name: input.name,
        type: input.type,
        variables: input.variables || {},
        headers: input.headers || {},
      })
      .returning();

    if (!inserted) {
      throw new Error('Failed to insert environment');
    }

    return {
      id: inserted.id,
      projectId: inserted.projectId,
      name: inserted.name,
      type: inserted.type as Environment['type'],
      variables: (inserted.variables as Record<string, string>) || {},
      headers: (inserted.headers as Record<string, string>) || {},
      createdAt: inserted.createdAt,
      updatedAt: inserted.updatedAt,
    };
  }

  async listEnvironmentsByProject(projectId: string): Promise<Environment[]> {
    const { db } = getDatabase();
    const rows = await db
      .select()
      .from(environments)
      .where(eq(environments.projectId, projectId))
      .orderBy(environments.name);

    return rows.map((r) => ({
      id: r.id,
      projectId: r.projectId,
      name: r.name,
      type: r.type as Environment['type'],
      variables: (r.variables as Record<string, string>) || {},
      headers: (r.headers as Record<string, string>) || {},
      createdAt: r.createdAt,
      updatedAt: r.updatedAt,
    }));
  }

  async getEnvironmentById(id: string): Promise<Environment | null> {
    const { db } = getDatabase();
    const [row] = await db.select().from(environments).where(eq(environments.id, id));
    if (!row) return null;

    return {
      id: row.id,
      projectId: row.projectId,
      name: row.name,
      type: row.type as Environment['type'],
      variables: (row.variables as Record<string, string>) || {},
      headers: (row.headers as Record<string, string>) || {},
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  }

  async updateEnvironment(
    id: string,
    input: {
      name?: string;
      type?: Environment['type'];
      variables?: Record<string, string>;
      headers?: Record<string, string>;
    },
  ): Promise<Environment | null> {
    const { db } = getDatabase();
    const updateValues: Record<string, unknown> = {
      updatedAt: new Date(),
    };
    if (input.name !== undefined) updateValues.name = input.name;
    if (input.type !== undefined) updateValues.type = input.type;
    if (input.variables !== undefined) updateValues.variables = input.variables;
    if (input.headers !== undefined) updateValues.headers = input.headers;

    const [updated] = await db
      .update(environments)
      .set(updateValues)
      .where(eq(environments.id, id))
      .returning();

    if (!updated) return null;

    return {
      id: updated.id,
      projectId: updated.projectId,
      name: updated.name,
      type: updated.type as Environment['type'],
      variables: (updated.variables as Record<string, string>) || {},
      headers: (updated.headers as Record<string, string>) || {},
      createdAt: updated.createdAt,
      updatedAt: updated.updatedAt,
    };
  }

  async deleteEnvironment(id: string): Promise<boolean> {
    const { db } = getDatabase();
    const deleted = await db.delete(environments).where(eq(environments.id, id)).returning();
    return deleted.length > 0;
  }
}

export const environmentsService = new EnvironmentsService();
