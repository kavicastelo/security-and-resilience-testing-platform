import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { eq, and } from 'drizzle-orm';
import { getDatabase } from '../services/db.js';
import { users, workspaceMemberships } from '../services/db/schema.js';
import { Role, RoleSchema } from '@security-lab/contracts';
import { DEFAULT_WORKSPACE_ID } from '../services/auth-token.service.js';

function extractWorkspaceId(request: any): string {
  if (request.params?.workspaceId) return request.params.workspaceId;
  const headerWs = request.headers['x-workspace-id'];
  if (typeof headerWs === 'string' && headerWs.trim().length > 0) return headerWs.trim();
  if (request.workspaceId) return request.workspaceId;
  const queryWs = (request.query as Record<string, string>)?.workspaceId;
  if (queryWs) return queryWs;
  return DEFAULT_WORKSPACE_ID;
}

function toScimUser(user: any, role: Role = 'ENGINEER', active = true, baseUrl = ''): any {
  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    id: user.id,
    userName: user.email,
    name: {
      formatted: user.name,
      givenName: user.name?.split(' ')[0] || user.name,
      familyName: user.name?.split(' ').slice(1).join(' ') || '',
    },
    emails: [
      {
        value: user.email,
        type: 'work',
        primary: true,
      },
    ],
    active,
    roles: [
      {
        value: role,
        primary: true,
      },
    ],
    meta: {
      resourceType: 'User',
      created: user.createdAt instanceof Date ? user.createdAt.toISOString() : new Date().toISOString(),
      lastModified: user.updatedAt instanceof Date ? user.updatedAt.toISOString() : new Date().toISOString(),
      location: `${baseUrl}/scim/v2/Users/${user.id}`,
    },
  };
}

export const scimRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // ServiceProviderConfig
  fastify.get('/scim/v2/ServiceProviderConfig', async (_request, reply) => {
    return reply.type('application/scim+json').send({
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
      documentationUri: 'https://security-lab.local/docs/scim',
      patch: { supported: true },
      bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
      filter: { supported: true, maxResults: 100 },
      changePassword: { supported: false },
      sort: { supported: false },
      etag: { supported: false },
      authenticationSchemes: [
        {
          name: 'OAuth Bearer Token',
          description: 'Authentication using Bearer token or API key',
          specUri: 'http://www.rfc-editor.org/info/rfc6750',
          type: 'oauthbearertoken',
          primary: true,
        },
      ],
    });
  });

  // Schemas
  fastify.get('/scim/v2/Schemas', async (_request, reply) => {
    return reply.type('application/scim+json').send({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      totalResults: 2,
      startIndex: 1,
      itemsPerPage: 2,
      Resources: [
        {
          id: 'urn:ietf:params:scim:schemas:core:2.0:User',
          name: 'User',
          description: 'User Account',
        },
        {
          id: 'urn:ietf:params:scim:schemas:core:2.0:Group',
          name: 'Group',
          description: 'Group / Role',
        },
      ],
    });
  });

  // List Users
  fastify.get('/scim/v2/Users', async (request, reply) => {
    const workspaceId = extractWorkspaceId(request);
    const query = request.query as Record<string, string>;
    const startIndex = Math.max(1, parseInt(query.startIndex || '1', 10));
    const count = Math.min(100, Math.max(1, parseInt(query.count || '50', 10)));
    const filter = query.filter || '';

    const { db } = getDatabase();

    // Parse filter like: userName eq "user@example.com" or emails.value eq "user@example.com"
    let emailFilter: string | null = null;
    const eqMatch = filter.match(/(?:userName|emails\.value)\s+eq\s+["']?([^"']+)["']?/i);
    if (eqMatch) {
      emailFilter = eqMatch[1]!.toLowerCase().trim();
    }

    const members = await db
      .select({
        user: users,
        role: workspaceMemberships.role,
      })
      .from(workspaceMemberships)
      .innerJoin(users, eq(workspaceMemberships.userId, users.id))
      .where(
        emailFilter
          ? and(eq(workspaceMemberships.workspaceId, workspaceId), eq(users.email, emailFilter))
          : eq(workspaceMemberships.workspaceId, workspaceId),
      );

    const totalResults = members.length;
    const paginated = members.slice(startIndex - 1, startIndex - 1 + count);
    const hostUrl = `${request.protocol}://${request.hostname}`;

    const resources = paginated.map((m) =>
      toScimUser(m.user, m.role as Role, true, hostUrl),
    );

    return reply.type('application/scim+json').send({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      totalResults,
      startIndex,
      itemsPerPage: paginated.length,
      Resources: resources,
    });
  });

  // Create / Provision User
  fastify.post('/scim/v2/Users', async (request, reply) => {
    const workspaceId = extractWorkspaceId(request);
    const body = request.body as Record<string, any>;

    const email = (
      body.userName ||
      (Array.isArray(body.emails) ? body.emails[0]?.value : undefined)
    )?.toLowerCase().trim();

    if (!email) {
      return reply.status(400).type('application/scim+json').send({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        status: '400',
        detail: 'userName or email is required',
      });
    }

    const name =
      body.name?.formatted ||
      [body.name?.givenName, body.name?.familyName].filter(Boolean).join(' ') ||
      body.displayName ||
      email.split('@')[0];

    // Role mapping
    let role: Role = 'ENGINEER';
    if (Array.isArray(body.roles) && body.roles[0]?.value) {
      const parsedRole = RoleSchema.safeParse(body.roles[0].value.toUpperCase());
      if (parsedRole.success) {
        role = parsedRole.data;
      }
    }

    const { db } = getDatabase();

    // 1. Find or create user
    let [user] = await db.select().from(users).where(eq(users.email, email));
    if (!user) {
      const [created] = await db
        .insert(users)
        .values({
          email,
          name,
          passwordHash: null,
        })
        .returning();
      user = created!;
    }

    // 2. Add to workspace
    const [membership] = await db
      .select()
      .from(workspaceMemberships)
      .where(
        and(
          eq(workspaceMemberships.workspaceId, workspaceId),
          eq(workspaceMemberships.userId, user.id),
        ),
      );

    if (!membership) {
      await db.insert(workspaceMemberships).values({
        workspaceId,
        userId: user.id,
        role,
      });
    }

    const hostUrl = `${request.protocol}://${request.hostname}`;
    const scimUser = toScimUser(user, role, body.active !== false, hostUrl);

    return reply
      .status(201)
      .header('Location', scimUser.meta.location)
      .type('application/scim+json')
      .send(scimUser);
  });

  // Get User by ID
  fastify.get<{ Params: { id: string } }>('/scim/v2/Users/:id', async (request, reply) => {
    const { id } = request.params;
    const workspaceId = extractWorkspaceId(request);
    const { db } = getDatabase();

    const [member] = await db
      .select({
        user: users,
        role: workspaceMemberships.role,
      })
      .from(workspaceMemberships)
      .innerJoin(users, eq(workspaceMemberships.userId, users.id))
      .where(
        and(
          eq(workspaceMemberships.workspaceId, workspaceId),
          eq(users.id, id),
        ),
      );

    if (!member) {
      return reply.status(404).type('application/scim+json').send({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        status: '404',
        detail: `User "${id}" not found in workspace`,
      });
    }

    const hostUrl = `${request.protocol}://${request.hostname}`;
    return reply
      .type('application/scim+json')
      .send(toScimUser(member.user, member.role as Role, true, hostUrl));
  });

  // Update User (PUT)
  fastify.put<{ Params: { id: string } }>('/scim/v2/Users/:id', async (request, reply) => {
    const { id } = request.params;
    const workspaceId = extractWorkspaceId(request);
    const body = request.body as Record<string, any>;
    const { db } = getDatabase();

    const [user] = await db.select().from(users).where(eq(users.id, id));
    if (!user) {
      return reply.status(404).type('application/scim+json').send({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        status: '404',
        detail: `User "${id}" not found`,
      });
    }

    // Check active
    const active = body.active !== false;
    if (!active) {
      // Deprovision: remove membership
      await db
        .delete(workspaceMemberships)
        .where(
          and(
            eq(workspaceMemberships.workspaceId, workspaceId),
            eq(workspaceMemberships.userId, id),
          ),
        );
    } else {
      let role: Role = 'ENGINEER';
      if (Array.isArray(body.roles) && body.roles[0]?.value) {
        const parsed = RoleSchema.safeParse(body.roles[0].value.toUpperCase());
        if (parsed.success) role = parsed.data;
      }
      await db
        .insert(workspaceMemberships)
        .values({ workspaceId, userId: id, role })
        .onConflictDoUpdate({
          target: [workspaceMemberships.workspaceId, workspaceMemberships.userId],
          set: { role, updatedAt: new Date() },
        });
    }

    const hostUrl = `${request.protocol}://${request.hostname}`;
    return reply.type('application/scim+json').send(toScimUser(user, 'ENGINEER', active, hostUrl));
  });

  // Patch User (PATCH)
  fastify.patch<{ Params: { id: string } }>('/scim/v2/Users/:id', async (request, reply) => {
    const { id } = request.params;
    const workspaceId = extractWorkspaceId(request);
    const body = request.body as Record<string, any>;
    const operations = Array.isArray(body.Operations) ? body.Operations : [];

    const { db } = getDatabase();
    const [user] = await db.select().from(users).where(eq(users.id, id));
    if (!user) {
      return reply.status(404).type('application/scim+json').send({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        status: '404',
        detail: `User "${id}" not found`,
      });
    }

    let active = true;
    for (const op of operations) {
      if (op.op?.toLowerCase() === 'replace') {
        if (op.path === 'active' || op.value?.active !== undefined) {
          const val = op.path === 'active' ? op.value : op.value?.active;
          if (val === false || val === 'false') {
            active = false;
            // Deprovision: remove from workspace
            await db
              .delete(workspaceMemberships)
              .where(
                and(
                  eq(workspaceMemberships.workspaceId, workspaceId),
                  eq(workspaceMemberships.userId, id),
                ),
              );
          }
        }
      }
    }

    const hostUrl = `${request.protocol}://${request.hostname}`;
    return reply.type('application/scim+json').send(toScimUser(user, 'ENGINEER', active, hostUrl));
  });

  // Delete User (DELETE)
  fastify.delete<{ Params: { id: string } }>('/scim/v2/Users/:id', async (request, reply) => {
    const { id } = request.params;
    const workspaceId = extractWorkspaceId(request);
    const { db } = getDatabase();

    await db
      .delete(workspaceMemberships)
      .where(
        and(
          eq(workspaceMemberships.workspaceId, workspaceId),
          eq(workspaceMemberships.userId, id),
        ),
      );

    return reply.status(204).send();
  });

  // Groups (Roles)
  fastify.get('/scim/v2/Groups', async (request, reply) => {
    const workspaceId = extractWorkspaceId(request);
    const { db } = getDatabase();

    const members = await db
      .select({
        user: users,
        role: workspaceMemberships.role,
      })
      .from(workspaceMemberships)
      .innerJoin(users, eq(workspaceMemberships.userId, users.id))
      .where(eq(workspaceMemberships.workspaceId, workspaceId));

    const roles: Role[] = ['ADMIN', 'ENGINEER', 'AUDITOR'];
    const hostUrl = `${request.protocol}://${request.hostname}`;

    const groups = roles.map((r) => {
      const roleMembers = members.filter((m) => m.role === r);
      return {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
        id: `role-${r.toLowerCase()}`,
        displayName: r,
        members: roleMembers.map((m) => ({
          value: m.user.id,
          display: m.user.name,
          $ref: `${hostUrl}/scim/v2/Users/${m.user.id}`,
        })),
        meta: {
          resourceType: 'Group',
          location: `${hostUrl}/scim/v2/Groups/role-${r.toLowerCase()}`,
        },
      };
    });

    return reply.type('application/scim+json').send({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      totalResults: groups.length,
      startIndex: 1,
      itemsPerPage: groups.length,
      Resources: groups,
    });
  });
};
