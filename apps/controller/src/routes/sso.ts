import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { eq } from 'drizzle-orm';
import { SsoConfigSchema } from '@security-lab/contracts';
import { ssoService } from '../services/sso/sso.service.js';
import { requireAdmin, requireAuditor } from '../plugins/rbac.js';
import { getDatabase } from '../services/db.js';
import { workspaces } from '../services/db/schema.js';

export const ssoRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // 1. SAML SP Metadata endpoint (Public)
  fastify.get<{ Params: { workspaceId: string } }>(
    '/api/v1/auth/sso/saml/:workspaceId/metadata',
    async (request, reply) => {
      const { workspaceId } = request.params;
      const hostUrl = `${request.protocol}://${request.hostname}`;

      try {
        const metadataXml = await ssoService.getSamlMetadata(workspaceId, hostUrl);
        return reply.type('application/xml').send(metadataXml);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'Failed to generate SAML metadata';
        return reply.status(400).send({
          success: false,
          error: { code: 'SAML_METADATA_ERROR', message },
        });
      }
    },
  );

  // 2. SAML ACS (Assertion Consumer Service) endpoint (Public POST)
  fastify.post<{ Params: { workspaceId: string }; Body: { SAMLResponse?: string; samlResponse?: string } }>(
    '/api/v1/auth/sso/saml/:workspaceId/acs',
    async (request, reply) => {
      const { workspaceId } = request.params;
      const body = request.body || {};
      const samlResponseBase64 = body.SAMLResponse || body.samlResponse;

      if (!samlResponseBase64) {
        return reply.status(400).send({
          success: false,
          error: {
            code: 'MISSING_SAML_RESPONSE',
            message: 'SAMLResponse payload is required',
          },
        });
      }

      const hostUrl = `${request.protocol}://${request.hostname}`;

      try {
        const result = await ssoService.processSamlResponse(workspaceId, samlResponseBase64, hostUrl);
        return reply.send({
          success: true,
          data: result,
        });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'SAML authentication failed';
        return reply.status(401).send({
          success: false,
          error: {
            code: 'SAML_AUTH_FAILED',
            message,
          },
        });
      }
    },
  );

  // 3. OIDC Login Initiation (Public)
  fastify.get<{ Params: { workspaceId: string } }>(
    '/api/v1/auth/sso/oidc/:workspaceId/login',
    async (request, reply) => {
      const { workspaceId } = request.params;
      const hostUrl = `${request.protocol}://${request.hostname}`;

      try {
        const authUrl = await ssoService.getOidcAuthUrl(workspaceId, hostUrl);
        return reply.send({
          success: true,
          data: { authUrl },
        });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'Failed to initiate OIDC login';
        return reply.status(400).send({
          success: false,
          error: { code: 'OIDC_LOGIN_ERROR', message },
        });
      }
    },
  );

  // 4. OIDC Callback / Token Exchange (Public POST)
  fastify.post<{ Params: { workspaceId: string }; Body: { idToken?: string; id_token?: string; claims?: Record<string, unknown> } }>(
    '/api/v1/auth/sso/oidc/:workspaceId/callback',
    async (request, reply) => {
      const { workspaceId } = request.params;
      const body = request.body || {};
      const idToken = body.idToken || body.id_token;
      const claims = body.claims;

      if (!idToken && !claims) {
        return reply.status(400).send({
          success: false,
          error: {
            code: 'MISSING_OIDC_TOKEN',
            message: 'idToken or claims payload is required',
          },
        });
      }

      try {
        const result = await ssoService.processOidcCallback(workspaceId, idToken || claims!);
        return reply.send({
          success: true,
          data: result,
        });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'OIDC authentication failed';
        return reply.status(401).send({
          success: false,
          error: {
            code: 'OIDC_AUTH_FAILED',
            message,
          },
        });
      }
    },
  );

  // 5. Get Workspace SSO Configuration (ADMIN / AUDITOR)
  fastify.get<{ Params: { id: string } }>(
    '/api/v1/workspaces/:id/sso',
    { preHandler: [requireAuditor] },
    async (request, reply) => {
      const { id } = request.params;
      const config = await ssoService.getWorkspaceSsoConfig(id);
      return reply.send({
        success: true,
        data: config || { enabled: false, provider: 'saml', defaultRole: 'ENGINEER' },
      });
    },
  );

  // 6. Update Workspace SSO Configuration (ADMIN only)
  fastify.put<{ Params: { id: string } }>(
    '/api/v1/workspaces/:id/sso',
    { preHandler: [requireAdmin] },
    async (request, reply) => {
      const { id } = request.params;
      const parseResult = SsoConfigSchema.safeParse(request.body);
      if (!parseResult.success) {
        return reply.status(400).send({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid SSO configuration',
            details: parseResult.error.format(),
          },
        });
      }

      const { db } = getDatabase();
      const [updated] = await db
        .update(workspaces)
        .set({
          ssoConfig: parseResult.data,
          updatedAt: new Date(),
        })
        .where(eq(workspaces.id, id))
        .returning();

      if (!updated) {
        return reply.status(404).send({
          success: false,
          error: { code: 'WORKSPACE_NOT_FOUND', message: `Workspace "${id}" not found` },
        });
      }

      return reply.send({
        success: true,
        data: parseResult.data,
      });
    },
  );
};
