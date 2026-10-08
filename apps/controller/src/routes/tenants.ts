import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { CreateTenantEnrollmentKeySchema } from '@security-lab/contracts';
import { tenantsService } from '../services/tenants.service.js';
import { enrollmentKeysService } from '../services/enrollment-keys.service.js';

const CreateTenantSchema = z.object({
  name: z.string().min(2).max(100),
  slug: z.string().min(2).max(100).regex(/^[a-z0-9-]+$/, 'Slug must be alphanumeric with hyphens'),
  plan: z.string().optional(),
  settings: z.record(z.string(), z.unknown()).optional(),
});

export async function tenantsRoutes(fastify: FastifyInstance) {
  // Ensure default tenant exists on route initialization
  await tenantsService.ensureDefaultTenant();

  // POST /api/v1/tenants
  fastify.post('/', async (request: FastifyRequest, reply: FastifyReply) => {
    const parseResult = CreateTenantSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: parseResult.error.errors.map((e) => e.message).join(', '),
        },
      });
    }

    try {
      const tenant = await tenantsService.createTenant(parseResult.data);
      return reply.status(201).send({
        success: true,
        data: tenant,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return reply.status(400).send({
        success: false,
        error: { code: 'TENANT_CREATION_FAILED', message: msg },
      });
    }
  });

  // GET /api/v1/tenants
  fastify.get('/', async (_request: FastifyRequest, reply: FastifyReply) => {
    const list = await tenantsService.listTenants();
    return reply.status(200).send({
      success: true,
      data: list,
    });
  });

  // GET /api/v1/tenants/:id
  fastify.get('/:id', async (request: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply) => {
    const { id } = request.params;
    let tenant = await tenantsService.getTenantById(id);
    if (!tenant) {
      tenant = await tenantsService.getTenantBySlug(id);
    }

    if (!tenant) {
      return reply.status(404).send({
        success: false,
        error: { code: 'NOT_FOUND', message: `Tenant "${id}" not found` },
      });
    }

    return reply.status(200).send({
      success: true,
      data: tenant,
    });
  });

  // POST /api/v1/tenants/:tenantId/enrollment-keys
  fastify.post(
    '/:tenantId/enrollment-keys',
    async (request: FastifyRequest<{ Params: { tenantId: string } }>, reply: FastifyReply) => {
      const { tenantId } = request.params;
      const parseResult = CreateTenantEnrollmentKeySchema.safeParse(request.body);
      if (!parseResult.success) {
        return reply.status(400).send({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: parseResult.error.errors.map((e) => e.message).join(', '),
          },
        });
      }

      try {
        const keyResponse = await enrollmentKeysService.createEnrollmentKey(
          tenantId,
          parseResult.data,
        );
        return reply.status(201).send({
          success: true,
          data: keyResponse,
        });
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return reply.status(400).send({
          success: false,
          error: { code: 'ENROLLMENT_KEY_CREATION_FAILED', message: msg },
        });
      }
    },
  );

  // GET /api/v1/tenants/:tenantId/enrollment-keys
  fastify.get(
    '/:tenantId/enrollment-keys',
    async (request: FastifyRequest<{ Params: { tenantId: string } }>, reply: FastifyReply) => {
      const { tenantId } = request.params;
      const list = await enrollmentKeysService.listEnrollmentKeys(tenantId);
      return reply.status(200).send({
        success: true,
        data: list,
      });
    },
  );

  // POST /api/v1/tenants/:tenantId/enrollment-keys/:keyId/revoke
  fastify.post(
    '/:tenantId/enrollment-keys/:keyId/revoke',
    async (
      request: FastifyRequest<{ Params: { tenantId: string; keyId: string } }>,
      reply: FastifyReply,
    ) => {
      const { tenantId, keyId } = request.params;
      const revoked = await enrollmentKeysService.revokeEnrollmentKey(tenantId, keyId);
      if (!revoked) {
        return reply.status(404).send({
          success: false,
          error: { code: 'NOT_FOUND', message: `Enrollment key "${keyId}" not found or already revoked` },
        });
      }

      return reply.status(200).send({
        success: true,
        message: 'Tenant enrollment key revoked successfully',
      });
    },
  );
}
