import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import crypto from 'node:crypto';
import { SecurityContractEngine, ExecutionContext } from '@security-lab/test-sdk';
import { logger } from '@security-lab/logger';
import { requireEngineer, requireAuditor } from '../plugins/rbac.js';
import { extractTenantScope } from '../services/tenant-context.js';
import { contractsService } from '../services/contracts.service.js';

const VerifyContractBodySchema = z.object({
  spec: z.union([z.string(), z.record(z.string(), z.any())]).optional(),
  specUrl: z.string().optional(),
  specPath: z.string().optional(),
  targetUrl: z.string().optional(),
  options: z.record(z.string(), z.any()).optional(),
});

const SaveSpecBodySchema = z.object({
  targetId: z.string(),
  name: z.string().min(1, 'Specification name is required'),
  type: z.enum(['openapi', 'graphql']),
  content: z.string().min(1, 'Specification content is required'),
  metadata: z.record(z.unknown()).optional(),
});

const IntrospectGraphQLBodySchema = z.object({
  targetId: z.string(),
  endpointUrl: z.string().url('Valid GraphQL endpoint URL is required'),
  headers: z.record(z.string()).optional(),
});

export const contractsRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // 1. Verify contract compliance using SecurityContractEngine
  fastify.post('/api/v1/contracts/verify', async (request, reply) => {
    const parseResult = VerifyContractBodySchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid contract verification payload',
          details: parseResult.error.format(),
        },
      });
    }

    const { spec, specUrl, specPath, targetUrl, options } = parseResult.data;
    const engine = new SecurityContractEngine();

    const input = {
      targetUrl: targetUrl || '',
      options: {
        spec,
        specUrl,
        specPath,
        ...(options || {}),
      },
    };

    const validation = engine.validate(input);
    if (!validation.valid) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'CONTRACT_VALIDATION_ERROR',
          message: 'Contract input validation failed',
          details: validation.errors,
        },
      });
    }

    const executionId = crypto.randomUUID();
    const testRunId = crypto.randomUUID();
    const correlationId = (request.headers['x-correlation-id'] as string) || crypto.randomUUID();

    let targetHostname = 'localhost';
    let targetPort = 80;
    if (targetUrl) {
      try {
        const parsed = new URL(targetUrl);
        targetHostname = parsed.hostname;
        targetPort = parsed.port ? parseInt(parsed.port, 10) : parsed.protocol === 'https:' ? 443 : 80;
      } catch {
        // use default
      }
    }

    const context: ExecutionContext = {
      correlationId,
      executionId,
      testRunId,
      target: {
        id: crypto.randomUUID(),
        name: 'Contract Verification Target',
        baseUrl: targetUrl || 'http://localhost',
        scope: {
          allowedHosts: [targetHostname],
          allowedPorts: [targetPort],
          allowPrivateIps: true,
          excludedPaths: [],
          testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
          limits: { maxRps: 50, maxConcurrency: 5, maxDuration: '5m' },
        },
      },
      abortSignal: new AbortController().signal,
      reportProgress: (percent, msg) => {
        logger.debug({ executionId, percent, msg }, 'Contract engine progress');
      },
      logger,
    };

    try {
      const result = await engine.execute(input, context);
      return reply.send({
        success: result.success,
        data: result,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return reply.status(500).send({
        success: false,
        error: {
          code: 'CONTRACT_EXECUTION_ERROR',
          message,
        },
      });
    }
  });

  // 2. Query saved contract specifications for a target
  fastify.get<{ Querystring: { targetId?: string } }>(
    '/api/v1/contracts/specs',
    { preHandler: [requireAuditor] },
    async (request, reply) => {
      const { targetId } = request.query;
      if (!targetId) {
        return reply.status(400).send({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Query parameter "targetId" is required',
          },
        });
      }

      const tenantId = extractTenantScope(request);
      const specs = await contractsService.listSpecsByTarget(targetId, tenantId);

      return reply.send({
        success: true,
        data: specs,
      });
    },
  );

  // 3. Save / Persist an OpenAPI or GraphQL specification
  fastify.post(
    '/api/v1/contracts/specs',
    { preHandler: [requireEngineer] },
    async (request, reply) => {
      const parseResult = SaveSpecBodySchema.safeParse(request.body);
      if (!parseResult.success) {
        return reply.status(400).send({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid contract specification payload',
            details: parseResult.error.format(),
          },
        });
      }

      try {
        const tenantId = extractTenantScope(request);
        const specRecord = await contractsService.saveSpec(parseResult.data, tenantId);

        return reply.status(201).send({
          success: true,
          data: specRecord,
        });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'Failed to persist contract specification';
        return reply.status(400).send({
          success: false,
          error: {
            code: 'SPEC_VALIDATION_ERROR',
            message,
          },
        });
      }
    },
  );

  // 4. Server-Side GraphQL Introspection with SSRF Boundary Protection
  fastify.post(
    '/api/v1/contracts/graphql/introspect',
    { preHandler: [requireEngineer] },
    async (request, reply) => {
      const parseResult = IntrospectGraphQLBodySchema.safeParse(request.body);
      if (!parseResult.success) {
        return reply.status(400).send({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid GraphQL introspection payload',
            details: parseResult.error.format(),
          },
        });
      }

      const { targetId, endpointUrl, headers } = parseResult.data;
      const tenantId = extractTenantScope(request);

      try {
        const result = await contractsService.introspectGraphQL(targetId, endpointUrl, headers, tenantId);
        return reply.send({
          success: true,
          data: result,
        });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'GraphQL introspection failed';
        const isSsrf = message.includes('violates target scope') || message.includes('SSRF');
        return reply.status(isSsrf ? 400 : 502).send({
          success: false,
          error: {
            code: isSsrf ? 'SSRF_SCOPE_VIOLATION' : 'INTROSPECTION_FAILED',
            message,
          },
        });
      }
    },
  );
};
