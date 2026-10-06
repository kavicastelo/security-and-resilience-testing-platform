import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import crypto from 'node:crypto';
import { SecurityContractEngine, ExecutionContext } from '@security-lab/test-sdk';
import { logger } from '@security-lab/logger';

const VerifyContractBodySchema = z.object({
  spec: z.union([z.string(), z.record(z.string(), z.any())]).optional(),
  specUrl: z.string().optional(),
  specPath: z.string().optional(),
  targetUrl: z.string().optional(),
  options: z.record(z.string(), z.any()).optional(),
});

export const contractsRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
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
        targetPort = parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' ? 443 : 80);
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
};
