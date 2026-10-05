import { FastifyInstance } from 'fastify';
import { logger, withCorrelation } from '@security-lab/logger';
import { CORRELATION_HEADER } from '../middleware/correlation.js';

export async function requestLoggerPlugin(fastify: FastifyInstance): Promise<void> {
  fastify.addHook('onRequest', async (request) => {
    const correlationId = (request.headers[CORRELATION_HEADER] as string) || 'unknown';
    const reqLogger = withCorrelation(correlationId, logger);
    (request as unknown as { log: typeof reqLogger }).log = reqLogger;

    reqLogger.debug(
      {
        method: request.method,
        url: request.url,
        ip: request.ip,
      },
      'Incoming HTTP request',
    );
  });

  fastify.addHook('onResponse', async (request, reply) => {
    const correlationId = (request.headers[CORRELATION_HEADER] as string) || 'unknown';
    const reqLogger = withCorrelation(correlationId, logger);

    reqLogger.info(
      {
        method: request.method,
        url: request.url,
        statusCode: reply.statusCode,
        responseTimeMs: reply.elapsedTime,
      },
      'HTTP request completed',
    );
  });
}
