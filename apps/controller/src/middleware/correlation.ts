import { FastifyReply, FastifyRequest } from 'fastify';
import { randomUUID } from 'node:crypto';

export const CORRELATION_HEADER = 'x-correlation-id';

export async function correlationMiddleware(
  request: FastifyRequest,
  reply: FastifyReply,
): Promise<void> {
  const existingCorrelationId = request.headers[CORRELATION_HEADER];
  const correlationId =
    typeof existingCorrelationId === 'string' && existingCorrelationId.length > 0
      ? existingCorrelationId
      : randomUUID();

  request.headers[CORRELATION_HEADER] = correlationId;
  reply.header(CORRELATION_HEADER, correlationId);
}
