import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { telemetryRegistry } from '../telemetry.js';

export const metricsRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  fastify.get('/metrics', async (_request, reply) => {
    const output = telemetryRegistry.exportPrometheus();
    reply.header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    return reply.status(200).send(output);
  });
};
