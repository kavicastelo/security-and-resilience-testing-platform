import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { HealthCheckResponse } from '@security-lab/contracts';
import { checkDatabaseHealth } from '../services/db.js';

export const healthRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  const handler = async (): Promise<HealthCheckResponse> => {
    const dbStatus = await checkDatabaseHealth();
    const isOk = dbStatus === 'up';

    return {
      status: isOk ? 'ok' : 'degraded',
      version: '0.1.0',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      services: {
        database: dbStatus,
      },
    };
  };

  // Root health endpoint
  fastify.get('/health', handler);

  // Versioned API health endpoint
  fastify.get('/api/v1/health', handler);
};
