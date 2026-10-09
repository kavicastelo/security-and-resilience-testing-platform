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

  // Root service discovery & metadata endpoint
  fastify.get('/', async () => {
    const dbStatus = await checkDatabaseHealth();
    return {
      name: 'Security Lab Controller API',
      version: '0.1.0',
      status: dbStatus === 'up' ? 'ok' : 'degraded',
      health: '/health',
      ready: '/ready',
      api: '/api/v1',
      services: {
        database: dbStatus,
      },
    };
  });

  // Root health endpoint
  fastify.get('/health', handler);
  fastify.get('/ready', handler);

  // Versioned API health endpoint
  fastify.get('/api/v1/health', handler);
  fastify.get('/api/v1/ready', handler);
};

