import Fastify, { FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import sensible from '@fastify/sensible';
import { config } from '../config/index.js';
import { correlationMiddleware } from '../middleware/correlation.js';
import { requestLoggerPlugin } from '../plugins/logger.js';
import { healthRoutes } from '../routes/health.js';
import { projectsRoutes } from '../routes/projects.js';
import { environmentsRoutes } from '../routes/environments.js';
import { targetsRoutes } from '../routes/targets.js';
import { testRunsRoutes } from '../routes/test-runs.js';
import { findingsRoutes } from '../routes/findings.js';
import { reportsRoutes } from '../routes/reports.js';
import { releasesRoutes } from '../routes/releases.js';
import { policiesRoutes } from '../routes/policies.js';
import { contractsRoutes } from '../routes/contracts.js';
import { logger } from '@security-lab/logger';

export interface BuildAppOptions {
  disableLogging?: boolean;
}

export function buildApp(options: BuildAppOptions = {}): FastifyInstance {
  const app = Fastify({
    logger: false, // We use custom centralized logger
    trustProxy: true,
  });

  // Global Error Handler
  app.setErrorHandler((error: Error & { statusCode?: number; code?: string }, request, reply) => {
    const correlationId = (request.headers['x-correlation-id'] as string) || 'unknown';
    logger.error(
      {
        err: error,
        correlationId,
        url: request.url,
        method: request.method,
      },
      'Unhandled controller error occurred',
    );

    reply.status(error.statusCode || 500).send({
      success: false,
      error: {
        code: error.code || 'INTERNAL_SERVER_ERROR',
        message:
          config.NODE_ENV === 'production' && !error.statusCode
            ? 'An internal server error occurred'
            : error.message,
        correlationId,
      },
    });
  });

  // Middleware & Plugins
  app.addHook('onRequest', correlationMiddleware);

  if (!options.disableLogging) {
    app.register(requestLoggerPlugin);
  }

  app.register(cors, {
    origin: config.CORS_ORIGIN,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  });

  app.register(sensible);

  // Register Routes
  app.register(healthRoutes);
  app.register(projectsRoutes);
  app.register(environmentsRoutes);
  app.register(targetsRoutes);
  app.register(testRunsRoutes);
  app.register(findingsRoutes);
  app.register(reportsRoutes);
  app.register(releasesRoutes);
  app.register(policiesRoutes);
  app.register(contractsRoutes);

  return app;
}
