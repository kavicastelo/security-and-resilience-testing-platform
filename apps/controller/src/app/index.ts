import Fastify, { FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import sensible from '@fastify/sensible';
import rateLimit from '@fastify/rate-limit';
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
import { tenantsRoutes } from '../routes/tenants.js';
import { agentsRoutes } from '../routes/agents.js';
import { managementRoutes } from '../routes/management.js';
import { agentJobReaper } from '../services/agent-dispatcher.service.js';
import { registerAuthHooks, AuthPluginOptions } from '../plugins/auth.js';
import { SharedRateLimitStore } from '../services/rate-limit-store.js';
import { logger } from '@security-lab/logger';

export interface RateLimitOverrides {
  generalMax?: number;
  scanMax?: number;
  purgeMax?: number;
}

export interface BuildAppOptions extends AuthPluginOptions {
  disableLogging?: boolean;
  enableReaper?: boolean;
  rateLimitOverrides?: RateLimitOverrides;
}

declare module 'fastify' {
  interface FastifyInstance {
    rateLimitOverrides?: RateLimitOverrides;
  }
}

export function buildApp(options: BuildAppOptions = {}): FastifyInstance {
  const app = Fastify({
    logger: false, // We use custom centralized logger
    trustProxy: true,
  });

  // Decorate rateLimitOverrides on app instance for route access
  app.decorate('rateLimitOverrides', options.rateLimitOverrides);

  // Global Error Handler
  app.setErrorHandler((error: Error & { statusCode?: number; code?: string }, request, reply) => {
    const correlationId = (request.headers['x-correlation-id'] as string) || 'unknown';

    // RFC 6585 Standard 429 Response Format for Rate Limiting
    if (error.statusCode === 429 || error.code === 'FST_ERR_RATE_LIMIT_EXCEEDED') {
      const retryAfter = Number(reply.getHeader('retry-after')) || 60;
      return reply.status(429).send({
        statusCode: 429,
        error: 'Too Many Requests',
        message: error.message || 'Rate limit exceeded. Please wait before retrying.',
        retryAfter,
      });
    }

    logger.error(
      {
        err: error,
        correlationId,
        url: request.url,
        method: request.method,
      },
      'Unhandled controller error occurred',
    );

    return reply.status(error.statusCode || 500).send({
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

  // Tiered Rate Limiting & Resource Protection (Prompt 10)
  const defaultGeneralMax = config.NODE_ENV === 'production' ? 120 : 1000;
  const generalMax = options.rateLimitOverrides?.generalMax ?? defaultGeneralMax;
  app.register(rateLimit, {
    store: SharedRateLimitStore,
    global: true,
    max: generalMax,
    timeWindow: '1 minute',
    hook: 'preHandler',
    keyGenerator: (request) => {
      // Key rate limits by authenticated keyId, tenantId, or client IP.
      // Never key by raw client-supplied x-tenant-id header to prevent spoofing bypass.
      if (request.auth?.keyId) {
        return `auth:${request.auth.keyId}`;
      }
      if (request.auth?.tenantId) {
        return `tenant:${request.auth.tenantId}`;
      }
      return `ip:${request.ip}`;
    },
    allowList: (request) => {
      const url = request.url;
      // SSE streams, events, and health check are completely exempt from rate limiting
      return url.includes('/stream') || url.includes('/events') || url === '/health';
    },
    errorResponseBuilder: (request, context) => {
      const retryAfter = Math.ceil(context.ttl / 1000) || 60;
      let message = 'Rate limit exceeded. Please wait before retrying.';
      if (
        request.url.includes('/execute') ||
        (request.url.startsWith('/api/v1/test-runs') && request.method === 'POST')
      ) {
        message = 'Rate limit exceeded for scan execution. Please wait before retrying.';
      } else if (request.url.includes('/purge')) {
        message = 'Rate limit exceeded for administrative purge operations. Please wait before retrying.';
      }
      return {
        statusCode: 429,
        error: 'Too Many Requests',
        message,
        retryAfter,
      };
    },
  });

  // Centralized Authentication & Access Control (Prompt 01)
  registerAuthHooks(app, {
    bypassAuth: options.bypassAuth ?? (config.SECURITY_LAB_BYPASS_AUTH_IN_TESTS && config.NODE_ENV !== 'production'),
    apiKey: options.apiKey,
    adminKey: options.adminKey,
    tenantKeyMap: options.tenantKeyMap,
    defaultTenantId: options.defaultTenantId,
  });

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
  app.register(tenantsRoutes, { prefix: '/api/v1/tenants' });
  app.register(agentsRoutes, { prefix: '/api/v1/agents' });
  app.register(managementRoutes, { prefix: '/api/v1/management' });

  // Background Reaper Lifecycle
  app.addHook('onReady', async () => {
    if (options.enableReaper !== false) {
      agentJobReaper.start();
    }
  });

  app.addHook('onClose', async () => {
    agentJobReaper.stop();
  });

  return app;
}
