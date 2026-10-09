import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import crypto from 'node:crypto';
import { config } from '../config/index.js';
import { DEFAULT_TENANT_ID } from '../services/tenants.service.js';
import { logger } from '@security-lab/logger';

export type UserRole = 'admin' | 'operator' | 'agent' | 'public';

export interface AuthContext {
  role: UserRole;
  keyId?: string;
  tenantId?: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    auth?: AuthContext;
  }
}

export interface TenantKeyConfig {
  role: UserRole;
  tenantId: string;
}

export interface AuthPluginOptions {
  bypassAuth?: boolean;
  apiKey?: string;
  adminKey?: string;
  defaultTenantId?: string;
  tenantKeyMap?: Record<string, TenantKeyConfig>;
}

/**
 * Constant-time string comparison using SHA-256 pre-hashing.
 * Pre-hashing normalizes input lengths to 32 bytes to eliminate timing side channels.
 */
export function timingSafeCompare(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }
  const hashA = crypto.createHash('sha256').update(Buffer.from(a)).digest();
  const hashB = crypto.createHash('sha256').update(Buffer.from(b)).digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

/**
 * Extracts authentication credential from Authorization: Bearer or X-API-Key headers.
 */
export function extractAuthToken(request: FastifyRequest): string | null {
  const authHeader = request.headers.authorization;
  if (typeof authHeader === 'string') {
    const parts = authHeader.trim().split(' ');
    if (parts.length === 2 && parts[0]?.toLowerCase() === 'bearer') {
      const token = parts[1]?.trim();
      return token && token.length > 0 ? token : null;
    }
  }

  const xApiKey = request.headers['x-api-key'];
  if (typeof xApiKey === 'string' && xApiKey.trim().length > 0) {
    return xApiKey.trim();
  }

  // Also support API key / token in query parameters for direct browser viewing & report downloads
  const query = request.query as Record<string, unknown> | undefined;
  if (query) {
    const candidate = query.apiKey || query.api_key || query.token || query.key;
    if (typeof candidate === 'string' && candidate.trim().length > 0) {
      return candidate.trim();
    }
  }

  return null;
}

/**
 * Public routes explicitly exempted from authentication.
 */
function isPublicRoute(url: string, method: string): boolean {
  if (method !== 'GET') return false;
  const cleanUrl = (url || '').split('?')[0]!.replace(/\/$/, '');
  if (
    cleanUrl === '' ||
    cleanUrl === '/health' ||
    cleanUrl === '/ready' ||
    cleanUrl === '/api/v1/health' ||
    cleanUrl === '/api/v1/ready' ||
    cleanUrl === '/favicon.ico'
  ) {
    return true;
  }

  // In non-production environments (local-first dev/test), allow direct browser access to reports and artifact downloads
  if (config.NODE_ENV !== 'production') {
    if (
      /^\/api\/v1\/test-runs\/[^/]+\/report$/.test(cleanUrl) ||
      /^\/api\/v1\/test-runs\/[^/]+\/reports$/.test(cleanUrl) ||
      /^\/api\/v1\/test-runs\/[^/]+\/reports\/[^/]+\/download$/.test(cleanUrl) ||
      /^\/api\/v1\/test-runs\/[^/]+\/artifacts\/[^/]+\/download$/.test(cleanUrl)
    ) {
      return true;
    }
  }

  return false;
}


/**
 * Determines whether a route is an agent daemon-facing worker endpoint.
 * These endpoints enforce their own specialized TEK or agent token authentication.
 */
function isAgentDaemonRoute(url: string): boolean {
  const cleanUrl = (url || '').split('?')[0]!.replace(/\/$/, '');
  if (!cleanUrl.startsWith('/api/v1/agents')) return false;
  if (cleanUrl.endsWith('/register')) return true;
  if (cleanUrl.endsWith('/heartbeat')) return true;
  if (cleanUrl.endsWith('/poll')) return true;
  if (cleanUrl.includes('/jobs/') && !cleanUrl.endsWith('/dispatch')) return true;
  if (cleanUrl.endsWith('/rotate-token')) return true;
  return false;
}

/**
 * Registers centralized authentication hooks directly on the Fastify instance.
 */
export function registerAuthHooks(fastify: FastifyInstance, options: AuthPluginOptions = {}): void {
  const effectiveApiKey = options.apiKey || config.SECURITY_LAB_API_KEY;
  const effectiveAdminKey = options.adminKey || config.SECURITY_LAB_ADMIN_KEY;
  const bypassAuth = options.bypassAuth ?? false;
  const defaultTenantId = options.defaultTenantId || DEFAULT_TENANT_ID;

  if (config.NODE_ENV === 'production' && bypassAuth) {
    throw new Error('FATAL: Authentication bypass is strictly forbidden in production mode');
  }

  fastify.decorateRequest('auth', undefined);

  fastify.addHook('onRequest', async (request: FastifyRequest, reply: FastifyReply) => {
    // 1. Allowlisted public routes
    if (isPublicRoute(request.url, request.method)) {
      const token = extractAuthToken(request);
      if (!token) {
        request.auth = { role: 'public', tenantId: defaultTenantId };
        return;
      }
      // If a credential was provided on a public route, continue to validate it
    }

    // 2. Test-mode bypass (only allowed in non-production environments)
    if (bypassAuth) {
      request.auth = { role: 'admin', keyId: 'bypass-test-key', tenantId: defaultTenantId };
      return;
    }

    // 3. Agent daemon-facing worker endpoints (handled by agentsRoutes with TEK or Agent tokens)
    if (isAgentDaemonRoute(request.url)) {
      request.auth = { role: 'agent', tenantId: defaultTenantId };
      return;
    }

    // 4. Extract token
    const token = extractAuthToken(request);
    if (!token) {
      return reply.status(401).send({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Valid API key or bearer token required',
        },
      });
    }

    // 5. Check Tenant-Scoped Keys
    if (options.tenantKeyMap) {
      for (const [keyCandidate, keyConfig] of Object.entries(options.tenantKeyMap)) {
        if (timingSafeCompare(token, keyCandidate)) {
          request.auth = {
            role: keyConfig.role,
            keyId: `tenant-key-${keyConfig.tenantId}`,
            tenantId: keyConfig.tenantId,
          };
          break;
        }
      }
    }

    // 6. Verify against Admin Key
    if (!request.auth && effectiveAdminKey && timingSafeCompare(token, effectiveAdminKey)) {
      request.auth = { role: 'admin', keyId: 'admin-key', tenantId: defaultTenantId };
    }

    // 7. Verify against Operator Key
    if (!request.auth && effectiveApiKey && timingSafeCompare(token, effectiveApiKey)) {
      request.auth = { role: 'operator', keyId: 'operator-key', tenantId: defaultTenantId };
    }

    // 8. Fail closed
    if (!request.auth) {
      logger.warn(
        {
          event: 'auth.rejected',
          url: request.url,
          method: request.method,
          ip: request.ip,
        },
        'Request rejected: Invalid API key or bearer token',
      );

      return reply.status(401).send({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Invalid API key or bearer token',
        },
      });
    }

    // 9. Centralized Tenant Verification & Anti-Spoofing Guard (REM-02)
    const isSingleTenant = process.env.SECURITY_LAB_SINGLE_TENANT_MODE === 'true';
    if (!isSingleTenant && request.auth.role !== 'admin') {
      const headerTenant = request.headers['x-tenant-id'];
      if (typeof headerTenant === 'string' && headerTenant.trim().length > 0) {
        const requestedTenantId = headerTenant.trim();
        if (request.auth.tenantId && requestedTenantId !== request.auth.tenantId) {
          logger.warn(
            {
              event: 'tenant.spoof_attempt',
              authenticatedTenantId: request.auth.tenantId,
              requestedTenantId,
              role: request.auth.role,
              url: request.url,
            },
            'Tenant spoofing attempt blocked by preHandler guard',
          );
          return reply.status(403).send({
            success: false,
            error: {
              code: 'TENANT_MISMATCH',
              message: `Tenant spoofing detected: Authenticated tenant is '${request.auth.tenantId}', but requested '${requestedTenantId}'`,
            },
          });
        }
      }
    }
  });
}

export const authPlugin = Object.assign(
  async (fastify: FastifyInstance, options: AuthPluginOptions = {}) => {
    registerAuthHooks(fastify, options);
  },
  {
    [Symbol.for('skip-override')]: true,
  },
);
