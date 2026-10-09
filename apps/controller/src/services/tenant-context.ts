import { FastifyRequest } from 'fastify';
import { DEFAULT_TENANT_ID } from './tenants.service.js';
import { logger } from '@security-lab/logger';

export class TenantMismatchError extends Error {
  readonly statusCode = 403;
  readonly code = 'TENANT_MISMATCH';

  constructor(message = 'Tenant header does not match authenticated tenant scope') {
    super(message);
    this.name = 'TenantMismatchError';
  }
}

/**
 * Extracts optional tenant scope for database queries and resource lookups.
 * - For administrators: returns explicit x-tenant-id if provided; otherwise returns undefined
 *   to allow platform-wide administrative visibility and cross-tenant orchestration.
 * - For standard operators/users: returns their bound tenantId. If they attempt to specify
 *   a conflicting x-tenant-id header, rejects with TenantMismatchError (HTTP 403).
 */
export function extractTenantScope(request: FastifyRequest): string | undefined {
  const headerTenantRaw = request.headers['x-tenant-id'];
  const headerTenant = typeof headerTenantRaw === 'string' && headerTenantRaw.trim().length > 0
    ? headerTenantRaw.trim()
    : undefined;

  // Single-tenant local mode override
  if (process.env.SECURITY_LAB_SINGLE_TENANT_MODE === 'true') {
    return headerTenant || DEFAULT_TENANT_ID;
  }

  const auth = request.auth;

  // 1. Admin callers can explicitly specify a target tenant via header,
  // or have unrestricted multi-tenant scope across the system.
  if (auth?.role === 'admin') {
    return headerTenant;
  }

  // 2. Authenticated operator or tenant-bound credentials
  const boundTenantId = auth?.tenantId || DEFAULT_TENANT_ID;

  // 3. Spoofing Guard: If non-admin attempts to supply a conflicting x-tenant-id header, reject immediately
  if (headerTenant && headerTenant !== boundTenantId) {
    logger.warn(
      {
        event: 'security.tenant_spoof_attempt',
        callerKeyId: auth?.keyId,
        boundTenantId,
        headerTenant,
        url: request.url,
        method: request.method,
        ip: request.ip,
      },
      'Blocked active tenant spoofing attempt: client header does not match bound tenant',
    );
    throw new TenantMismatchError(`Access denied: client cannot impersonate tenant "${headerTenant}"`);
  }

  return boundTenantId;
}

/**
 * Extracts trusted tenant ID strictly from authenticated context.
 * Guaranteed to return a non-empty string.
 * Used when persisting new tenant-owned entities (e.g. creating projects).
 */
export function extractTenantId(request: FastifyRequest): string {
  const scope = extractTenantScope(request);
  return scope || request.auth?.tenantId || DEFAULT_TENANT_ID;
}
