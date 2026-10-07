import { FastifyRequest } from 'fastify';
import { DEFAULT_TENANT_ID } from './tenants.service.js';

export function extractTenantId(request: FastifyRequest): string {
  const headerTenant = request.headers['x-tenant-id'];
  if (headerTenant && typeof headerTenant === 'string' && headerTenant.trim().length > 0) {
    return headerTenant.trim();
  }

  const query = request.query as Record<string, unknown> | undefined;
  if (query && typeof query.tenantId === 'string' && query.tenantId.trim().length > 0) {
    return query.tenantId.trim();
  }

  return DEFAULT_TENANT_ID;
}
