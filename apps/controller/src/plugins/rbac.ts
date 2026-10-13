import { FastifyRequest, FastifyReply } from 'fastify';
import { Role } from '@security-lab/contracts';
import { logger } from '@security-lab/logger';

/**
 * Normalizes legacy or mixed-case roles to canonical contracts Role ('ADMIN', 'ENGINEER', 'AUDITOR').
 */
export function normalizeRole(role?: string | null): Role | null {
  if (!role) return null;
  const upper = role.toUpperCase();
  if (upper === 'ADMIN' || upper === 'OPERATOR') return 'ADMIN';
  if (upper === 'ENGINEER') return 'ENGINEER';
  if (upper === 'AUDITOR' || upper === 'VIEWER') return 'AUDITOR';
  return null;
}

/**
 * Fastify preHandler hook generator that enforces Role-Based Access Control (RBAC).
 * Evaluates request.user?.role and fallback request.auth?.role against allowedRoles.
 * Emits structured observability logs on rejection.
 */
export function requireRole(allowedRoles: Role[]) {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    // If route was explicitly identified as public by auth hook (e.g. non-prod reports, health), allow through
    if (request.auth?.role === 'public') {
      return;
    }

    // Determine effective user role
    const rawRole = request.user?.role || request.auth?.role;
    const normalized = normalizeRole(rawRole);

    if (!normalized || !allowedRoles.includes(normalized)) {
      const actorId =
        request.user?.id ||
        request.auth?.userId ||
        request.auth?.keyId ||
        'anonymous';

      logger.warn(
        {
          event: 'rbac.rejected',
          actor_id: actorId,
          requested_role: allowedRoles,
          user_role: normalized || rawRole || 'none',
          endpoint: request.url,
          method: request.method,
          ip: request.ip,
        },
        `RBAC authorization rejected: Actor '${actorId}' with role '${normalized || rawRole}' does not possess required roles [${allowedRoles.join(', ')}]`,
      );

      return reply.status(403).send({
        success: false,
        error: {
          code: 'FORBIDDEN',
          message: `Insufficient permissions: Requires one of roles [${allowedRoles.join(', ')}]`,
        },
      });
    }
  };
}

export const requireAdmin = requireRole(['ADMIN']);
export const requireEngineer = requireRole(['ADMIN', 'ENGINEER']);
export const requireAuditor = requireRole(['ADMIN', 'ENGINEER', 'AUDITOR']);
