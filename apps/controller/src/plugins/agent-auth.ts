import { FastifyRequest } from 'fastify';
import { eq } from 'drizzle-orm';
import { getDatabase } from '../services/db.js';
import { agents } from '../services/db/schema.js';
import { agentDispatcherService } from '../services/agent-dispatcher.service.js';
import {
  verifyAgentRequest,
  computeKeyFingerprint,
} from '@security-lab/crypto';
import { logger } from '@security-lab/logger';

export interface AgentAuthResult {
  agent: typeof agents.$inferSelect | null;
  error?: string;
  code?: string;
}

/**
 * Verifies agent requests via asymmetric Ed25519 signature (Phase 15)
 * or falls back to legacy Bearer token authentication for backwards compatibility.
 */
export async function authenticateAgentRequest(request: FastifyRequest): Promise<AgentAuthResult> {
  const xAgentSignature = request.headers['x-agent-signature'] as string | undefined;
  const xAgentTimestamp = request.headers['x-agent-timestamp'] as string | undefined;
  const xAgentId = request.headers['x-agent-id'] as string | undefined;

  // 1. Asymmetric Cryptographic Attestation Flow (Primary)
  if (xAgentSignature && xAgentSignature.trim().length > 0) {
    if (!xAgentId || !xAgentTimestamp) {
      return {
        agent: null,
        error: 'Missing required headers: X-Agent-Id and X-Agent-Timestamp are required when using asymmetric signature',
        code: 'MALFORMED_REQUEST',
      };
    }

    const { db } = getDatabase();
    if (!db) {
      return { agent: null, error: 'Database unavailable', code: 'INTERNAL_ERROR' };
    }

    const [agent] = await db
      .select()
      .from(agents)
      .where(eq(agents.id, xAgentId.trim()))
      .limit(1);

    if (!agent) {
      logger.warn({ agentId: xAgentId }, 'Agent not found for asymmetric signature authentication');
      return { agent: null, error: `Agent "${xAgentId}" not found`, code: 'UNAUTHORIZED' };
    }

    if (agent.revokedAt) {
      return {
        agent: null,
        error: `Agent has been revoked: ${agent.revocationReason || 'administrative action'}`,
        code: 'AGENT_REVOKED',
      };
    }

    if (!agent.publicKey) {
      logger.warn({ agentId: xAgentId }, 'Agent has no registered public key for asymmetric attestation');
      return {
        agent: null,
        error: 'Agent does not have an enrolled asymmetric public key. Please re-enroll agent.',
        code: 'MISSING_PUBLIC_KEY',
      };
    }

    // Path canonicalization (strip query string)
    const cleanPath = (request.url || '').split('?')[0] || '/';

    const verification = verifyAgentRequest(agent.publicKey, {
      method: request.method,
      path: cleanPath,
      timestamp: xAgentTimestamp.trim(),
      body: request.body,
      signature: xAgentSignature.trim(),
      maxDriftMs: 60000, // 60-second replay window
    });

    if (!verification.valid) {
      logger.warn(
        {
          agentId: agent.id,
          code: verification.code,
          error: verification.error,
          url: cleanPath,
          method: request.method,
          timestamp: xAgentTimestamp,
        },
        'Cryptographic agent signature verification rejected',
      );
      return {
        agent: null,
        error: verification.error || 'Cryptographic signature verification failed',
        code: verification.code || 'INVALID_SIGNATURE',
      };
    }

    return { agent };
  }

  // 2. Legacy Bearer Token / HMAC Fallback Flow (Backwards Compatibility)
  const authHeader = request.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.replace('Bearer ', '').trim();
    const tokenResult = await agentDispatcherService.authenticateAgent(token);
    if (!tokenResult.agent) {
      return {
        agent: null,
        error: tokenResult.error || 'Invalid or expired agent token',
        code: tokenResult.code || 'UNAUTHORIZED',
      };
    }
    return { agent: tokenResult.agent };
  }

  return {
    agent: null,
    error: 'Missing agent credentials: valid X-Agent-Signature or Bearer token required',
    code: 'UNAUTHORIZED',
  };
}
