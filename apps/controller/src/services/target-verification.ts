import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import { eq } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { targets } from './db/schema.js';
import { targetsService } from './targets.service.js';
import { logger } from '@security-lab/logger';
import { executeHttpRequest } from '@security-lab/test-runner';
import { canonicalizeIp } from '@security-lab/domain';

export type VerificationMethodType = 'DNS_TXT' | 'HTTP_WELL_KNOWN' | 'AUTO' | 'LOCAL_OVERRIDE';

export interface VerificationResult {
  verified: boolean;
  status: 'VERIFIED' | 'FAILED' | 'PENDING';
  method?: string;
  message: string;
  details?: Record<string, unknown>;
}

export interface ChallengeInstructions {
  targetId: string;
  token: string;
  status: string;
  verifiedAt?: string | null;
  verificationMethod?: string | null;
  dns: {
    recordType: 'TXT';
    recordName: string;
    recordValue: string;
    alternativeRecordName: string;
  };
  http: {
    url: string;
    expectedContent: string;
  };
}

/**
 * Checks if a hostname corresponds to loopback (local development).
 */
export function isLocalHost(host: string): boolean {
  const clean = host.replace(/^\[|\]$/g, '').toLowerCase().trim();
  if (clean === 'localhost' || clean === '127.0.0.1' || clean === '::1') {
    return true;
  }
  const canon = canonicalizeIp(clean);
  if (canon && (canon.startsWith('127.') || canon === '::1' || canon === '127.0.0.1')) {
    return true;
  }
  return false;
}

/**
 * Generates a cryptographically strong 64-hex-character challenge token.
 */
export function generateChallengeToken(): string {
  return `sec-${crypto.randomBytes(28).toString('hex')}`;
}

export class TargetVerificationService {
  /**
   * Generates or retrieves challenge instructions for a target.
   */
  async getChallengeInstructions(
    targetId: string,
    tenantId?: string,
  ): Promise<ChallengeInstructions> {
    const target = await targetsService.getTargetById(targetId, tenantId);
    if (!target) {
      throw new Error(`Target "${targetId}" not found`);
    }

    const { db } = getDatabase();
    let token = target.verificationToken;

    if (!token) {
      token = generateChallengeToken();
      await db
        .update(targets)
        .set({
          verificationToken: token,
          updatedAt: new Date(),
        })
        .where(eq(targets.id, targetId));
    }

    const parsedUrl = new URL(target.baseUrl);
    const domain = parsedUrl.hostname;
    const challengeHost = `_security-lab-challenge.${domain}`;

    return {
      targetId: target.id,
      token,
      status: target.verificationStatus || 'PENDING',
      verifiedAt: target.verifiedAt?.toISOString() || null,
      verificationMethod: target.verificationMethod || null,
      dns: {
        recordType: 'TXT',
        recordName: challengeHost,
        recordValue: token,
        alternativeRecordName: domain,
      },
      http: {
        url: `${target.baseUrl.replace(/\/+$/, '')}/.well-known/security-lab-challenge.txt`,
        expectedContent: token,
      },
    };
  }

  /**
   * Verifies DNS TXT record for domain ownership.
   * Checks both `_security-lab-challenge.<domain>` and `<domain>`.
   */
  async verifyDnsTxt(domain: string, expectedToken: string): Promise<{ success: boolean; details: string }> {
    const candidates = [`_security-lab-challenge.${domain}`, domain];
    const attemptedErrors: string[] = [];

    for (const host of candidates) {
      try {
        const records = await dns.resolveTxt(host);
        // Flatten chunks within each TXT record entry
        const flatRecords = records.map((entry) => entry.join(''));
        logger.debug({ host, flatRecords }, 'DNS TXT records resolved');

        for (const record of flatRecords) {
          const trimmed = record.trim();
          if (
            trimmed === expectedToken ||
            trimmed === `security-lab-verification=${expectedToken}` ||
            trimmed.includes(expectedToken)
          ) {
            return {
              success: true,
              details: `Found matching TXT record on "${host}": ${trimmed}`,
            };
          }
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        attemptedErrors.push(`Host "${host}": ${msg}`);
      }
    }

    return {
      success: false,
      details: `No matching TXT record containing "${expectedToken}". Resolvers returned: ${attemptedErrors.join('; ')}`,
    };
  }

  /**
   * Verifies target ownership via HTTP `/.well-known/security-lab-challenge.txt`.
   */
  async verifyHttpWellKnown(
    baseUrl: string,
    expectedToken: string,
  ): Promise<{ success: boolean; details: string }> {
    const targetUrl = `${baseUrl.replace(/\/+$/, '')}/.well-known/security-lab-challenge.txt`;

    try {
      // Use executeHttpRequest to benefit from SSRF checks and secure agent
      const parsed = new URL(targetUrl);
      const host = parsed.hostname;
      const isLocal = isLocalHost(host);

      const response = await executeHttpRequest(targetUrl, {
        method: 'GET',
        headers: {
          'User-Agent': 'SecurityLab-OwnershipVerifier/1.0',
          Accept: 'text/plain',
        },
        dnsOptions: {
          allowPrivateIps: isLocal,
          allowLoopback: isLocal,
        },
      });

      if (response.status < 200 || response.status >= 300) {
        return {
          success: false,
          details: `HTTP GET "${targetUrl}" returned HTTP status ${response.status}`,
        };
      }

      const bodyText = (await response.text()).trim();
      if (bodyText === expectedToken || bodyText.includes(expectedToken)) {
        return {
          success: true,
          details: `HTTP GET "${targetUrl}" successfully returned matching challenge token`,
        };
      }

      return {
        success: false,
        details: `HTTP GET "${targetUrl}" returned non-matching body: "${bodyText.substring(0, 100)}"`,
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        success: false,
        details: `HTTP verification request to "${targetUrl}" failed: ${msg}`,
      };
    }
  }

  /**
   * Performs ownership verification challenge for a target.
   */
  async verifyTargetOwnership(
    targetId: string,
    requestedMethod: VerificationMethodType = 'AUTO',
    tenantId?: string,
  ): Promise<VerificationResult> {
    const target = await targetsService.getTargetById(targetId, tenantId);
    if (!target) {
      throw new Error(`Target "${targetId}" not found`);
    }

    const { db } = getDatabase();
    const parsed = new URL(target.baseUrl);
    const host = parsed.hostname;

    // Check if localhost / 127.0.0.1
    if (isLocalHost(host)) {
      await db
        .update(targets)
        .set({
          verificationStatus: 'VERIFIED',
          verificationMethod: 'LOCAL_OVERRIDE',
          verifiedAt: new Date(),
          updatedAt: new Date(),
        })
        .where(eq(targets.id, targetId));

      return {
        verified: true,
        status: 'VERIFIED',
        method: 'LOCAL_OVERRIDE',
        message: 'Localhost and loopback targets are automatically verified for local development.',
      };
    }

    // Ensure challenge token exists
    let token = target.verificationToken;
    if (!token) {
      token = generateChallengeToken();
      await db
        .update(targets)
        .set({
          verificationToken: token,
          updatedAt: new Date(),
        })
        .where(eq(targets.id, targetId));
    }

    let verified = false;
    let successfulMethod: string | undefined;
    const diagnostics: Record<string, unknown> = {};

    // 1. Try DNS TXT if requested or AUTO
    if (requestedMethod === 'DNS_TXT' || requestedMethod === 'AUTO') {
      const dnsResult = await this.verifyDnsTxt(host, token);
      diagnostics.dnsTxt = dnsResult;
      if (dnsResult.success) {
        verified = true;
        successfulMethod = 'DNS_TXT';
      }
    }

    // 2. Try HTTP Well-Known if not verified and (HTTP_WELL_KNOWN or AUTO)
    if (!verified && (requestedMethod === 'HTTP_WELL_KNOWN' || requestedMethod === 'AUTO')) {
      const httpResult = await this.verifyHttpWellKnown(target.baseUrl, token);
      diagnostics.httpWellKnown = httpResult;
      if (httpResult.success) {
        verified = true;
        successfulMethod = 'HTTP_WELL_KNOWN';
      }
    }

    if (verified && successfulMethod) {
      const verifiedAt = new Date();
      await db
        .update(targets)
        .set({
          verificationStatus: 'VERIFIED',
          verificationMethod: successfulMethod,
          verifiedAt,
          updatedAt: new Date(),
        })
        .where(eq(targets.id, targetId));

      logger.info(
        { targetId, host, method: successfulMethod },
        'Target ownership successfully verified',
      );

      return {
        verified: true,
        status: 'VERIFIED',
        method: successfulMethod,
        message: `Target ownership verified successfully via ${successfulMethod}`,
        details: diagnostics,
      };
    }

    // If verification failed
    await db
      .update(targets)
      .set({
        verificationStatus: 'FAILED',
        updatedAt: new Date(),
      })
      .where(eq(targets.id, targetId));

    logger.warn(
      { targetId, host, requestedMethod, diagnostics },
      'Target ownership verification challenge failed',
    );

    return {
      verified: false,
      status: 'FAILED',
      message: 'Target ownership verification challenge failed. Check DNS TXT or HTTP .well-known configuration.',
      details: diagnostics,
    };
  }
}

export const targetVerificationService = new TargetVerificationService();
