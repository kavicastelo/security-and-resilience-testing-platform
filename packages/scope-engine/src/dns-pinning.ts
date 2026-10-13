import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns/promises';
import {
  TargetScope,
  canonicalizeIp,
  isProhibitedIp,
  matchesAllowedHost,
  isCloudMetadataHost,
} from '@security-lab/domain';
import { logger } from '@security-lab/logger';

export class DnsPinningError extends Error {
  readonly hostname: string;
  readonly resolvedIp?: string;
  readonly violations: string[];

  constructor(message: string, hostname: string, resolvedIp?: string, violations: string[] = []) {
    super(message);
    this.name = 'DnsPinningError';
    this.hostname = hostname;
    this.resolvedIp = resolvedIp;
    this.violations = violations;
  }
}

export class ScopeViolationError extends Error {
  readonly violations: string[];

  constructor(message: string, violations: string[] = []) {
    super(message);
    this.name = 'ScopeViolationError';
    this.violations = violations;
  }
}

export interface PinnedDnsRecord {
  ip: string;
  family: 4 | 6;
  pinnedAt: number;
}

export interface DnsPinningOptions {
  allowPrivateIps?: boolean;
  allowLoopback?: boolean;
  ttlMs?: number;
  cache?: DnsPinningCache;
  customResolver?: (hostname: string) => Promise<string[] | { address: string; family: number }[]>;
  dnsResolver?: (hostname: string) => Promise<string[] | { address: string; family: number }[]>;
}

export class DnsPinningCache {
  private cache = new Map<string, PinnedDnsRecord>();

  get(hostname: string, ttlMs: number = 60000): PinnedDnsRecord | null {
    const clean = hostname.toLowerCase().trim();
    const entry = this.cache.get(clean);
    if (!entry) return null;
    if (Date.now() - entry.pinnedAt > ttlMs) {
      this.cache.delete(clean);
      return null;
    }
    return entry;
  }

  set(hostname: string, ip: string, family: 4 | 6): void {
    const clean = hostname.toLowerCase().trim();
    this.cache.set(clean, {
      ip,
      family,
      pinnedAt: Date.now(),
    });
  }

  clear(): void {
    this.cache.clear();
  }
}

export const globalDnsPinningCache = new DnsPinningCache();

/**
 * Creates a pre-socket DNS lookup hook function compatible with Node.js http.Agent,
 * https.Agent, and net.Socket options.lookup.
 *
 * Enforces:
 * 1. Immediate resolution prior to socket connection.
 * 2. Strict anti-SSRF verification (cloud metadata, loopback, link-local, private RFC 1918).
 * 3. Scope boundary alignment with scope.allowedHosts.
 * 4. Pinned IP caching preventing Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding.
 */
export function createDnsPinningLookup(
  scopeOrOptions?: TargetScope | (DnsPinningOptions & { scope?: TargetScope }),
  optionsOrCache?: DnsPinningOptions | DnsPinningCache,
  cacheArg?: DnsPinningCache,
) {
  let scope: TargetScope | undefined;
  let options: DnsPinningOptions = {};
  let cache: DnsPinningCache = globalDnsPinningCache;

  if (scopeOrOptions && ('allowedHosts' in scopeOrOptions || 'testing' in scopeOrOptions)) {
    scope = scopeOrOptions as TargetScope;
    if (optionsOrCache && !(optionsOrCache instanceof DnsPinningCache)) {
      options = optionsOrCache as DnsPinningOptions;
      if (cacheArg) cache = cacheArg;
    } else if (optionsOrCache instanceof DnsPinningCache) {
      cache = optionsOrCache;
    }
  } else if (scopeOrOptions) {
    options = scopeOrOptions as DnsPinningOptions;
    scope = (scopeOrOptions as { scope?: TargetScope }).scope;
    if (options.cache) cache = options.cache;
    if (optionsOrCache instanceof DnsPinningCache) cache = optionsOrCache;
  }

  const allowPrivate =
    options.allowPrivateIps ??
    scope?.allowPrivateIps ??
    false;

  const allowLoopback =
    options.allowLoopback ??
    (scope?.allowedHosts
      ? scope.allowedHosts.some(
          (h: string) => h.toLowerCase() === 'localhost' || matchesAllowedHost('127.0.0.1', h),
        )
      : false);

  return (
    hostname: string,
    _lookupOpts: unknown,
    callback: (err: NodeJS.ErrnoException | Error | null, address: string, family?: number) => void,
  ): void => {
    const cleanHost = hostname.replace(/^\[|\]$/g, '').toLowerCase().trim();

    // 1. Direct Cloud Metadata Host check
    if (isCloudMetadataHost(cleanHost)) {
      const err = new DnsPinningError(
        `Pre-socket DNS pinning rejected access to cloud metadata host "${cleanHost}"`,
        cleanHost,
        cleanHost,
        [`Access to cloud metadata host "${cleanHost}" is strictly prohibited`],
      );
      logger.warn({ event: 'dns_pinning.blocked', hostname: cleanHost, reason: 'cloud_metadata' }, err.message);
      return callback(err, '', 4);
    }

    // 2. Direct IP Address Literal handling
    const directIp = canonicalizeIp(cleanHost);
    if (directIp) {
      const check = isProhibitedIp(directIp, { allowPrivate, allowLoopback });
      if (check.prohibited && check.reason) {
        const err = new DnsPinningError(
          `Pre-socket DNS pinning blocked direct IP connection to "${directIp}": ${check.reason}`,
          cleanHost,
          directIp,
          [check.reason],
        );
        logger.warn({ event: 'dns_pinning.blocked', ip: directIp, reason: check.reason }, err.message);
        return callback(err, '', 4);
      }

      // Check whether direct IP is in scope.allowedHosts if scope is specified
      if (scope?.allowedHosts && scope.allowedHosts.length > 0) {
        const matchesScope = scope.allowedHosts.some(
          (h: string) => matchesAllowedHost(cleanHost, h) || matchesAllowedHost(directIp, h),
        );
        if (!matchesScope) {
          const err = new ScopeViolationError(
            `Direct IP "${directIp}" is not in target scope allowedHosts: [${scope.allowedHosts.join(', ')}]`,
            [`Direct IP "${directIp}" outside allowedHosts`],
          );
          return callback(err, '', 4);
        }
      }

      const family = directIp.includes(':') ? 6 : 4;
      return callback(null, directIp, family);
    }

    // 3. Domain Name: Check for pinned IP in cache
    const ttl = options.ttlMs ?? 60000;
    const pinned = cache.get(cleanHost, ttl);
    if (pinned) {
      logger.debug(
        { event: 'dns_pinning.cache_hit', hostname: cleanHost, ip: pinned.ip },
        `Using pinned IP ${pinned.ip} for host ${cleanHost}`,
      );
      return callback(null, pinned.ip, pinned.family);
    }

    // 4. Resolve domain name and evaluate every resolved candidate IP
    (async () => {
      try {
        let addresses: { address: string; family: number }[] = [];

        const resolver = options.customResolver || options.dnsResolver;
        if (resolver) {
          const customResult = await resolver(cleanHost);
          addresses = customResult.map((item) =>
            typeof item === 'string'
              ? { address: item, family: item.includes(':') ? 6 : 4 }
              : item,
          );
        } else {
          const lookupResults = await dns.lookup(cleanHost, { all: true });
          addresses = lookupResults;
        }

        if (!addresses || addresses.length === 0) {
          throw new DnsPinningError(
            `DNS resolution returned zero records for host "${cleanHost}"`,
            cleanHost,
          );
        }

        // Validate each resolved IP against prohibited ranges (anti-SSRF / DNS rebinding)
        for (const candidate of addresses) {
          const canonCandidate = canonicalizeIp(candidate.address) || candidate.address;
          const ipCheck = isProhibitedIp(canonCandidate, { allowPrivate, allowLoopback });
          if (ipCheck.prohibited && ipCheck.reason) {
            const rebindingMsg = `DNS rebinding protection triggered: Host "${cleanHost}" resolved to prohibited address "${candidate.address}": ${ipCheck.reason}`;
            logger.warn(
              {
                event: 'dns_rebinding.detected',
                hostname: cleanHost,
                resolvedIp: candidate.address,
                reason: ipCheck.reason,
              },
              rebindingMsg,
            );
            throw new DnsPinningError(rebindingMsg, cleanHost, candidate.address, [ipCheck.reason]);
          }
        }

        // Validate that domain matches scope.allowedHosts if defined
        if (scope?.allowedHosts && scope.allowedHosts.length > 0) {
          const isAllowedDomain = scope.allowedHosts.some((h: string) => matchesAllowedHost(cleanHost, h));
          if (!isAllowedDomain) {
            throw new ScopeViolationError(
              `Host "${cleanHost}" is not within authorized scope allowedHosts: [${scope.allowedHosts.join(', ')}]`,
              [`Host "${cleanHost}" is not in scope allowedHosts`],
            );
          }
        }

        // Pin the first verified IP
        const primary = addresses[0]!;
        const verifiedIp = canonicalizeIp(primary.address) || primary.address;
        const family = (primary.family === 6 || verifiedIp.includes(':')) ? 6 : 4;

        cache.set(cleanHost, verifiedIp, family);
        logger.info(
          {
            event: 'dns_pinning.pinned',
            hostname: cleanHost,
            pinnedIp: verifiedIp,
            family,
          },
          `Pre-socket DNS pinning established: ${cleanHost} -> ${verifiedIp}`,
        );

        callback(null, verifiedIp, family);
      } catch (err: unknown) {
        callback(err instanceof Error ? err : new Error(String(err)), '', 4);
      }
    })();
  };
}

/**
 * Creates an http.Agent with pre-socket DNS pinning enforced.
 */
export function createSecureHttpAgent(
  scope: TargetScope,
  options: DnsPinningOptions = {},
  cache?: DnsPinningCache,
): http.Agent {
  return new http.Agent({
    keepAlive: false,
    lookup: createDnsPinningLookup(scope, options, cache) as any,
  });
}

/**
 * Creates an https.Agent with pre-socket DNS pinning enforced.
 */
export function createSecureHttpsAgent(
  scope: TargetScope,
  options: DnsPinningOptions = {},
  cache?: DnsPinningCache,
): https.Agent {
  return new https.Agent({
    keepAlive: false,
    lookup: createDnsPinningLookup(scope, options, cache) as any,
  });
}

/**
 * Explicitly resolves, pins, and verifies a hostname or URL against scope boundaries.
 */
export async function pinDnsResolution(
  hostnameOrUrl: string,
  scope: TargetScope,
  options: DnsPinningOptions = {},
  cache: DnsPinningCache = globalDnsPinningCache,
): Promise<{ ip: string; family: 4 | 6; hostname: string }> {
  let hostname = hostnameOrUrl;
  try {
    const parsed = new URL(hostnameOrUrl);
    hostname = parsed.hostname;
  } catch {
    // Treat as raw hostname
  }

  const lookup = createDnsPinningLookup(scope, options, cache);

  return new Promise((resolve, reject) => {
    lookup(hostname, {}, (err, address, family) => {
      if (err) {
        return reject(err);
      }
      if (!address) {
        return reject(new DnsPinningError(`DNS pinning yielded null address for host ${hostname}`, hostname));
      }
      resolve({
        ip: address,
        family: (family === 6 || address.includes(':')) ? 6 : 4,
        hostname,
      });
    });
  });
}
