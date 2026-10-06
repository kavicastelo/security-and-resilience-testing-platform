import dns from 'node:dns/promises';
import { TargetScope, TargetTestingCapabilities } from './index.js';
import {
  canonicalizeIp,
  isCloudMetadataHost,
  isProhibitedIp,
  matchesAllowedHost,
} from './ip-utils.js';

export interface ScopeValidationResult {
  valid: boolean;
  violations: string[];
  normalizedUrl?: string;
  matchedHost?: string;
}

export interface ScopeCheckOptions {
  requestedCapability?: keyof TargetTestingCapabilities;
  requestedRps?: number;
  requestedConcurrency?: number;
  allowUnresolvedDns?: boolean;
}

/**
 * Validates a candidate URL and execution parameters strictly against a registered TargetScope.
 * This function forms the primary synchronous security boundary of the platform.
 * It canonicalizes all alternative IP encodings (hex, octal, decimal, IPv4-mapped IPv6)
 * and verifies protocol, cloud metadata, CIDR ranges, allowed hosts, ports, and paths.
 */
export function validateUrlAgainstScope(
  candidateUrl: string,
  scope: TargetScope,
  options: ScopeCheckOptions = {},
): ScopeValidationResult {
  const violations: string[] = [];

  let parsed: URL;
  try {
    parsed = new URL(candidateUrl);
  } catch {
    return {
      valid: false,
      violations: [`Invalid URL format: "${candidateUrl}" could not be parsed as a standard HTTP/HTTPS URI`],
    };
  }

  // 1. Protocol check: strictly HTTP and HTTPS permitted
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    violations.push(`Protocol "${parsed.protocol}" is forbidden. Only "http:" and "https:" are permitted.`);
  }

  // 2. Hostname canonicalization and cloud metadata protection
  const cleanHost = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase().trim();

  if (isCloudMetadataHost(cleanHost)) {
    violations.push(`Access to cloud metadata IP/host "${cleanHost}" is strictly prohibited.`);
  }

  // 3. Alternative IP representation canonicalization & boundary check
  const canonicalIp = canonicalizeIp(cleanHost);
  let isAllowedHost = false;

  if (canonicalIp) {
    // If the host is an IP, check if loopback or private ranges are explicitly authorized in scope
    const allowLoopback = scope.allowedHosts.some(
      (h) => matchesAllowedHost('127.0.0.1', h) || h.toLowerCase() === 'localhost',
    );
    const allowPrivate =
      scope.allowPrivateIps === true ||
      scope.allowedHosts.some((h) => matchesAllowedHost(canonicalIp, h));

    const ipCheck = isProhibitedIp(canonicalIp, { allowPrivate, allowLoopback });
    if (ipCheck.prohibited && ipCheck.reason) {
      violations.push(ipCheck.reason);
    }

    // Must also be within scope.allowedHosts
    isAllowedHost = scope.allowedHosts.some(
      (allowedHost) =>
        matchesAllowedHost(cleanHost, allowedHost) ||
        matchesAllowedHost(canonicalIp, allowedHost),
    );
  } else {
    // Host is a domain name: verify against allowedHosts with exact wildcard subdomain matching
    isAllowedHost = scope.allowedHosts.some((allowedHost) =>
      matchesAllowedHost(cleanHost, allowedHost),
    );
  }

  if (!isAllowedHost) {
    violations.push(
      `Host "${cleanHost}" is not within the authorized scope allowedHosts: [${scope.allowedHosts.join(', ')}]`,
    );
  }

  // 4. Allowed ports validation
  const effectivePort = parsed.port
    ? parseInt(parsed.port, 10)
    : parsed.protocol === 'https:'
      ? 443
      : 80;

  if (!scope.allowedPorts.includes(effectivePort)) {
    violations.push(
      `Port "${effectivePort}" is not within authorized scope allowedPorts: [${scope.allowedPorts.join(', ')}]`,
    );
  }

  // 5. Excluded paths protection
  const pathname = parsed.pathname;
  for (const excludedPath of scope.excludedPaths) {
    const cleanExcluded = excludedPath.trim();
    if (
      cleanExcluded &&
      (pathname === cleanExcluded ||
        pathname.startsWith(cleanExcluded.endsWith('/') ? cleanExcluded : `${cleanExcluded}/`))
    ) {
      violations.push(`Path "${pathname}" matches excluded sensitive path: "${cleanExcluded}"`);
    }
  }

  // 6. Capability authorization gate
  if (options.requestedCapability) {
    const isPermitted = scope.testing[options.requestedCapability];
    if (!isPermitted) {
      violations.push(
        `Execution capability "${options.requestedCapability}" is disabled for this target. Explicit opt-in required in target scope.`,
      );
    }
  }

  // 7. Safety limits clamps
  if (options.requestedRps && options.requestedRps > scope.limits.maxRps) {
    violations.push(
      `Requested RPS (${options.requestedRps}) exceeds target scope limit of ${scope.limits.maxRps} RPS`,
    );
  }

  if (options.requestedConcurrency && options.requestedConcurrency > scope.limits.maxConcurrency) {
    violations.push(
      `Requested concurrency (${options.requestedConcurrency}) exceeds target scope limit of ${scope.limits.maxConcurrency}`,
    );
  }

  return {
    valid: violations.length === 0,
    violations,
    normalizedUrl: parsed.toString(),
    matchedHost: isAllowedHost ? cleanHost : undefined,
  };
}

/**
 * Asynchronously validates a candidate URL against TargetScope, including DNS resolution
 * to protect against DNS rebinding, split-horizon DNS, and unauthorized private IP resolution.
 */
export async function validateUrlWithDns(
  candidateUrl: string,
  scope: TargetScope,
  options: ScopeCheckOptions = {},
): Promise<ScopeValidationResult> {
  // First execute static security boundary checks
  const staticResult = validateUrlAgainstScope(candidateUrl, scope, options);
  if (!staticResult.valid) {
    return staticResult;
  }

  let parsed: URL;
  try {
    parsed = new URL(candidateUrl);
  } catch {
    return staticResult;
  }

  const cleanHost = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase().trim();
  const directIp = canonicalizeIp(cleanHost);
  if (directIp) {
    // Already validated as direct IP
    return staticResult;
  }

  // Host is a domain name: perform DNS resolution to evaluate resolved A and AAAA addresses
  try {
    const addresses = await dns.lookup(cleanHost, { all: true });
    const dnsViolations: string[] = [];

    const allowLoopback = scope.allowedHosts.some(
      (h) => h.toLowerCase() === 'localhost' || matchesAllowedHost('127.0.0.1', h),
    );
    const allowPrivate =
      scope.allowPrivateIps === true ||
      scope.allowedHosts.some((h) => {
        const c = canonicalizeIp(h);
        return c !== null && !isProhibitedIp(c, { allowPrivate: true }).prohibited;
      });

    for (const record of addresses) {
      const canonResolved = canonicalizeIp(record.address) || record.address;
      const ipCheck = isProhibitedIp(canonResolved, { allowPrivate, allowLoopback });
      if (ipCheck.prohibited && ipCheck.reason) {
        dnsViolations.push(
          `Domain "${cleanHost}" resolved to prohibited address "${record.address}": ${ipCheck.reason} SSRF / DNS rebinding protection triggered.`,
        );
      }
    }

    if (dnsViolations.length > 0) {
      return {
        valid: false,
        violations: [...staticResult.violations, ...dnsViolations],
        normalizedUrl: parsed.toString(),
      };
    }
  } catch (err: unknown) {
    if (options.allowUnresolvedDns) {
      return staticResult;
    }
    const msg = err instanceof Error ? err.message : String(err);
    return {
      valid: false,
      violations: [`DNS resolution failed for host "${cleanHost}": ${msg}`],
      normalizedUrl: parsed.toString(),
    };
  }

  return staticResult;
}
