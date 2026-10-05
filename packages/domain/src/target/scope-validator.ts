import { TargetScope, TargetTestingCapabilities } from './index.js';

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
}

// Prohibited Link-Local Cloud Metadata addresses
const CLOUD_METADATA_IPS = new Set([
  '169.254.169.254', // AWS, GCP, Azure, OpenStack
  'fd00:ec2::254',   // AWS IPv6 metadata
  'metadata.google.internal',
]);

/**
 * Validates a candidate URL and execution parameters strictly against a registered TargetScope.
 * This function forms the primary security boundary of the platform.
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

  // 1. Protocol check: only HTTP and HTTPS permitted
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    violations.push(`Protocol "${parsed.protocol}" is forbidden. Only "http:" and "https:" are permitted.`);
  }

  // 2. Cloud metadata IP protection
  const hostname = parsed.hostname.toLowerCase();
  if (CLOUD_METADATA_IPS.has(hostname)) {
    violations.push(`Access to cloud metadata IP/host "${hostname}" is strictly prohibited.`);
  }

  // 3. Allowed hosts validation
  const isAllowedHost = scope.allowedHosts.some((allowedHost) => {
    const cleanAllowed = allowedHost.toLowerCase().trim();
    if (cleanAllowed === hostname) return true;
    // Support wildcard subdomain e.g. *.example.com
    if (cleanAllowed.startsWith('*.') && hostname.endsWith(cleanAllowed.slice(1))) {
      return true;
    }
    return false;
  });

  if (!isAllowedHost) {
    violations.push(
      `Host "${hostname}" is not within the authorized scope allowedHosts: [${scope.allowedHosts.join(', ')}]`,
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
    if (cleanExcluded && (pathname === cleanExcluded || pathname.startsWith(cleanExcluded.endsWith('/') ? cleanExcluded : `${cleanExcluded}/`))) {
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
    matchedHost: isAllowedHost ? hostname : undefined,
  };
}
