import {
  TargetScope,
  ScopeValidationResult,
  ScopeCheckOptions,
  validateUrlAgainstScope,
  validateUrlWithDns,
  canonicalizeIp,
  parseIpv4ToBytes,
  parseIpv6ToBytes,
  matchIpv4Cidr,
  matchIpv6Cidr,
  isProhibitedIp,
  matchesAllowedHost,
  isCloudMetadataHost,
} from '@security-lab/domain';

export {
  validateUrlAgainstScope,
  validateUrlWithDns,
  canonicalizeIp,
  parseIpv4ToBytes,
  parseIpv6ToBytes,
  matchIpv4Cidr,
  matchIpv6Cidr,
  isProhibitedIp,
  matchesAllowedHost,
  isCloudMetadataHost,
};

export type { ScopeValidationResult, ScopeCheckOptions };

/**
 * Validates a candidate target URL against a registered TargetScope.
 * Combines synchronous syntax and CIDR checks with asynchronous DNS inspection.
 */
export async function validateTargetInScope(
  candidateUrl: string,
  scope: TargetScope,
  options: ScopeCheckOptions = {},
): Promise<ScopeValidationResult> {
  return validateUrlWithDns(candidateUrl, scope, options);
}

/**
 * Validates whether an IP address matches a given CIDR notation (IPv4 or IPv6).
 */
export function isIpInCidr(ip: string, cidr: string): boolean {
  const canonical = canonicalizeIp(ip);
  if (!canonical) return false;

  const v4Bytes = parseIpv4ToBytes(canonical);
  if (v4Bytes) {
    return matchIpv4Cidr(v4Bytes, cidr);
  }

  const v6Bytes = parseIpv6ToBytes(canonical);
  if (v6Bytes) {
    return matchIpv6Cidr(v6Bytes, cidr);
  }

  return false;
}
