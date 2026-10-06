/**
 * Parses any valid IPv4 address in standard dotted-quad, octal, hexadecimal,
 * decimal integer, or mixed shorthand format into a 4-byte Uint8Array.
 * Returns null if the input is not a valid IPv4 representation.
 */
export function parseIpv4ToBytes(input: string): Uint8Array | null {
  const trimmed = input.trim().toLowerCase();
  if (!trimmed) return null;

  // Single number notation (decimal, hex, or octal integer)
  if (/^(0x[0-9a-f]+|0[0-7]+|\d+)$/i.test(trimmed)) {
    let num: number;
    if (trimmed.startsWith('0x')) {
      num = parseInt(trimmed, 16);
    } else if (trimmed.startsWith('0') && trimmed.length > 1) {
      num = parseInt(trimmed, 8);
    } else {
      num = parseInt(trimmed, 10);
    }
    if (isNaN(num) || num < 0 || num > 0xffffffff) return null;
    return new Uint8Array([
      (num >>> 24) & 0xff,
      (num >>> 16) & 0xff,
      (num >>> 8) & 0xff,
      num & 0xff,
    ]);
  }

  // Dotted parts notation (1 to 4 parts)
  const parts = trimmed.split('.');
  if (parts.length < 1 || parts.length > 4) return null;

  const parsedParts: number[] = [];
  for (const part of parts) {
    if (!/^(0x[0-9a-f]+|0[0-7]+|\d+)$/i.test(part)) return null;
    let val: number;
    if (part.startsWith('0x')) {
      val = parseInt(part, 16);
    } else if (part.startsWith('0') && part.length > 1) {
      val = parseInt(part, 8);
    } else {
      val = parseInt(part, 10);
    }
    if (isNaN(val) || val < 0) return null;
    parsedParts.push(val);
  }

  if (parsedParts.length === 4) {
    const p0 = parsedParts[0]!;
    const p1 = parsedParts[1]!;
    const p2 = parsedParts[2]!;
    const p3 = parsedParts[3]!;
    if (p0 > 255 || p1 > 255 || p2 > 255 || p3 > 255) return null;
    return new Uint8Array([p0, p1, p2, p3]);
  } else if (parsedParts.length === 3) {
    const p0 = parsedParts[0]!;
    const p1 = parsedParts[1]!;
    const p2 = parsedParts[2]!;
    if (p0 > 255 || p1 > 255 || p2 > 65535) return null;
    return new Uint8Array([
      p0,
      p1,
      (p2 >>> 8) & 0xff,
      p2 & 0xff,
    ]);
  } else if (parsedParts.length === 2) {
    const p0 = parsedParts[0]!;
    const p1 = parsedParts[1]!;
    if (p0 > 255 || p1 > 16777215) return null;
    return new Uint8Array([
      p0,
      (p1 >>> 16) & 0xff,
      (p1 >>> 8) & 0xff,
      p1 & 0xff,
    ]);
  } else if (parsedParts.length === 1) {
    const p0 = parsedParts[0]!;
    if (p0 > 0xffffffff) return null;
    return new Uint8Array([
      (p0 >>> 24) & 0xff,
      (p0 >>> 16) & 0xff,
      (p0 >>> 8) & 0xff,
      p0 & 0xff,
    ]);
  }

  return null;
}

/**
 * Parses any valid IPv6 address (including bracketed, compressed, or IPv4-mapped forms)
 * into a 16-byte Uint8Array. Returns null if invalid.
 */
export function parseIpv6ToBytes(input: string): Uint8Array | null {
  let clean = input.replace(/^\[|\]$/g, '').toLowerCase().trim();
  if (!clean) return null;

  // Handle embedded IPv4 at the end, e.g. ::ffff:192.168.1.1
  const lastColon = clean.lastIndexOf(':');
  if (lastColon !== -1) {
    const potentialIpv4 = clean.slice(lastColon + 1);
    const v4Bytes = parseIpv4ToBytes(potentialIpv4);
    if (v4Bytes && potentialIpv4.includes('.')) {
      const v0 = v4Bytes[0]!;
      const v1 = v4Bytes[1]!;
      const v2 = v4Bytes[2]!;
      const v3 = v4Bytes[3]!;
      const hexPart1 = (((v0 << 8) | v1) >>> 0).toString(16);
      const hexPart2 = (((v2 << 8) | v3) >>> 0).toString(16);
      clean = clean.slice(0, lastColon + 1) + hexPart1 + ':' + hexPart2;
    }
  }

  // Expand ::
  if (clean.includes('::')) {
    const halves = clean.split('::');
    if (halves.length > 2) return null;
    const leftStr = halves[0];
    const rightStr = halves[1];
    const leftParts = leftStr ? leftStr.split(':') : [];
    const rightParts = rightStr ? rightStr.split(':') : [];
    const missing = 8 - (leftParts.length + rightParts.length);
    if (missing < 0) return null;
    const middle = Array(missing).fill('0');
    clean = [...leftParts, ...middle, ...rightParts].join(':');
  }

  const parts = clean.split(':');
  if (parts.length !== 8) return null;

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const part = parts[i];
    if (part === undefined) return null;
    const val = parseInt(part, 16);
    if (isNaN(val) || val < 0 || val > 0xffff) return null;
    bytes[i * 2] = (val >>> 8) & 0xff;
    bytes[i * 2 + 1] = val & 0xff;
  }
  return bytes;
}

/**
 * Canonicalizes any IPv4 or IPv6 representation (hex, octal, decimal, IPv4-mapped IPv6)
 * to a standardized string format (dotted decimal for IPv4, canonical colon notation for IPv6).
 * Returns null if the host string is not an IP address.
 */
export function canonicalizeIp(host: string): string | null {
  const clean = host.replace(/^\[|\]$/g, '').trim().toLowerCase();

  // Try IPv4 first
  const v4Bytes = parseIpv4ToBytes(clean);
  if (v4Bytes) {
    return `${v4Bytes[0]!}.${v4Bytes[1]!}.${v4Bytes[2]!}.${v4Bytes[3]!}`;
  }

  // Try IPv6
  const v6Bytes = parseIpv6ToBytes(clean);
  if (v6Bytes) {
    // Check if IPv4-mapped IPv6 (::ffff:x.x.x.x)
    const isMapped =
      v6Bytes[0] === 0 &&
      v6Bytes[1] === 0 &&
      v6Bytes[2] === 0 &&
      v6Bytes[3] === 0 &&
      v6Bytes[4] === 0 &&
      v6Bytes[5] === 0 &&
      v6Bytes[6] === 0 &&
      v6Bytes[7] === 0 &&
      v6Bytes[8] === 0 &&
      v6Bytes[9] === 0 &&
      v6Bytes[10] === 255 &&
      v6Bytes[11] === 255;

    if (isMapped) {
      return `${v6Bytes[12]!}.${v6Bytes[13]!}.${v6Bytes[14]!}.${v6Bytes[15]!}`;
    }

    // Check if IPv4-compatible IPv6 (deprecated, ::x.x.x.x)
    const isCompat =
      v6Bytes[0] === 0 &&
      v6Bytes[1] === 0 &&
      v6Bytes[2] === 0 &&
      v6Bytes[3] === 0 &&
      v6Bytes[4] === 0 &&
      v6Bytes[5] === 0 &&
      v6Bytes[6] === 0 &&
      v6Bytes[7] === 0 &&
      v6Bytes[8] === 0 &&
      v6Bytes[9] === 0 &&
      v6Bytes[10] === 0 &&
      v6Bytes[11] === 0 &&
      (v6Bytes[12]! > 0 || v6Bytes[13]! > 0 || v6Bytes[14]! > 0 || v6Bytes[15]! > 1);

    if (isCompat) {
      return `${v6Bytes[12]!}.${v6Bytes[13]!}.${v6Bytes[14]!}.${v6Bytes[15]!}`;
    }

    // Reconstruct canonical IPv6 string
    const words: string[] = [];
    for (let i = 0; i < 8; i++) {
      const b0 = v6Bytes[i * 2]!;
      const b1 = v6Bytes[i * 2 + 1]!;
      const val = ((b0 << 8) | b1) >>> 0;
      words.push(val.toString(16));
    }
    return words.join(':');
  }

  return null;
}

/**
 * Checks if an IPv4 address matches a given CIDR notation (e.g. 10.0.0.0/8).
 */
export function matchIpv4Cidr(ipBytes: Uint8Array, cidr: string): boolean {
  const [baseIpStr, prefixStr] = cidr.split('/');
  if (!baseIpStr || !prefixStr) return false;

  const baseBytes = parseIpv4ToBytes(baseIpStr);
  if (!baseBytes) return false;

  const prefix = parseInt(prefixStr, 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return false;

  const ip0 = ipBytes[0]!;
  const ip1 = ipBytes[1]!;
  const ip2 = ipBytes[2]!;
  const ip3 = ipBytes[3]!;

  const base0 = baseBytes[0]!;
  const base1 = baseBytes[1]!;
  const base2 = baseBytes[2]!;
  const base3 = baseBytes[3]!;

  const ipNum = (((ip0 << 24) | (ip1 << 16) | (ip2 << 8) | ip3) >>> 0);
  const baseNum = (((base0 << 24) | (base1 << 16) | (base2 << 8) | base3) >>> 0);

  const mask = prefix === 0 ? 0 : ((~0 << (32 - prefix)) >>> 0);
  return (ipNum & mask) === (baseNum & mask);
}

/**
 * Checks if an IPv6 address matches a given CIDR notation (e.g. fe80::/10, fc00::/7).
 */
export function matchIpv6Cidr(ipBytes: Uint8Array, cidr: string): boolean {
  const [baseIpStr, prefixStr] = cidr.split('/');
  if (!baseIpStr || !prefixStr) return false;

  const baseBytes = parseIpv6ToBytes(baseIpStr);
  if (!baseBytes) return false;

  const prefix = parseInt(prefixStr, 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 128) return false;

  const fullBytes = Math.floor(prefix / 8);
  const remBits = prefix % 8;

  for (let i = 0; i < fullBytes; i++) {
    const curIp = ipBytes[i];
    const curBase = baseBytes[i];
    if (curIp === undefined || curBase === undefined || curIp !== curBase) return false;
  }

  if (remBits > 0) {
    const curIp = ipBytes[fullBytes];
    const curBase = baseBytes[fullBytes];
    if (curIp === undefined || curBase === undefined) return false;
    const mask = (0xff << (8 - remBits)) & 0xff;
    if ((curIp & mask) !== (curBase & mask)) return false;
  }

  return true;
}

// Prohibited Cloud Provider Metadata Addresses
const CLOUD_METADATA_IPS = new Set([
  '169.254.169.254', // AWS, GCP, Azure, OpenStack, DigitalOcean
  'fd00:ec2::254',   // AWS IPv6 IMDS
  '100.100.100.200', // Alibaba Cloud metadata
]);

const CLOUD_METADATA_HOSTNAMES = new Set([
  'metadata.google.internal',
  'metadata.local',
  'instance-data',
  '169.254.169.254',
  'fd00:ec2::254',
]);

/**
 * Returns true if the hostname is a known cloud metadata endpoint.
 */
export function isCloudMetadataHost(hostname: string): boolean {
  const clean = hostname.replace(/^\[|\]$/g, '').trim().toLowerCase();
  return CLOUD_METADATA_HOSTNAMES.has(clean);
}

/**
 * Returns true if the IP is a known cloud metadata IP address.
 */
export function isCloudMetadataIp(ipStr: string): boolean {
  const canon = canonicalizeIp(ipStr);
  if (!canon) return false;
  if (CLOUD_METADATA_IPS.has(canon)) return true;

  // Also check IPv6 AWS metadata (fd00:ec2::254)
  const v6Bytes = parseIpv6ToBytes(ipStr);
  if (v6Bytes) {
    const awsMetadata = parseIpv6ToBytes('fd00:ec2::254');
    if (awsMetadata && v6Bytes.every((b, i) => b === awsMetadata[i])) {
      return true;
    }
  }

  return false;
}

/**
 * Returns true if the IP is in IPv4 or IPv6 link-local range (169.254.0.0/16 or fe80::/10).
 */
export function isLinkLocalIp(ipStr: string): boolean {
  const v4Bytes = parseIpv4ToBytes(ipStr);
  if (v4Bytes) {
    return matchIpv4Cidr(v4Bytes, '169.254.0.0/16');
  }
  const v6Bytes = parseIpv6ToBytes(ipStr);
  if (v6Bytes) {
    return matchIpv6Cidr(v6Bytes, 'fe80::/10');
  }
  return false;
}

/**
 * Returns true if the IP is loopback (127.0.0.0/8, ::1) or unspecified (0.0.0.0/8, ::).
 */
export function isLoopbackIp(ipStr: string): boolean {
  const v4Bytes = parseIpv4ToBytes(ipStr);
  if (v4Bytes) {
    return matchIpv4Cidr(v4Bytes, '127.0.0.0/8') || matchIpv4Cidr(v4Bytes, '0.0.0.0/8');
  }
  const v6Bytes = parseIpv6ToBytes(ipStr);
  if (v6Bytes) {
    return (
      matchIpv6Cidr(v6Bytes, '::1/128') ||
      matchIpv6Cidr(v6Bytes, '::/128')
    );
  }
  return false;
}

/**
 * Returns true if the IP is in private RFC 1918 subnets, ULA (fc00::/7), or CGNAT (100.64.0.0/10).
 */
export function isPrivateSubnetIp(ipStr: string): boolean {
  const v4Bytes = parseIpv4ToBytes(ipStr);
  if (v4Bytes) {
    return (
      matchIpv4Cidr(v4Bytes, '10.0.0.0/8') ||
      matchIpv4Cidr(v4Bytes, '172.16.0.0/12') ||
      matchIpv4Cidr(v4Bytes, '192.168.0.0/16') ||
      matchIpv4Cidr(v4Bytes, '100.64.0.0/10')
    );
  }
  const v6Bytes = parseIpv6ToBytes(ipStr);
  if (v6Bytes) {
    return matchIpv6Cidr(v6Bytes, 'fc00::/7');
  }
  return false;
}

/**
 * Returns true if the IP is multicast, broadcast, or reserved space.
 */
export function isMulticastOrBroadcast(ipStr: string): boolean {
  const v4Bytes = parseIpv4ToBytes(ipStr);
  if (v4Bytes) {
    return (
      matchIpv4Cidr(v4Bytes, '224.0.0.0/4') || // Multicast
      matchIpv4Cidr(v4Bytes, '240.0.0.0/4') || // Reserved
      matchIpv4Cidr(v4Bytes, '255.255.255.255/32') // Broadcast
    );
  }
  const v6Bytes = parseIpv6ToBytes(ipStr);
  if (v6Bytes) {
    return matchIpv6Cidr(v6Bytes, 'ff00::/8'); // Multicast
  }
  return false;
}

export interface ProhibitedIpCheckOptions {
  allowPrivate?: boolean;
  allowLoopback?: boolean;
}

/**
 * Evaluates an IP address against security boundary policies.
 * Cloud metadata, link-local, and multicast/broadcast are always prohibited.
 * Loopback and RFC 1918 private IPs are prohibited unless explicitly authorized.
 */
export function isProhibitedIp(
  ipStr: string,
  options: ProhibitedIpCheckOptions = {},
): { prohibited: boolean; reason?: string } {
  // Canonicalize IP
  const canon = canonicalizeIp(ipStr);
  if (!canon) {
    return { prohibited: false };
  }

  // 1. Cloud metadata check (unconditional)
  if (isCloudMetadataIp(canon)) {
    return {
      prohibited: true,
      reason: `Access to cloud metadata IP "${canon}" is strictly prohibited.`,
    };
  }

  // 2. Link-local check (unconditional)
  if (isLinkLocalIp(canon)) {
    return {
      prohibited: true,
      reason: `Access to link-local address "${canon}" is strictly prohibited.`,
    };
  }

  // 3. Multicast and broadcast check (unconditional)
  if (isMulticastOrBroadcast(canon)) {
    return {
      prohibited: true,
      reason: `Access to multicast, broadcast, or reserved address "${canon}" is strictly prohibited.`,
    };
  }

  // 4. Loopback check
  if (!options.allowLoopback && !options.allowPrivate && isLoopbackIp(canon)) {
    return {
      prohibited: true,
      reason: `Access to loopback address "${canon}" is prohibited unless explicitly authorized in target scope.`,
    };
  }

  // 5. Private RFC 1918 / ULA check
  if (!options.allowPrivate && isPrivateSubnetIp(canon)) {
    return {
      prohibited: true,
      reason: `Access to private network address "${canon}" is prohibited unless explicitly authorized in target scope.`,
    };
  }

  return { prohibited: false };
}

/**
 * Checks whether a hostname or IP matches an allowed host pattern.
 * Supports exact hostname matches, canonical IP matches, and exact wildcard subdomain matching (*.domain.com).
 */
export function matchesAllowedHost(hostname: string, allowedHost: string): boolean {
  const cleanHost = hostname.replace(/^\[|\]$/g, '').toLowerCase().trim();
  const cleanAllowed = allowedHost.replace(/^\[|\]$/g, '').toLowerCase().trim();

  // 1. Exact match
  if (cleanHost === cleanAllowed) {
    return true;
  }

  // 2. Canonical IP match (e.g. if allowed is 127.0.0.1 and host is 2130706433 or [::ffff:127.0.0.1])
  const canonHost = canonicalizeIp(cleanHost);
  const canonAllowed = canonicalizeIp(cleanAllowed);
  if (canonHost && canonAllowed && canonHost === canonAllowed) {
    return true;
  }

  // 3. Wildcard subdomain matching: *.example.com
  if (cleanAllowed.startsWith('*.')) {
    const baseDomain = cleanAllowed.slice(2); // e.g. "example.com"
    // Must end with .baseDomain and have at least one character before the dot
    if (cleanHost.endsWith(`.${baseDomain}`) && cleanHost.length > baseDomain.length + 1) {
      return true;
    }
  }

  return false;
}
