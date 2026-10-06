import { describe, it, expect } from 'vitest';
import {
  validateUrlAgainstScope,
  validateUrlWithDns,
  TargetScope,
  canonicalizeIp,
  parseIpv4ToBytes,
  parseIpv6ToBytes,
  matchIpv4Cidr,
  matchIpv6Cidr,
  isProhibitedIp,
} from '@security-lab/domain';

describe('Scope Security Boundary Engine', () => {
  const baseScope: TargetScope = {
    allowedHosts: ['staging.example.com', '*.api.example.com'],
    allowedPorts: [80, 443],
    excludedPaths: ['/admin/reset-db', '/billing/charge'],
    testing: {
      activeScanning: false, // Default defensive safe setting
      loadTesting: false,
      chaosTesting: false,
    },
    limits: {
      maxRps: 50,
      maxConcurrency: 10,
      maxDuration: '5m',
    },
  };

  it('permits valid in-scope URLs on allowed host and port', () => {
    const res = validateUrlAgainstScope('https://staging.example.com/api/v1/users', baseScope);
    expect(res.valid).toBe(true);
    expect(res.violations).toHaveLength(0);
    expect(res.matchedHost).toBe('staging.example.com');
  });

  it('permits wildcard subdomain matches', () => {
    const res = validateUrlAgainstScope('https://v1.api.example.com/health', baseScope);
    expect(res.valid).toBe(true);
    expect(res.violations).toHaveLength(0);
  });

  it('blocks unauthorized hostnames (SSRF / Scope Traversal defense)', () => {
    const res = validateUrlAgainstScope('https://unauthorized-domain.com/secret', baseScope);
    expect(res.valid).toBe(false);
    expect(res.violations[0]).toContain('not within the authorized scope allowedHosts');
  });

  it('blocks unauthorized network ports', () => {
    const res = validateUrlAgainstScope('https://staging.example.com:8443/login', baseScope);
    expect(res.valid).toBe(false);
    expect(res.violations[0]).toContain('Port "8443" is not within authorized scope');
  });

  it('strictly blocks AWS / GCP / Azure Cloud Metadata IP (169.254.169.254)', () => {
    const res = validateUrlAgainstScope('http://169.254.169.254/latest/meta-data/', baseScope);
    expect(res.valid).toBe(false);
    expect(res.violations.some((v) => v.toLowerCase().includes('cloud metadata'))).toBe(true);
  });

  it('strictly blocks alternative encodings of cloud metadata IP (decimal, hex, octal)', () => {
    // Decimal integer (2852039166 === 169.254.169.254)
    const decRes = validateUrlAgainstScope('http://2852039166/latest/meta-data/', baseScope);
    expect(decRes.valid).toBe(false);
    expect(decRes.violations.some((v) => v.toLowerCase().includes('cloud metadata'))).toBe(true);

    // Hexadecimal (0xa9fea9fe === 169.254.169.254)
    const hexRes = validateUrlAgainstScope('http://0xa9fea9fe/latest/meta-data/', baseScope);
    expect(hexRes.valid).toBe(false);
    expect(hexRes.violations.some((v) => v.toLowerCase().includes('cloud metadata'))).toBe(true);

    // Dotted Octal (0251.0376.0251.0376 === 169.254.169.254)
    const octRes = validateUrlAgainstScope('http://0251.0376.0251.0376/latest/meta-data/', baseScope);
    expect(octRes.valid).toBe(false);
    expect(octRes.violations.some((v) => v.toLowerCase().includes('cloud metadata'))).toBe(true);
  });

  it('strictly blocks IPv4-mapped IPv6 and IPv6 metadata addresses', () => {
    // IPv4-mapped dotted IPv6
    const mappedRes1 = validateUrlAgainstScope('http://[::ffff:169.254.169.254]/', baseScope);
    expect(mappedRes1.valid).toBe(false);
    expect(mappedRes1.violations.some((v) => v.toLowerCase().includes('cloud metadata'))).toBe(true);

    // IPv4-mapped hex IPv6 (::ffff:a9fe:a9fe)
    const mappedRes2 = validateUrlAgainstScope('http://[::ffff:a9fe:a9fe]/', baseScope);
    expect(mappedRes2.valid).toBe(false);
    expect(mappedRes2.violations.some((v) => v.toLowerCase().includes('cloud metadata'))).toBe(true);

    // AWS IPv6 IMDS (fd00:ec2::254)
    const awsV6Res = validateUrlAgainstScope('http://[fd00:ec2::254]/', baseScope);
    expect(awsV6Res.valid).toBe(false);
    expect(awsV6Res.violations.some((v) => v.toLowerCase().includes('cloud metadata'))).toBe(true);

    // IPv6 Link-Local (fe80::1)
    const linkLocalV6 = validateUrlAgainstScope('http://[fe80::1]/', baseScope);
    expect(linkLocalV6.valid).toBe(false);
    expect(linkLocalV6.violations.some((v) => v.toLowerCase().includes('link-local') || v.toLowerCase().includes('prohibited'))).toBe(true);
  });

  it('blocks cloud metadata hostnames', () => {
    const gcp = validateUrlAgainstScope('http://metadata.google.internal/computeMetadata/v1/', baseScope);
    expect(gcp.valid).toBe(false);
    expect(gcp.violations.some((v) => v.toLowerCase().includes('cloud metadata'))).toBe(true);

    const localMeta = validateUrlAgainstScope('http://metadata.local/meta-data', baseScope);
    expect(localMeta.valid).toBe(false);
    expect(localMeta.violations.some((v) => v.toLowerCase().includes('cloud metadata'))).toBe(true);

    const instanceData = validateUrlAgainstScope('http://instance-data/latest', baseScope);
    expect(instanceData.valid).toBe(false);
    expect(instanceData.violations.some((v) => v.toLowerCase().includes('cloud metadata'))).toBe(true);
  });

  it('blocks unlisted loopback addresses in all representations', () => {
    // 127.0.0.1 direct
    const loop1 = validateUrlAgainstScope('http://127.0.0.1/admin', baseScope);
    expect(loop1.valid).toBe(false);
    expect(loop1.violations.some((v) => v.toLowerCase().includes('loopback'))).toBe(true);

    // 127.0.0.2
    const loop2 = validateUrlAgainstScope('http://127.0.0.2/admin', baseScope);
    expect(loop2.valid).toBe(false);
    expect(loop2.violations.some((v) => v.toLowerCase().includes('loopback'))).toBe(true);

    // Decimal 2130706433 (127.0.0.1)
    const loopDec = validateUrlAgainstScope('http://2130706433/admin', baseScope);
    expect(loopDec.valid).toBe(false);
    expect(loopDec.violations.some((v) => v.toLowerCase().includes('loopback'))).toBe(true);

    // Hex 0x7f000001 (127.0.0.1)
    const loopHex = validateUrlAgainstScope('http://0x7f000001/admin', baseScope);
    expect(loopHex.valid).toBe(false);
    expect(loopHex.violations.some((v) => v.toLowerCase().includes('loopback'))).toBe(true);

    // Octal 0177.0.0.1
    const loopOct = validateUrlAgainstScope('http://0177.0.0.1/admin', baseScope);
    expect(loopOct.valid).toBe(false);
    expect(loopOct.violations.some((v) => v.toLowerCase().includes('loopback'))).toBe(true);

    // IPv6 loopback [::1]
    const loopV6 = validateUrlAgainstScope('http://[::1]/admin', baseScope);
    expect(loopV6.valid).toBe(false);
    expect(loopV6.violations.some((v) => v.toLowerCase().includes('loopback'))).toBe(true);
  });

  it('blocks unlisted RFC 1918 private subnets', () => {
    // 10.0.0.0/8
    const rfc10 = validateUrlAgainstScope('http://10.0.0.1/api', baseScope);
    expect(rfc10.valid).toBe(false);
    expect(rfc10.violations.some((v) => v.toLowerCase().includes('private'))).toBe(true);

    // 172.16.0.0/12
    const rfc172 = validateUrlAgainstScope('http://172.16.0.1/api', baseScope);
    expect(rfc172.valid).toBe(false);
    expect(rfc172.violations.some((v) => v.toLowerCase().includes('private'))).toBe(true);

    // 192.168.0.0/16
    const rfc192 = validateUrlAgainstScope('http://192.168.1.1/api', baseScope);
    expect(rfc192.valid).toBe(false);
    expect(rfc192.violations.some((v) => v.toLowerCase().includes('private'))).toBe(true);
  });

  it('allows loopback or private IPs only when explicitly enumerated in allowedHosts', () => {
    const localDevScope: TargetScope = {
      ...baseScope,
      allowedHosts: ['127.0.0.1', '192.168.1.100'],
      allowedPorts: [80, 443, 3000],
    };

    const resLoop = validateUrlAgainstScope('http://127.0.0.1:3000/api', localDevScope);
    expect(resLoop.valid).toBe(true);
    expect(resLoop.violations).toHaveLength(0);

    const resPrivate = validateUrlAgainstScope('http://192.168.1.100:3000/api', localDevScope);
    expect(resPrivate.valid).toBe(true);
    expect(resPrivate.violations).toHaveLength(0);

    // Different unlisted private IP is still blocked
    const resOtherPrivate = validateUrlAgainstScope('http://192.168.1.200:3000/api', localDevScope);
    expect(resOtherPrivate.valid).toBe(false);
  });

  it('enforces precise wildcard subdomain boundary checks (preventing evil-domain matches)', () => {
    // Valid subdomains
    expect(validateUrlAgainstScope('https://v1.api.example.com/test', baseScope).valid).toBe(true);
    expect(validateUrlAgainstScope('https://auth.api.example.com/test', baseScope).valid).toBe(true);

    // Suffix spoofing: evil-api.example.com must NOT match *.api.example.com
    const evilRes1 = validateUrlAgainstScope('https://evil-api.example.com/test', baseScope);
    expect(evilRes1.valid).toBe(false);
    expect(evilRes1.violations[0]).toContain('not within the authorized scope allowedHosts');

    // Domain confusion: api.example.com.attacker.com must NOT match *.api.example.com
    const evilRes2 = validateUrlAgainstScope('https://api.example.com.attacker.com/test', baseScope);
    expect(evilRes2.valid).toBe(false);
  });

  it('strictly blocks excluded sensitive paths', () => {
    const res = validateUrlAgainstScope('https://staging.example.com/admin/reset-db', baseScope);
    expect(res.valid).toBe(false);
    expect(res.violations.some((v) => v.includes('matches excluded sensitive path'))).toBe(true);

    const subpathRes = validateUrlAgainstScope('https://staging.example.com/admin/reset-db/confirm', baseScope);
    expect(subpathRes.valid).toBe(false);
  });

  it('blocks active scanning when testing.activeScanning is false', () => {
    const res = validateUrlAgainstScope('https://staging.example.com/api/v1/login', baseScope, {
      requestedCapability: 'activeScanning',
    });
    expect(res.valid).toBe(false);
    expect(res.violations.some((v) => v.includes('activeScanning" is disabled for this target'))).toBe(true);
  });

  it('allows active scanning when target scope explicitly authorizes it', () => {
    const activeScope: TargetScope = {
      ...baseScope,
      testing: {
        ...baseScope.testing,
        activeScanning: true,
      },
    };

    const res = validateUrlAgainstScope('https://staging.example.com/api/v1/login', activeScope, {
      requestedCapability: 'activeScanning',
    });
    expect(res.valid).toBe(true);
    expect(res.violations).toHaveLength(0);
  });

  it('enforces safety clamps on requested RPS and concurrency', () => {
    const res = validateUrlAgainstScope('https://staging.example.com/api/v1/items', baseScope, {
      requestedRps: 150, // limit is 50
      requestedConcurrency: 25, // limit is 10
    });
    expect(res.valid).toBe(false);
    expect(res.violations.some((v) => v.includes('exceeds target scope limit of 50 RPS'))).toBe(true);
    expect(res.violations.some((v) => v.includes('exceeds target scope limit of 10'))).toBe(true);
  });

  describe('IP & CIDR Utilities Verification', () => {
    it('accurately parses and canonicalizes IPv4 representations', () => {
      expect(canonicalizeIp('127.0.0.1')).toBe('127.0.0.1');
      expect(canonicalizeIp('2130706433')).toBe('127.0.0.1');
      expect(canonicalizeIp('0x7f000001')).toBe('127.0.0.1');
      expect(canonicalizeIp('0177.0.0.1')).toBe('127.0.0.1');
      expect(canonicalizeIp('0251.0376.0251.0376')).toBe('169.254.169.254');
      expect(canonicalizeIp('2852039166')).toBe('169.254.169.254');
      expect(canonicalizeIp('0xa9fea9fe')).toBe('169.254.169.254');
    });

    it('accurately handles IPv6 and IPv4-mapped IPv6', () => {
      expect(canonicalizeIp('::ffff:169.254.169.254')).toBe('169.254.169.254');
      expect(canonicalizeIp('::ffff:a9fe:a9fe')).toBe('169.254.169.254');
      expect(canonicalizeIp('::ffff:127.0.0.1')).toBe('127.0.0.1');
      expect(canonicalizeIp('::1')).toBe('0:0:0:0:0:0:0:1');
    });

    it('matches CIDR subnets correctly', () => {
      const v4_1 = parseIpv4ToBytes('10.5.20.1')!;
      expect(matchIpv4Cidr(v4_1, '10.0.0.0/8')).toBe(true);
      expect(matchIpv4Cidr(v4_1, '192.168.0.0/16')).toBe(false);

      const v4_2 = parseIpv4ToBytes('172.25.1.1')!;
      expect(matchIpv4Cidr(v4_2, '172.16.0.0/12')).toBe(true);

      const v4_3 = parseIpv4ToBytes('172.33.1.1')!;
      expect(matchIpv4Cidr(v4_3, '172.16.0.0/12')).toBe(false);

      const v6 = parseIpv6ToBytes('fe80::1234')!;
      expect(matchIpv6Cidr(v6, 'fe80::/10')).toBe(true);
    });

    it('evaluates isProhibitedIp policies correctly', () => {
      expect(isProhibitedIp('169.254.169.254').prohibited).toBe(true);
      expect(isProhibitedIp('127.0.0.1').prohibited).toBe(true);
      expect(isProhibitedIp('127.0.0.1', { allowLoopback: true }).prohibited).toBe(false);
      expect(isProhibitedIp('10.10.10.10').prohibited).toBe(true);
      expect(isProhibitedIp('10.10.10.10', { allowPrivate: true }).prohibited).toBe(false);
      expect(isProhibitedIp('93.184.216.34').prohibited).toBe(false); // Public IP
    });
  });

  describe('Asynchronous DNS Scope Validation (validateUrlWithDns)', () => {
    it('passes for direct authorized IP without performing DNS', async () => {
      const localScope: TargetScope = {
        ...baseScope,
        allowedHosts: ['127.0.0.1'],
        allowedPorts: [80, 443],
      };
      const res = await validateUrlWithDns('http://127.0.0.1/health', localScope);
      expect(res.valid).toBe(true);
      expect(res.violations).toHaveLength(0);
    });

    it('detects DNS resolution to loopback when loopback is unauthorized', async () => {
      // In local machine, localhost resolves to 127.0.0.1/::1. baseScope does NOT authorize loopback.
      const res = await validateUrlWithDns('http://localhost/test', baseScope);
      expect(res.valid).toBe(false);
      expect(res.violations.length).toBeGreaterThan(0);
    });
  });
});
