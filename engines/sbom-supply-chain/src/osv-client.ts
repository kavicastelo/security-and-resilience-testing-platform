import {
  SbomComponent,
  SbomAdvisoryMatch,
  OsvVulnerabilityItem,
  OsvBatchResponse,
} from './types.js';
import { createLogger } from '@security-lab/logger';

const logger = createLogger({ name: 'osv-client' });

// Built-in offline advisory database cache for reliable local/offline verification
const KNOWN_ADVISORY_CACHE: Record<
  string,
  Array<{
    id: string;
    aliases: string[];
    summary: string;
    details: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    cvssScore?: number;
    fixedVersion?: string;
    vulnerableCheck: (version: string) => boolean;
    referenceUrls: string[];
  }>
> = {
  lodash: [
    {
      id: 'GHSA-35jh-r3h4-6jhm',
      aliases: ['CVE-2021-23337'],
      summary: 'Command Injection and Prototype Pollution in lodash',
      details:
        'Lodash versions prior to 4.17.21 are vulnerable to Command Injection via template when passing untrusted user input.',
      severity: 'high',
      cvssScore: 7.4,
      fixedVersion: '4.17.21',
      vulnerableCheck: (v) => isVersionLessThan(v, '4.17.21'),
      referenceUrls: ['https://nvd.nist.gov/vuln/detail/CVE-2021-23337'],
    },
    {
      id: 'GHSA-p6mc-m468-83gw',
      aliases: ['CVE-2020-8203'],
      summary: 'Prototype pollution in lodash',
      details: 'Lodash versions prior to 4.17.19 are vulnerable to Prototype Pollution in zipObjectDeep.',
      severity: 'high',
      cvssScore: 7.4,
      fixedVersion: '4.17.19',
      vulnerableCheck: (v) => isVersionLessThan(v, '4.17.19'),
      referenceUrls: ['https://nvd.nist.gov/vuln/detail/CVE-2020-8203'],
    },
  ],
  'log4j-core': [
    {
      id: 'GHSA-jfh8-c2jp-5v3q',
      aliases: ['CVE-2021-44228', 'Log4Shell'],
      summary: 'Remote Code Execution in Apache Log4j (Log4Shell)',
      details:
        'Apache Log4j2 versions 2.0-beta9 through 2.14.1 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints.',
      severity: 'critical',
      cvssScore: 10.0,
      fixedVersion: '2.15.0',
      vulnerableCheck: (v) => isVersionLessThan(v, '2.15.0'),
      referenceUrls: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
    },
  ],
  axios: [
    {
      id: 'GHSA-cph5-m8f7-6c5x',
      aliases: ['CVE-2021-3749'],
      summary: 'Regular Expression Denial of Service in axios',
      details: 'axios versions prior to 0.21.2 contain a regular expression denial of service flaw.',
      severity: 'high',
      cvssScore: 7.5,
      fixedVersion: '0.21.2',
      vulnerableCheck: (v) => isVersionLessThan(v, '0.21.2'),
      referenceUrls: ['https://nvd.nist.gov/vuln/detail/CVE-2021-3749'],
    },
  ],
  'spring-core': [
    {
      id: 'GHSA-36p3-wjmg-h94x',
      aliases: ['CVE-2022-22965', 'Spring4Shell'],
      summary: 'Remote Code Execution in Spring Framework (Spring4Shell)',
      details: 'A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution.',
      severity: 'critical',
      cvssScore: 9.8,
      fixedVersion: '5.3.18',
      vulnerableCheck: (v) => isVersionLessThan(v, '5.3.18'),
      referenceUrls: ['https://nvd.nist.gov/vuln/detail/CVE-2022-22965'],
    },
  ],
  minimist: [
    {
      id: 'GHSA-xvch-5gv4-984h',
      aliases: ['CVE-2021-44906'],
      summary: 'Prototype Pollution in minimist',
      details: 'Minimist prior to 1.2.6 is vulnerable to Prototype Pollution.',
      severity: 'medium',
      cvssScore: 5.6,
      fixedVersion: '1.2.6',
      vulnerableCheck: (v) => isVersionLessThan(v, '1.2.6'),
      referenceUrls: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44906'],
    },
  ],
};

/**
 * Basic semantic version comparison helper.
 */
function isVersionLessThan(v1: string, v2: string): boolean {
  const clean1 = v1.replace(/[^0-9.]/g, '').split('.').map((n) => parseInt(n, 10) || 0);
  const clean2 = v2.replace(/[^0-9.]/g, '').split('.').map((n) => parseInt(n, 10) || 0);

  const len = Math.max(clean1.length, clean2.length);
  for (let i = 0; i < len; i++) {
    const part1 = clean1[i] ?? 0;
    const part2 = clean2[i] ?? 0;
    if (part1 < part2) return true;
    if (part1 > part2) return false;
  }
  return false;
}

function mapOsvSeverityScore(vuln: OsvVulnerabilityItem): { severity: 'critical' | 'high' | 'medium' | 'low' | 'info'; score?: number } {
  if (Array.isArray(vuln.severity)) {
    for (const s of vuln.severity) {
      if (s.score && typeof s.score === 'string') {
        const scoreNum = parseFloat(s.score);
        if (!isNaN(scoreNum)) {
          if (scoreNum >= 9.0) return { severity: 'critical', score: scoreNum };
          if (scoreNum >= 7.0) return { severity: 'high', score: scoreNum };
          if (scoreNum >= 4.0) return { severity: 'medium', score: scoreNum };
          return { severity: 'low', score: scoreNum };
        }
      }
    }
  }

  // Fallback to text heuristic
  const text = `${vuln.summary || ''} ${vuln.details || ''}`.toLowerCase();
  if (text.includes('critical') || text.includes('remote code execution') || text.includes('rce')) {
    return { severity: 'critical', score: 9.8 };
  }
  if (text.includes('high') || text.includes('prototype pollution') || text.includes('sql injection')) {
    return { severity: 'high', score: 7.5 };
  }
  return { severity: 'medium', score: 5.0 };
}

function extractFixedVersion(vuln: OsvVulnerabilityItem): string | undefined {
  if (Array.isArray(vuln.affected)) {
    for (const aff of vuln.affected) {
      if (Array.isArray(aff.ranges)) {
        for (const range of aff.ranges) {
          if (Array.isArray(range.events)) {
            for (const ev of range.events) {
              if (ev.fixed) return ev.fixed;
            }
          }
        }
      }
    }
  }
  return undefined;
}

export class OsvClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly offlineMode: boolean;

  constructor(options: { baseUrl?: string; timeoutMs?: number; offlineMode?: boolean } = {}) {
    this.baseUrl = options.baseUrl || 'https://api.osv.dev/v1';
    this.timeoutMs = options.timeoutMs || 3000;
    this.offlineMode = options.offlineMode === true;
  }

  /**
   * Queries vulnerabilities for a batch of components.
   */
  async matchComponents(components: SbomComponent[]): Promise<Map<string, SbomAdvisoryMatch[]>> {
    const results = new Map<string, SbomAdvisoryMatch[]>();

    if (components.length === 0) return results;

    // Check cached database first for instantaneous offline resolution
    for (const comp of components) {
      const pkgName = comp.name.toLowerCase();
      const simpleName = pkgName.includes('/') ? (pkgName.split('/').pop() ?? pkgName) : pkgName;
      const cached = KNOWN_ADVISORY_CACHE[pkgName] || KNOWN_ADVISORY_CACHE[simpleName];

      if (cached) {
        const matches: SbomAdvisoryMatch[] = [];
        for (const adv of cached) {
          if (adv.vulnerableCheck(comp.version)) {
            matches.push({
              id: adv.id,
              aliases: adv.aliases,
              summary: adv.summary,
              details: adv.details,
              severity: adv.severity,
              cvssScore: adv.cvssScore,
              fixedVersion: adv.fixedVersion,
              referenceUrls: adv.referenceUrls,
            });
          }
        }
        if (matches.length > 0) {
          results.set(`${comp.name}@${comp.version}`, matches);
        }
      }
    }

    if (this.offlineMode) {
      return results;
    }

    // Try batch online query for components not resolved or for comprehensive enrichment
    try {
      const queries = components.map((c) => ({
        package: {
          name: c.name,
          ecosystem: c.ecosystem,
          purl: c.purl,
        },
        version: c.version !== 'unknown' ? c.version : undefined,
      }));

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      const response = await fetch(`${this.baseUrl}/querybatch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries }),
        signal: controller.signal,
      }).finally(() => clearTimeout(timer));

      if (response.ok) {
        const data = (await response.json()) as OsvBatchResponse;
        if (Array.isArray(data.results)) {
          for (let i = 0; i < data.results.length; i++) {
            const comp = components[i];
            const item = data.results[i];
            if (!comp || !item || !Array.isArray(item.vulns) || item.vulns.length === 0) continue;

            const key = `${comp.name}@${comp.version}`;
            const existing = results.get(key) || [];
            const existingIds = new Set(existing.map((e) => e.id));

            for (const v of item.vulns) {
              if (existingIds.has(v.id)) continue;
              const { severity, score } = mapOsvSeverityScore(v);
              const fixed = extractFixedVersion(v);

              existing.push({
                id: v.id,
                aliases: v.aliases || [],
                summary: v.summary,
                details: v.details,
                severity,
                cvssScore: score,
                fixedVersion: fixed,
                referenceUrls: v.references?.map((r) => r.url) || [],
              });
            }

            results.set(key, existing);
          }
        }
      }
    } catch (err: unknown) {
      // Gracefully fall back to local cached advisories on network timeout/offline
      logger.debug(
        { error: err instanceof Error ? err.message : String(err) },
        'OSV online advisory lookup unavailable or timed out; utilizing cached vulnerability database.',
      );
    }

    return results;
  }
}
