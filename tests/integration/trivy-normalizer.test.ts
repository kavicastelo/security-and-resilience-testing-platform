import { describe, it, expect } from 'vitest';
import { normalizeTrivyResults } from '@security-lab/domain';

describe('Aqua Trivy Vulnerability & Misconfiguration Normalizer', () => {
  it('normalizes Trivy JSON results with CVEs and infrastructure misconfigurations', () => {
    const rawTrivyReport = {
      SchemaVersion: 2,
      ArtifactName: 'customer-portal-backend:v1.2.0',
      ArtifactType: 'container_image',
      Results: [
        {
          Target: 'alpine:3.18 (alpine 3.18.4)',
          Class: 'os-pkgs',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2023-44487',
              PkgName: 'nghttp2-libs',
              InstalledVersion: '1.55.1-r0',
              FixedVersion: '1.57.0-r0',
              Severity: 'CRITICAL',
              Title: 'HTTP/2 Rapid Reset Denial of Service',
              Description: 'The HTTP/2 protocol allows a denial of service (server resource consumption) via rapid resets.',
              PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2023-44487',
              CweIDs: ['CWE-400'],
            },
            {
              VulnerabilityID: 'CVE-2023-5363',
              PkgName: 'openssl',
              InstalledVersion: '3.1.2-r0',
              FixedVersion: '3.1.4-r0',
              Severity: 'HIGH',
              Title: 'OpenSSL Incorrect cipher key processing',
              PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2023-5363',
            },
          ],
          Misconfigurations: [
            {
              ID: 'AVD-DS-0001',
              Title: 'Container running as root',
              Description: 'Running container as root increases privilege escalation risks.',
              Resolution: 'Add USER directive with unprivileged UID.',
              Severity: 'MEDIUM',
              PrimaryURL: 'https://avd.aquasec.com/appshield/ds001',
            },
          ],
        },
      ],
    };

    const findings = normalizeTrivyResults(rawTrivyReport);
    expect(findings).toHaveLength(3);

    // 1. Critical HTTP/2 Rapid Reset CVE
    const cveRapidReset = findings.find((f) => f.title.includes('CVE-2023-44487'));
    expect(cveRapidReset).toBeDefined();
    expect(cveRapidReset?.severity).toBe('critical');
    expect(cveRapidReset?.category).toBe('software_composition_analysis');
    expect(cveRapidReset?.recommendation).toContain('Upgrade nghttp2-libs to version 1.57.0-r0');
    expect(cveRapidReset?.evidence?.actual).toContain('1.55.1-r0');
    expect(cveRapidReset?.metadata?.packageName).toBe('nghttp2-libs');

    // 2. High OpenSSL CVE
    const cveOpenssl = findings.find((f) => f.title.includes('CVE-2023-5363'));
    expect(cveOpenssl).toBeDefined();
    expect(cveOpenssl?.severity).toBe('high');
    expect(cveOpenssl?.recommendation).toContain('Upgrade openssl to version 3.1.4-r0');

    // 3. Medium Misconfiguration
    const misconfig = findings.find((f) => f.title.includes('AVD-DS-0001'));
    expect(misconfig).toBeDefined();
    expect(misconfig?.severity).toBe('medium');
    expect(misconfig?.category).toBe('infrastructure_as_code');
    expect(misconfig?.recommendation).toContain('Add USER directive');
  });

  it('handles null, undefined, or empty reports safely', () => {
    expect(normalizeTrivyResults(null)).toHaveLength(0);
    expect(normalizeTrivyResults({})).toHaveLength(0);
    expect(normalizeTrivyResults({ Results: [] })).toHaveLength(0);
  });
});
