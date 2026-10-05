import { FindingSeverity } from '../finding/index.js';
import { NormalizedFinding } from './zap.normalizer.js';

export interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Status?: string;
  Severity?: string;
  Title?: string;
  Description?: string;
  PrimaryURL?: string;
  CweIDs?: string[];
  CVSS?: Record<string, { V3Score?: number; V3Vector?: string }>;
  References?: string[];
}

export interface TrivyMisconfiguration {
  ID: string;
  Title: string;
  Description?: string;
  Message?: string;
  Resolution?: string;
  Severity?: string;
  PrimaryURL?: string;
  References?: string[];
}

export interface TrivyResultItem {
  Target?: string;
  Class?: string;
  Type?: string;
  Vulnerabilities?: TrivyVulnerability[];
  Misconfigurations?: TrivyMisconfiguration[];
}

export interface TrivyReportRoot {
  SchemaVersion?: number;
  ArtifactName?: string;
  ArtifactType?: string;
  Results?: TrivyResultItem[];
}

function mapTrivySeverity(sev?: string): FindingSeverity {
  const s = String(sev || '').toUpperCase().trim();
  switch (s) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    default:
      return 'info';
  }
}

/**
 * Normalizes raw Aqua Trivy scan reports into standard Security Lab findings.
 */
export function normalizeTrivyResults(rawReport: unknown): NormalizedFinding[] {
  if (!rawReport || typeof rawReport !== 'object') {
    return [];
  }

  const results: TrivyResultItem[] = [];

  if (Array.isArray(rawReport)) {
    results.push(...(rawReport as TrivyResultItem[]));
  } else {
    const reportObj = rawReport as TrivyReportRoot;
    if (Array.isArray(reportObj.Results)) {
      results.push(...reportObj.Results);
    }
  }

  const findings: NormalizedFinding[] = [];

  for (const item of results) {
    const targetName = item.Target || 'Target Artifact';

    // 1. Process Vulnerabilities (CVEs)
    if (Array.isArray(item.Vulnerabilities)) {
      for (const vuln of item.Vulnerabilities) {
        const severity = mapTrivySeverity(vuln.Severity);
        const title = vuln.Title
          ? `${vuln.VulnerabilityID}: ${vuln.Title}`
          : `${vuln.VulnerabilityID} in ${vuln.PkgName || 'package'}`;

        const desc =
          vuln.Description ||
          `Vulnerability ${vuln.VulnerabilityID} detected in package ${vuln.PkgName || 'unknown'} (installed: ${vuln.InstalledVersion || 'unknown'}).`;

        const recommendation = vuln.FixedVersion
          ? `Upgrade ${vuln.PkgName || 'package'} to version ${vuln.FixedVersion} or higher.`
          : vuln.PrimaryURL
            ? `Review security advisory at ${vuln.PrimaryURL}.`
            : undefined;

        const cweId = vuln.CweIDs?.[0];

        findings.push({
          title,
          category: 'software_composition_analysis',
          severity,
          confidence: 'certain',
          description: desc,
          recommendation,
          cweId,
          evidence: {
            expected: `Non-vulnerable ${vuln.PkgName || 'package'} dependency`,
            actual: `${vuln.PkgName}@${vuln.InstalledVersion} is vulnerable to ${vuln.VulnerabilityID} (fixed in ${vuln.FixedVersion || 'none'})`,
          },
          metadata: {
            vulnerabilityId: vuln.VulnerabilityID,
            packageName: vuln.PkgName,
            installedVersion: vuln.InstalledVersion,
            fixedVersion: vuln.FixedVersion,
            target: targetName,
            cweIds: vuln.CweIDs,
            primaryUrl: vuln.PrimaryURL,
            source: 'aqua_trivy',
          },
        });
      }
    }

    // 2. Process Misconfigurations
    if (Array.isArray(item.Misconfigurations)) {
      for (const misconfig of item.Misconfigurations) {
        const severity = mapTrivySeverity(misconfig.Severity);
        const title = `${misconfig.ID}: ${misconfig.Title}`;
        const desc = misconfig.Description || misconfig.Message || 'Infrastructure or container misconfiguration detected.';
        const recommendation = misconfig.Resolution;

        findings.push({
          title,
          category: 'infrastructure_as_code',
          severity,
          confidence: 'firm',
          description: desc,
          recommendation,
          evidence: {
            expected: 'Infrastructure or configuration follows hardened security standards',
            actual: misconfig.Message || title,
          },
          metadata: {
            misconfigId: misconfig.ID,
            target: targetName,
            primaryUrl: misconfig.PrimaryURL,
            source: 'aqua_trivy',
          },
        });
      }
    }
  }

  return findings;
}
