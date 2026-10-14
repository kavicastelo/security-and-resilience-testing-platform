import { ReportInput } from '@security-lab/contracts';
import { FindingSeverity } from '@security-lab/domain';
import { mapFindingToCompliance } from './compliance/index.js';

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help?: { text: string };
  properties?: Record<string, unknown>;
}

export interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note' | 'none';
  message: { text: string };
  locations?: {
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number };
    };
  }[];
  fingerprints?: Record<string, string>;
  properties?: Record<string, unknown>;
}

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: {
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: SarifRule[];
      };
    };
    results: SarifResult[];
    properties?: Record<string, unknown>;
  }[];
}

function mapSeverityToSarifLevel(severity: FindingSeverity): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
    default:
      return 'note';
  }
}

/**
 * Generates SARIF v2.1.0 JSON with integrated compliance metadata (OWASP Top 10, ASVS, PCI-DSS).
 */
export function generateSarifComplianceReport(input: ReportInput): SarifLog {
  const { target, findings, evidence = [], findingDiff } = input;
  const targetUri = target?.baseUrl || 'https://target.local';

  const evidenceMap = new Map<string, (typeof evidence)[number]>();
  for (const ev of evidence) {
    if (ev && ev.id) {
      evidenceMap.set(ev.id, ev);
    }
  }

  const diffStatusMap = new Map<string, string>();
  if (findingDiff?.details) {
    for (const d of findingDiff.details) {
      diffStatusMap.set(d.fingerprint, d.diffStatus);
    }
  }

  const rulesMap = new Map<string, SarifRule>();
  const results: SarifResult[] = [];

  for (const finding of findings) {
    const compliance = mapFindingToCompliance(finding);
    const ruleId = `${finding.testDefinitionId}/${finding.category}`;

    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        name: finding.category.replace(/_/g, ' '),
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description },
        help: finding.recommendation ? { text: finding.recommendation } : undefined,
        properties: {
          category: finding.category,
          precision: finding.confidence || 'high',
          'problem.severity': finding.severity,
          tags: [
            'security',
            compliance.owaspTop10.id,
            `OWASP-${compliance.owaspTop10.id}`,
            `ASVS-${compliance.asvs.requirementId}`,
            `PCI-DSS-${compliance.pciDss.requirementId}`,
            compliance.cwe,
          ],
          compliance: {
            owasp: compliance.owaspTop10,
            owaspTop10: compliance.owaspTop10,
            asvs: compliance.asvs,
            pciDss: compliance.pciDss,
            cwe: compliance.cwe,
          },
        },
      });
    }

    const diffStatus =
      diffStatusMap.get(finding.fingerprint) ||
      (finding.occurrenceCount && finding.occurrenceCount > 1 ? 'RECURRING' : 'NEW');

    results.push({
      ruleId,
      level: mapSeverityToSarifLevel(finding.severity),
      message: {
        text: `[${finding.severity.toUpperCase()}] ${finding.title}: ${finding.description}`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: targetUri },
            region: { startLine: 1 },
          },
        },
      ],
      fingerprints: {
        identity: finding.fingerprint,
      },
      properties: {
        findingId: finding.id,
        evidenceId: finding.evidenceId,
        category: finding.category,
        severity: finding.severity,
        remediation: finding.recommendation,
        diffStatus,
        occurrenceCount: finding.occurrenceCount || 1,
        compliance: {
          owaspTop10: compliance.owaspTop10.id,
          asvs: compliance.asvs.requirementId,
          pciDss: compliance.pciDss.requirementId,
          cwe: compliance.cwe,
        },
      },
    });
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Security & Resilience Testing Platform',
            version: '1.0.0',
            informationUri: 'https://securitylab.internal',
            rules: Array.from(rulesMap.values()),
          },
        },
        results,
        properties: {
          complianceFrameworks: ['OWASP_TOP_10_2021', 'OWASP_ASVS_4_0', 'PCI_DSS_4_0'],
        },
      },
    ],
  };
}

export const generateEnrichedSarifReport = generateSarifComplianceReport;

