import { ReportInput } from './types.js';
import { FindingSeverity } from '@security-lab/domain';

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
 * Generates SARIF v2.1.0 JSON object for integration with GitHub Code Scanning, GitLab SAST, SonarQube.
 */
export function generateSarifReport(input: ReportInput): SarifLog {
  const { target, findings } = input;
  const targetUri = target?.baseUrl || 'https://target.local';

  const rulesMap = new Map<string, SarifRule>();
  const results: SarifResult[] = [];

  for (const finding of findings) {
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
        },
      });
    }

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
            name: 'Security Lab',
            version: '1.0.0',
            informationUri: 'https://github.com/kavicastelo/security-and-resilience-testing-platform',
            rules: Array.from(rulesMap.values()),
          },
        },
        results,
      },
    ],
  };
}
