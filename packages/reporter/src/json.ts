import { ReportInput } from '@security-lab/contracts';
import { calculatePostureScore } from '@security-lab/scoring';
import { assessCompliance } from './compliance/index.js';

/**
 * Generates structured executive compliance JSON report object.
 */
export function generateComplianceJsonReport(input: ReportInput) {
  const { testRun, target, executions = [], findings = [], metrics = [], releaseGate, findingDiff } = input;
  const posture = input.posture || calculatePostureScore(findings);
  const targetUrl = target?.baseUrl || 'N/A';
  const targetName = target?.name || testRun.targetId;

  const compliance = assessCompliance(findings, testRun.id, targetUrl);

  const riskLevel =
    (posture as any).riskLevel ||
    (posture.score >= 80 ? 'LOW' : posture.score >= 50 ? 'MEDIUM' : 'HIGH');

  return {
    reportType: 'ENTERPRISE_SECURITY_AND_COMPLIANCE_REPORT',
    version: '1.0.0',
    generatedAt: new Date().toISOString(),
    testRunId: testRun.id,
    testRun: {
      id: testRun.id,
      projectId: testRun.projectId,
      profileId: testRun.profileId,
      status: testRun.status,
      triggeredBy: testRun.triggeredBy,
      startedAt: testRun.startedAt,
      completedAt: testRun.completedAt,
    },
    target: {
      id: target?.id || testRun.targetId,
      name: targetName,
      baseUrl: targetUrl,
      verificationStatus: (target as any)?.verificationStatus || 'UNKNOWN',
    },
    securityPosture: {
      score: posture.score,
      grade: posture.grade,
      riskLevel,
    },
    releaseGate: releaseGate
      ? {
          decision: releaseGate.decision,
          passed: releaseGate.passed,
          violationsCount: releaseGate.violations?.length || 0,
          violations: releaseGate.violations || [],
        }
      : null,
    findingDiff: findingDiff || null,
    totalFindings: findings.length,
    countsBySeverity: compliance.countsBySeverity,
    frameworks: compliance.frameworks,
    complianceSummary: {
      owaspTop10: compliance.owaspTop10,
      asvs: compliance.asvs,
      pciDss: compliance.pciDss,
    },
    executionsCount: executions.length,
    findingsCount: findings.length,
    findings: compliance.findings,
    metrics,
  };
}

/**
 * Generates an executive compliance JSON report serialized as a formatted JSON string.
 */
export function generateJsonComplianceReport(input: ReportInput): string {
  return JSON.stringify(generateComplianceJsonReport(input), null, 2);
}
