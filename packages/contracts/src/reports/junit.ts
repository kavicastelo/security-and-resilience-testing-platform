import { ReportInput } from './types.js';
import { generateCurlCommand } from './curl-generator.js';

function escapeXml(unsafe: string): string {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Generates standard JUnit XML string for CI/CD test reporting.
 */
export function generateJUnitXml(input: ReportInput): string {
  const { testRun, target, executions, findings, evidence = [], findingDiff } = input;
  const targetName = target?.name || testRun.targetId;
  const totalFindings = findings.length;

  // Build evidence lookup map
  const evidenceMap = new Map<string, (typeof evidence)[number]>();
  for (const ev of evidence) {
    if (ev && ev.id) {
      evidenceMap.set(ev.id, ev);
    }
  }

  // Build diff status lookup map by fingerprint
  const diffStatusMap = new Map<string, string>();
  if (findingDiff?.details) {
    for (const d of findingDiff.details) {
      diffStatusMap.set(d.fingerprint, d.diffStatus);
    }
  }

  const totalErrors = executions.filter((e) => e.status === 'failed' && e.errorMessage).length;
  const totalDurationSec =
    executions.reduce((acc, e) => acc + (e.durationMs || 0), 0) / 1000;

  const suitesXml: string[] = [];

  let totalTestCasesCount = 0;

  for (const exec of executions) {
    const engineFindings = findings.filter(
      (f) => f.executionId === exec.id || f.testDefinitionId === exec.engineId,
    );
    const execDurationSec = (exec.durationMs || 0) / 1000;
    const testCases: string[] = [];

    if (exec.errorMessage) {
      testCases.push(`    <testcase classname="${escapeXml(exec.engineId)}" name="Engine Execution" time="${execDurationSec}">
      <error type="ExecutionError" message="${escapeXml(exec.errorMessage)}">
        ${escapeXml(exec.errorMessage)}
      </error>
    </testcase>`);
    }

    if (engineFindings.length === 0 && !exec.errorMessage) {
      testCases.push(
        `    <testcase classname="${escapeXml(exec.engineId)}" name="Security Baseline Verification" time="${execDurationSec}" />`,
      );
    } else {
      for (const finding of engineFindings) {
        const diffStatus =
          diffStatusMap.get(finding.fingerprint) ||
          (finding.occurrenceCount && finding.occurrenceCount > 1 ? 'RECURRING' : 'NEW');

        const ev = finding.evidenceId ? evidenceMap.get(finding.evidenceId) : undefined;
        const meta = (finding.metadata || {}) as Record<string, unknown>;
        const curlCmd =
          (meta.reproductionCurl as string) ||
          (meta.curl as string) ||
          (meta.curlCommand as string) ||
          (ev?.request ? generateCurlCommand(ev.request) : '');

        testCases.push(`    <testcase classname="${escapeXml(exec.engineId)}" name="${escapeXml(finding.title)}" time="0">
      <failure type="${escapeXml(finding.category)}" message="${escapeXml(finding.title)} [${finding.severity.toUpperCase()}]">
Severity: ${finding.severity.toUpperCase()}
Category: ${finding.category}
Diff Status: ${diffStatus}
Occurrence Count: ${finding.occurrenceCount || 1}
Description: ${finding.description}
Recommendation: ${finding.recommendation || 'N/A'}
Evidence ID: ${finding.evidenceId || 'N/A'}${curlCmd ? `\n\nReproduction Command:\n${curlCmd}` : ''}
      </failure>
    </testcase>`);
      }
    }

    totalTestCasesCount += testCases.length;

    suitesXml.push(`  <testsuite id="${exec.id}" name="${escapeXml(exec.engineId)}" tests="${testCases.length}" failures="${engineFindings.length}" errors="${exec.errorMessage ? 1 : 0}" time="${execDurationSec}">
${testCases.join('\n')}
  </testsuite>`);
  }

  const diffPropertiesXml = findingDiff
    ? `  <properties>
    <property name="newFindings" value="${findingDiff.newCount}" />
    <property name="recurringFindings" value="${findingDiff.recurringCount}" />
    <property name="fixedFindings" value="${findingDiff.fixedCount}" />
  </properties>\n`
    : '';

  const finalTestsCount = Math.max(
    totalTestCasesCount,
    testRun.summary?.totalTests || 1,
  );

  return `<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="Security Lab: ${escapeXml(targetName)}" tests="${finalTestsCount}" failures="${totalFindings}" errors="${totalErrors}" time="${totalDurationSec.toFixed(3)}">
${diffPropertiesXml}${suitesXml.join('\n')}
</testsuites>`;
}

