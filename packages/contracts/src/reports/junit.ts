import { ReportInput } from './types.js';

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
  const { testRun, target, executions, findings } = input;
  const targetName = target?.name || testRun.targetId;
  const totalFindings = findings.length;

  const totalErrors = executions.filter((e) => e.status === 'failed' && e.errorMessage).length;
  const totalDurationSec =
    executions.reduce((acc, e) => acc + (e.durationMs || 0), 0) / 1000;

  const suitesXml: string[] = [];

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
        testCases.push(`    <testcase classname="${escapeXml(exec.engineId)}" name="${escapeXml(finding.title)}" time="0">
      <failure type="${escapeXml(finding.category)}" message="${escapeXml(finding.title)} [${finding.severity.toUpperCase()}]">
Severity: ${finding.severity.toUpperCase()}
Category: ${finding.category}
Description: ${finding.description}
Recommendation: ${finding.recommendation || 'N/A'}
Evidence ID: ${finding.evidenceId || 'N/A'}
      </failure>
    </testcase>`);
      }
    }

    suitesXml.push(`  <testsuite id="${exec.id}" name="${escapeXml(exec.engineId)}" tests="${testCases.length}" failures="${engineFindings.length}" errors="${exec.errorMessage ? 1 : 0}" time="${execDurationSec}">
${testCases.join('\n')}
  </testsuite>`);
  }

  return `<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="Security Lab: ${escapeXml(targetName)}" tests="${Math.max(totalFindings, 1)}" failures="${totalFindings}" errors="${totalErrors}" time="${totalDurationSec.toFixed(3)}">
${suitesXml.join('\n')}
</testsuites>`;
}
