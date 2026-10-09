import { Command } from 'commander';
import pc from 'picocolors';
import { apiClient } from '../api/client.js';
import { formatCliError } from '../output/formatters.js';
import { TestRun, Finding, FindingSeverity } from '@security-lab/domain';

interface TestRunExecutionResponse {
  testRun: TestRun;
  executions: {
    id: string;
    engineId: string;
    status: string;
    durationMs?: number;
    error?: string;
  }[];
  findings: Finding[];
}

function formatSeverityBadge(severity: FindingSeverity): string {
  switch (severity) {
    case 'critical':
      return pc.bgRed(pc.white(pc.bold(' CRITICAL ')));
    case 'high':
      return pc.red(pc.bold(' HIGH '));
    case 'medium':
      return pc.yellow(pc.bold(' MEDIUM '));
    case 'low':
      return pc.blue(pc.bold(' LOW '));
    case 'info':
      return pc.cyan(' INFO ');
    default:
      return severity;
  }
}

async function executeScan(options: {
  project: string;
  target: string;
  engineId: string;
  profileId: string;
  activeScan?: boolean;
  failOn: string;
}): Promise<void> {
  try {
    // eslint-disable-next-line no-console
    console.log(
      pc.cyan(
        `\nInitiating containerized security scan [${pc.bold(options.engineId)}] for target ${pc.bold(options.target)}...`,
      ),
    );

    // 1. Create TestRun record
    const run = await apiClient.post<TestRun>('/api/v1/test-runs', {
      projectId: options.project,
      targetId: options.target,
      profileId: options.profileId,
      triggeredBy: 'manual',
      metadata: {
        activeScan: options.activeScan ?? false,
      },
    });

    // eslint-disable-next-line no-console
    console.log(`TestRun created [ID: ${pc.dim(run.id)}] - Spawning ephemeral container runner...`);

    // 2. Execute TestRun (synchronous wait mode)
    const result = await apiClient.post<TestRunExecutionResponse>(`/api/v1/test-runs/${run.id}/execute?wait=true`, {
      engineIds: [options.engineId],
      options: {
        activeScan: options.activeScan,
      },
    });

    const { testRun, executions, findings } = result;

    // eslint-disable-next-line no-console
    console.log(pc.bold(pc.cyan('\nContainer Execution Summary:')));
    for (const exec of executions) {
      const statusBadge =
        exec.status === 'completed'
          ? pc.green('PASSED')
          : exec.status === 'failed'
            ? pc.red('FAILED')
            : pc.yellow(exec.status);
      // eslint-disable-next-line no-console
      console.log(`  ● [${statusBadge}] ${pc.bold(exec.engineId)} (${exec.durationMs ?? 0}ms)`);
      if (exec.error) {
        // eslint-disable-next-line no-console
        console.log(`    ${pc.red(`Error: ${exec.error}`)}`);
      }
    }

    // eslint-disable-next-line no-console
    console.log(pc.bold(pc.cyan('\nFindings Summary:')));
    const counts = testRun.summary.findingsCount;
    const criticalCount = counts?.critical ?? 0;
    const highCount = counts?.high ?? 0;
    const mediumCount = counts?.medium ?? 0;
    const lowCount = counts?.low ?? 0;
    const infoCount = counts?.info ?? 0;
    // eslint-disable-next-line no-console
    console.log(
      `  Critical: ${criticalCount > 0 ? pc.red(criticalCount) : 0} | ` +
      `High: ${highCount > 0 ? pc.red(highCount) : 0} | ` +
      `Medium: ${mediumCount > 0 ? pc.yellow(mediumCount) : 0} | ` +
      `Low: ${lowCount > 0 ? pc.blue(lowCount) : 0} | ` +
      `Info: ${infoCount}`,
    );

    if (findings.length > 0) {
      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan('\nNormalized Vulnerabilities & Misconfigurations:')));
      for (const f of findings) {
        // eslint-disable-next-line no-console
        console.log(`\n  ${formatSeverityBadge(f.severity)} ${pc.bold(f.title)}`);
        // eslint-disable-next-line no-console
        console.log(`    Category:       ${pc.dim(f.category)}`);
        // eslint-disable-next-line no-console
        console.log(`    Description:    ${f.description}`);
        if (f.recommendation) {
          // eslint-disable-next-line no-console
          console.log(`    Remediation:    ${pc.green(f.recommendation)}`);
        }
        if (f.evidenceId) {
          // eslint-disable-next-line no-console
          console.log(`    Evidence:       Hashed forensic record [${pc.dim(f.evidenceId)}]`);
        }
      }
    } else {
      // eslint-disable-next-line no-console
      console.log(pc.green('\n✔ Zero vulnerabilities or misconfigurations detected by scanner.'));
    }

    // eslint-disable-next-line no-console
    console.log(
      `\nScan status: ${
        testRun.status === 'completed'
          ? pc.green(pc.bold('COMPLETED'))
          : pc.red(pc.bold(testRun.status.toUpperCase()))
      }\n`,
    );

    // Evaluate failure threshold
    const severityOrder: Record<string, number> = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
      info: 0,
    };

    const failThreshold = severityOrder[options.failOn.toLowerCase()] ?? 3;
    const hasThresholdViolation = findings.some(
      (f) => (severityOrder[f.severity] ?? 0) >= failThreshold,
    );

    if (hasThresholdViolation || testRun.status === 'failed') {
      console.error(pc.red(`✖ Scan failed criteria (threshold: ${options.failOn.toUpperCase()}).`));
      process.exit(1);
    }
  } catch (err: unknown) {
    console.error(formatCliError(err, 'Container scanner execution failed'));
    process.exit(1);
  }
}

export const scanCommand = new Command('scan')
  .description('Launch isolated containerized security scanners (OWASP ZAP, Aqua Trivy)');

// Subcommand: zap
scanCommand
  .command('zap')
  .description('Execute OWASP ZAP baseline or active vulnerability scan')
  .requiredOption('-p, --project <projectId>', 'Project ID')
  .requiredOption('-t, --target <targetId>', 'Target ID')
  .option('--active', 'Enable active penetration scanning (requires target activeScanning authorization)', false)
  .option('--fail-on <severity>', 'Fail exit code threshold (critical, high, medium, low)', 'high')
  .action(async (options) => {
    await executeScan({
      project: options.project,
      target: options.target,
      engineId: 'engine-container-zap',
      profileId: 'zap',
      activeScan: options.active,
      failOn: options.failOn,
    });
  });

// Subcommand: trivy
scanCommand
  .command('trivy')
  .description('Execute Aqua Trivy software composition analysis (SCA) & misconfiguration audit')
  .requiredOption('-p, --project <projectId>', 'Project ID')
  .requiredOption('-t, --target <targetId>', 'Target ID')
  .option('--fail-on <severity>', 'Fail exit code threshold (critical, high, medium, low)', 'high')
  .action(async (options) => {
    await executeScan({
      project: options.project,
      target: options.target,
      engineId: 'engine-container-trivy',
      profileId: 'trivy',
      failOn: options.failOn,
    });
  });
