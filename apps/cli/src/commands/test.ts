import fs from 'node:fs';
import path from 'node:path';
import { Command } from 'commander';
import pc from 'picocolors';
import { apiClient } from '../api/client.js';
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

export const testCommand = new Command('test')
  .description('Execute security and resilience test suites against authorized targets');

// Subcommand: run
testCommand
  .command('run')
  .description('Trigger and execute a test run against an authorized target')
  .requiredOption('-p, --project <projectId>', 'Project ID')
  .requiredOption('-t, --target <targetId>', 'Target ID')
  .option('-e, --engine <engineIds...>', 'Specific engine ID(s) to execute')
  .option('-f, --file <filePath>', 'Path to declarative YAML test definition')
  .option('--fail-on <severity>', 'Fail exit code threshold (critical, high, medium, low)', 'high')
  .action(async (options) => {
    try {
      let definitionYaml: string | undefined;

      if (options.file) {
        const resolvedPath = path.resolve(process.cwd(), options.file);
        if (!fs.existsSync(resolvedPath)) {
          console.error(pc.red(`✖ Test definition file not found: ${resolvedPath}`));
          process.exit(1);
        }
        definitionYaml = fs.readFileSync(resolvedPath, 'utf-8');
      }

      // eslint-disable-next-line no-console
      console.log(pc.cyan(`\nInitiating test run for target ${pc.bold(options.target)}...`));

      // 1. Create TestRun record
      const run = await apiClient.post<TestRun>('/api/v1/test-runs', {
        projectId: options.project,
        targetId: options.target,
        profileId: options.file ? 'declarative' : 'native-class-a',
        triggeredBy: 'manual',
        metadata: {
          definitionYaml,
          engines: options.engine,
        },
      });

      // eslint-disable-next-line no-console
      console.log(`TestRun created [ID: ${pc.dim(run.id)}] - Executing test engines in-process...`);

      // 2. Execute TestRun
      const result = await apiClient.post<TestRunExecutionResponse>(`/api/v1/test-runs/${run.id}/execute`, {
        engineIds: options.engine,
        definitionYaml,
      });

      const { testRun, executions, findings } = result;

      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan('\nEngine Executions:')));
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
        console.log(pc.bold(pc.cyan('\nIdentified Security Findings:')));
        for (const f of findings) {
          // eslint-disable-next-line no-console
          console.log(`\n  ${formatSeverityBadge(f.severity)} ${pc.bold(f.title)}`);
          // eslint-disable-next-line no-console
          console.log(`    Category:       ${pc.dim(f.category)}`);
          // eslint-disable-next-line no-console
          console.log(`    Description:    ${f.description}`);
          if (f.recommendation) {
            // eslint-disable-next-line no-console
            console.log(`    Recommendation: ${pc.green(f.recommendation)}`);
          }
          if (f.evidenceId) {
            // eslint-disable-next-line no-console
            console.log(`    Evidence:       Hashed forensic record [${pc.dim(f.evidenceId)}]`);
          }
        }
      } else {
        // eslint-disable-next-line no-console
        console.log(pc.green('\n✔ Zero security findings identified against defensive baseline.'));
      }

      // eslint-disable-next-line no-console
      console.log(`\nTestRun status: ${testRun.status === 'completed' ? pc.green(pc.bold('COMPLETED')) : pc.red(pc.bold(testRun.status.toUpperCase()))}\n`);

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
        console.error(pc.red(`✖ Test run failed criteria (threshold: ${options.failOn.toUpperCase()}).`));
        process.exit(1);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(pc.red(`✖ Test execution failed: ${msg}`));
      process.exit(1);
    }
  });

// Subcommand: list
testCommand
  .command('list')
  .description('List previous test runs')
  .option('-p, --project <projectId>', 'Filter by Project ID')
  .option('-t, --target <targetId>', 'Filter by Target ID')
  .action(async (options) => {
    try {
      const query = new URLSearchParams();
      if (options.project) query.set('projectId', options.project);
      if (options.target) query.set('targetId', options.target);

      const queryString = query.toString() ? `?${query.toString()}` : '';
      const runs = await apiClient.get<TestRun[]>(`/api/v1/test-runs${queryString}`);

      if (runs.length === 0) {
        // eslint-disable-next-line no-console
        console.log(pc.yellow('No test runs found. Trigger one with: security-lab test run'));
        return;
      }

      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan('\nTest Runs History:')));
      for (const r of runs) {
        const statusBadge =
          r.status === 'completed'
            ? pc.green(r.status)
            : r.status === 'failed'
              ? pc.red(r.status)
              : pc.yellow(r.status);
        // eslint-disable-next-line no-console
        console.log(`\n  ● [${statusBadge}] Run ${pc.bold(r.id)}`);
        // eslint-disable-next-line no-console
        console.log(`    Target:    ${r.targetId}`);
        // eslint-disable-next-line no-console
        console.log(`    Profile:   ${r.profileId || 'default'}`);
        const fc = r.summary.findingsCount;
        // eslint-disable-next-line no-console
        console.log(
          `    Findings:  Critical: ${fc?.critical ?? 0}, High: ${fc?.high ?? 0}, Medium: ${fc?.medium ?? 0}, Low: ${fc?.low ?? 0}`,
        );
        // eslint-disable-next-line no-console
        console.log(`    Created:   ${new Date(r.createdAt).toLocaleString()}`);
      }
      // eslint-disable-next-line no-console
      console.log('');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(pc.red(`✖ Failed to list test runs: ${msg}`));
      process.exit(1);
    }
  });

// Subcommand: findings
testCommand
  .command('findings')
  .description('Inspect findings from a test run')
  .requiredOption('-r, --run <runId>', 'Test Run ID')
  .action(async (options) => {
    try {
      const findingsList = await apiClient.get<Finding[]>(`/api/v1/test-runs/${options.run}/findings`);

      if (findingsList.length === 0) {
        // eslint-disable-next-line no-console
        console.log(pc.green(`✔ No findings for test run ${options.run}`));
        return;
      }

      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan(`\nFindings for Test Run ${options.run}:`)));
      for (const f of findingsList) {
        // eslint-disable-next-line no-console
        console.log(`\n  ${formatSeverityBadge(f.severity)} ${pc.bold(f.title)}`);
        // eslint-disable-next-line no-console
        console.log(`    Category:       ${pc.dim(f.category)}`);
        // eslint-disable-next-line no-console
        console.log(`    Description:    ${f.description}`);
        if (f.recommendation) {
          // eslint-disable-next-line no-console
          console.log(`    Recommendation: ${pc.green(f.recommendation)}`);
        }
      }
      // eslint-disable-next-line no-console
      console.log('');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(pc.red(`✖ Failed to retrieve findings: ${msg}`));
      process.exit(1);
    }
  });

// Subcommand: get
testCommand
  .command('get <id>')
  .description('Inspect details, summary, and status of a specific test run')
  .option('--format <format>', 'Output format (table, json)', 'table')
  .action(async (id: string, options) => {
    try {
      const run = await apiClient.get<TestRun>(`/api/v1/test-runs/${id}`);

      if (options.format === 'json') {
        // eslint-disable-next-line no-console
        console.log(JSON.stringify(run, null, 2));
        return;
      }

      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan(`\nTest Run: ${run.id}`)));
      // eslint-disable-next-line no-console
      console.log(`  Target ID:   ${pc.dim(run.targetId)}`);
      // eslint-disable-next-line no-console
      console.log(`  Project ID:  ${pc.dim(run.projectId)}`);
      // eslint-disable-next-line no-console
      console.log(`  Status:      ${run.status === 'completed' ? pc.green(run.status) : pc.yellow(run.status)}`);
      // eslint-disable-next-line no-console
      console.log(`  Profile:     ${run.profileId || 'default'}`);
      // eslint-disable-next-line no-console
      console.log(`  Total Tests: ${run.summary?.totalTests ?? 0}`);
      // eslint-disable-next-line no-console
      console.log(`  Passed:      ${pc.green(String(run.summary?.passedTests ?? 0))}`);
      // eslint-disable-next-line no-console
      console.log(`  Failed:      ${pc.red(String(run.summary?.failedTests ?? 0))}`);
      // eslint-disable-next-line no-console
      console.log(`  Created:     ${new Date(run.createdAt).toLocaleString()}\n`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(pc.red(`✖ Failed to get test run "${id}": ${msg}`));
      process.exit(1);
    }
  });

// Subcommand: delete
testCommand
  .command('delete <id>')
  .description('Delete a test run and its associated findings and metrics')
  .action(async (id: string) => {
    try {
      await apiClient.delete(`/api/v1/test-runs/${id}`);
      // eslint-disable-next-line no-console
      console.log(pc.green(`✔ Test Run [ID: ${id}] and associated records deleted successfully.`));
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(pc.red(`✖ Failed to delete test run "${id}": ${msg}`));
      process.exit(1);
    }
  });

