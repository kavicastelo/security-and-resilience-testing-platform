import { Command } from 'commander';
import pc from 'picocolors';
import { apiClient } from '../api/client.js';
import { formatCliError } from '../output/formatters.js';

interface Finding {
  id: string;
  fingerprint: string;
  title: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: string;
  description: string;
  risk?: string;
  recommendation?: string;
  testDefinitionId: string;
  testRunId: string;
  firstDetectedAt: string;
}

function formatSeverity(sev: string): string {
  switch (sev.toLowerCase()) {
    case 'critical':
      return pc.bgRed(pc.white(pc.bold(' CRITICAL ')));
    case 'high':
      return pc.red(pc.bold(' HIGH '));
    case 'medium':
      return pc.yellow(pc.bold(' MEDIUM '));
    case 'low':
      return pc.blue(pc.bold(' LOW '));
    default:
      return pc.dim(' INFO ');
  }
}

function formatStatus(status: string): string {
  switch (status.toLowerCase()) {
    case 'resolved':
      return pc.green('RESOLVED');
    case 'false_positive':
      return pc.dim('FALSE_POSITIVE');
    case 'risk_accepted':
      return pc.magenta('RISK_ACCEPTED');
    case 'suppressed':
      return pc.dim('SUPPRESSED');
    default:
      return pc.yellow('OPEN');
  }
}

export const findingsCommand = new Command('findings')
  .description('Inspect, query, triage, and manage security findings');

// Subcommand: list
findingsCommand
  .command('list')
  .description('List security findings across test executions')
  .option('-t, --target <targetId>', 'Filter by target ID')
  .option('-r, --run <runId>', 'Filter by test run ID')
  .option('-s, --severity <severity>', 'Filter by severity (critical, high, medium, low, info)')
  .option('--status <status>', 'Filter by status (open, resolved, false_positive, risk_accepted, suppressed)')
  .option('--format <format>', 'Output format (table, json)', 'table')
  .action(async (options) => {
    try {
      const params = new URLSearchParams();
      if (options.target) params.set('targetId', options.target);
      if (options.run) params.set('testRunId', options.run);
      if (options.severity) params.set('severity', options.severity);
      if (options.status) params.set('status', options.status);

      const qs = params.toString() ? `?${params.toString()}` : '';
      const findings = await apiClient.get<Finding[]>(`/api/v1/findings${qs}`);

      if (options.format === 'json') {
        // eslint-disable-next-line no-console
        console.log(JSON.stringify(findings, null, 2));
        return;
      }

      if (findings.length === 0) {
        // eslint-disable-next-line no-console
        console.log(pc.green('\n✔ No findings match the specified criteria.\n'));
        return;
      }

      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan(`\nSecurity Findings (${findings.length} total):`)));
      for (const f of findings) {
        // eslint-disable-next-line no-console
        console.log(`\n  ${formatSeverity(f.severity)} [${formatStatus(f.status)}] ${pc.bold(f.title)}`);
        // eslint-disable-next-line no-console
        console.log(`    ID:         ${pc.dim(f.id)}`);
        // eslint-disable-next-line no-console
        console.log(`    Category:   ${f.category} (Engine: ${f.testDefinitionId})`);
        // eslint-disable-next-line no-console
        console.log(`    Run ID:     ${pc.dim(f.testRunId)}`);
        // eslint-disable-next-line no-console
        console.log(`    Summary:    ${pc.dim(f.description.slice(0, 100))}${f.description.length > 100 ? '...' : ''}`);
      }
      // eslint-disable-next-line no-console
      console.log('');
    } catch (err: unknown) {
      console.error(formatCliError(err, 'Failed to list findings'));
      process.exit(1);
    }
  });

// Subcommand: get
findingsCommand
  .command('get <id>')
  .description('Inspect details and forensic evidence of a finding')
  .option('--format <format>', 'Output format (table, json)', 'table')
  .action(async (id: string, options) => {
    try {
      const finding = await apiClient.get<Finding>(`/api/v1/findings/${id}`);

      if (options.format === 'json') {
        // eslint-disable-next-line no-console
        console.log(JSON.stringify(finding, null, 2));
        return;
      }

      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan(`\nFinding: ${finding.title}`)));
      // eslint-disable-next-line no-console
      console.log(`  ID:             ${pc.dim(finding.id)}`);
      // eslint-disable-next-line no-console
      console.log(`  Severity:       ${formatSeverity(finding.severity)}`);
      // eslint-disable-next-line no-console
      console.log(`  Status:         ${formatStatus(finding.status)}`);
      // eslint-disable-next-line no-console
      console.log(`  Category:       ${finding.category}`);
      // eslint-disable-next-line no-console
      console.log(`  Engine:         ${finding.testDefinitionId}`);
      // eslint-disable-next-line no-console
      console.log(`  Fingerprint:    ${pc.dim(finding.fingerprint)}`);
      // eslint-disable-next-line no-console
      console.log(`  Description:    ${finding.description}`);
      if (finding.risk) {
        // eslint-disable-next-line no-console
        console.log(`  Risk Impact:    ${finding.risk}`);
      }
      if (finding.recommendation) {
        // eslint-disable-next-line no-console
        console.log(`  Recommendation: ${pc.green(finding.recommendation)}`);
      }
      // eslint-disable-next-line no-console
      console.log(`  Detected At:    ${new Date(finding.firstDetectedAt).toLocaleString()}\n`);
    } catch (err: unknown) {
      console.error(formatCliError(err, `Failed to get finding "${id}"`));
      process.exit(1);
    }
  });

// Subcommand: triage
findingsCommand
  .command('triage <id>')
  .description('Update the triage status of a finding')
  .requiredOption(
    '-s, --status <status>',
    'New status: open, resolved, false_positive, risk_accepted, suppressed',
  )
  .option('-n, --notes <notes>', 'Remediation or triage notes')
  .action(async (id: string, options) => {
    try {
      const updated = await apiClient.patch<Finding>(`/api/v1/findings/${id}`, {
        status: options.status,
        notes: options.notes,
      });

      // eslint-disable-next-line no-console
      console.log(pc.green(`✔ Finding "${updated.title}" [ID: ${updated.id}] status updated to: ${formatStatus(updated.status)}`));
    } catch (err: unknown) {
      console.error(formatCliError(err, `Failed to triage finding "${id}"`));
      process.exit(1);
    }
  });

// Subcommand: delete
findingsCommand
  .command('delete <id>')
  .description('Delete a finding record')
  .action(async (id: string) => {
    try {
      await apiClient.delete(`/api/v1/findings/${id}`);
      // eslint-disable-next-line no-console
      console.log(pc.green(`✔ Finding [ID: ${id}] deleted successfully.`));
    } catch (err: unknown) {
      console.error(formatCliError(err, `Failed to delete finding "${id}"`));
      process.exit(1);
    }
  });
