import { Command } from 'commander';
import pc from 'picocolors';
import { SeedDataResult } from '@security-lab/contracts';
import { apiClient } from '../api/client.js';
import { renderSummaryBox } from '../output/table.js';
import { createSpinner } from '../output/spinner.js';
import { formatCliError, formatSuccess } from '../output/formatters.js';

export const seedCommand = new Command('seed')
  .description('Seed demonstration test suite with Nova Banking Core API, findings, agents, and webhooks')
  .option('-f, --force', 'Force overwrite/seed even if demo projects already exist', false)
  .option('-t, --tenant <tenantId>', 'Target tenant ID to seed into')
  .action(async (options: { force?: boolean; tenant?: string }) => {
    const spinner = createSpinner('Seeding realistic enterprise demo records...');
    spinner.start();
    try {
      const result = await apiClient.post<SeedDataResult>('/api/v1/management/seed', {
        force: Boolean(options.force),
        tenantId: options.tenant,
      });

      if (!result.success) {
        spinner.warn(pc.yellow(result.message || 'Demo data was not seeded.'));
        return;
      }

      spinner.succeed(formatSuccess('Demo data successfully seeded into database!'));

      const summary = renderSummaryBox('DEMO SEED SUMMARY', [
        { label: 'Project', value: result.projectName || 'Core Banking Gateway (Demo)', color: (v) => pc.bold(pc.green(v)) },
        { label: 'Project ID', value: result.projectId || 'N/A', color: (v) => pc.dim(v) },
        { label: 'Targets', value: result.targetsCreated ?? 0, color: (v) => pc.cyan(v) },
        { label: 'Findings', value: result.findingsCreated ?? 0, color: (v) => pc.red(v) },
        { label: 'Evidence Records', value: result.evidenceCreated ?? 0, color: (v) => pc.yellow(v) },
        { label: 'Agent Nodes', value: result.agentsCreated ?? 0, color: (v) => pc.magenta(v) },
        { label: 'Webhooks', value: result.webhooksCreated ?? 0, color: (v) => pc.blue(v) },
        { label: 'Performance Metrics', value: result.metricsCreated ?? 0, color: (v) => pc.cyan(v) },
      ]);

      // eslint-disable-next-line no-console
      console.log('\n' + summary + '\n');
      // eslint-disable-next-line no-console
      console.log(pc.dim('Note: All seeded entities are tagged with (Demo) and isolated.'));
    } catch (err: unknown) {
      spinner.fail('Failed to seed demo data');
      // eslint-disable-next-line no-console
      console.error(formatCliError(err, 'Demo seeding failed'));
      process.exit(1);
    }
  });
