import fs from 'node:fs/promises';
import path from 'node:path';
import { Command } from 'commander';
import pc from 'picocolors';
import { apiClient } from '../api/client.js';
import { formatCliError } from '../output/formatters.js';

export const reportCommand = new Command('report')
  .description('Generate and export machine-readable and executive security & resilience reports');

reportCommand
  .command('generate')
  .description('Generate JUnit XML, SARIF v2.1.0, HTML executive, or JSON reports for a TestRun')
  .requiredOption('-r, --run <testRunId>', 'TestRun ID')
  .option('-f, --format <format>', 'Report format: junit, sarif, html, json', 'html')
  .option('-o, --output <filePath>', 'Path to save report output')
  .option('--policy <policyId>', 'Policy ID for release gating assessment')
  .action(async (options) => {
    try {
      const format = options.format.toLowerCase();
      const validFormats = ['junit', 'sarif', 'html', 'json'];
      if (!validFormats.includes(format)) {
        console.error(pc.red(`Invalid format "${options.format}". Supported formats: ${validFormats.join(', ')}`));
        process.exit(1);
      }

      // eslint-disable-next-line no-console
      console.log(
        pc.cyan(
          `\nGenerating ${pc.bold(format.toUpperCase())} report for TestRun ${pc.bold(options.run)}...`,
        ),
      );

      const queryParams = new URLSearchParams({ format });
      if (options.policy) {
        queryParams.set('policyId', options.policy);
      }

      const reportContent = await apiClient.getText(
        `/api/v1/test-runs/${options.run}/report?${queryParams.toString()}`,
      );

      if (options.output) {
        const outPath = path.resolve(process.cwd(), options.output);
        await fs.mkdir(path.dirname(outPath), { recursive: true });
        await fs.writeFile(outPath, reportContent, 'utf-8');
        // eslint-disable-next-line no-console
        console.log(pc.green(`\n✔ Report successfully exported to: ${pc.bold(outPath)}`));
      } else {
        // eslint-disable-next-line no-console
        console.log(reportContent);
      }
    } catch (err: unknown) {
      console.error(formatCliError(err, 'Failed to generate report'));
      process.exit(1);
    }
  });
