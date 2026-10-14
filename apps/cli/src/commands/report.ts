import fs from 'node:fs/promises';
import path from 'node:path';
import { Command } from 'commander';
import pc from 'picocolors';
import { apiClient } from '../api/client.js';
import { formatCliError } from '../output/formatters.js';

interface ReportOptions {
  run?: string;
  format: string;
  output?: string;
  policy?: string;
}

const validFormats = ['junit', 'sarif', 'html', 'json', 'pdf'];

async function executeReportGeneration(options: ReportOptions): Promise<void> {
  try {
    const rawFormats = options.format
      .split(',')
      .map((f) => f.trim().toLowerCase())
      .filter(Boolean);

    for (const fmt of rawFormats) {
      if (!validFormats.includes(fmt)) {
        console.error(
          pc.red(`Invalid format "${fmt}". Supported formats: ${validFormats.join(', ')}`),
        );
        process.exit(1);
      }
    }

    if (!options.run) {
      console.error(pc.red('Missing required option: --run <testRunId>'));
      process.exit(1);
    }

    for (const fmt of rawFormats) {
      // eslint-disable-next-line no-console
      console.log(
        pc.cyan(
          `\nGenerating ${pc.bold(fmt.toUpperCase())} report for TestRun ${pc.bold(options.run)}...`,
        ),
      );

      const queryParams = new URLSearchParams({ format: fmt });
      if (options.policy) {
        queryParams.set('policyId', options.policy);
      }

      const endpoint = `/api/v1/test-runs/${options.run}/report?${queryParams.toString()}`;

      let outputPath = options.output;
      if (outputPath && rawFormats.length > 1) {
        const parsed = path.parse(outputPath);
        outputPath = path.join(parsed.dir, `${parsed.name}-${fmt}${parsed.ext || `.${fmt}`}`);
      }

      if (fmt === 'pdf') {
        const pdfBuffer = await apiClient.getBuffer(endpoint);
        if (outputPath) {
          const resolvedPath = path.resolve(process.cwd(), outputPath);
          await fs.mkdir(path.dirname(resolvedPath), { recursive: true });
          await fs.writeFile(resolvedPath, pdfBuffer);
          // eslint-disable-next-line no-console
          console.log(pc.green(`✔ PDF Report successfully exported to: ${pc.bold(resolvedPath)}`));
        } else {
          const defaultPath = path.resolve(process.cwd(), `security-report-${options.run}.pdf`);
          await fs.writeFile(defaultPath, pdfBuffer);
          // eslint-disable-next-line no-console
          console.log(pc.green(`✔ PDF Report exported to default path: ${pc.bold(defaultPath)}`));
        }
      } else {
        const reportText = await apiClient.getText(endpoint);
        if (outputPath) {
          const resolvedPath = path.resolve(process.cwd(), outputPath);
          await fs.mkdir(path.dirname(resolvedPath), { recursive: true });
          await fs.writeFile(resolvedPath, reportText, 'utf-8');
          // eslint-disable-next-line no-console
          console.log(
            pc.green(`✔ ${fmt.toUpperCase()} Report successfully exported to: ${pc.bold(resolvedPath)}`),
          );
        } else {
          // eslint-disable-next-line no-console
          console.log(reportText);
        }
      }
    }
  } catch (err: unknown) {
    console.error(formatCliError(err, 'Failed to generate report'));
    process.exit(1);
  }
}

export const reportCommand = new Command('report')
  .description('Generate and export machine-readable and executive security & resilience reports')
  .option('-r, --run <testRunId>', 'TestRun ID')
  .option('-f, --format <format>', 'Report format: junit, sarif, html, json, pdf', 'html')
  .option('-o, --output <filePath>', 'Path to save report output')
  .option('--policy <policyId>', 'Policy ID for release gating assessment')
  .action(async (options: ReportOptions) => {
    await executeReportGeneration(options);
  });

reportCommand
  .command('generate')
  .description('Generate JUnit XML, SARIF v2.1.0, HTML executive, JSON, or PDF reports for a TestRun')
  .requiredOption('-r, --run <testRunId>', 'TestRun ID')
  .option('-f, --format <format>', 'Report format: junit, sarif, html, json, pdf', 'html')
  .option('-o, --output <filePath>', 'Path to save report output')
  .option('--policy <policyId>', 'Policy ID for release gating assessment')
  .action(async (options: ReportOptions) => {
    await executeReportGeneration(options);
  });
