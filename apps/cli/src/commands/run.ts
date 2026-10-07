import { Command } from 'commander';
import { localRunner } from '../runner/local-runner.js';
import { formatError } from '../output/formatters.js';


export const runCommand = new Command('run')
  .description('Execute security and resilience test suites against a target')
  .option('-l, --local', 'Execute in standalone local offline mode (no controller or database required)', false)
  .option('-t, --target <url>', 'Target URL to test')
  .option('-c, --config <path>', 'Path to project configuration file (.securitylab.yaml)')
  .option('-f, --format <format>', 'Report format to export (terminal, sarif, junit, html, json)', 'terminal')
  .option('-o, --output <path>', 'Output file path for generated report')
  .option('--fail-on <decision>', 'Fail threshold: failed, warning, or never', 'failed')
  .option('-e, --engines <engines...>', 'Specific engines to execute (headers, cors, tls, auth, bola, contract)')
  .option('--silent', 'Suppress console logs (exit code only)', false)
  .action(async (options) => {
    try {
      // Standalone Local Mode Execution
      const result = await localRunner.run({
        configPath: options.config,
        targetUrl: options.target,
        engines: options.engines,
        failOn: options.failOn as 'failed' | 'warning' | 'never',
        format: options.format as 'terminal' | 'sarif' | 'junit' | 'html' | 'json',
        outputFile: options.output,
        silent: options.silent,
      });

      process.exit(result.exitCode);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(formatError(`Execution failed: ${message}`));
      process.exit(1);
    }
  });
