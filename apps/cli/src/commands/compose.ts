import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { Command } from 'commander';
import pc from 'picocolors';
import { isInteractiveTerminal, createSpinner } from '../output/spinner.js';
import { renderSummaryBox, renderTable } from '../output/table.js';
import { formatSuccess, formatError } from '../output/formatters.js';

export interface ComposeOptions {
  name?: string;
  url?: string;
  preset?: string;
  engines?: string[];
  output?: string;
  rps?: string;
  concurrency?: string;
  dryRun?: boolean;
}

export const composeCommand = new Command('compose')
  .description('Interactive test plan composer to sequence security engines and generate runnable test plans')
  .option('-n, --name <name>', 'Test plan name', 'Custom Test Plan')
  .option('-u, --url <url>', 'Target base URL to test', 'http://localhost:3000')
  .option('-p, --preset <preset>', 'Engine preset (smoke, owasp, contracts, full)', 'owasp')
  .option('-e, --engines <engines...>', 'Custom list of engines (headers, cors, tls, auth, bola, contract)')
  .option('-o, --output <path>', 'Destination YAML file path', 'test-plan.yaml')
  .option('--rps <rps>', 'Max requests per second limit', '100')
  .option('--concurrency <concurrency>', 'Max concurrency limit', '10')
  .option('--dry-run', 'Print composed plan to stdout without writing to disk', false)
  .action(async (options: ComposeOptions) => {
    try {
      const isInteractive = isInteractiveTerminal() && !options.preset && !options.engines;
      let planName = options.name || 'Custom Test Plan';
      let targetUrl = options.url || 'http://localhost:3000';
      let selectedEngines: string[] = ['headers', 'cors', 'tls', 'auth', 'bola'];
      let maxRps = parseInt(options.rps || '100', 10);
      let maxConcurrency = parseInt(options.concurrency || '10', 10);
      let outputPath = options.output || 'test-plan.yaml';

      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan('\n🛡️  Security Lab — Interactive Test Plan Composer\n')));

      if (isInteractive) {
        const rl = readline.createInterface({ input, output });
        try {
          const answerName = await rl.question(
            `${pc.bold('?')} Plan Name ${pc.dim(`(${planName})`)}: `,
          );
          if (answerName.trim()) {
            planName = answerName.trim();
          }

          const answerUrl = await rl.question(
            `${pc.bold('?')} Target URL ${pc.dim(`(${targetUrl})`)}: `,
          );
          if (answerUrl.trim()) {
            targetUrl = answerUrl.trim();
          }

          // eslint-disable-next-line no-console
          console.log('\nSelect Engine Execution Preset:');
          // eslint-disable-next-line no-console
          console.log(`  ${pc.cyan('1)')} ${pc.bold('OWASP API Top 10')} (headers, cors, tls, auth, bola) [Recommended]`);
          // eslint-disable-next-line no-console
          console.log(`  ${pc.cyan('2)')} ${pc.bold('Fast Smoke Suite')} (headers, cors, tls)`);
          // eslint-disable-next-line no-console
          console.log(`  ${pc.cyan('3)')} ${pc.bold('API Schema & Contracts')} (headers, contract)`);
          // eslint-disable-next-line no-console
          console.log(`  ${pc.cyan('4)')} ${pc.bold('Full Enterprise Security')} (headers, cors, tls, auth, bola, contract)`);

          const answerPreset = await rl.question(`${pc.bold('?')} Choice [1-4] ${pc.dim('(1)')}: `);
          const choice = answerPreset.trim();
          if (choice === '2') {
            selectedEngines = ['headers', 'cors', 'tls'];
          } else if (choice === '3') {
            selectedEngines = ['headers', 'contract'];
          } else if (choice === '4') {
            selectedEngines = ['headers', 'cors', 'tls', 'auth', 'bola', 'contract'];
          } else {
            selectedEngines = ['headers', 'cors', 'tls', 'auth', 'bola'];
          }

          const answerRps = await rl.question(`${pc.bold('?')} Max RPS safety limit ${pc.dim(`(${maxRps})`)}: `);
          if (answerRps.trim()) {
            maxRps = parseInt(answerRps.trim(), 10) || maxRps;
          }

          const answerOut = await rl.question(`${pc.bold('?')} Output File ${pc.dim(`(${outputPath})`)}: `);
          if (answerOut.trim()) {
            outputPath = answerOut.trim();
          }
        } finally {
          rl.close();
        }
      } else {
        if (options.engines && options.engines.length > 0) {
          selectedEngines = options.engines;
        } else if (options.preset) {
          const p = options.preset.toLowerCase();
          if (p === 'smoke') {
            selectedEngines = ['headers', 'cors', 'tls'];
          } else if (p === 'contracts' || p === 'contract') {
            selectedEngines = ['headers', 'contract'];
          } else if (p === 'full') {
            selectedEngines = ['headers', 'cors', 'tls', 'auth', 'bola', 'contract'];
          } else {
            selectedEngines = ['headers', 'cors', 'tls', 'auth', 'bola'];
          }
        }
      }

      // Format engines table preview
      const engineTableHeaders = ['ORDER', 'ENGINE ID', 'CLASS', 'DESCRIPTION'];
      const engineDetails: Record<string, { cls: string; desc: string }> = {
        headers: { cls: 'Class A (Native)', desc: 'Security response headers (HSTS, CSP, X-Frame-Options)' },
        cors: { cls: 'Class A (Native)', desc: 'Cross-Origin Resource Sharing preflight & origin reflection' },
        tls: { cls: 'Class A (Native)', desc: 'TLS protocol version, cipher suites & certificate validity' },
        auth: { cls: 'Class A (Native)', desc: 'Authentication token expiration, weakness & bypass checks' },
        bola: { cls: 'Class A (Native)', desc: 'Broken Object-Level Authorization & privilege escalation' },
        contract: { cls: 'Class A (Native)', desc: 'OpenAPI / JSON Schema contract drift validation' },
      };

      const engineRows = selectedEngines.map((eng, idx) => [
        idx + 1,
        pc.bold(eng),
        engineDetails[eng]?.cls || 'Class A',
        engineDetails[eng]?.desc || 'Custom Engine Execution',
      ]);

      // eslint-disable-next-line no-console
      console.log(pc.bold('Sequenced Engine Pipeline:'));
      // eslint-disable-next-line no-console
      console.log(renderTable(engineTableHeaders, engineRows, { borderStyle: 'unicode' }));

      // Plan YAML Content
      const planYaml = `# Security Lab Test Plan Specification
# Generated via: security-lab plan compose
version: "1.0"
name: "${planName}"

target:
  baseUrl: "${targetUrl}"
  limits:
    maxRps: ${maxRps}
    maxConcurrency: ${maxConcurrency}
    maxDuration: "5m"

definitions:
  engines:
${selectedEngines.map((e) => `    - "${e}"`).join('\n')}

policy:
  name: "${planName} Policy Gate"
  maxAllowedSeverity: "high"
  maxCriticalFindings: 0
  maxHighFindings: 0
  minPostureScore: 80
  failOn: "failed"

reporters:
  formats:
    - "terminal"
    - "sarif"
    - "junit"
  outputDir: "./reports"
`;

      if (options.dryRun) {
        // eslint-disable-next-line no-console
        console.log(`\n${pc.bold(pc.cyan('--- DRY RUN: Generated Plan Specification ---'))}\n`);
        // eslint-disable-next-line no-console
        console.log(planYaml);
        return;
      }

      const spinner = createSpinner(`Saving plan to ${outputPath}...`).start();
      const resolvedPath = path.resolve(process.cwd(), outputPath);
      fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });
      fs.writeFileSync(resolvedPath, planYaml, 'utf-8');
      spinner.succeed(`Plan composed and saved to: ${pc.bold(path.basename(resolvedPath))}`);

      // eslint-disable-next-line no-console
      console.log('');
      // eslint-disable-next-line no-console
      console.log(
        renderSummaryBox('Composed Test Plan Summary', [
          { label: 'Plan Name', value: planName },
          { label: 'Target URL', value: targetUrl },
          { label: 'Engine Count', value: selectedEngines.length },
          { label: 'Engines', value: selectedEngines.join(', ') },
          { label: 'Safety Limit', value: `${maxRps} RPS / ${maxConcurrency} conc` },
          { label: 'Saved To', value: path.basename(resolvedPath) },
        ]),
      );

      // eslint-disable-next-line no-console
      console.log(`\n${formatSuccess('Test plan ready for execution!')}`);
      // eslint-disable-next-line no-console
      console.log(`  Execute using: ${pc.bold(pc.cyan(`security-lab run --local --config ${path.basename(resolvedPath)}`))}\n`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(formatError(`Failed to compose test plan: ${msg}`));
      process.exit(1);
    }
  });
