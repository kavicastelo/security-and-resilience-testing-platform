import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { Command } from 'commander';
import pc from 'picocolors';
import { isInteractiveTerminal, createSpinner } from '../output/spinner.js';
import { renderSummaryBox } from '../output/table.js';
import { formatSuccess, formatError } from '../output/formatters.js';

export interface InitOptions {
  yes?: boolean;
  name?: string;
  url?: string;
  profile?: string;
  config?: string;
}

export const initCommand = new Command('init')
  .description('Interactive setup wizard to initialize Security Lab configuration in the current repository')
  .option('-y, --yes', 'Accept defaults and skip interactive prompts (ideal for CI/CD)', false)
  .option('-n, --name <name>', 'Project name')
  .option('-u, --url <url>', 'Default target URL to test', 'http://localhost:3000')
  .option('-p, --profile <profile>', 'Testing profile preset (standard, smoke, resilience, full)', 'standard')
  .option('-c, --config <path>', 'Destination config filename', '.securitylab.yaml')
  .action(async (options: InitOptions) => {
    try {
      const isInteractive = isInteractiveTerminal() && !options.yes;
      let projectName = options.name || path.basename(process.cwd());
      let targetUrl = options.url || 'http://localhost:3000';
      let selectedProfile = options.profile || 'standard';
      let selectedEngines: string[] = ['headers', 'cors', 'tls', 'auth', 'bola'];
      let maxSeverity = 'high';

      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan('\n🛡️  Security Lab — Repository Initialization Wizard\n')));

      if (isInteractive) {
        const rl = readline.createInterface({ input, output });

        try {
          // 1. Project Name
          const answerName = await rl.question(
            `${pc.bold('?')} Project Name ${pc.dim(`(${projectName})`)}: `,
          );
          if (answerName.trim()) {
            projectName = answerName.trim();
          }

          // 2. Target Base URL
          const answerUrl = await rl.question(
            `${pc.bold('?')} Target Base URL to scan ${pc.dim(`(${targetUrl})`)}: `,
          );
          if (answerUrl.trim()) {
            targetUrl = answerUrl.trim();
          }

          // 3. Testing Profile
          // eslint-disable-next-line no-console
          console.log(`\nSelect Testing Profile:`);
          // eslint-disable-next-line no-console
          console.log(`  ${pc.cyan('1)')} ${pc.bold('Standard API Security')} (headers, cors, tls, auth, bola) [Recommended]`);
          // eslint-disable-next-line no-console
          console.log(`  ${pc.cyan('2)')} ${pc.bold('Fast Smoke Scan')} (headers, cors, tls)`);
          // eslint-disable-next-line no-console
          console.log(`  ${pc.cyan('3)')} ${pc.bold('Full Resilience & Contracts')} (headers, cors, tls, auth, bola, contract)`);
          // eslint-disable-next-line no-console
          console.log(`  ${pc.cyan('4)')} ${pc.bold('Microservice Contract Only')} (contract)`);

          const answerProfile = await rl.question(`${pc.bold('?')} Choice [1-4] ${pc.dim('(1)')}: `);
          const choice = answerProfile.trim();
          if (choice === '2') {
            selectedProfile = 'smoke';
            selectedEngines = ['headers', 'cors', 'tls'];
          } else if (choice === '3') {
            selectedProfile = 'resilience';
            selectedEngines = ['headers', 'cors', 'tls', 'auth', 'bola', 'contract'];
          } else if (choice === '4') {
            selectedProfile = 'contract';
            selectedEngines = ['contract'];
          } else {
            selectedProfile = 'standard';
            selectedEngines = ['headers', 'cors', 'tls', 'auth', 'bola'];
          }

          // 4. Policy Gate Strictness
          const answerGate = await rl.question(
            `${pc.bold('?')} Block release on critical or high vulnerabilities? (Y/n) ${pc.dim('(Y)')}: `,
          );
          if (answerGate.trim().toLowerCase() === 'n') {
            maxSeverity = 'medium';
          }
        } finally {
          rl.close();
        }
      } else {
        // Non-interactive fallback: map profile to engines
        if (selectedProfile === 'smoke') {
          selectedEngines = ['headers', 'cors', 'tls'];
        } else if (selectedProfile === 'resilience') {
          selectedEngines = ['headers', 'cors', 'tls', 'auth', 'bola', 'contract'];
        } else if (selectedProfile === 'contract') {
          selectedEngines = ['contract'];
        } else {
          selectedEngines = ['headers', 'cors', 'tls', 'auth', 'bola'];
        }
      }

      const spinner = createSpinner('Generating Security Lab workspace files...').start();

      // Parse target URL hostname for allowedHosts and port
      let targetHostname = 'localhost';
      let targetPort = 3000;
      try {
        const parsed = new URL(targetUrl);
        targetHostname = parsed.hostname;
        targetPort = parsed.port
          ? parseInt(parsed.port, 10)
          : parsed.protocol === 'https:'
            ? 443
            : 80;
      } catch {
        // Use defaults
      }

      // Generate .securitylab.yaml configuration
      const configYaml = `# Security Lab Project Configuration
# Generated by: security-lab init
version: "1.0"
name: "${projectName}"

target:
  name: "${projectName} Target"
  baseUrl: "${targetUrl}"
  allowedHosts:
    - "${targetHostname}"
  allowedPorts:
    - ${targetPort}
  excludedPaths:
    - "/admin"
    - "/metrics"
    - "/healthz"

definitions:
  engines:
${selectedEngines.map((e) => `    - "${e}"`).join('\n')}

policy:
  name: "${projectName} Default Release Gate"
  maxAllowedSeverity: "${maxSeverity}"
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
  sarifFile: "./reports/security-lab.sarif"
  junitFile: "./reports/junit.xml"
`;

      const targetConfigPath = path.resolve(process.cwd(), options.config || '.securitylab.yaml');
      fs.writeFileSync(targetConfigPath, configYaml, 'utf-8');

      // Create .security-lab working directory
      const localDir = path.resolve(process.cwd(), '.security-lab');
      if (!fs.existsSync(localDir)) {
        fs.mkdirSync(localDir, { recursive: true });
        fs.writeFileSync(path.join(localDir, '.gitignore'), '# Security Lab local cache\n*\n!.gitignore\n', 'utf-8');
      }

      spinner.succeed(`Configuration saved to ${pc.bold(path.basename(targetConfigPath))}`);

      // Summary Box
      // eslint-disable-next-line no-console
      console.log('');
      // eslint-disable-next-line no-console
      console.log(
        renderSummaryBox('Security Lab Configuration Initialized', [
          { label: 'Project Name', value: projectName },
          { label: 'Target Base URL', value: targetUrl },
          { label: 'Testing Profile', value: selectedProfile },
          { label: 'Enabled Engines', value: selectedEngines.join(', ') },
          { label: 'Config File', value: path.basename(targetConfigPath) },
        ]),
      );

      // eslint-disable-next-line no-console
      console.log(`\n${formatSuccess('Ready to run security tests!')}`);
      // eslint-disable-next-line no-console
      console.log(`  Execute your first test suite with: ${pc.bold(pc.cyan('security-lab run --local'))}\n`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(formatError(`Failed to initialize configuration: ${msg}`));
      process.exit(1);
    }
  });
