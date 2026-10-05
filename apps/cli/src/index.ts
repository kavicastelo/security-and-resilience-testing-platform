#!/usr/bin/env node
import { Command } from 'commander';
import { versionCommand } from './commands/version.js';
import { projectCommand } from './commands/project.js';
import { targetCommand } from './commands/target.js';
import { testCommand } from './commands/test.js';
import pc from 'picocolors';

const program = new Command();

program
  .name('security-lab')
  .description('Security QA for Enterprise Applications - Local-First Security & Resilience Testing Platform')
  .version('0.1.0', '-v, --version', 'output current version')
  .option('-a, --api-url <url>', 'Controller API URL', 'http://localhost:4000')
  .option('-k, --api-key <key>', 'Authentication API Key')
  .option('--format <format>', 'Output format (table, json, yaml, junit)', 'table')
  .option('--verbose', 'Enable verbose logging output', false);

// Registered and implemented commands: version, project, target, test
program.addCommand(versionCommand);
program.addCommand(projectCommand);
program.addCommand(targetCommand);
program.addCommand(testCommand);

program
  .command('scan')
  .description('[PLANNED: Phase 2] Launch containerized scanners (Class B/C runners) against authorized targets')
  .action(() => {
    // eslint-disable-next-line no-console
    console.log(pc.yellow('ℹ Command "scan" is planned for Phase 2 (Isolated Container Test Runners).'));
  });

program
  .command('report')
  .description('[PLANNED: Phase 3] Generate machine-readable findings and release gate reports')
  .action(() => {
    // eslint-disable-next-line no-console
    console.log(pc.yellow('ℹ Command "report" is planned for Phase 3 (Evidence & Policy Gate Reporting).'));
  });

program.parse(process.argv);
