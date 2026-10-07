#!/usr/bin/env node
import { Command } from 'commander';
import { versionCommand } from './commands/version.js';
import { projectCommand } from './commands/project.js';
import { targetCommand } from './commands/target.js';
import { testCommand } from './commands/test.js';
import { scanCommand } from './commands/scan.js';
import { loadCommand } from './commands/load.js';
import { reportCommand } from './commands/report.js';
import { gateCommand } from './commands/gate.js';
import { policyCommand } from './commands/policy.js';
import { findingsCommand } from './commands/findings.js';
import { contractCommand } from './commands/contract.js';
import { runCommand } from './commands/run.js';

const program = new Command();


program
  .name('security-lab')
  .description('Security QA for Enterprise Applications - Local-First Security & Resilience Testing Platform')
  .version('0.1.0', '-v, --version', 'output current version')
  .option('-a, --api-url <url>', 'Controller API URL', 'http://localhost:4000')
  .option('-k, --api-key <key>', 'Authentication API Key')
  .option('--format <format>', 'Output format (table, json, yaml, junit)', 'table')
  .option('--verbose', 'Enable verbose logging output', false);

// Registered and implemented commands: version, project, target, test, scan, load, resilience, report, gate, policy, findings, contract
program.addCommand(versionCommand);
program.addCommand(projectCommand);
program.addCommand(targetCommand);
program.addCommand(testCommand);
program.addCommand(scanCommand);
program.addCommand(loadCommand);
program.addCommand(
  new Command('resilience')
    .description('Alias for Class C resilience & load testing')
    .addCommand(loadCommand.commands[0]!)
    .addCommand(loadCommand.commands[1]!),
);
program.addCommand(reportCommand);
program.addCommand(gateCommand);
program.addCommand(policyCommand);
program.addCommand(findingsCommand);
program.addCommand(contractCommand);
program.addCommand(runCommand);

program.parse(process.argv);



