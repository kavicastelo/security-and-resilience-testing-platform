#!/usr/bin/env node
import { Command } from 'commander';
import { versionCommand } from './commands/version.js';
import pc from 'picocolors';

const program = new Command();

program
  .name('security-lab')
  .description('Security QA for Enterprise Applications - Local-First Security & Resilience Testing Platform')
  .version('0.1.0', '-v, --version', 'output current version')
  .option('-u, --api-url <url>', 'Controller API URL', 'http://localhost:4000')
  .option('-k, --api-key <key>', 'Authentication API Key')
  .option('--format <format>', 'Output format (table, json, yaml, junit)', 'table')
  .option('--verbose', 'Enable verbose logging output', false);

// 1. Registered and implemented command: version
program.addCommand(versionCommand);

// 2. Future command skeletons with clear PLANNED status
program
  .command('project')
  .description('[PLANNED: Phase 1] Manage test projects and workspaces')
  .action(() => {
    // eslint-disable-next-line no-console
    console.log(pc.yellow('ℹ Command "project" is planned for Phase 1 (Project Management & Persistence).'));
  });

program
  .command('target')
  .description('[PLANNED: Phase 1] Register, inspect, and validate authorized target scopes')
  .action(() => {
    // eslint-disable-next-line no-console
    console.log(pc.yellow('ℹ Command "target" is planned for Phase 1 (Scope Registration & Security Boundaries).'));
  });

program
  .command('test')
  .description('[PLANNED: Phase 2] Execute native security and resilience test definitions')
  .action(() => {
    // eslint-disable-next-line no-console
    console.log(pc.yellow('ℹ Command "test" is planned for Phase 2 (Native Test Engine Execution).'));
  });

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
