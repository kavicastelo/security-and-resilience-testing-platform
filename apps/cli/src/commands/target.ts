import { Command } from 'commander';
import pc from 'picocolors';
import { apiClient } from '../api/client.js';
import { formatCliError } from '../output/formatters.js';
import { Target } from '@security-lab/domain';

export const targetCommand = new Command('target')
  .description('Register, inspect, update, and validate authorized target scopes');

// Subcommand: list
targetCommand
  .command('list')
  .description('List registered targets')
  .option('-p, --project <projectId>', 'Filter by Project ID')
  .option('--format <format>', 'Output format (table, json)', 'table')
  .action(async (options) => {
    try {
      const path = options.project
        ? `/api/v1/projects/${options.project}/targets`
        : '/api/v1/targets';
      const targets = await apiClient.get<Target[]>(path);

      if (options.format === 'json') {
        // eslint-disable-next-line no-console
        console.log(JSON.stringify(targets, null, 2));
        return;
      }

      if (targets.length === 0) {
        // eslint-disable-next-line no-console
        console.log(pc.yellow('No targets registered. Add one with: security-lab target create'));
        return;
      }

      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan('\nRegistered Targets & Security Scopes:')));
      for (const t of targets) {
        // eslint-disable-next-line no-console
        console.log(`\n  ${pc.green('●')} ${pc.bold(t.name)} [ID: ${pc.dim(t.id)}]`);
        // eslint-disable-next-line no-console
        console.log(`    Base URL:        ${pc.cyan(t.baseUrl)}`);
        // eslint-disable-next-line no-console
        console.log(`    Allowed Hosts:   ${t.scope.allowedHosts.join(', ')}`);
        // eslint-disable-next-line no-console
        console.log(`    Allowed Ports:   ${t.scope.allowedPorts.join(', ')}`);
        // eslint-disable-next-line no-console
        console.log(
          `    Testing Gates:   activeScanning=${t.scope.testing.activeScanning ? pc.green('yes') : pc.red('no')}, loadTesting=${t.scope.testing.loadTesting ? pc.green('yes') : pc.red('no')}`,
        );
        // eslint-disable-next-line no-console
        console.log(`    Safety Limits:   maxRps=${t.scope.limits.maxRps}, maxConcurrency=${t.scope.limits.maxConcurrency}`);
      }
      // eslint-disable-next-line no-console
      console.log('');
    } catch (err: unknown) {
      console.error(formatCliError(err, 'Failed to list targets'));
      process.exit(1);
    }
  });

// Subcommand: get
targetCommand
  .command('get <id>')
  .description('Inspect details and defensive boundaries of a specific target')
  .option('--format <format>', 'Output format (table, json)', 'table')
  .action(async (id: string, options) => {
    try {
      const target = await apiClient.get<Target>(`/api/v1/targets/${id}`);

      if (options.format === 'json') {
        // eslint-disable-next-line no-console
        console.log(JSON.stringify(target, null, 2));
        return;
      }

      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan(`\nTarget: ${target.name} [${target.id}]`)));
      // eslint-disable-next-line no-console
      console.log(`  Project ID:      ${pc.dim(target.projectId)}`);
      // eslint-disable-next-line no-console
      console.log(`  Base URL:        ${pc.cyan(target.baseUrl)}`);
      // eslint-disable-next-line no-console
      console.log(`  Allowed Hosts:   ${target.scope.allowedHosts.join(', ')}`);
      // eslint-disable-next-line no-console
      console.log(`  Allowed Ports:   ${target.scope.allowedPorts.join(', ')}`);
      // eslint-disable-next-line no-console
      console.log(`  Excluded Paths:  ${target.scope.excludedPaths.length > 0 ? target.scope.excludedPaths.join(', ') : 'None'}`);
      // eslint-disable-next-line no-console
      console.log(`  Active Scanning: ${target.scope.testing.activeScanning ? pc.green('Authorized') : pc.red('Blocked')}`);
      // eslint-disable-next-line no-console
      console.log(`  Load Testing:    ${target.scope.testing.loadTesting ? pc.green('Authorized') : pc.red('Blocked')}`);
      // eslint-disable-next-line no-console
      console.log(`  Max RPS:         ${target.scope.limits.maxRps}`);
      // eslint-disable-next-line no-console
      console.log(`  Max Concurrency: ${target.scope.limits.maxConcurrency}`);
      // eslint-disable-next-line no-console
      console.log(`  Created:         ${new Date(target.createdAt).toLocaleString()}\n`);
    } catch (err: unknown) {
      console.error(formatCliError(err, `Failed to get target "${id}"`));
      process.exit(1);
    }
  });

// Subcommand: create
targetCommand
  .command('create')
  .description('Register a new target with strict scope boundaries')
  .requiredOption('-p, --project <projectId>', 'Parent Project ID')
  .requiredOption('-n, --name <name>', 'Target name')
  .requiredOption('-u, --url <url>', 'Base URL (must match allowed hosts/ports)')
  .requiredOption('--hosts <hosts>', 'Comma-separated allowed hosts (e.g. api.example.com)')
  .option('--ports <ports>', 'Comma-separated allowed ports (default: 80,443)', '80,443')
  .option('--exclude-paths <paths>', 'Comma-separated excluded paths (e.g. /admin,/reset)')
  .option('--active', 'Authorize active security scanning', false)
  .option('--load', 'Authorize load & resilience testing', false)
  .option('--max-rps <rps>', 'Max requests per second safety limit', '100')
  .option('--max-concurrency <concurrency>', 'Max concurrency safety limit', '20')
  .action(async (options) => {
    try {
      const allowedHosts = options.hosts.split(',').map((h: string) => h.trim());
      const allowedPorts = options.ports.split(',').map((p: string) => parseInt(p.trim(), 10));
      const excludedPaths = options.excludePaths
        ? options.excludePaths.split(',').map((p: string) => p.trim())
        : [];

      const target = await apiClient.post<Target>(`/api/v1/projects/${options.project}/targets`, {
        name: options.name,
        baseUrl: options.url,
        allowedHosts,
        allowedPorts,
        excludedPaths,
        testing: {
          activeScanning: options.active,
          loadTesting: options.load,
          chaosTesting: false,
        },
        limits: {
          maxRps: parseInt(options.maxRps, 10),
          maxConcurrency: parseInt(options.maxConcurrency, 10),
          maxDuration: '10m',
        },
      });

      // eslint-disable-next-line no-console
      console.log(pc.green(`✔ Target "${target.name}" registered successfully! ID: ${target.id}`));
      // eslint-disable-next-line no-console
      console.log(`  Allowed Hosts: [${target.scope.allowedHosts.join(', ')}]`);
      // eslint-disable-next-line no-console
      console.log(`  Allowed Ports: [${target.scope.allowedPorts.join(', ')}]`);
    } catch (err: unknown) {
      console.error(formatCliError(err, 'Failed to register target'));
      process.exit(1);
    }
  });

// Subcommand: update
targetCommand
  .command('update <id>')
  .description('Update target metadata or security boundaries')
  .option('-n, --name <name>', 'Target name')
  .option('-u, --url <url>', 'Base URL')
  .option('--hosts <hosts>', 'Comma-separated allowed hosts')
  .option('--ports <ports>', 'Comma-separated allowed ports')
  .option('--exclude-paths <paths>', 'Comma-separated excluded paths')
  .option('--active <bool>', 'Authorize active scanning (true/false)')
  .option('--load <bool>', 'Authorize load testing (true/false)')
  .option('--max-rps <rps>', 'Max RPS safety limit')
  .option('--max-concurrency <concurrency>', 'Max concurrency safety limit')
  .action(async (id: string, options) => {
    try {
      const payload: Record<string, unknown> = {};
      if (options.name) payload.name = options.name;
      if (options.url) payload.baseUrl = options.url;
      if (options.hosts) {
        payload.allowedHosts = options.hosts.split(',').map((h: string) => h.trim());
      }
      if (options.ports) {
        payload.allowedPorts = options.ports.split(',').map((p: string) => parseInt(p.trim(), 10));
      }
      if (options.excludePaths) {
        payload.excludedPaths = options.excludePaths.split(',').map((p: string) => p.trim());
      }

      const testing: Record<string, boolean> = {};
      if (options.active !== undefined) testing.activeScanning = options.active === 'true' || options.active === true;
      if (options.load !== undefined) testing.loadTesting = options.load === 'true' || options.load === true;
      if (Object.keys(testing).length > 0) payload.testing = testing;

      const limits: Record<string, unknown> = {};
      if (options.maxRps) limits.maxRps = parseInt(options.maxRps, 10);
      if (options.maxConcurrency) limits.maxConcurrency = parseInt(options.maxConcurrency, 10);
      if (Object.keys(limits).length > 0) payload.limits = limits;

      const target = await apiClient.put<Target>(`/api/v1/targets/${id}`, payload);

      // eslint-disable-next-line no-console
      console.log(pc.green(`✔ Target "${target.name}" [ID: ${target.id}] updated successfully!`));
      // eslint-disable-next-line no-console
      console.log(`  Base URL:      ${target.baseUrl}`);
      // eslint-disable-next-line no-console
      console.log(`  Allowed Hosts: [${target.scope.allowedHosts.join(', ')}]`);
    } catch (err: unknown) {
      console.error(formatCliError(err, `Failed to update target "${id}"`));
      process.exit(1);
    }
  });

// Subcommand: delete
targetCommand
  .command('delete <id>')
  .description('Delete a target and all associated test runs and findings')
  .action(async (id: string) => {
    try {
      await apiClient.delete(`/api/v1/targets/${id}`);
      // eslint-disable-next-line no-console
      console.log(pc.green(`✔ Target [ID: ${id}] and associated records deleted successfully.`));
    } catch (err: unknown) {
      console.error(formatCliError(err, `Failed to delete target "${id}"`));
      process.exit(1);
    }
  });

// Subcommand: validate
targetCommand
  .command('validate')
  .description('Pre-flight validate a candidate URL and test parameters against target scope')
  .requiredOption('-t, --target <targetId>', 'Target ID to evaluate against')
  .requiredOption('-u, --url <candidateUrl>', 'Candidate URL to validate')
  .option('--capability <cap>', 'Requested capability (activeScanning, loadTesting, chaosTesting)')
  .option('--rps <rps>', 'Requested requests per second')
  .option('--concurrency <concurrency>', 'Requested concurrency')
  .action(async (options) => {
    try {
      interface ScopeValidationResponse {
        targetName: string;
        candidateUrl: string;
        valid: boolean;
        violations: string[];
      }

      const result = await apiClient.post<ScopeValidationResponse>(
        `/api/v1/targets/${options.target}/validate-scope`,
        {
          candidateUrl: options.url,
          capability: options.capability,
          requestedRps: options.rps ? parseInt(options.rps, 10) : undefined,
          requestedConcurrency: options.concurrency ? parseInt(options.concurrency, 10) : undefined,
        },
      );

      // eslint-disable-next-line no-console
      console.log(`\nEvaluating: ${pc.cyan(result.candidateUrl)}`);
      // eslint-disable-next-line no-console
      console.log(`Target:     ${pc.bold(result.targetName)}`);

      if (result.valid) {
        // eslint-disable-next-line no-console
        console.log(`\n${pc.bold(pc.green('✔ SCOPE VERIFIED: URL and parameters are within authorized boundaries.'))}\n`);
      } else {
        // eslint-disable-next-line no-console
        console.log(`\n${pc.bold(pc.red('✖ SCOPE VIOLATION: Execution is BLOCKED by defensive boundaries:'))}`);
        for (const v of result.violations) {
          // eslint-disable-next-line no-console
          console.log(`  - ${pc.yellow(v)}`);
        }
        // eslint-disable-next-line no-console
        console.log('');
        process.exit(1);
      }
    } catch (err: unknown) {
      console.error(formatCliError(err, 'Scope validation error'));
      process.exit(1);
    }
  });
