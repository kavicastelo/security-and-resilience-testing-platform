import { Command } from 'commander';
import pc from 'picocolors';
import { apiClient } from '../api/client.js';
import { Target } from '@security-lab/domain';

export const targetCommand = new Command('target')
  .description('Register, inspect, and validate authorized target scopes');

// Subcommand: list
targetCommand
  .command('list')
  .description('List registered targets')
  .option('-p, --project <projectId>', 'Filter by Project ID')
  .action(async (options) => {
    try {
      const path = options.project
        ? `/api/v1/projects/${options.project}/targets`
        : '/api/v1/targets';
      const targets = await apiClient.get<Target[]>(path);

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
      const msg = err instanceof Error ? err.message : String(err);
      console.error(pc.red(`✖ Failed to list targets: ${msg}`));
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
      const msg = err instanceof Error ? err.message : String(err);
      console.error(pc.red(`✖ Failed to register target: ${msg}`));
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
      const msg = err instanceof Error ? err.message : String(err);
      console.error(pc.red(`✖ Scope validation error: ${msg}`));
      process.exit(1);
    }
  });
