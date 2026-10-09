import { Command } from 'commander';
import pc from 'picocolors';
import { apiClient } from '../api/client.js';
import { formatCliError } from '../output/formatters.js';

interface PolicyRule {
  id: string;
  name: string;
  description?: string;
  condition: {
    maxAllowedSeverity?: string;
    maxCountBySeverity?: {
      critical?: number;
      high?: number;
      medium?: number;
      low?: number;
    };
    maxP95LatencyMs?: number;
    maxErrorRatePercent?: number;
    minPassPercentage?: number;
  };
  action: 'block_release' | 'warn';
}

interface Policy {
  id: string;
  name: string;
  description?: string;
  rules: PolicyRule[];
  isDefault?: boolean;
  createdAt?: string;
}

export const policyCommand = new Command('policy')
  .description('Manage release gate policies and deployment thresholds');

// Subcommand: list
policyCommand
  .command('list')
  .description('List all registered release gate policies')
  .option('--format <format>', 'Output format (table, json)', 'table')
  .action(async (options) => {
    try {
      const policies = await apiClient.get<Policy[]>('/api/v1/policies');

      if (options.format === 'json') {
        // eslint-disable-next-line no-console
        console.log(JSON.stringify(policies, null, 2));
        return;
      }

      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan('\nRelease Gate Policies:')));
      for (const p of policies) {
        const isBaseline = p.id === '00000000-0000-0000-0000-000000000001' || p.isDefault;
        // eslint-disable-next-line no-console
        console.log(`\n  ${pc.green('●')} ${pc.bold(p.name)} [ID: ${pc.dim(p.id)}] ${isBaseline ? pc.bgBlue(pc.white(' BASELINE ')) : ''}`);
        if (p.description) {
          // eslint-disable-next-line no-console
          console.log(`    ${pc.dim(p.description)}`);
        }
        // eslint-disable-next-line no-console
        console.log(`    Rules configured: ${p.rules?.length || 0}`);
      }
      // eslint-disable-next-line no-console
      console.log('');
    } catch (err: unknown) {
      console.error(formatCliError(err, 'Failed to list policies'));
      process.exit(1);
    }
  });

// Subcommand: get
policyCommand
  .command('get <id>')
  .description('Inspect details and rules of a specific policy')
  .option('--format <format>', 'Output format (table, json)', 'table')
  .action(async (id: string, options) => {
    try {
      const policy = await apiClient.get<Policy>(`/api/v1/policies/${id}`);

      if (options.format === 'json') {
        // eslint-disable-next-line no-console
        console.log(JSON.stringify(policy, null, 2));
        return;
      }

      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan(`\nPolicy: ${policy.name}`)));
      // eslint-disable-next-line no-console
      console.log(`  ID:          ${pc.dim(policy.id)}`);
      if (policy.description) {
        // eslint-disable-next-line no-console
        console.log(`  Description: ${policy.description}`);
      }

      // eslint-disable-next-line no-console
      console.log(pc.bold('\n  Configured Rules:'));
      for (const r of policy.rules || []) {
        // eslint-disable-next-line no-console
        console.log(`    • ${pc.bold(r.name)} [Action: ${r.action === 'block_release' ? pc.red('BLOCK') : pc.yellow('WARN')}]`);
        if (r.condition.maxCountBySeverity) {
          const c = r.condition.maxCountBySeverity;
          // eslint-disable-next-line no-console
          console.log(`      Severity Caps: Crit=${c.critical ?? 0}, High=${c.high ?? 0}, Med=${c.medium ?? 0}`);
        }
        if (r.condition.maxP95LatencyMs) {
          // eslint-disable-next-line no-console
          console.log(`      Max P95 Latency: ${r.condition.maxP95LatencyMs}ms`);
        }
        if (r.condition.maxErrorRatePercent) {
          // eslint-disable-next-line no-console
          console.log(`      Max Error Rate:  ${r.condition.maxErrorRatePercent}%`);
        }
      }
      // eslint-disable-next-line no-console
      console.log('');
    } catch (err: unknown) {
      console.error(formatCliError(err, `Failed to get policy "${id}"`));
      process.exit(1);
    }
  });

// Subcommand: create
policyCommand
  .command('create')
  .description('Create a custom release gate policy')
  .requiredOption('-n, --name <name>', 'Policy name')
  .option('-d, --description <desc>', 'Policy description')
  .option('--critical <n>', 'Maximum critical findings allowed', '0')
  .option('--high <n>', 'Maximum high findings allowed', '0')
  .option('--medium <n>', 'Maximum medium findings allowed', '5')
  .option('--max-p95 <ms>', 'Maximum P95 latency threshold in ms', '500')
  .option('--max-error-rate <rate>', 'Maximum error rate percentage', '1.0')
  .action(async (options) => {
    try {
      const rules: PolicyRule[] = [
        {
          id: `rule-severity-${Date.now()}`,
          name: 'Vulnerability Severity Thresholds',
          description: `Zero critical findings and maximum ${options.high} high findings allowed`,
          condition: {
            maxCountBySeverity: {
              critical: parseInt(options.critical, 10),
              high: parseInt(options.high, 10),
              medium: parseInt(options.medium, 10),
            },
          },
          action: 'block_release',
        },
        {
          id: `rule-latency-sla-${Date.now()}`,
          name: 'P95 Latency SLA Gating',
          description: `P95 response latency under load must not exceed ${options.maxP95}ms`,
          condition: {
            maxP95LatencyMs: parseInt(options.maxP95, 10),
            maxErrorRatePercent: parseFloat(options.maxErrorRate),
          },
          action: 'block_release',
        },
      ];

      const policy = await apiClient.post<Policy>('/api/v1/policies', {
        name: options.name,
        description: options.description,
        rules,
      });

      // eslint-disable-next-line no-console
      console.log(pc.green(`✔ Policy "${policy.name}" created successfully! ID: ${policy.id}`));
    } catch (err: unknown) {
      console.error(formatCliError(err, 'Failed to create policy'));
      process.exit(1);
    }
  });

// Subcommand: update
policyCommand
  .command('update <id>')
  .description('Update a custom policy')
  .option('-n, --name <name>', 'Policy name')
  .option('-d, --description <desc>', 'Policy description')
  .option('--critical <n>', 'Maximum critical findings allowed')
  .option('--high <n>', 'Maximum high findings allowed')
  .option('--medium <n>', 'Maximum medium findings allowed')
  .option('--max-p95 <ms>', 'Maximum P95 latency threshold in ms')
  .option('--max-error-rate <rate>', 'Maximum error rate percentage')
  .action(async (id: string, options) => {
    try {
      const payload: Record<string, unknown> = {};
      if (options.name) payload.name = options.name;
      if (options.description !== undefined) payload.description = options.description;

      if (options.critical !== undefined || options.high !== undefined || options.medium !== undefined || options.maxP95 !== undefined) {
        payload.rules = [
          {
            id: `rule-severity-${Date.now()}`,
            name: 'Vulnerability Severity Thresholds',
            condition: {
              maxCountBySeverity: {
                critical: options.critical ? parseInt(options.critical, 10) : 0,
                high: options.high ? parseInt(options.high, 10) : 0,
                medium: options.medium ? parseInt(options.medium, 10) : 5,
              },
            },
            action: 'block_release',
          },
          {
            id: `rule-latency-sla-${Date.now()}`,
            name: 'P95 Latency SLA Gating',
            condition: {
              maxP95LatencyMs: options.maxP95 ? parseInt(options.maxP95, 10) : 500,
              maxErrorRatePercent: options.maxErrorRate ? parseFloat(options.maxErrorRate) : 1.0,
            },
            action: 'block_release',
          },
        ];
      }

      const policy = await apiClient.put<Policy>(`/api/v1/policies/${id}`, payload);
      // eslint-disable-next-line no-console
      console.log(pc.green(`✔ Policy "${policy.name}" [ID: ${policy.id}] updated successfully!`));
    } catch (err: unknown) {
      console.error(formatCliError(err, `Failed to update policy "${id}"`));
      process.exit(1);
    }
  });

// Subcommand: delete
policyCommand
  .command('delete <id>')
  .description('Delete a custom release gate policy')
  .action(async (id: string) => {
    try {
      await apiClient.delete(`/api/v1/policies/${id}`);
      // eslint-disable-next-line no-console
      console.log(pc.green(`✔ Policy [ID: ${id}] deleted successfully.`));
    } catch (err: unknown) {
      console.error(formatCliError(err, `Failed to delete policy "${id}"`));
      process.exit(1);
    }
  });
