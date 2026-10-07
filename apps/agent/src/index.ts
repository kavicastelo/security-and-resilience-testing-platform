#!/usr/bin/env node
import { Command } from 'commander';
import { loadAgentConfig } from './config.js';
import { AgentDaemon } from './daemon.js';
import { AgentClient } from './client.js';
import { logger } from '@security-lab/logger';

export * from './config.js';
export * from './client.js';
export * from './worker.js';
export * from './daemon.js';

const program = new Command();

program
  .name('security-lab-agent')
  .description('Distributed Execution Agent for Security Lab hybrid-cloud testing')
  .version('0.1.0');

program
  .command('start')
  .description('Starts the agent daemon in polling mode')
  .option('-u, --url <url>', 'Control plane URL (default: env CONTROLLER_URL or http://localhost:4000)')
  .option('-t, --token <token>', 'Agent enrollment token (default: env AGENT_TOKEN)')
  .option('-i, --id <id>', 'Agent ID (default: env AGENT_ID)')
  .option('-n, --name <name>', 'Agent name identifier')
  .option('--tags <tags>', 'Comma-separated tags (e.g. vpc-production,on-premise)')
  .option('--tenant <tenantId>', 'Tenant ID for multi-tenant SaaS control plane')
  .action(async (options) => {
    const config = loadAgentConfig({
      controllerUrl: options.url,
      agentToken: options.token,
      agentId: options.id,
      name: options.name,
      tags: options.tags ? options.tags.split(',').map((t: string) => t.trim()) : undefined,
      tenantId: options.tenant,
    });

    const daemon = new AgentDaemon(config);

    const shutdown = async () => {
      logger.info('Received termination signal...');
      await daemon.stop();
      process.exit(0);
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);

    await daemon.start();
  });

program
  .command('register')
  .description('Enrolls a new agent with the control plane and prints the authentication token')
  .requiredOption('-u, --url <url>', 'Control plane URL')
  .requiredOption('-n, --name <name>', 'Agent name identifier')
  .option('--tags <tags>', 'Comma-separated tags')
  .option('--tenant <tenantId>', 'Tenant ID')
  .action(async (options) => {
    const client = new AgentClient(options.url);
    const tags = options.tags ? options.tags.split(',').map((t: string) => t.trim()) : ['default'];

    try {
      const res = await client.register(
        {
          name: options.name,
          tags,
          capabilities: ['engine-native-headers', 'engine-native-cors', 'engine-native-tls'],
        },
        options.tenant,
      );

      console.info('\n--- Agent Enrolled Successfully ---');
      console.info(`Agent ID:   ${res.agentId}`);
      console.info(`Tenant ID:  ${res.tenantId}`);
      console.info(`Token:      ${res.token}`);
      console.info('------------------------------------\n');
      console.info('Save this token in your environment as AGENT_TOKEN or Kubernetes secret.');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`Enrollment failed: ${msg}`);
      process.exit(1);
    }
  });

// Only parse when invoked directly via CLI
if (process.argv[1]?.endsWith('security-lab-agent') || process.argv[1]?.endsWith('index.js')) {
  program.parse(process.argv);
}
