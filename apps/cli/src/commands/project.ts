import { Command } from 'commander';
import pc from 'picocolors';
import { apiClient } from '../api/client.js';
import { Project } from '@security-lab/domain';

export const projectCommand = new Command('project')
  .description('Manage security test projects and workspaces');

// Subcommand: list
projectCommand
  .command('list')
  .description('List all registered projects')
  .action(async () => {
    try {
      const projects = await apiClient.get<Project[]>('/api/v1/projects');
      if (projects.length === 0) {
        // eslint-disable-next-line no-console
        console.log(pc.yellow('No projects found. Create one with: security-lab project create --name <name>'));
        return;
      }

      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan('\nRegistered Projects:')));
      for (const p of projects) {
        // eslint-disable-next-line no-console
        console.log(`  ${pc.green('●')} ${pc.bold(p.name)} [ID: ${pc.dim(p.id)}]`);
        if (p.description) {
          // eslint-disable-next-line no-console
          console.log(`    ${pc.dim(p.description)}`);
        }
      }
      // eslint-disable-next-line no-console
      console.log('');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(pc.red(`✖ Failed to list projects: ${msg}`));
      process.exit(1);
    }
  });

// Subcommand: create
projectCommand
  .command('create')
  .description('Create a new project')
  .requiredOption('-n, --name <name>', 'Project name')
  .option('-d, --description <desc>', 'Project description')
  .action(async (options) => {
    try {
      const project = await apiClient.post<Project>('/api/v1/projects', {
        name: options.name,
        description: options.description,
      });

      // eslint-disable-next-line no-console
      console.log(pc.green(`✔ Project "${project.name}" created successfully! ID: ${project.id}`));
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(pc.red(`✖ Failed to create project: ${msg}`));
      process.exit(1);
    }
  });
