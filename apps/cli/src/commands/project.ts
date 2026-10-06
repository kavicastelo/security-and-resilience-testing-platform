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
  .option('--format <format>', 'Output format (table, json)', 'table')
  .action(async (options) => {
    try {
      const projects = await apiClient.get<Project[]>('/api/v1/projects');

      if (options.format === 'json') {
        // eslint-disable-next-line no-console
        console.log(JSON.stringify(projects, null, 2));
        return;
      }

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

// Subcommand: get
projectCommand
  .command('get <id>')
  .description('Inspect details of a specific project')
  .option('--format <format>', 'Output format (table, json)', 'table')
  .action(async (id: string, options) => {
    try {
      const project = await apiClient.get<Project>(`/api/v1/projects/${id}`);

      if (options.format === 'json') {
        // eslint-disable-next-line no-console
        console.log(JSON.stringify(project, null, 2));
        return;
      }

      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan('\nProject Details:')));
      // eslint-disable-next-line no-console
      console.log(`  Name:        ${pc.bold(project.name)}`);
      // eslint-disable-next-line no-console
      console.log(`  ID:          ${pc.dim(project.id)}`);
      if (project.description) {
        // eslint-disable-next-line no-console
        console.log(`  Description: ${project.description}`);
      }
      // eslint-disable-next-line no-console
      console.log(`  Created:     ${new Date(project.createdAt).toLocaleString()}\n`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(pc.red(`✖ Failed to get project "${id}": ${msg}`));
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

// Subcommand: update
projectCommand
  .command('update <id>')
  .description('Update project attributes')
  .option('-n, --name <name>', 'New project name')
  .option('-d, --description <desc>', 'New project description')
  .action(async (id: string, options) => {
    try {
      const payload: { name?: string; description?: string } = {};
      if (options.name) payload.name = options.name;
      if (options.description !== undefined) payload.description = options.description;

      const project = await apiClient.put<Project>(`/api/v1/projects/${id}`, payload);

      // eslint-disable-next-line no-console
      console.log(pc.green(`✔ Project "${project.name}" [ID: ${project.id}] updated successfully!`));
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(pc.red(`✖ Failed to update project "${id}": ${msg}`));
      process.exit(1);
    }
  });

// Subcommand: delete
projectCommand
  .command('delete <id>')
  .description('Delete a project and all associated targets and environments')
  .action(async (id: string) => {
    try {
      await apiClient.delete(`/api/v1/projects/${id}`);
      // eslint-disable-next-line no-console
      console.log(pc.green(`✔ Project [ID: ${id}] deleted successfully.`));
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(pc.red(`✖ Failed to delete project "${id}": ${msg}`));
      process.exit(1);
    }
  });
