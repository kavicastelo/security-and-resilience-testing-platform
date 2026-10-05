import { Command } from 'commander';
import pc from 'picocolors';

export const versionCommand = new Command('version')
  .description('Display Security Lab platform and CLI version details')
  .action(() => {
    // eslint-disable-next-line no-console
    console.log(`
${pc.bold(pc.cyan('Security Lab Platform'))}
  CLI Version:      ${pc.green('0.1.0')}
  Architecture:     ${pc.yellow('Modular Monolith (Local-First)')}
  Engine Boundary:  ${pc.magenta('Contract v0.1.0')}
  Positioning:      Security QA for Enterprise Applications
    `);
  });
