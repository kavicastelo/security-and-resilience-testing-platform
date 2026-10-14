import { Command } from 'commander';
import { composeCommand } from './compose.js';

export const planCommand = new Command('plan')
  .description('Design, compose, sequence, and manage security test execution plans');

planCommand.addCommand(composeCommand);
