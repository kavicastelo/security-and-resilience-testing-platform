import { Command } from 'commander';
import pc from 'picocolors';
import readline from 'node:readline';
import { saveStoredApiKey, clearStoredApiKey } from '../config/index.js';

export const loginCommand = new Command('login')
  .description('Configure API credentials for controller communication')
  .option('-k, --key <key>', 'API key for authentication')
  .action(async (options: { key?: string }, command: Command) => {
    try {
      const parentApiKey = (command?.parent?.opts?.() as { apiKey?: string })?.apiKey;
      let apiKey = options.key?.trim() || parentApiKey?.trim();

      if (!apiKey) {
        if (!process.stdin.isTTY) {
          console.error(pc.red('✖ API key must be provided via -k or --key in non-interactive environments.'));
          process.exit(1);
        }

        const rl = readline.createInterface({
          input: process.stdin,
          output: process.stdout,
        });

        apiKey = await new Promise<string>((resolve) => {
          rl.question('Enter your SECURITY_LAB_API_KEY: ', (answer) => {
            rl.close();
            resolve(answer.trim());
          });
        });
      }

      if (!apiKey || apiKey.length === 0) {
        console.error(pc.red('✖ API key cannot be empty.'));
        process.exit(1);
      }

      saveStoredApiKey(apiKey);
      console.log(pc.green('✔ API key successfully saved to local credentials store.'));
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(pc.red(`✖ Failed to save API key: ${msg}`));
      process.exit(1);
    }
  });

export const logoutCommand = new Command('logout')
  .description('Remove stored API credentials')
  .action(() => {
    try {
      clearStoredApiKey();
      console.log(pc.green('✔ Stored API credentials removed.'));
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(pc.red(`✖ Failed to remove credentials: ${msg}`));
      process.exit(1);
    }
  });
