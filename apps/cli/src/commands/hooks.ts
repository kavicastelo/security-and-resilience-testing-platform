import fs from 'node:fs';
import path from 'node:path';
import { Command } from 'commander';
import pc from 'picocolors';
import { renderSummaryBox } from '../output/table.js';
import { formatSuccess, formatError, formatWarning } from '../output/formatters.js';

export interface InstallHooksOptions {
  type?: string;
  engines?: string[];
  target?: string;
  failOn?: string;
  force?: boolean;
}

export const installHooksCommand = new Command('install-hooks')
  .description('Install Git pre-commit hooks to run automated Security Lab checks before code is committed')
  .option('-t, --type <type>', 'Git hook type (pre-commit or pre-push)', 'pre-commit')
  .option('-e, --engines <engines...>', 'Engines to execute on commit', ['headers', 'cors', 'contract'])
  .option('-u, --target <url>', 'Target URL or environment')
  .option('--fail-on <level>', 'Failure threshold: failed or warning', 'failed')
  .option('-f, --force', 'Overwrite existing git hook script if already present', false)
  .action(async (options: InstallHooksOptions) => {
    try {
      const hookType = options.type || 'pre-commit';
      const engines = options.engines || ['headers', 'cors', 'contract'];
      const failOn = options.failOn || 'failed';
      const targetParam = options.target ? ` --target "${options.target}"` : '';
      const enginesParam = engines.length > 0 ? ` --engines ${engines.join(' ')}` : '';

      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan('\n🛡️  Security Lab — Git Hook Installer\n')));

      // Find git directory
      let currentDir = process.cwd();
      let gitDir: string | null = null;

      for (let i = 0; i < 5; i++) {
        const candidate = path.join(currentDir, '.git');
        if (fs.existsSync(candidate) && fs.statSync(candidate).isDirectory()) {
          gitDir = candidate;
          break;
        }
        const parent = path.dirname(currentDir);
        if (parent === currentDir) break;
        currentDir = parent;
      }

      if (!gitDir) {
        console.error(
          formatError(
            'No .git directory found. Ensure you are running this command inside a Git repository.',
          ),
        );
        process.exit(1);
      }

      const hooksDir = path.join(gitDir, 'hooks');
      if (!fs.existsSync(hooksDir)) {
        fs.mkdirSync(hooksDir, { recursive: true });
      }

      const hookFile = path.join(hooksDir, hookType);

      if (fs.existsSync(hookFile) && !options.force) {
        // eslint-disable-next-line no-console
        console.log(
          formatWarning(
            `Git hook "${hookType}" already exists at ${pc.bold(hookFile)}.\nUse --force to overwrite.`,
          ),
        );
        process.exit(1);
      }

      // Shell script content for git hook
      const scriptContent = `#!/bin/sh
# Security Lab Pre-Commit Safety Check
# Generated automatically by: security-lab install-hooks

echo "🛡️  Running Security Lab pre-commit verification..."

# Check if security-lab CLI or npx is available
if ! command -v npx >/dev/null 2>&1; then
  echo "⚠️  npx command not found. Skipping Security Lab pre-commit check."
  exit 0
fi

# Run fast local verification in standalone offline mode
npx --no-install security-lab run --local --silent --fail-on ${failOn}${targetParam}${enginesParam}
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  echo "❌ Security Lab pre-commit verification FAILED (Exit Code: $EXIT_CODE)."
  echo "   Policy violations or high-severity vulnerabilities were detected."
  echo "   Run 'security-lab run --local' to inspect details and remediation diffs."
  exit 1
fi

echo "✔ Security Lab pre-commit checks passed."
exit 0
`;

      fs.writeFileSync(hookFile, scriptContent, { mode: 0o755, encoding: 'utf-8' });

      // On Unix-like environments ensure executable permission
      try {
        fs.chmodSync(hookFile, 0o755);
      } catch {
        // May be ignored on pure Windows without chmod support
      }

      // eslint-disable-next-line no-console
      console.log(
        renderSummaryBox('Git Hook Installation Succeeded', [
          { label: 'Hook Type', value: hookType },
          { label: 'Installed Path', value: path.relative(process.cwd(), hookFile) },
          { label: 'Target Engines', value: engines.join(', ') },
          { label: 'Failure Threshold', value: failOn },
          { label: 'Executable Mode', value: '0755' },
        ]),
      );

      // eslint-disable-next-line no-console
      console.log(`\n${formatSuccess(`Pre-commit hook active! Your commits will now be validated.`)}\n`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(formatError(`Failed to install Git hook: ${msg}`));
      process.exit(1);
    }
  });
