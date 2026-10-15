import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import util from 'node:util';
import { exec } from 'node:child_process';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { TerminalSpinner, createSpinner, isInteractiveTerminal } from '../../apps/cli/src/output/spinner.js';
import {
  renderTable,
  renderFindingsTable,
  renderSummaryBox,
  stripAnsi,
  visibleLength,
} from '../../apps/cli/src/output/table.js';
import { formatTerminalDiff, createUnifiedDiff } from '../../apps/cli/src/output/diff.js';
import { Finding } from '@security-lab/domain';

const execPromise = util.promisify(exec);
const cliBinPath = path.resolve(__dirname, '../../apps/cli/dist/index.js');

describe('Phase UI-17: Developer CLI Modernization, Interactive Wizards & Rich Terminal UX', () => {
  let tempDir: string;
  let mockServer: http.Server;
  let mockPort: number;
  let challengeToken: string;

  beforeAll(async () => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-lab-cli-ui17-'));
    challengeToken = 'test-challenge-token-12345';

    mockServer = http.createServer((req, res) => {
      if (req.url === '/.well-known/security-lab-challenge') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(challengeToken);
        return;
      }

      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body>OK</body></html>');
    });

    await new Promise<void>((resolve) => {
      mockServer.listen(0, '127.0.0.1', () => {
        const addr = mockServer.address();
        if (addr && typeof addr === 'object') {
          mockPort = addr.port;
        }
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      mockServer.close(() => resolve());
    });

    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  describe('1. Terminal Output Utilities (Spinners, Tables, Diffs)', () => {
    it('detects non-interactive CI/test environment and suppresses animated timers', () => {
      const isInteractive = isInteractiveTerminal();
      expect(isInteractive).toBe(false);

      const spinner = createSpinner('Test scanning');
      expect(() => {
        spinner.start();
        spinner.update('Updated message');
        spinner.warn('Warning message');
        spinner.succeed('Success message');
        spinner.fail('Failure message');
        spinner.stop();
      }).not.toThrow();
    });

    it('computes visible string length correctly by stripping ANSI codes', () => {
      const rawText = '\u001b[31m\u001b[1mCRITICAL\u001b[22m\u001b[39m';
      expect(stripAnsi(rawText)).toBe('CRITICAL');
      expect(visibleLength(rawText)).toBe(8);
    });

    it('renders aligned Unicode box tables', () => {
      const headers = ['NAME', 'STATUS', 'SCORE'];
      const rows = [
        ['API Gateway', 'ACTIVE', '95'],
        ['Auth Service', 'REVIEW', '82'],
      ];

      const table = renderTable(headers, rows, { borderStyle: 'unicode' });
      expect(table).toContain('┌');
      expect(table).toContain('┐');
      expect(table).toContain('└');
      expect(table).toContain('┘');
      expect(table).toContain('API Gateway');
      expect(table).toContain('Auth Service');
    });

    it('renders formatted findings tables with severity tags', () => {
      const sampleFindings: Finding[] = [
        {
          id: 'find-1',
          fingerprint: 'fp-1',
          title: 'Missing Content-Security-Policy',
          category: 'headers',
          severity: 'high',
          confidence: 'firm',
          status: 'open',
          description: 'CSP header missing',
          recommendation: 'Configure CSP default-src self',
          testDefinitionId: 'headers',
          testRunId: 'tr-1',
          executionId: 'ex-1',
          targetId: 't-1',
          occurrenceCount: 1,
          firstDetectedAt: new Date(),
          lastDetectedAt: new Date(),
          flappingScore: 0,
          isFlapping: false,
          triageHistory: [],
        },
      ];

      const findingsTable = renderFindingsTable(sampleFindings);
      expect(findingsTable).toContain('SEVERITY');
      expect(findingsTable).toContain('Missing Content-Security-Policy');
      expect(findingsTable).toContain('HIGH');
    });

    it('renders release governance summary boxes', () => {
      const summaryBox = renderSummaryBox('Test Summary', [
        { label: 'Total Scans', value: 14 },
        { label: 'Overall Status', value: 'PASSED' },
      ]);

      expect(summaryBox).toContain('Test Summary');
      expect(summaryBox).toContain('Total Scans');
      expect(summaryBox).toContain('PASSED');
      expect(summaryBox).toContain('┌');
      expect(summaryBox).toContain('┘');
    });

    it('formats terminal code diffs with additions and deletions', () => {
      const originalCode = `const port = 3000;\napp.listen(port);`;
      const updatedCode = `const port = process.env.PORT || 3000;\napp.use(helmet());\napp.listen(port);`;

      const diff = createUnifiedDiff('server.ts', originalCode, updatedCode);
      expect(diff).toContain('--- a/server.ts');
      expect(diff).toContain('+++ b/server.ts');
      expect(diff).toContain('+app.use(helmet());');

      const formatted = formatTerminalDiff(diff, { showLineNumbers: true });
      expect(formatted).toBeDefined();
      expect(formatted.length).toBeGreaterThan(0);
    });
  });

  describe('2. CLI Command Registrations & Subprocess Invocations', () => {
    it('registers init, plan, compose, verify, install-hooks, and seed commands', async () => {
      const { stdout } = await execPromise(`node "${cliBinPath}" --help`);
      expect(stdout).toContain('init');
      expect(stdout).toContain('plan');
      expect(stdout).toContain('compose');
      expect(stdout).toContain('verify');
      expect(stdout).toContain('install-hooks');
      expect(stdout).toContain('seed');
    });

    it('registers seed command and displays options', async () => {
      const { stdout } = await execPromise(`node "${cliBinPath}" seed --help`);
      expect(stdout).toContain('security-lab seed');
      expect(stdout).toContain('--force');
      expect(stdout).toContain('--tenant');
    });

    it('registers verify subcommand under target command', async () => {
      const { stdout } = await execPromise(`node "${cliBinPath}" target --help`);
      expect(stdout).toContain('verify');
    });

    it('registers compose subcommand under plan command', async () => {
      const { stdout } = await execPromise(`node "${cliBinPath}" plan --help`);
      expect(stdout).toContain('compose');
    });
  });

  describe('3. Automated Non-Interactive Wizards (Init, Compose, Verify, Hooks)', () => {
    it('executes "security-lab init --yes" non-interactively to generate configuration', async () => {
      const testProjectDir = path.join(tempDir, 'init-test');
      fs.mkdirSync(testProjectDir, { recursive: true });

      const cmd = `node "${cliBinPath}" init --yes --name "MySecureApp" --url "http://127.0.0.1:8080" --profile smoke --config ".securitylab.yaml"`;
      const { stdout } = await execPromise(cmd, { cwd: testProjectDir });

      expect(stdout).toContain('Security Lab Configuration Initialized');
      expect(stdout).toContain('MySecureApp');

      const generatedConfigFile = path.join(testProjectDir, '.securitylab.yaml');
      expect(fs.existsSync(generatedConfigFile)).toBe(true);

      const content = fs.readFileSync(generatedConfigFile, 'utf-8');
      expect(content).toContain('name: "MySecureApp"');
      expect(content).toContain('baseUrl: "http://127.0.0.1:8080"');
      expect(content).toContain('- "headers"');
      expect(content).toContain('- "cors"');
      expect(content).toContain('- "tls"');

      // Local directory should also be created
      expect(fs.existsSync(path.join(testProjectDir, '.security-lab'))).toBe(true);
    });

    it('executes "security-lab plan compose" to generate a runnable YAML plan', async () => {
      const testPlanDir = path.join(tempDir, 'compose-test');
      fs.mkdirSync(testPlanDir, { recursive: true });

      const planPath = 'custom-plan.yaml';
      const cmd = `node "${cliBinPath}" plan compose --name "Payment API Suite" --url "http://127.0.0.1:9000" --preset owasp --output "${planPath}" --rps 150 --concurrency 25`;
      const { stdout } = await execPromise(cmd, { cwd: testPlanDir });

      expect(stdout).toContain('Composed Test Plan Summary');
      expect(stdout).toContain('Payment API Suite');
      expect(stdout).toContain('150 RPS / 25 conc');

      const fullPlanPath = path.join(testPlanDir, planPath);
      expect(fs.existsSync(fullPlanPath)).toBe(true);

      const planYaml = fs.readFileSync(fullPlanPath, 'utf-8');
      expect(planYaml).toContain('name: "Payment API Suite"');
      expect(planYaml).toContain('maxRps: 150');
      expect(planYaml).toContain('- "bola"');
    });

    it('supports dry-run mode for plan compose', async () => {
      const cmd = `node "${cliBinPath}" compose --name "DryRunPlan" --preset smoke --dry-run`;
      const { stdout } = await execPromise(cmd);

      expect(stdout).toContain('--- DRY RUN: Generated Plan Specification ---');
      expect(stdout).toContain('name: "DryRunPlan"');
    });

    it('verifies target ownership via direct HTTP well-known challenge probe', async () => {
      const cmd = `node "${cliBinPath}" target verify --url "http://127.0.0.1:${mockPort}" --token "${challengeToken}" --offline --poll-interval 200 --max-attempts 3`;
      const { stdout } = await execPromise(cmd);

      expect(stdout).toContain('Target Ownership Challenge');
      expect(stdout).toContain('Ownership confirmed');
      expect(stdout).toContain('Scope authorized');
    });

    it('installs pre-commit Git hook into .git/hooks', async () => {
      const gitRepoDir = path.join(tempDir, 'fake-git-repo');
      const gitHooksDir = path.join(gitRepoDir, '.git', 'hooks');
      fs.mkdirSync(gitHooksDir, { recursive: true });

      const cmd = `node "${cliBinPath}" install-hooks --type pre-commit --engines headers cors contract`;
      const { stdout } = await execPromise(cmd, { cwd: gitRepoDir });

      expect(stdout).toContain('Git Hook Installation Succeeded');
      expect(stdout).toContain('pre-commit');

      const hookFile = path.join(gitHooksDir, 'pre-commit');
      expect(fs.existsSync(hookFile)).toBe(true);

      const content = fs.readFileSync(hookFile, 'utf-8');
      expect(content).toContain('Security Lab pre-commit verification');
      expect(content).toContain('--engines headers cors contract');
    });
  });
});
