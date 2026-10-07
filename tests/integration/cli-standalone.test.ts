import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import util from 'node:util';
import { exec } from 'node:child_process';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { localRunner } from '../../apps/cli/src/runner/local-runner.js';
import {
  parseProjectConfig,
  loadProjectConfigFile,
  findProjectConfigFile,
} from '@security-lab/contracts';

const execPromise = util.promisify(exec);

describe('Phase 13: Standalone CLI & CI/CD Pipeline Suite', () => {
  let server: http.Server;
  let serverPort: number;
  let serverUrl: string;
  let mockMode: 'insecure' | 'secure' = 'insecure';
  let tempDir: string;

  beforeAll(async () => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-lab-cli-test-'));

    server = http.createServer((req, res) => {
      if (mockMode === 'insecure') {
        // Vulnerable endpoint: missing HSTS, CSP, X-Frame-Options; arbitrary origin reflection with credentials
        if (req.method === 'OPTIONS') {
          res.writeHead(200, {
            'Access-Control-Allow-Origin': req.headers.origin || 'http://attacker.example.com',
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
          });
          res.end();
          return;
        }

        res.writeHead(200, {
          'Content-Type': 'text/html',
          Server: 'Apache/2.4.41',
          'X-Powered-By': 'Express',
        });
        res.end('<html><body>Insecure Service</body></html>');
      } else {
        // Hardened endpoint: full defensive headers and safe CORS
        if (req.method === 'OPTIONS') {
          res.writeHead(204, {
            'Access-Control-Allow-Origin': 'https://trusted.example.com',
            'Access-Control-Allow-Methods': 'GET,POST',
          });
          res.end();
          return;
        }

        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
          'Content-Security-Policy': "default-src 'self'",
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
        });
        res.end('<html><body>Hardened Service</body></html>');
      }
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        if (addr && typeof addr === 'object') {
          serverPort = addr.port;
          serverUrl = `http://127.0.0.1:${serverPort}`;
        }
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });

    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error
    }
  });

  describe('1. Standalone In-Process Local Runner Execution', () => {
    it('executes Class A engines offline and returns exitCode 1 on insecure target (fail-on=failed)', async () => {
      mockMode = 'insecure';

      const summary = await localRunner.run({
        targetUrl: serverUrl,
        failOn: 'failed',
        silent: true,
        engines: ['headers', 'cors'],
      });

      expect(summary.totalTests).toBeGreaterThan(0);
      expect(summary.totalFindings).toBeGreaterThan(0);
      expect(summary.exitCode).toBe(1);
      expect(summary.policyVerdict).toBe('failed');
      expect(summary.postureScore).toBeDefined();
      expect(summary.postureScore.overallScore).toBeLessThan(100);

      // Verify findings contain header/cors issues
      const findingTypes = summary.findings.map((f) => f.title.toLowerCase());
      expect(findingTypes.some((t) => t.includes('strict transport security') || t.includes('content security policy') || t.includes('cors'))).toBe(true);
    });

    it('returns exitCode 0 on hardened target when policy criteria are satisfied', async () => {
      mockMode = 'secure';

      const summary = await localRunner.run({
        targetUrl: serverUrl,
        failOn: 'failed',
        silent: true,
        engines: ['headers', 'cors'],
      });

      expect(summary.totalTests).toBeGreaterThan(0);
      // Hardened server should pass release gate
      expect(summary.exitCode).toBe(0);
      expect(summary.policyVerdict).toBe('passed');
      expect(summary.postureScore.overallScore).toBeGreaterThanOrEqual(80);
    });

    it('respects failOn: "never" even when findings exist', async () => {
      mockMode = 'insecure';

      const summary = await localRunner.run({
        targetUrl: serverUrl,
        failOn: 'never',
        silent: true,
        engines: ['headers'],
      });

      expect(summary.totalFindings).toBeGreaterThan(0);
      expect(summary.exitCode).toBe(0);
    });

    it('enforces scope boundary security and rejects disallowed hosts', async () => {
      await expect(
        localRunner.run({
          targetUrl: 'http://malicious-external-target.com',
          scopeConfig: {
            allowedHosts: ['127.0.0.1'],
          },
          silent: true,
        })
      ).rejects.toThrow(/violates security boundary/);
    });
  });

  describe('2. Project Configuration (.securitylab.yaml)', () => {
    it('parses valid .securitylab.yaml correctly', () => {
      const yamlContent = `
version: "1.0"
target:
  name: "Local Service"
  baseUrl: "http://127.0.0.1:8080"
  allowedHosts:
    - "127.0.0.1"
    - "localhost"
  allowedPorts:
    - 8080
definitions:
  - id: "def-health"
    name: "Health Endpoint Check"
    steps:
      - name: "Check Health Status"
        request:
          method: "GET"
          path: "/health"
        assertions:
          - type: "statusCode"
            operator: "equals"
            expected: 200
policy:
  failOn: "failed"
  maxCriticalFindings: 0
  maxHighFindings: 0
  minPostureScore: 75
reporters:
  sarif:
    enabled: true
    output: "reports/security.sarif"
  junit:
    enabled: true
    output: "reports/junit.xml"
`;
      const parsed = parseProjectConfig(yamlContent);
      expect(parsed.version).toBe('1.0');
      expect(parsed.target.baseUrl).toBe('http://127.0.0.1:8080');
      expect(parsed.target.allowedHosts).toContain('127.0.0.1');
      expect(parsed.definitions.items).toHaveLength(1);
      expect(parsed.policy.maxCriticalFindings).toBe(0);
      expect(parsed.reporters?.sarif?.enabled).toBe(true);
      expect(parsed.reporters?.sarif?.output).toBe('reports/security.sarif');
    });

    it('throws validation error on invalid configuration', () => {
      const invalidYaml = `
version: "1.0"
target:
  name: "Bad Target"
  baseUrl: "not-a-valid-url"
`;
      expect(() => parseProjectConfig(invalidYaml)).toThrow();
    });

    it('discovers and loads configuration from disk', () => {
      const configPath = path.join(tempDir, '.securitylab.yaml');
      fs.writeFileSync(
        configPath,
        `
target:
  baseUrl: "http://127.0.0.1:${serverPort}"
  allowedHosts: ["127.0.0.1"]
policy:
  failOn: "warning"
`
      );

      const loaded = loadProjectConfigFile(configPath);
      expect(loaded).not.toBeNull();
      expect(loaded?.config.target.baseUrl).toBe(`http://127.0.0.1:${serverPort}`);

      const discoveredPath = findProjectConfigFile(tempDir);
      expect(discoveredPath).toBe(configPath);
    });
  });

  describe('3. Report Generation to Disk', () => {
    it('exports SARIF report to specified output path', async () => {
      mockMode = 'insecure';
      const sarifFile = path.join(tempDir, 'output.sarif');

      const summary = await localRunner.run({
        targetUrl: serverUrl,
        failOn: 'never',
        format: 'sarif',
        outputPath: sarifFile,
        silent: true,
        engines: ['headers', 'cors'],
      });

      expect(fs.existsSync(sarifFile)).toBe(true);
      const content = JSON.parse(fs.readFileSync(sarifFile, 'utf-8'));
      expect(content.version).toBe('2.1.0');
      expect(content.runs).toBeDefined();
      expect(content.runs.length).toBeGreaterThan(0);
      expect(content.runs[0].results.length).toBe(summary.totalFindings);
    });

    it('exports JUnit XML report to specified output path', async () => {
      mockMode = 'insecure';
      const junitFile = path.join(tempDir, 'output-junit.xml');

      await localRunner.run({
        targetUrl: serverUrl,
        failOn: 'never',
        format: 'junit',
        outputPath: junitFile,
        silent: true,
        engines: ['headers'],
      });

      expect(fs.existsSync(junitFile)).toBe(true);
      const xml = fs.readFileSync(junitFile, 'utf-8');
      expect(xml).toContain('<?xml');
      expect(xml).toContain('<testsuites');
      expect(xml).toContain('<testcase');
    });

    it('exports Executive HTML report to specified output path', async () => {
      mockMode = 'insecure';
      const htmlFile = path.join(tempDir, 'output.html');

      await localRunner.run({
        targetUrl: serverUrl,
        failOn: 'never',
        format: 'html',
        outputPath: htmlFile,
        silent: true,
        engines: ['headers'],
      });

      expect(fs.existsSync(htmlFile)).toBe(true);
      const html = fs.readFileSync(htmlFile, 'utf-8');
      expect(html).toContain('<!DOCTYPE html>');
      expect(html).toContain('SECURITY LAB');
      expect(html).toContain('Security Posture Assessment');
    });
  });

  describe('4. CI/CD GitHub Step Summary Integration', () => {
    it('writes markdown summary table to process.env.GITHUB_STEP_SUMMARY', async () => {
      const summaryFile = path.join(tempDir, 'github_step_summary.md');
      process.env.GITHUB_STEP_SUMMARY = summaryFile;

      try {
        await localRunner.run({
          targetUrl: serverUrl,
          failOn: 'never',
          silent: true,
          engines: ['headers'],
        });

        expect(fs.existsSync(summaryFile)).toBe(true);
        const md = fs.readFileSync(summaryFile, 'utf-8');
        expect(md).toContain('## 🛡️ Security Lab — Release Gate Summary');
        expect(md).toContain('Posture Score');
        expect(md).toContain('| Critical | High | Medium | Low |');
      } finally {
        delete process.env.GITHUB_STEP_SUMMARY;
      }
    });
  });

  describe('5. End-to-End CLI Binary Invocation via Child Process', () => {
    it(
      'executes standalone CLI binary via subprocess without controller',
      async () => {
        mockMode = 'insecure';
        const cliBin = path.resolve(__dirname, '../../apps/cli/dist/index.js');
        const sarifOut = path.join(tempDir, 'e2e-cli.sarif');

        // Execute node cli with --local, --fail-on never, --format sarif
        const cmd = `node "${cliBin}" run --local --target "${serverUrl}" --fail-on never --format sarif --output "${sarifOut}" -e "headers"`;

        const { stdout: output } = await execPromise(cmd);
        expect(output).toContain('SECURITY LAB');
        expect(output).toContain('Standalone Local Security QA Runner');
        expect(output).toContain('Target URL:');
        expect(output).toContain('RELEASE GATE:');
        expect(fs.existsSync(sarifOut)).toBe(true);
      },
      30000,
    );
  });
});
