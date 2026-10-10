import fs from 'node:fs';
import path from 'node:path';
import { TestEngine, TestEngineError, EngineExecutionError } from '../engine.js';
import { TestCapability } from '../capability.js';
import { ExecutionContext } from '../context.js';
import { TestInput, TestResult, ValidationResult, RawEngineFinding } from '../result.js';
import { normalizeZapAlerts } from '@security-lab/domain';
import { dockerRunner, IDockerRunner } from '../runners/docker.runner.js';
import { createScratchDirectory } from '../runners/scratch-dir.js';

export const SAMPLE_ZAP_BASELINE_REPORT = {
  '@programName': 'OWASP ZAP',
  '@version': '2.14.0',
  site: [
    {
      '@name': 'Target Web Application',
      alerts: [
        {
          pluginid: '10038',
          alertRef: '10038',
          alert: 'Content Security Policy (CSP) Header Not Set',
          name: 'Content Security Policy (CSP) Header Not Set',
          riskcode: '2',
          confidence: '2',
          riskdesc: 'Medium (Medium)',
          desc: 'Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks.',
          instances: [
            {
              uri: '/',
              method: 'GET',
              param: '',
              attack: '',
              evidence: '',
            },
          ],
          count: '1',
          solution: 'Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.',
          reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
          cweid: '693',
          wascid: '15',
        },
        {
          pluginid: '10020',
          alertRef: '10020',
          alert: 'Missing Anti-Clickjacking Header',
          name: 'Missing Anti-Clickjacking Header',
          riskcode: '2',
          confidence: '2',
          desc: 'The response does not include either Content-Security-Policy with frame-ancestors directive or X-Frame-Options.',
          instances: [
            {
              uri: '/',
              method: 'GET',
            },
          ],
          solution: 'Configure X-Frame-Options or frame-ancestors directive in Content-Security-Policy.',
          cweid: '1021',
        },
      ],
    },
  ],
};

export class ZapScannerEngine implements TestEngine {
  readonly id = 'engine-container-zap';
  readonly version = '1.0.0';
  readonly executionClass = 'class_b_container' as const;

  constructor(private readonly runner: IDockerRunner = dockerRunner) {}

  capabilities(): TestCapability[] {
    return [
      {
        id: 'zap_baseline',
        name: 'OWASP ZAP Baseline Security Audit',
        category: 'passive_analysis',
        description: 'Runs OWASP ZAP container to detect common web application vulnerabilities and defensive posture gaps',
        isDisruptive: false,
      },
      {
        id: 'zap_active',
        name: 'OWASP ZAP Active Penetration Scanner',
        category: 'active_fuzzing',
        description: 'Dispatches active attack vectors and payload injection checks (requires target activeScanning authorization)',
        isDisruptive: true,
      },
    ];
  }

  validate(input: TestInput): ValidationResult {
    try {
      new URL(input.targetUrl);
      return { valid: true };
    } catch {
      return {
        valid: false,
        errors: [{ path: 'targetUrl', message: `Invalid target URL: "${input.targetUrl}"` }],
      };
    }
  }

  async execute(input: TestInput, context: ExecutionContext): Promise<TestResult> {
    const startTime = Date.now();
    context.reportProgress(10, 'Initializing OWASP ZAP runner configuration...');

    // 1. Enforce scope gate: Active scanning requires explicit opt-in
    const isActiveScan = input.options?.activeScan === true;
    if (isActiveScan && !context.target.scope.testing.activeScanning) {
      return {
        engineId: this.id,
        durationMs: Date.now() - startTime,
        success: false,
        findings: [],
        metrics: [],
        error: 'Active scanning is strictly disabled in target security scope. Explicit authorization required.',
      };
    }

    // 2. Reject simulation outside test environment
    const isSimulatedRequested = input.options?.simulated === true;
    if (isSimulatedRequested && process.env.NODE_ENV !== 'test') {
      throw new EngineExecutionError(
        'Simulated scanner execution is disabled in production',
        this.id,
      );
    }

    const image = (input.options?.dockerImage as string) || process.env.ZAP_IMAGE || 'ghcr.io/zaproxy/zaproxy:stable';
    const mockReport = input.options?.mockReport || SAMPLE_ZAP_BASELINE_REPORT;
    const isSimulated =
      process.env.NODE_ENV === 'test' &&
      (isSimulatedRequested || process.env.SECURITY_LAB_MOCK_CONTAINERS === 'true');

    context.reportProgress(20, 'Provisioning ephemeral host scratch directory for ZAP report transport...');

    // 2. Provision isolated host scratch directory under os.tmpdir()
    const scratch = await createScratchDirectory('zap');
    const reportFilePath = path.join(scratch.path, 'report.json');

    context.reportProgress(30, 'Dispatching container runner for OWASP ZAP scan...');

    let rawJson: unknown;
    try {
      if (isSimulated) {
        // In simulation mode, write the mock report into the scratch directory
        await fs.promises.writeFile(reportFilePath, JSON.stringify(mockReport), 'utf-8');
      }

      const zapArgs = ['zap-baseline.py', '-t', input.targetUrl, '-J', 'report.json', '-I', '-m', '1'];
      if (Array.isArray(input.options?.extraArgs)) {
        zapArgs.push(...(input.options.extraArgs as string[]));
      }

      const runResult = await this.runner.execute({
        image,
        user: '1000:1000',
        tmpfs: ['/home/zap:rw,exec,mode=1777,size=1048576k'],
        args: zapArgs,
        volumes: [
          {
            hostPath: scratch.path,
            containerPath: '/zap/wrk',
            mode: 'rw',
          },
        ],
        timeoutMs:
          input.timeoutMs ||
          (typeof input.options?.timeoutMs === 'number' ? input.options.timeoutMs : 300000),
        abortSignal: context.abortSignal,
        simulated: isSimulated,
        mockStdout: JSON.stringify(mockReport),
      });

      // 3. Artifact transport: Read report.json directly from host scratch directory
      if (fs.existsSync(reportFilePath)) {
        try {
          const reportRaw = await fs.promises.readFile(reportFilePath, 'utf-8');
          rawJson = JSON.parse(reportRaw);
        } catch (parseErr: unknown) {
          if (runResult.simulated) {
            rawJson = mockReport;
          } else {
            const parseMsg = parseErr instanceof Error ? parseErr.message : String(parseErr);
            throw new TestEngineError(`Failed to parse OWASP ZAP report.json: ${parseMsg}`, this.id, parseErr);
          }
        }
      } else {
        if (runResult.simulated) {
          rawJson = mockReport;
        } else {
          // Fail fast: do NOT silently substitute mock data when real execution fails
          throw new TestEngineError(
            `OWASP ZAP container finished (exit code ${runResult.exitCode}) but failed to produce report.json at /zap/wrk/report.json. Output: ${runResult.stderr || runResult.stdout || 'None'}`,
            this.id,
          );
        }
      }
    } catch (err: unknown) {
      if (input.options?.throwOnError) {
        throw err;
      }
      const msg = err instanceof Error ? err.message : String(err);
      return {
        engineId: this.id,
        durationMs: Date.now() - startTime,
        success: false,
        findings: [],
        metrics: [],
        error: `OWASP ZAP container run failed: ${msg}`,
      };
    } finally {
      // 4. Always destroy ephemeral scratch directory
      await scratch.destroy();
    }

    context.reportProgress(75, 'Normalizing ZAP alerts into platform findings schema...');

    const normalizedFindings = normalizeZapAlerts(rawJson);

    const findings: RawEngineFinding[] = normalizedFindings.map((nf) => ({
      title: nf.title,
      category: nf.category,
      severity: nf.severity,
      description: nf.description,
      recommendation: nf.recommendation,
      evidence: nf.evidence,
      metadata: nf.metadata,
    }));

    context.reportProgress(100, `OWASP ZAP completed: ${findings.length} findings normalized.`);

    return {
      engineId: this.id,
      durationMs: Date.now() - startTime,
      success: findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length === 0,
      findings,
      metrics: [
        { name: 'zap_findings_count', value: findings.length, unit: 'count' },
        { name: 'zap_critical_count', value: findings.filter((f) => f.severity === 'critical').length, unit: 'count' },
        { name: 'zap_high_count', value: findings.filter((f) => f.severity === 'high').length, unit: 'count' },
      ],
      rawOutput: rawJson,
    };
  }
}
