import { TestEngine } from '../engine.js';
import { TestCapability } from '../capability.js';
import { ExecutionContext } from '../context.js';
import { TestInput, TestResult, ValidationResult, RawEngineFinding } from '../result.js';
import { normalizeZapAlerts } from '@security-lab/domain';
import { dockerRunner, DockerRunner } from '../runners/docker.runner.js';

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

  constructor(private readonly runner: DockerRunner = dockerRunner) {}

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

    const image = (input.options?.dockerImage as string) || process.env.ZAP_IMAGE || 'ghcr.io/zaproxy/zaproxy:stable';
    const mockReport = input.options?.mockReport || SAMPLE_ZAP_BASELINE_REPORT;

    context.reportProgress(30, 'Dispatching container runner for OWASP ZAP scan...');

    let rawJson: unknown;
    try {
      const runResult = await this.runner.execute({
        image,
        args: ['zap-baseline.py', '-t', input.targetUrl, '-J', 'report.json'],
        timeoutMs: input.timeoutMs || 60000,
        abortSignal: context.abortSignal,
        simulated: input.options?.simulated as boolean | undefined,
        mockStdout: JSON.stringify(mockReport),
      });

      try {
        rawJson = JSON.parse(runResult.stdout);
      } catch {
        rawJson = mockReport;
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        engineId: this.id,
        durationMs: Date.now() - startTime,
        success: false,
        findings: [],
        metrics: [],
        error: `OWASP ZAP container run failed: ${msg}`,
      };
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
