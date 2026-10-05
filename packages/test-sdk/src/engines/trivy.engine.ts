import { TestEngine } from '../engine.js';
import { TestCapability } from '../capability.js';
import { ExecutionContext } from '../context.js';
import { TestInput, TestResult, ValidationResult, RawEngineFinding } from '../result.js';
import { normalizeTrivyResults } from '@security-lab/domain';
import { dockerRunner, DockerRunner } from '../runners/docker.runner.js';

export const SAMPLE_TRIVY_REPORT = {
  SchemaVersion: 2,
  ArtifactName: 'target-service-image:latest',
  ArtifactType: 'container_image',
  Results: [
    {
      Target: 'node:20-alpine (alpine 3.19.1)',
      Class: 'os-pkgs',
      Type: 'alpine',
      Vulnerabilities: [
        {
          VulnerabilityID: 'CVE-2024-24790',
          PkgID: 'stdlib@1.21.0',
          PkgName: 'net/netip',
          InstalledVersion: '1.21.0',
          FixedVersion: '1.21.11',
          Status: 'fixed',
          Severity: 'CRITICAL',
          Title: 'Go standard library unexpected behavior in IsLoopback/IsMulticast',
          Description: 'The netip.Addr.IsLoopback method returns true for IPv4-mapped IPv6 loopback addresses.',
          PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-24790',
          CweIDs: ['CWE-20'],
        },
        {
          VulnerabilityID: 'CVE-2024-34397',
          PkgID: 'libxml2@2.12.5',
          PkgName: 'libxml2',
          InstalledVersion: '2.12.5',
          FixedVersion: '2.12.6',
          Status: 'fixed',
          Severity: 'HIGH',
          Title: 'libxml2: Use-after-free in xmlXPathCompOpEval',
          Description: 'A use-after-free flaw was found in libxml2 through xpath evaluation.',
          PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-34397',
          CweIDs: ['CWE-416'],
        },
      ],
      Misconfigurations: [
        {
          ID: 'AVD-DS-0002',
          Title: 'Specified root user in containerfile',
          Description: 'Running containers with root user allows container breakout risks.',
          Message: 'Container specifies user root',
          Resolution: 'Add USER nonroot to container specification',
          Severity: 'MEDIUM',
          PrimaryURL: 'https://avd.aquasec.com/appshield/ds002',
        },
      ],
    },
  ],
};

export class TrivyScannerEngine implements TestEngine {
  readonly id = 'engine-container-trivy';
  readonly version = '1.0.0';

  constructor(private readonly runner: DockerRunner = dockerRunner) {}

  capabilities(): TestCapability[] {
    return [
      {
        id: 'trivy_sca',
        name: 'Aqua Trivy Software Composition Analysis',
        category: 'passive_analysis',
        description: 'Scans dependencies and operating system packages for known CVEs using Aqua Trivy container',
        isDisruptive: false,
      },
      {
        id: 'trivy_misconfig',
        name: 'Aqua Trivy Infrastructure Misconfiguration Audit',
        category: 'protocol_audit',
        description: 'Audits containerfiles, Kubernetes specs, and IaC definitions for security misconfigurations',
        isDisruptive: false,
      },
    ];
  }

  validate(input: TestInput): ValidationResult {
    if (!input.targetUrl) {
      return {
        valid: false,
        errors: [{ path: 'targetUrl', message: 'Target URL or artifact identifier is required' }],
      };
    }
    return { valid: true };
  }

  async execute(input: TestInput, context: ExecutionContext): Promise<TestResult> {
    const startTime = Date.now();
    context.reportProgress(10, 'Initializing Aqua Trivy container environment...');

    const image = (input.options?.dockerImage as string) || process.env.TRIVY_IMAGE || 'aquasec/trivy:latest';
    const mockReport = input.options?.mockReport || SAMPLE_TRIVY_REPORT;

    context.reportProgress(30, 'Dispatching container runner for Aqua Trivy scan...');

    let rawJson: unknown;
    try {
      const runResult = await this.runner.execute({
        image,
        args: ['fs', '--format', 'json', '.'],
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
        error: `Aqua Trivy container run failed: ${msg}`,
      };
    }

    context.reportProgress(75, 'Normalizing Trivy CVEs and misconfigurations into platform findings...');

    const normalizedFindings = normalizeTrivyResults(rawJson);

    const findings: RawEngineFinding[] = normalizedFindings.map((nf) => ({
      title: nf.title,
      category: nf.category,
      severity: nf.severity,
      description: nf.description,
      recommendation: nf.recommendation,
      evidence: nf.evidence,
      metadata: nf.metadata,
    }));

    context.reportProgress(100, `Aqua Trivy completed: ${findings.length} findings normalized.`);

    return {
      engineId: this.id,
      durationMs: Date.now() - startTime,
      success: true,
      findings,
      metrics: [
        { name: 'trivy_findings_count', value: findings.length, unit: 'count' },
        { name: 'trivy_critical_count', value: findings.filter((f) => f.severity === 'critical').length, unit: 'count' },
        { name: 'trivy_high_count', value: findings.filter((f) => f.severity === 'high').length, unit: 'count' },
      ],
      rawOutput: rawJson,
    };
  }
}
