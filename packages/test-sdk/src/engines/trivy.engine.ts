import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { TestEngine, TestEngineError } from '../engine.js';
import { TestCapability } from '../capability.js';
import { ExecutionContext } from '../context.js';
import { TestInput, TestResult, ValidationResult, RawEngineFinding } from '../result.js';
import { normalizeTrivyResults } from '@security-lab/domain';
import { dockerRunner, DockerRunner } from '../runners/docker.runner.js';
import { createScratchDirectory, EphemeralScratchDirectory } from '../runners/scratch-dir.js';
import { VolumeMount } from '../runners/docker-policy.js';

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
  readonly executionClass = 'class_b_container' as const;

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
    if (!input.targetUrl && !input.options?.targetPath && !input.options?.targetImage) {
      return {
        valid: false,
        errors: [{ path: 'targetUrl', message: 'Target URL, targetPath, or targetImage is required' }],
      };
    }
    return { valid: true };
  }

  async execute(input: TestInput, context: ExecutionContext): Promise<TestResult> {
    const startTime = Date.now();
    context.reportProgress(10, 'Initializing Aqua Trivy container environment...');

    const image = (input.options?.dockerImage as string) || process.env.TRIVY_IMAGE || 'aquasec/trivy:latest';
    const mockReport = input.options?.mockReport || SAMPLE_TRIVY_REPORT;
    const isSimulated = input.options?.simulated === true || process.env.SECURITY_LAB_MOCK_CONTAINERS === 'true';

    // 1. Provision ephemeral scratch output directory for report transport
    const outScratch = await createScratchDirectory('trivy-out');
    const reportFilePath = path.join(outScratch.path, 'report.json');
    let inScratch: EphemeralScratchDirectory | undefined;

    context.reportProgress(20, 'Resolving scan target and volume configuration...');

    // 2. Resolve target type: Container Image vs Filesystem Directory
    const rawTarget = (input.targetUrl || '').trim();
    const explicitImage = input.options?.targetImage as string | undefined;
    const explicitPath = input.options?.targetPath as string | undefined;
    const scanType = input.options?.scanType as string | undefined;

    const isImageScan =
      scanType === 'image' ||
      Boolean(explicitImage) ||
      rawTarget.startsWith('image://') ||
      rawTarget.startsWith('docker://') ||
      (!rawTarget.startsWith('http://') &&
        !rawTarget.startsWith('https://') &&
        !rawTarget.startsWith('file://') &&
        !explicitPath &&
        rawTarget.includes(':'));

    const volumes: VolumeMount[] = [
      {
        hostPath: outScratch.path,
        containerPath: '/trivy-out',
        mode: 'rw',
      },
    ];

    let trivyArgs: string[];

    if (isImageScan) {
      const targetImage =
        explicitImage || rawTarget.replace(/^(image|docker):\/\//, '') || 'target-service-image:latest';
      trivyArgs = ['image', '--format', 'json', '--output', '/trivy-out/report.json', targetImage];
      context.reportProgress(30, `Configured Aqua Trivy for container image scan: ${targetImage}`);
    } else {
      // Filesystem or Repository Scan
      let hostTargetDir: string | undefined = explicitPath;
      if (!hostTargetDir && rawTarget.startsWith('file://')) {
        hostTargetDir = rawTarget.replace(/^file:\/\//, '');
      }

      // Ensure target volume resides inside system temp dir to comply with CIS volume sandbox policy
      const tempDir = path.resolve(os.tmpdir()).toLowerCase().replace(/\\/g, '/');
      let safeMountDir: string;

      if (hostTargetDir && path.resolve(hostTargetDir).toLowerCase().replace(/\\/g, '/').startsWith(tempDir)) {
        safeMountDir = path.resolve(hostTargetDir);
      } else {
        inScratch = await createScratchDirectory('trivy-src');
        safeMountDir = inScratch.path;

        if (hostTargetDir && fs.existsSync(hostTargetDir)) {
          try {
            await fs.promises.cp(hostTargetDir, inScratch.path, {
              recursive: true,
              filter: (src) => !src.includes('node_modules') && !src.includes('.git'),
            });
          } catch {
            // Non-fatal if copy cannot read some files
          }
        }
      }

      volumes.push({
        hostPath: safeMountDir,
        containerPath: '/target-src',
        mode: 'ro',
      });

      trivyArgs = ['fs', '--format', 'json', '--output', '/trivy-out/report.json', '/target-src'];
      context.reportProgress(30, 'Configured Aqua Trivy for filesystem scan with read-only target mount');
    }

    let rawJson: unknown;

    try {
      if (isSimulated) {
        // In simulation mode, write the mock report into the scratch output directory
        await fs.promises.writeFile(reportFilePath, JSON.stringify(mockReport), 'utf-8');
      }

      const runResult = await this.runner.execute({
        image,
        args: trivyArgs,
        volumes,
        timeoutMs: input.timeoutMs || 60000,
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
            throw new TestEngineError(`Failed to parse Aqua Trivy report.json: ${parseMsg}`, this.id, parseErr);
          }
        }
      } else {
        if (runResult.simulated) {
          rawJson = mockReport;
        } else {
          // Fail fast: do NOT silently substitute mock data when real execution fails
          throw new TestEngineError(
            `Aqua Trivy container finished (exit code ${runResult.exitCode}) but failed to produce report.json at /trivy-out/report.json. Output: ${runResult.stderr || runResult.stdout || 'None'}`,
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
        error: `Aqua Trivy container run failed: ${msg}`,
      };
    } finally {
      // 4. Always destroy ephemeral scratch directories post-run
      await outScratch.destroy();
      if (inScratch) {
        await inScratch.destroy();
      }
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
