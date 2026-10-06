import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth } from '../../apps/controller/src/services/db.js';
import {
  ZapScannerEngine,
  TrivyScannerEngine,
  DockerRunner,
  ContainerSecurityError,
  createScratchDirectory,
  isApprovedImage,
  validateVolumePath,
  ExecutionContext,
  TestEngineError,
} from '@security-lab/test-sdk';
import { logger } from '@security-lab/logger';
import { FastifyInstance } from 'fastify';

describe('Class B Container Scanners Pipeline (OWASP ZAP & Aqua Trivy)', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;
  let server: http.Server;
  let serverPort: number;
  let serverUrl: string;

  let projectId: string;
  let targetId: string;
  let testRunId: string;

  beforeAll(async () => {
    // 1. Controller Fastify instance
    app = buildApp({ disableLogging: true });
    const health = await checkDatabaseHealth();
    isDbAvailable = health === 'up';

    // 2. Mock HTTP target
    server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', service: 'container-audit-target' }));
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
    await app.close();
    await closeDatabase();
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  const createDummyContext = (activeScanning = false): ExecutionContext => ({
    correlationId: 'test-container-corr-1',
    testRunId: '00000000-0000-0000-0000-000000000010',
    executionId: '00000000-0000-0000-0000-000000000011',
    target: {
      id: '00000000-0000-0000-0000-000000000012',
      name: 'Container Audit Target',
      baseUrl: serverUrl,
      scope: {
        allowedHosts: ['127.0.0.1'],
        allowedPorts: [serverPort],
        excludedPaths: [],
        testing: { activeScanning, loadTesting: false, chaosTesting: false },
        limits: { maxRps: 100, maxConcurrency: 10, maxDuration: '1m' },
      },
    },
    logger,
    abortSignal: new AbortController().signal,
    reportProgress: () => {},
  });

  describe('ZapScannerEngine Unit Checks', () => {
    const zapEngine = new ZapScannerEngine();

    it('exposes Class B scanner capabilities', () => {
      expect(zapEngine.id).toBe('engine-container-zap');
      const caps = zapEngine.capabilities();
      expect(caps.some((c) => c.id === 'zap_baseline')).toBe(true);
      expect(caps.some((c) => c.id === 'zap_active')).toBe(true);
    });

    it('blocks active scan when target scope forbids activeScanning', async () => {
      const result = await zapEngine.execute(
        {
          targetUrl: serverUrl,
          options: { activeScan: true },
        },
        createDummyContext(false), // activeScanning = false
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Active scanning is strictly disabled in target security scope');
    });

    it('executes passive baseline scan in simulated container mode', async () => {
      const result = await zapEngine.execute(
        {
          targetUrl: serverUrl,
          options: { simulated: true },
        },
        createDummyContext(false),
      );

      expect(result.success).toBe(true);
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.engineId).toBe('engine-container-zap');
    });
  });

  describe('TrivyScannerEngine Unit Checks', () => {
    const trivyEngine = new TrivyScannerEngine();

    it('exposes Trivy SCA and misconfiguration capabilities', () => {
      expect(trivyEngine.id).toBe('engine-container-trivy');
      const caps = trivyEngine.capabilities();
      expect(caps.some((c) => c.id === 'trivy_sca')).toBe(true);
    });

    it('executes Trivy scan in simulated container mode and yields CVE findings', async () => {
      const result = await trivyEngine.execute(
        {
          targetUrl: serverUrl,
          options: { simulated: true },
        },
        createDummyContext(false),
      );

      expect(result.findings.length).toBeGreaterThan(0);
      const cveFinding = result.findings.find((f) => f.title.includes('CVE-2024-24790'));
      expect(cveFinding).toBeDefined();
      expect(cveFinding?.category).toBe('software_composition_analysis');
    });
  });

  describe('Controller End-to-End Class B Execution & Forensic Persistence', () => {
    it('sets up project and target for containerized scanner tests', async () => {
      expect(isDbAvailable).toBe(true);
      const randomSuffix = Math.floor(Math.random() * 100000);

      // Create Project
      const projRes = await app.inject({
        method: 'POST',
        url: '/api/v1/projects',
        payload: {
          name: `Container Pipeline Project ${randomSuffix}`,
          description: 'Class B scanner testing project',
        },
      });
      expect(projRes.statusCode).toBe(201);
      projectId = JSON.parse(projRes.payload).data.id;

      // Create Target
      const targetRes = await app.inject({
        method: 'POST',
        url: `/api/v1/projects/${projectId}/targets`,
        payload: {
          name: `Container Target ${randomSuffix}`,
          baseUrl: serverUrl,
          allowedHosts: ['127.0.0.1'],
          allowedPorts: [serverPort],
          excludedPaths: [],
          testing: {
            activeScanning: false, // passive only
            loadTesting: false,
            chaosTesting: false,
          },
          limits: {
            maxRps: 50,
            maxConcurrency: 5,
            maxDuration: '2m',
          },
        },
      });
      expect(targetRes.statusCode).toBe(201);
      targetId = JSON.parse(targetRes.payload).data.id;
    });

    it('creates TestRun with profile "class-b-scanners"', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        payload: {
          projectId,
          targetId,
          profileId: 'class-b-scanners',
          triggeredBy: 'manual',
          metadata: {
            simulated: true, // fast execution mode for testing
          },
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      testRunId = body.data.id;
    });

    it('dispatches Class B execution and records class_b_container in test_executions', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/test-runs/${testRunId}/execute?wait=true`,
        payload: {
          engineIds: ['engine-container-zap', 'engine-container-trivy'],
          options: {
            simulated: true,
          },
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);

      const { executions, findings } = body.data;
      expect(executions).toHaveLength(2);

      const zapExec = executions.find((e: { engineId: string }) => e.engineId === 'engine-container-zap');
      expect(zapExec).toBeDefined();
      expect(zapExec.status).toBe('completed');

      const trivyExec = executions.find((e: { engineId: string }) => e.engineId === 'engine-container-trivy');
      expect(trivyExec).toBeDefined();
      expect(trivyExec.status).toBe('completed');

      // Findings verification
      expect(findings.length).toBeGreaterThan(0);
      for (const finding of findings) {
        expect(finding.fingerprint).toBeDefined();
        expect(finding.testRunId).toBe(testRunId);
        expect(finding.targetId).toBe(targetId);
      }
    });

    it('retrieves normalized findings for Class B scanners via GET /api/v1/test-runs/:id/findings', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/test-runs/${testRunId}/findings`,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.length).toBeGreaterThan(0);

      // Verify presence of ZAP or Trivy normalized categories
      const categories = body.data.map((f: { category: string }) => f.category);
      expect(
        categories.includes('web_application_security') ||
          categories.includes('software_composition_analysis') ||
          categories.includes('infrastructure_as_code'),
      ).toBe(true);
    });

    it('verifies immutable forensic evidence records with SHA-256 for container findings', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/test-runs/${testRunId}/evidence`,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.length).toBeGreaterThan(0);

      for (const record of body.data) {
        expect(record.immutableHash).toMatch(/^[a-f0-9]{64}$/);
        expect(record.testRunId).toBe(testRunId);
      }
    });
  });

  describe('DockerRunner Security Sandbox & CIS Benchmark Enforcement', () => {
    const runner = new DockerRunner();

    it('enforces approved image allowlist and rejects unauthorized images', () => {
      // Approved scanner images
      expect(isApprovedImage('ghcr.io/zaproxy/zaproxy:stable')).toBe(true);
      expect(isApprovedImage('zaproxy/zaproxy:weekly')).toBe(true);
      expect(isApprovedImage('aquasec/trivy:latest')).toBe(true);
      expect(isApprovedImage('ghcr.io/aquasecurity/trivy:0.49.1')).toBe(true);
      expect(isApprovedImage('grafana/k6:latest')).toBe(true);

      // Unapproved images
      expect(isApprovedImage('ubuntu:latest')).toBe(false);
      expect(isApprovedImage('alpine:3.18')).toBe(false);
      expect(isApprovedImage('attacker/malicious-scanner:v1')).toBe(false);
      expect(isApprovedImage('busybox')).toBe(false);
    });

    it('blocks Docker socket mount attempts with ContainerSecurityError', async () => {
      const socketMounts = [
        '/var/run/docker.sock',
        '/var/run/docker.sock/',
        '\\\\.\\pipe\\docker_engine',
        '/run/docker.sock',
      ];

      for (const socketPath of socketMounts) {
        await expect(
          runner.execute({
            image: 'ghcr.io/zaproxy/zaproxy:stable',
            volumes: [{ hostPath: socketPath, containerPath: '/var/run/docker.sock' }],
            simulated: true,
          }),
        ).rejects.toThrowError(ContainerSecurityError);
      }
    });

    it('blocks host root and sensitive system directory mounts', async () => {
      const forbiddenPaths = [
        '/',
        '/etc',
        '/root',
        '/bin',
        '/usr',
        '/sys',
        '/proc',
        'C:\\Windows',
        'C:\\Program Files',
      ];

      for (const badPath of forbiddenPaths) {
        await expect(
          runner.execute({
            image: 'ghcr.io/zaproxy/zaproxy:stable',
            volumes: [{ hostPath: badPath, containerPath: '/data' }],
            simulated: true,
          }),
        ).rejects.toThrowError(ContainerSecurityError);
      }
    });

    it('prohibits --network host to prevent network namespace escape', async () => {
      await expect(
        runner.execute({
          image: 'ghcr.io/zaproxy/zaproxy:stable',
          network: 'host',
          simulated: true,
        }),
      ).rejects.toThrowError(ContainerSecurityError);

      await expect(
        runner.execute({
          image: 'ghcr.io/zaproxy/zaproxy:stable',
          network: 'container:some_container_id',
          simulated: true,
        }),
      ).rejects.toThrowError(ContainerSecurityError);
    });

    it('rejects execution when image is not in approved allowlist', async () => {
      await expect(
        runner.execute({
          image: 'ubuntu:latest',
          simulated: true,
        }),
      ).rejects.toThrowError(ContainerSecurityError);
    });

    it('creates, verifies, and cleanly destroys ephemeral scratch directories', async () => {
      const scratch = await createScratchDirectory('test-scratch');
      expect(scratch.path).toBeDefined();

      // Verify scratch directory is recognized as valid by volume validator
      const validation = validateVolumePath(scratch.path);
      expect(validation.valid).toBe(true);

      // Verify execution succeeds with valid scratch directory in simulated mode
      const result = await runner.execute({
        image: 'ghcr.io/zaproxy/zaproxy:stable',
        volumes: [{ hostPath: scratch.path, containerPath: '/zap/wrk' }],
        simulated: true,
        mockStdout: '{"status":"ok"}',
      });
      expect(result.simulated).toBe(true);

      // Cleanup scratch directory
      await scratch.destroy();
    });

    it('fails fast on real Docker execution timeout without silent mock fallback', async () => {
      const runner = new DockerRunner();
      // Execute without simulated: true and with short timeout
      // Should fail fast with error instead of silently returning mockStdout
      await expect(
        runner.execute({
          image: 'ghcr.io/zaproxy/zaproxy:stable',
          mockStdout: '{"silent_mock":true}',
          simulated: false,
          timeoutMs: 150,
        }),
      ).rejects.toThrow();
    });

    it('cleans up and rejects on abortSignal without silent mock fallback', async () => {
      const runner = new DockerRunner();
      const controller = new AbortController();
      const execPromise = runner.execute({
        image: 'ghcr.io/zaproxy/zaproxy:stable',
        mockStdout: '{"silent_mock":true}',
        simulated: false,
        abortSignal: controller.signal,
      });
      controller.abort();
      await expect(execPromise).rejects.toThrow();
    });
  });

  describe('Class B Volume Exchange & Report Parsing (Real vs Simulated)', () => {
    it('ZAP: mounts ephemeral volume to /zap/wrk:rw and parses real report.json with exit code 2 (warnings)', async () => {
      let capturedHostPath = '';
      const customReport = {
        '@programName': 'OWASP ZAP',
        '@version': '2.14.0',
        site: [
          {
            '@name': 'Custom Real Test Site',
            alerts: [
              {
                pluginid: '99001',
                alertRef: '99001',
                alert: 'Custom Real ZAP Finding Alert',
                name: 'Custom Real ZAP Finding Alert',
                riskcode: '1',
                confidence: '2',
                riskdesc: 'Low (Medium)',
                desc: 'Real scanner test finding generated in test scratch volume.',
                instances: [{ uri: '/api/v1/test', method: 'GET' }],
                solution: 'Review real scanner alerts.',
              },
            ],
          },
        ],
      };

      const mockRunner = {
        execute: async (options: { volumes?: { hostPath: string; containerPath: string; mode?: string }[] }) => {
          const wrkVol = options.volumes?.find((v) => v.containerPath === '/zap/wrk');
          expect(wrkVol).toBeDefined();
          expect(wrkVol?.mode).toBe('rw');
          expect(validateVolumePath(wrkVol!.hostPath).valid).toBe(true);

          capturedHostPath = wrkVol!.hostPath;
          // Simulate ZAP writing real report.json to /zap/wrk/report.json
          const reportFile = path.join(capturedHostPath, 'report.json');
          await fs.promises.writeFile(reportFile, JSON.stringify(customReport), 'utf-8');

          return {
            exitCode: 2, // ZAP returns exit code 2 when WARN alerts are present
            stdout: 'ZAP Baseline completed with warnings',
            stderr: '',
            durationMs: 50,
            simulated: false,
          };
        },
      } as unknown as DockerRunner;

      const engine = new ZapScannerEngine(mockRunner);
      const result = await engine.execute(
        {
          targetUrl: serverUrl,
          options: { simulated: false },
        },
        createDummyContext(false),
      );

      expect(result.success).toBe(true);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]?.title).toBe('Custom Real ZAP Finding Alert');
      expect(result.metrics.find((m) => m.name === 'zap_findings_count')?.value).toBe(1);

      // Verify scratch directory was cleanly destroyed in finally
      expect(fs.existsSync(capturedHostPath)).toBe(false);
    });

    it('ZAP: fails fast and throws TestEngineError when report.json is missing and simulated: false', async () => {
      const mockRunner = {
        execute: async () => ({
          exitCode: 1,
          stdout: '',
          stderr: 'Container crashed before writing report',
          durationMs: 15,
          simulated: false,
        }),
      } as unknown as DockerRunner;

      const engine = new ZapScannerEngine(mockRunner);

      // 1. With throwOnError: true, throws TestEngineError
      await expect(
        engine.execute(
          {
            targetUrl: serverUrl,
            options: { simulated: false, throwOnError: true },
          },
          createDummyContext(false),
        ),
      ).rejects.toThrowError(TestEngineError);

      // 2. Without throwOnError, returns success: false with clear message and ZERO mock fallback
      const result = await engine.execute(
        {
          targetUrl: serverUrl,
          options: { simulated: false },
        },
        createDummyContext(false),
      );

      expect(result.success).toBe(false);
      expect(result.findings).toEqual([]);
      expect(result.error).toContain('failed to produce report.json at /zap/wrk/report.json');
    });

    it('Trivy: mounts target and output scratch volumes and parses real report.json', async () => {
      let capturedOutPath = '';
      const customReport = {
        SchemaVersion: 2,
        ArtifactName: 'test-artifact',
        ArtifactType: 'filesystem',
        Results: [
          {
            Target: 'package.json',
            Class: 'lang-pkgs',
            Type: 'npm',
            Vulnerabilities: [
              {
                VulnerabilityID: 'CVE-2025-99999',
                PkgName: 'vulnerable-test-lib',
                InstalledVersion: '1.0.0',
                FixedVersion: '1.0.1',
                Severity: 'HIGH',
                Title: 'Custom Test Real Vulnerability in Trivy Output',
                PrimaryURL: 'https://avd.aquasec.com/test',
              },
            ],
          },
        ],
      };

      const mockRunner = {
        execute: async (options: {
          args?: string[];
          volumes?: { hostPath: string; containerPath: string; mode?: string }[];
        }) => {
          expect(options.args).toEqual([
            'fs',
            '--format',
            'json',
            '--output',
            '/trivy-out/report.json',
            '/target-src',
          ]);

          const outVol = options.volumes?.find((v) => v.containerPath === '/trivy-out');
          const srcVol = options.volumes?.find((v) => v.containerPath === '/target-src');

          expect(outVol).toBeDefined();
          expect(outVol?.mode).toBe('rw');
          expect(srcVol).toBeDefined();
          expect(srcVol?.mode).toBe('ro');

          capturedOutPath = outVol!.hostPath;
          const reportFile = path.join(capturedOutPath, 'report.json');
          await fs.promises.writeFile(reportFile, JSON.stringify(customReport), 'utf-8');

          return {
            exitCode: 0,
            stdout: '',
            stderr: '',
            durationMs: 40,
            simulated: false,
          };
        },
      } as unknown as DockerRunner;

      const engine = new TrivyScannerEngine(mockRunner);
      const result = await engine.execute(
        {
          targetUrl: serverUrl,
          options: { simulated: false },
        },
        createDummyContext(false),
      );

      expect(result.success).toBe(true);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]?.title).toContain('CVE-2025-99999');
      expect(result.metrics.find((m) => m.name === 'trivy_high_count')?.value).toBe(1);

      // Verify scratch directory destroyed
      expect(fs.existsSync(capturedOutPath)).toBe(false);
    });

    it('Trivy: handles container image scanning mode without mounting source directory', async () => {
      const mockRunner = {
        execute: async (options: {
          args?: string[];
          volumes?: { hostPath: string; containerPath: string; mode?: string }[];
        }) => {
          expect(options.args).toEqual([
            'image',
            '--format',
            'json',
            '--output',
            '/trivy-out/report.json',
            'alpine:3.19',
          ]);

          // Image mode only mounts outScratch to /trivy-out, no /target-src
          expect(options.volumes?.some((v) => v.containerPath === '/target-src')).toBe(false);
          const outVol = options.volumes?.find((v) => v.containerPath === '/trivy-out');
          expect(outVol).toBeDefined();

          const reportFile = path.join(outVol!.hostPath, 'report.json');
          await fs.promises.writeFile(
            reportFile,
            JSON.stringify({ SchemaVersion: 2, ArtifactName: 'alpine:3.19', Results: [] }),
            'utf-8',
          );

          return {
            exitCode: 0,
            stdout: '',
            stderr: '',
            durationMs: 30,
            simulated: false,
          };
        },
      } as unknown as DockerRunner;

      const engine = new TrivyScannerEngine(mockRunner);
      const result = await engine.execute(
        {
          targetUrl: 'alpine:3.19',
          options: { simulated: false },
        },
        createDummyContext(false),
      );

      expect(result.success).toBe(true);
      expect(result.findings).toEqual([]);
    });

    it('Trivy: fails fast and throws TestEngineError when report.json is missing and simulated: false', async () => {
      const mockRunner = {
        execute: async () => ({
          exitCode: 1,
          stdout: '',
          stderr: 'Trivy execution crashed',
          durationMs: 20,
          simulated: false,
        }),
      } as unknown as DockerRunner;

      const engine = new TrivyScannerEngine(mockRunner);

      // 1. With throwOnError: true, throws TestEngineError
      await expect(
        engine.execute(
          {
            targetUrl: serverUrl,
            options: { simulated: false, throwOnError: true },
          },
          createDummyContext(false),
        ),
      ).rejects.toThrowError(TestEngineError);

      // 2. Without throwOnError, returns success: false with clear error and ZERO mock fallback
      const result = await engine.execute(
        {
          targetUrl: serverUrl,
          options: { simulated: false },
        },
        createDummyContext(false),
      );

      expect(result.success).toBe(false);
      expect(result.findings).toEqual([]);
      expect(result.error).toContain('failed to produce report.json at /trivy-out/report.json');
    });
  });
});
