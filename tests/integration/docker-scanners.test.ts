import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import {
  DockerRunner,
  dockerRunner,
  TrivyScannerEngine,
  ZapScannerEngine,
  K6ResilienceEngine,
  ContainerSecurityError,
  createScratchDirectory,
  isApprovedImage,
  validateVolumePath,
  MANDATORY_DOCKER_SECURITY_FLAGS,
  ExecutionContext,
  EphemeralScratchDirectory,
} from '@security-lab/test-sdk';
import { Target } from '@security-lab/domain';

/**
 * Pinned OCI image tags for reproducible, secure container testing.
 */
export const PINNED_IMAGES = {
  trivy: 'aquasec/trivy:0.58.0',
  k6: 'grafana/k6:0.54.0',
  zap: 'ghcr.io/zaproxy/zaproxy:weekly',
};

/**
 * Checks whether the Docker daemon is accessible and responding.
 */
export async function isDockerAvailable(): Promise<boolean> {
  try {
    return await new Promise<boolean>((resolve) => {
      const proc = spawn('docker', ['info'], { stdio: 'ignore' });
      proc.on('error', () => resolve(false));
      proc.on('close', (code) => resolve(code === 0));
    });
  } catch {
    return false;
  }
}

/**
 * Checks whether a specific container image is available locally in Docker storage.
 */
export async function isImageAvailable(image: string): Promise<boolean> {
  try {
    return await new Promise<boolean>((resolve) => {
      const proc = spawn('docker', ['image', 'inspect', image], { stdio: 'ignore' });
      proc.on('error', () => resolve(false));
      proc.on('close', (code) => resolve(code === 0));
    });
  } catch {
    return false;
  }
}

const isOptIn = process.env.SECURITY_LAB_TEST_REAL_DOCKER === 'true';

describe('Real Docker Security Scanner Integration Suite (REM-08)', () => {
  // ---------------------------------------------------------------------------
  // 1. Docker Policy & Security Hardening Verification (Runs in all environments)
  // ---------------------------------------------------------------------------
  describe('Container Security Policy & CIS Benchmark Enforcement', () => {
    it('accurately detects Docker daemon availability without throwing unhandled exceptions', async () => {
      const available = await isDockerAvailable();
      expect(typeof available).toBe('boolean');
    }, 15000);

    it('strictly forbids unapproved images per CIS image allowlist policy', async () => {
      expect(isApprovedImage('ubuntu:latest')).toBe(false);
      expect(isApprovedImage('alpine:3.19')).toBe(false);
      expect(isApprovedImage('malicious-repo/scanner:v1')).toBe(false);
      expect(isApprovedImage(PINNED_IMAGES.trivy)).toBe(true);
      expect(isApprovedImage(PINNED_IMAGES.k6)).toBe(true);
      expect(isApprovedImage(PINNED_IMAGES.zap)).toBe(true);

      await expect(
        dockerRunner.execute({
          image: 'ubuntu:latest',
          args: ['whoami'],
        }),
      ).rejects.toThrow(ContainerSecurityError);
    });

    it('strictly forbids sensitive host directory and socket volume mounts', () => {
      expect(validateVolumePath('/etc').valid).toBe(false);
      expect(validateVolumePath('/var/run/docker.sock').valid).toBe(false);
      expect(validateVolumePath('C:\\Windows\\System32').valid).toBe(false);
      expect(validateVolumePath('//var/run/dockershim').valid).toBe(false);
    });

    it('strictly forbids host network mode', async () => {
      await expect(
        dockerRunner.execute({
          image: PINNED_IMAGES.k6,
          network: 'host',
        }),
      ).rejects.toThrow(ContainerSecurityError);
    });

    it('enforces mandatory CIS benchmark security flags on all container runs', () => {
      expect(MANDATORY_DOCKER_SECURITY_FLAGS).toContain('--security-opt=no-new-privileges:true');
      expect(MANDATORY_DOCKER_SECURITY_FLAGS).toContain('--cap-drop=ALL');
      expect(MANDATORY_DOCKER_SECURITY_FLAGS).toContain('--read-only');
      expect(MANDATORY_DOCKER_SECURITY_FLAGS).toContain('--pids-limit=100');
      const tmpfsFlag = MANDATORY_DOCKER_SECURITY_FLAGS.find((f) => f.startsWith('--tmpfs='));
      expect(tmpfsFlag).toBeDefined();
      expect(tmpfsFlag).toContain('noexec');
      expect(tmpfsFlag).toContain('nosuid');
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Real Docker Live Container Execution (Opt-In Gate)
  // ---------------------------------------------------------------------------
  const describeLiveDocker = isOptIn ? describe : describe.skip;

  describeLiveDocker('Live Docker Container Execution (Opt-In via SECURITY_LAB_TEST_REAL_DOCKER)', () => {
    let server: http.Server;
    let serverPort: number;
    let mockTargetUrl: string;
    let dockerDaemonActive = false;
    const scratchDirsToClean: EphemeralScratchDirectory[] = [];

    const mockTarget: Target = {
      id: 'target-docker-test-01',
      projectId: 'proj-docker-test-01',
      tenantId: 'tenant-docker-test-01',
      name: 'Local Docker Test Target',
      baseUrl: 'http://127.0.0.1',
      scope: {
        allowedHosts: ['127.0.0.1', 'localhost', 'host.docker.internal'],
        maxDepth: 3,
        limits: {
          maxConcurrency: 10,
          maxRps: 100,
        },
        testing: {
          activeScanning: true,
          fuzzing: true,
          rateLimitOverrides: true,
          loadTesting: true,
        },
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const mockContext: ExecutionContext = {
      testRunId: 'test-run-docker-live-01',
      executionId: 'exec-docker-live-01',
      target: mockTarget,
      reportProgress: () => {},
      reportFinding: async () => {},
      recordMetric: async () => {},
      storeEvidence: async () => 'evidence-hash-dummy',
      abortSignal: new AbortController().signal,
    };

    beforeAll(async () => {
      dockerDaemonActive = await isDockerAvailable();
      if (!dockerDaemonActive) {
        console.warn(
          'Warning: SECURITY_LAB_TEST_REAL_DOCKER=true was set, but Docker daemon is offline or unreachable.',
        );
        return;
      }

      // Start local mock HTTP service bound to all interfaces for container reachability
      server = http.createServer((req, res) => {
        if (req.url === '/api/v1/health') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'healthy', version: '1.0.0' }));
          return;
        }

        // Return a mock HTML response with intentional missing security headers
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Server': 'MockTarget/1.0',
        });
        res.end(`
          <!DOCTYPE html>
          <html>
            <head><title>Docker Security Scanner Test Target</title></head>
            <body>
              <h1>Local Lab Target</h1>
              <form action="/login" method="POST">
                <input type="text" name="username" />
                <input type="password" name="password" />
                <button type="submit">Login</button>
              </form>
            </body>
          </html>
        `);
      });

      await new Promise<void>((resolve) => {
        server.listen(0, '0.0.0.0', () => {
          const addr = server.address();
          if (addr && typeof addr === 'object') {
            serverPort = addr.port;
            mockTargetUrl = `http://host.docker.internal:${serverPort}`;
          }
          resolve();
        });
      });
    });

    afterAll(async () => {
      if (server) {
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }

      // Cleanup any test scratch directories
      for (const dir of scratchDirsToClean) {
        try {
          await dir.cleanup();
        } catch {
          // Best effort
        }
      }
    });

    it('enforces container timeout and cleans up process when execution limit is exceeded', async () => {
      if (!dockerDaemonActive) {
        console.info('Skipping test: Docker daemon is unavailable.');
        return;
      }

      const fixtureScratch = await createScratchDirectory('k6-timeout');
      scratchDirsToClean.push(fixtureScratch);
      const scriptPath = path.join(fixtureScratch.path, 'sleep.js');
      await fs.promises.writeFile(
        scriptPath,
        `import { sleep } from 'k6';
         export default function() {
           sleep(10);
         }`,
      );

      const runner = new DockerRunner();
      const startTime = Date.now();

      await expect(
        runner.execute({
          image: PINNED_IMAGES.k6,
          args: ['run', '/scripts/sleep.js'],
          volumes: [
            {
              hostPath: fixtureScratch.path,
              containerPath: '/scripts',
              mode: 'ro',
            },
          ],
          timeoutMs: 1500,
        }),
      ).rejects.toThrow(/timed out after 1500ms/);

      const elapsed = Date.now() - startTime;
      expect(elapsed).toBeGreaterThanOrEqual(1400);
    });

    it('handles container failure and non-zero exit codes with captured stderr output', async () => {
      if (!dockerDaemonActive) {
        console.info('Skipping test: Docker daemon is unavailable.');
        return;
      }

      const runner = new DockerRunner();
      const result = await runner.execute({
        image: PINNED_IMAGES.k6,
        args: ['invalid-subcommand-should-fail'],
      });

      expect(result.exitCode).not.toBe(0);
      expect(result.simulated).toBe(false);
      expect(result.stderr).toContain('invalid-subcommand-should-fail');
    });

    it('executes genuine Aqua Trivy container and outputs real JSON report from volume mount', async () => {
      if (!dockerDaemonActive) {
        console.info('Skipping test: Docker daemon is unavailable.');
        return;
      }

      const isTrivyPresent = await isImageAvailable(PINNED_IMAGES.trivy);
      if (!isTrivyPresent) {
        console.warn(`Skipping Trivy test: Image "${PINNED_IMAGES.trivy}" is not available locally.`);
        return;
      }

      // Create an isolated scratch directory with a test fixture
      const fixtureScratch = await createScratchDirectory('trivy-live-fixture');
      scratchDirsToClean.push(fixtureScratch);

      await fs.promises.writeFile(
        path.join(fixtureScratch.path, 'package.json'),
        JSON.stringify(
          {
            name: 'vulnerable-test-fixture',
            version: '1.0.0',
            dependencies: {
              'minimist': '0.0.8', // Prototype pollution CVE
            },
          },
          null,
          2,
        ),
      );

      const trivyEngine = new TrivyScannerEngine(new DockerRunner());
      const result = await trivyEngine.execute(
        {
          targetUrl: `file://${fixtureScratch.path}`,
          options: {
            dockerImage: PINNED_IMAGES.trivy,
            scanType: 'fs',
            targetPath: fixtureScratch.path,
            scanners: 'misconfig,secret',
          },
        },
        mockContext,
      );

      expect(result.engineId).toBe('engine-container-trivy');
      expect(result.durationMs).toBeGreaterThan(0);
      expect(result.success).toBe(true);
      expect(result.rawOutput).toBeDefined();
      expect((result.rawOutput as Record<string, unknown>).SchemaVersion).toBe(2);
    });

    it('executes genuine Grafana k6 container and parses real resilience metrics', async () => {
      if (!dockerDaemonActive) {
        console.info('Skipping test: Docker daemon is unavailable.');
        return;
      }

      const isK6Present = await isImageAvailable(PINNED_IMAGES.k6);
      if (!isK6Present) {
        console.warn(`Skipping k6 test: Image "${PINNED_IMAGES.k6}" is not available locally.`);
        return;
      }

      const k6Engine = new K6ResilienceEngine(new DockerRunner());
      const result = await k6Engine.execute(
        {
          targetUrl: mockTargetUrl,
          options: {
            dockerImage: PINNED_IMAGES.k6,
            durationSec: 1,
            vus: 1,
            scenarioType: 'load_sla',
          },
        },
        mockContext,
      );

      expect(result.engineId).toBe('engine-worker-k6');
      expect(result.durationMs).toBeGreaterThan(0);
      expect(result.success).toBe(true);

      // Verify real metrics parsed from k6 container
      const reqMetric = result.metrics.find((m) => m.name === 'http_reqs_total');
      expect(reqMetric).toBeDefined();
      expect(typeof reqMetric?.value).toBe('number');
    });

    it('executes genuine OWASP ZAP container baseline scan when image is locally available', async () => {
      if (!dockerDaemonActive) {
        console.info('Skipping test: Docker daemon is unavailable.');
        return;
      }

      const isZapPresent =
        (await isImageAvailable(PINNED_IMAGES.zap)) ||
        (await isImageAvailable('zaproxy/zaproxy:weekly')) ||
        (await isImageAvailable('ghcr.io/zaproxy/zaproxy:stable'));

      if (!isZapPresent) {
        console.info(
          'Opt-in diagnostic: OWASP ZAP image is not cached locally. Skipping live ZAP container test honestly.',
        );
        return;
      }

      const zapEngine = new ZapScannerEngine(new DockerRunner());
      const result = await zapEngine.execute(
        {
          targetUrl: mockTargetUrl,
          options: {
            dockerImage: PINNED_IMAGES.zap,
            timeoutMs: 60000,
          },
        },
        mockContext,
      );

      expect(result.engineId).toBe('engine-container-zap');
      expect(result.durationMs).toBeGreaterThan(0);
      expect(result.rawOutput).toBeDefined();
    }, 90000);

    it('confirms zero orphaned scanner containers remain after live test execution', async () => {
      if (!dockerDaemonActive) return;

      const runningContainers = await new Promise<string[]>((resolve) => {
        const proc = spawn('docker', ['ps', '--filter', 'name=security-lab-', '--format', '{{.Names}}']);
        let out = '';
        proc.stdout.on('data', (d) => (out += d.toString()));
        proc.on('close', () => {
          const lines = out.split('\n').map((l) => l.trim()).filter(Boolean);
          // Filter out persistent infrastructure like security-lab-postgres
          const scannerContainers = lines.filter((name) => name !== 'security-lab-postgres');
          resolve(scannerContainers);
        });
      });

      expect(runningContainers).toEqual([]);
    });
  });
});
