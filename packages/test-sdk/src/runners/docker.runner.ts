import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import { logger } from '@security-lab/logger';
import {
  enforceContainerSecurityPolicy,
  MANDATORY_DOCKER_SECURITY_FLAGS,
  VolumeMount,
  ContainerSecurityError,
} from './docker-policy.js';

export { VolumeMount, ContainerSecurityError };

export interface DockerRunOptions {
  image: string;
  args?: string[];
  env?: Record<string, string>;
  volumes?: VolumeMount[];
  network?: string;
  memoryLimit?: string;
  cpuLimit?: string;
  user?: string;
  timeoutMs?: number;
  abortSignal?: AbortSignal;
  simulated?: boolean;
  mockStdout?: string;
  mockExitCode?: number;
  executionId?: string;
}

export interface DockerRunResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
  simulated: boolean;
}

export class DockerRunner {
  /**
   * Checks whether the Docker daemon is accessible and responding.
   */
  async isDockerAvailable(): Promise<boolean> {
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
   * Cleans up an orphaned or timed-out container by name:
   * First attempts graceful stop with 2s grace period, then force removes the container.
   */
  async cleanupContainer(containerName: string): Promise<void> {
    try {
      await new Promise<void>((resolve) => {
        const stopProc = spawn('docker', ['stop', '-t', '2', containerName], { stdio: 'ignore' });
        const proceedToRm = () => {
          const rmProc = spawn('docker', ['rm', '-f', containerName], { stdio: 'ignore' });
          rmProc.on('error', () => resolve());
          rmProc.on('close', () => resolve());
        };
        stopProc.on('error', () => proceedToRm());
        stopProc.on('close', () => proceedToRm());
      });
      logger.debug({ containerName }, 'Terminated and removed container.');
    } catch {
      // Ignore cleanup error
    }
  }

  /**
   * Spawns an isolated, hardened Docker container runner enforcing CIS benchmark flags,
   * dropped capabilities, read-only rootfs, non-root user, memory/CPU caps, and volume isolation.
   */
  async execute(options: DockerRunOptions): Promise<DockerRunResult> {
    const startTime = Date.now();

    // 1. Mandatory Security Policy Pre-flight Validation
    enforceContainerSecurityPolicy(options);

    // 2. Explicit Simulated / Mock Execution Gating
    // Simulation is strictly opt-in via environment flag or options.simulated
    const isMockEnv =
      process.env.SECURITY_LAB_MOCK_CONTAINERS === 'true' ||
      options.simulated === true;

    if (isMockEnv) {
      logger.debug(
        { image: options.image },
        'Executing container in simulated sandbox mode (simulated explicitly requested).',
      );
      return {
        exitCode: options.mockExitCode ?? 0,
        stdout: options.mockStdout ?? '{}',
        stderr: '',
        durationMs: Date.now() - startTime,
        simulated: true,
      };
    }

    // 3. Assemble Hardened Docker CLI Arguments
    const containerId = options.executionId || crypto.randomUUID().slice(0, 8);
    const containerName = `security-lab-${containerId}`;

    const dockerArgs: string[] = [
      'run',
      '--rm',
      `--name=${containerName}`,
      ...MANDATORY_DOCKER_SECURITY_FLAGS,
    ];

    // Non-root user execution
    const user = options.user || '10001:10001';
    dockerArgs.push(`--user=${user}`);

    // Resource limits
    const memory = options.memoryLimit || '1024m';
    const cpus = options.cpuLimit || '1.0';
    dockerArgs.push(`--memory=${memory}`);
    dockerArgs.push(`--cpus=${cpus}`);

    // Isolated bridge network
    if (options.network) {
      dockerArgs.push(`--network=${options.network}`);
    }

    // Environment variables
    if (options.env) {
      for (const [key, val] of Object.entries(options.env)) {
        dockerArgs.push('-e', `${key}=${val}`);
      }
    }

    // Sanitized volume mounts
    if (options.volumes) {
      for (const vol of options.volumes) {
        dockerArgs.push('-v', `${vol.hostPath}:${vol.containerPath}:${vol.mode || 'ro'}`);
      }
    }

    // Container Image & Command Args
    dockerArgs.push(options.image);
    if (options.args && options.args.length > 0) {
      dockerArgs.push(...options.args);
    }

    logger.debug({ image: options.image, containerName }, 'Launching hardened Docker runner container...');

    return new Promise<DockerRunResult>((resolve, reject) => {
      let stdout = '';
      let stderr = '';
      let timedOut = false;
      let aborted = false;

      const proc = spawn('docker', dockerArgs, {
        signal: options.abortSignal,
      });

      const timeout = options.timeoutMs
        ? setTimeout(async () => {
            timedOut = true;
            proc.kill('SIGTERM');
            await this.cleanupContainer(containerName);
            reject(
              new Error(
                `Docker container ${containerName} (${options.image}) timed out after ${options.timeoutMs}ms`,
              ),
            );
          }, options.timeoutMs)
        : null;

      if (options.abortSignal) {
        options.abortSignal.addEventListener(
          'abort',
          async () => {
            aborted = true;
            await this.cleanupContainer(containerName);
            reject(new Error(`Docker container ${containerName} execution was aborted`));
          },
          { once: true },
        );
      }

      proc.stdout?.on('data', (data) => {
        stdout += data.toString();
      });

      proc.stderr?.on('data', (data) => {
        stderr += data.toString();
      });

      proc.on('error', (err) => {
        if (timeout) clearTimeout(timeout);
        if (timedOut || aborted) return;
        // Fail fast: do NOT silently mask Docker failures with mock data
        reject(
          new Error(
            `Failed to spawn Docker process for image ${options.image}: ${err.message}. Ensure Docker daemon is running or configure simulated execution.`,
          ),
        );
      });

      proc.on('close', (code) => {
        if (timeout) clearTimeout(timeout);
        if (timedOut || aborted) return;
        resolve({
          exitCode: code ?? 0,
          stdout,
          stderr,
          durationMs: Date.now() - startTime,
          simulated: false,
        });
      });
    });
  }
}

export const dockerRunner = new DockerRunner();
