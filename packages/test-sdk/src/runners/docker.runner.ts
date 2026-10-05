import { spawn } from 'node:child_process';
import { logger } from '@security-lab/logger';

export interface VolumeMount {
  hostPath: string;
  containerPath: string;
  mode?: 'ro' | 'rw';
}

export interface DockerRunOptions {
  image: string;
  args?: string[];
  env?: Record<string, string>;
  volumes?: VolumeMount[];
  network?: string;
  memoryLimit?: string;
  cpuLimit?: string;
  timeoutMs?: number;
  abortSignal?: AbortSignal;
  simulated?: boolean;
  mockStdout?: string;
  mockExitCode?: number;
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
   * Checks whether the Docker daemon is accessible.
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
   * Spawns an isolated, ephemeral Docker container runner enforcing security resource limits.
   */
  async execute(options: DockerRunOptions): Promise<DockerRunResult> {
    const startTime = Date.now();

    // Check for simulated / fallback execution mode
    const isMockEnv =
      process.env.SECURITY_LAB_MOCK_CONTAINERS === 'true' ||
      options.simulated === true ||
      options.mockStdout !== undefined;

    if (isMockEnv) {
      logger.debug(
        { image: options.image },
        'Executing container in simulated sandbox mode (mock output provided or requested).',
      );
      return {
        exitCode: options.mockExitCode ?? 0,
        stdout: options.mockStdout ?? '{}',
        stderr: '',
        durationMs: Date.now() - startTime,
        simulated: true,
      };
    }

    const dockerArgs: string[] = ['run', '--rm'];

    // Enforce memory and CPU caps for Class B isolation
    const memory = options.memoryLimit || '1024m';
    const cpus = options.cpuLimit || '1.0';
    dockerArgs.push('--memory', memory);
    dockerArgs.push('--cpus', cpus);

    if (options.network) {
      dockerArgs.push('--network', options.network);
    }

    // Environment variables
    if (options.env) {
      for (const [key, val] of Object.entries(options.env)) {
        dockerArgs.push('-e', `${key}=${val}`);
      }
    }

    // Volume mounts
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

    logger.debug({ image: options.image, args: dockerArgs }, 'Launching Docker runner container...');

    return new Promise<DockerRunResult>((resolve, reject) => {
      let stdout = '';
      let stderr = '';

      const proc = spawn('docker', dockerArgs, {
        signal: options.abortSignal,
      });

      const timeout = options.timeoutMs
        ? setTimeout(() => {
            proc.kill('SIGTERM');
          }, options.timeoutMs)
        : null;

      proc.stdout?.on('data', (data) => {
        stdout += data.toString();
      });

      proc.stderr?.on('data', (data) => {
        stderr += data.toString();
      });

      proc.on('error', (err) => {
        if (timeout) clearTimeout(timeout);
        // If docker cannot be spawned, fall back to mock output if available
        if (options.mockStdout !== undefined) {
          logger.warn(
            { err: err.message },
            'Docker execution failed; falling back to simulated output.',
          );
          resolve({
            exitCode: 0,
            stdout: options.mockStdout,
            stderr: '',
            durationMs: Date.now() - startTime,
            simulated: true,
          });
          return;
        }
        reject(new Error(`Failed to spawn Docker process for image ${options.image}: ${err.message}`));
      });

      proc.on('close', (code) => {
        if (timeout) clearTimeout(timeout);
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
