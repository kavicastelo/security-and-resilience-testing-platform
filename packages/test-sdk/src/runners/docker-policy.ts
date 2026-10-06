import os from 'node:os';
import path from 'node:path';

export class ContainerSecurityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ContainerSecurityError';
  }
}

/**
 * Approved OCI image patterns for Class B container scanners and Class C workers.
 * Arbitrary images (e.g. ubuntu, alpine, unverified third-party registries) are rejected.
 */
export const APPROVED_IMAGE_PATTERNS: RegExp[] = [
  // OWASP ZAP (GHCR and Docker Hub)
  /^(ghcr\.io\/|docker\.io\/)?zaproxy\/zaproxy(:[a-zA-Z0-9_.-]+)?$/i,
  /^(docker\.io\/)?owasp\/zap2docker-(stable|weekly|live)(:[a-zA-Z0-9_.-]+)?$/i,

  // Aqua Trivy (Docker Hub and GHCR)
  /^(docker\.io\/|ghcr\.io\/)?aquasec(urity)?\/trivy(:[a-zA-Z0-9_.-]+)?$/i,

  // Grafana k6 (Docker Hub and GHCR)
  /^(docker\.io\/|ghcr\.io\/)?grafana\/k6(:[a-zA-Z0-9_.-]+)?$/i,
];

/**
 * Validates whether a container image is on the approved allowlist.
 */
export function isApprovedImage(image: string): boolean {
  const cleanImage = image.trim();
  if (!cleanImage) return false;
  return APPROVED_IMAGE_PATTERNS.some((pattern) => pattern.test(cleanImage));
}

// Prohibited system and sensitive paths across POSIX and Windows hosts
const FORBIDDEN_SUBSTRINGS = [
  'docker.sock',
  'docker_engine',
  '/etc',
  '/proc',
  '/sys',
  '/dev',
  '/root',
  '/boot',
  '/sbin',
  '/usr',
  '/bin',
  '/lib',
  'system32',
  'windows',
  'program files',
  'programdata',
];

/**
 * Validates whether a host path is safe for volume mounting into a container.
 * Strictly forbids Docker sockets, host roots, and system directories.
 * Volume mounts must be restricted to ephemeral temporary scratch directories.
 */
export function validateVolumePath(hostPath: string): { valid: boolean; reason?: string } {
  const resolved = path.resolve(hostPath);
  const normalized = resolved.toLowerCase().replace(/\\/g, '/');

  // Check for Docker daemon socket escape
  if (
    normalized.includes('docker.sock') ||
    normalized.includes('docker_engine') ||
    normalized === '/var/run' ||
    normalized === '/run'
  ) {
    return {
      valid: false,
      reason: 'Mounting Docker socket or daemon runtime directory is strictly prohibited.',
    };
  }

  // Check for root directory mount
  const root = path.parse(resolved).root.toLowerCase().replace(/\\/g, '/');
  if (normalized === root || normalized === '/' || /^[a-z]:\/$/i.test(normalized)) {
    return {
      valid: false,
      reason: 'Mounting host filesystem root is strictly prohibited.',
    };
  }

  // Check for forbidden system directories
  for (const forbidden of FORBIDDEN_SUBSTRINGS) {
    if (normalized.includes(forbidden.toLowerCase())) {
      return {
        valid: false,
        reason: `Mounting sensitive host directory containing "${forbidden}" is strictly prohibited.`,
      };
    }
  }

  // Verify the directory resides inside OS temp dir or authorized scratch folder
  const tempDir = path.resolve(os.tmpdir()).toLowerCase().replace(/\\/g, '/');
  const isInsideTemp = normalized.startsWith(tempDir);

  if (!isInsideTemp) {
    return {
      valid: false,
      reason: `Host volume path "${hostPath}" must be located within the system temporary scratch directory (${tempDir}).`,
    };
  }

  return { valid: true };
}

/**
 * Validates container network mode.
 * Strictly forbids `--network host` to prevent container network escape.
 */
export function validateNetworkMode(network?: string): void {
  if (!network) return;
  const cleanNet = network.trim().toLowerCase();
  if (cleanNet === 'host' || cleanNet.startsWith('container:')) {
    throw new ContainerSecurityError(
      `Network mode "${network}" is strictly prohibited. Containers must run on an isolated bridge network.`,
    );
  }
}

/**
 * Mandatory security flags injected into all container runs per CIS Docker Benchmarks.
 */
export const MANDATORY_DOCKER_SECURITY_FLAGS: string[] = [
  '--security-opt=no-new-privileges:true',
  '--cap-drop=ALL',
  '--read-only',
  '--pids-limit=100',
  '--tmpfs=/tmp:rw,noexec,nosuid,size=65536k',
];

export interface VolumeMount {
  hostPath: string;
  containerPath: string;
  mode?: 'ro' | 'rw';
}

export interface ValidatedDockerRunOptions {
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

/**
 * Enforces container security policies on DockerRunOptions before execution.
 * Throws ContainerSecurityError if any policy rule is violated.
 */
export function enforceContainerSecurityPolicy(options: ValidatedDockerRunOptions): void {
  // 1. Image Allowlist Enforcement
  if (!isApprovedImage(options.image)) {
    throw new ContainerSecurityError(
      `Container image "${options.image}" is not in the approved image allowlist. Only verified scanners (ZAP, Trivy, k6) from trusted registries are permitted.`,
    );
  }

  // 2. Network Isolation Enforcement
  validateNetworkMode(options.network);

  // 3. Volume Mount Sanitization
  if (options.volumes && options.volumes.length > 0) {
    for (const vol of options.volumes) {
      const check = validateVolumePath(vol.hostPath);
      if (!check.valid) {
        throw new ContainerSecurityError(
          `Security violation in volume mount "${vol.hostPath}": ${check.reason}`,
        );
      }
    }
  }
}
