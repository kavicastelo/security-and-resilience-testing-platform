import {
  DockerfileRule,
  ParsedDockerfile,
  RuleEvaluationContext,
  K8sAuditRuleFinding,
} from '../types.js';

const SENSITIVE_SECRET_PATTERNS = [
  /(?:^|\s)[A-Za-z0-9_-]*(?:API[_-]?KEY|TOKEN|SECRET[_-]?KEY|SECRET|PASSWORD|PASSWD|AUTH[_-]?TOKEN|PRIVATE[_-]?KEY)\s*=\s*['"]?([^\s'"]+)['"]?/i,
  /(?:^|\s)[A-Za-z0-9_-]*(?:ACCESS[_-]?KEY|DATABASE[_-]?URL|DB[_-]?PASS)\s*=\s*['"]?([^\s'"]+)['"]?/i,
];

/**
 * Rule DOCKER-001: Root user execution or missing USER directive.
 */
export const dockerfileRootUserRule: DockerfileRule = {
  id: 'DOCKER-001-ROOT-USER',
  name: 'Dockerfile Must Specify Non-Root USER',
  severity: 'high',
  category: 'container_security',
  description:
    'Images should specify an unprivileged USER instruction (e.g., USER nonroot or USER 10001:10001). Omitting USER causes containers to default to UID 0 (root).',
  evaluate(dockerfile: ParsedDockerfile, _context: RuleEvaluationContext): K8sAuditRuleFinding[] {
    const findings: K8sAuditRuleFinding[] = [];
    const userInstructions = dockerfile.instructions.filter((i) => i.instruction === 'USER');

    if (userInstructions.length === 0) {
      findings.push({
        ruleId: this.id,
        title: 'Dockerfile Missing USER Directive (Defaults to Root)',
        description:
          'No USER instruction is declared in the Dockerfile. By default, container runtimes will execute commands and entrypoints as root (UID 0).',
        severity: this.severity,
        category: this.category,
        filePath: dockerfile.filePath,
        lineNumber: dockerfile.instructions[0]?.lineNumber || 1,
        violatingSnippet: 'Dockerfile has no USER instruction',
        recommendation:
          'Add a non-root USER instruction near the end of the Dockerfile (e.g., "RUN addgroup -S app && adduser -S app -G app\\nUSER app").',
      });
      return findings;
    }

    const lastUser = userInstructions[userInstructions.length - 1];
    if (!lastUser) return findings;

    const userArg = lastUser.args.trim().toLowerCase();

    if (userArg === 'root' || userArg === '0' || userArg.startsWith('0:') || userArg.startsWith('root:')) {
      findings.push({
        ruleId: this.id,
        title: `Dockerfile Explicitly Reverts to Root USER (${lastUser.args})`,
        description: `The final USER instruction in the Dockerfile sets "${lastUser.raw}", executing container processes with root privileges.`,
        severity: this.severity,
        category: this.category,
        filePath: dockerfile.filePath,
        lineNumber: lastUser.lineNumber,
        violatingSnippet: lastUser.raw,
        recommendation: 'Change the USER instruction to an unprivileged user name or non-zero UID.',
      });
    }

    return findings;
  },
};

/**
 * Rule DOCKER-002: Hardcoded secrets in ENV or ARG instructions.
 */
export const dockerfileHardcodedSecretRule: DockerfileRule = {
  id: 'DOCKER-002-HARDCODED-SECRET',
  name: 'Hardcoded Secrets in Dockerfile Instructions Forbidden',
  severity: 'critical',
  category: 'container_security',
  description:
    'Environment variables (ENV) and build arguments (ARG) are permanently embedded in the image manifest layer history and can be trivially extracted by anyone with image pull permissions.',
  evaluate(dockerfile: ParsedDockerfile, _context: RuleEvaluationContext): K8sAuditRuleFinding[] {
    const findings: K8sAuditRuleFinding[] = [];
    const secretInstructions = dockerfile.instructions.filter(
      (i) => i.instruction === 'ENV' || i.instruction === 'ARG',
    );

    for (const inst of secretInstructions) {
      for (const pattern of SENSITIVE_SECRET_PATTERNS) {
        const match = inst.args.match(pattern);
        if (match) {
          const matchedVal = match[1] || '';
          // Filter out dynamic expansion or trivial placeholders
          if (
            matchedVal.startsWith('$') ||
            matchedVal.startsWith('{') ||
            matchedVal === '""' ||
            matchedVal === "''" ||
            matchedVal.toLowerCase().includes('placeholder')
          ) {
            continue;
          }

          findings.push({
            ruleId: this.id,
            title: `Hardcoded Secret Detected in ${inst.instruction} Instruction`,
            description: `Instruction "${inst.raw}" contains what appears to be a plaintext credential or token embedded directly into the Dockerfile image metadata.`,
            severity: this.severity,
            category: this.category,
            filePath: dockerfile.filePath,
            lineNumber: inst.lineNumber,
            violatingSnippet: inst.raw,
            recommendation:
              'Remove secrets from Dockerfile. Inject credentials at runtime via environment variables or secret volumes, or use BuildKit "--mount=type=secret" during build time.',
          });
          break; // Avoid duplicate finding per instruction
        }
      }
    }

    return findings;
  },
};

/**
 * Rule DOCKER-003: Unpinned or latest base image tag.
 */
export const dockerfileUnpinnedBaseImageRule: DockerfileRule = {
  id: 'DOCKER-003-UNPINNED-BASE-IMAGE',
  name: 'Base Image Must Use Pinned Version Tag or Digest',
  severity: 'medium',
  category: 'container_security',
  description:
    'Using untagged images or the ":latest" tag results in non-deterministic builds, breaking reproducibility and potentially pulling vulnerable or corrupted upstream images without warning.',
  evaluate(dockerfile: ParsedDockerfile, _context: RuleEvaluationContext): K8sAuditRuleFinding[] {
    const findings: K8sAuditRuleFinding[] = [];
    const fromInstructions = dockerfile.instructions.filter((i) => i.instruction === 'FROM');

    for (const inst of fromInstructions) {
      // e.g. FROM node:latest AS build OR FROM alpine
      const parts = inst.args.split(/\s+/);
      const imageRef = parts[0] === '--platform' ? (parts[2] ?? '') : (parts[0] ?? '');
      if (!imageRef) continue;

      const isDigest = imageRef.includes('@sha256:');
      const hasTag = imageRef.includes(':');
      const isLatest = imageRef.endsWith(':latest');

      if (!isDigest && (!hasTag || isLatest)) {
        findings.push({
          ruleId: this.id,
          title: `Base Image Uses Unpinned or Latest Tag (${imageRef})`,
          description: `Base image "${imageRef}" in instruction "${inst.raw}" is not pinned to a specific immutable digest or version tag.`,
          severity: this.severity,
          category: this.category,
          filePath: dockerfile.filePath,
          lineNumber: inst.lineNumber,
          violatingSnippet: inst.raw,
          recommendation:
            'Pin base images to a specific semantic version tag (e.g. node:20.11.0-alpine) or immutable digest (image@sha256:...).',
        });
      }
    }

    return findings;
  },
};

/**
 * Rule DOCKER-004: Privilege escalation tools (sudo, SUID binaries).
 */
export const dockerfilePrivilegeEscalationRule: DockerfileRule = {
  id: 'DOCKER-004-PRIVILEGE-ESCALATION-TOOL',
  name: 'Privilege Escalation Utilities (sudo, SUID) Forbidden',
  severity: 'high',
  category: 'container_security',
  description:
    'Installing sudo or assigning SUID/SGID permissions inside container images introduces unnecessary privilege escalation paths for attackers.',
  evaluate(dockerfile: ParsedDockerfile, _context: RuleEvaluationContext): K8sAuditRuleFinding[] {
    const findings: K8sAuditRuleFinding[] = [];
    const runInstructions = dockerfile.instructions.filter((i) => i.instruction === 'RUN');

    for (const inst of runInstructions) {
      const lower = inst.args.toLowerCase();
      const hasSudo = /\bapt-get\s+install.*sudo\b|\byum\s+install.*sudo\b|\bapk\s+add.*sudo\b/.test(lower);
      const hasSuid = /chmod\s+[+]s\b|chmod\s+4[0-7]{3}\b/.test(lower);
      const hasInsecurePipe = /curl\s+[^|]+\|\s*(?:ba)?sh\b|wget\s+[^|]+\|\s*(?:ba)?sh\b/.test(lower);

      if (hasSudo) {
        findings.push({
          ruleId: this.id,
          title: 'Sudo Installed Inside Container Image',
          description: `Instruction "${inst.raw}" installs sudo inside the container image, increasing attack surface and facilitating privilege escalation.`,
          severity: 'high',
          category: this.category,
          filePath: dockerfile.filePath,
          lineNumber: inst.lineNumber,
          violatingSnippet: inst.raw,
          recommendation:
            'Do not install sudo in production containers. Design workloads to execute under unprivileged user accounts.',
        });
      }

      if (hasSuid) {
        findings.push({
          ruleId: this.id,
          title: 'SUID/SGID Permission Assigned to Binary',
          description: `Instruction "${inst.raw}" sets SUID or SGID permissions, enabling unprivileged users to execute binaries with elevated rights.`,
          severity: 'high',
          category: this.category,
          filePath: dockerfile.filePath,
          lineNumber: inst.lineNumber,
          violatingSnippet: inst.raw,
          recommendation:
            'Avoid setting SUID bits inside container images. Use capabilities or non-root user permissions instead.',
        });
      }

      if (hasInsecurePipe) {
        findings.push({
          ruleId: this.id,
          title: 'Insecure Script Piped Directly to Shell (curl | sh)',
          description: `Instruction "${inst.raw}" downloads and executes an unverified remote script directly into bash/sh, exposing the build to supply chain compromise.`,
          severity: 'medium',
          category: this.category,
          filePath: dockerfile.filePath,
          lineNumber: inst.lineNumber,
          violatingSnippet: inst.raw,
          recommendation:
            'Download scripts to a file, verify checksums or signatures, and execute the verified file.',
        });
      }
    }

    return findings;
  },
};

/**
 * Rule DOCKER-005: Sensitive port exposure.
 */
export const dockerfileSensitivePortRule: DockerfileRule = {
  id: 'DOCKER-005-SENSITIVE-PORT',
  name: 'Sensitive Ports (SSH, Docker Daemon) Forbidden in EXPOSE',
  severity: 'medium',
  category: 'container_security',
  description:
    'Exposing SSH (port 22) or Docker daemon sockets (port 2375/2376) indicates improper container architecture.',
  evaluate(dockerfile: ParsedDockerfile, _context: RuleEvaluationContext): K8sAuditRuleFinding[] {
    const findings: K8sAuditRuleFinding[] = [];
    const exposeInstructions = dockerfile.instructions.filter((i) => i.instruction === 'EXPOSE');

    for (const inst of exposeInstructions) {
      const ports = inst.args.split(/\s+/);
      for (const p of ports) {
        const portToken = p.split('/')[0] ?? '';
        const portNum = parseInt(portToken, 10);
        if (portNum === 22) {
          findings.push({
            ruleId: this.id,
            title: 'SSH Port 22 Exposed in Dockerfile',
            description: `Instruction "${inst.raw}" exposes SSH port 22. Containers should be managed via orchestrator exec sessions, not SSH daemons.`,
            severity: 'medium',
            category: this.category,
            filePath: dockerfile.filePath,
            lineNumber: inst.lineNumber,
            violatingSnippet: inst.raw,
            recommendation:
              'Remove SSH server and EXPOSE 22. Use "kubectl exec" or container logs for administrative debugging.',
          });
        } else if (portNum === 2375 || portNum === 2376) {
          findings.push({
            ruleId: this.id,
            title: `Docker Daemon Port ${portNum} Exposed in Dockerfile`,
            description: `Instruction "${inst.raw}" exposes unencrypted or remote Docker daemon port ${portNum}, risking host takeover.`,
            severity: 'high',
            category: this.category,
            filePath: dockerfile.filePath,
            lineNumber: inst.lineNumber,
            violatingSnippet: inst.raw,
            recommendation: 'Do not run Docker daemon inside containers without strict mTLS and sandboxing.',
          });
        }
      }
    }

    return findings;
  },
};

export const ALL_DOCKERFILE_RULES: DockerfileRule[] = [
  dockerfileRootUserRule,
  dockerfileHardcodedSecretRule,
  dockerfileUnpinnedBaseImageRule,
  dockerfilePrivilegeEscalationRule,
  dockerfileSensitivePortRule,
];
