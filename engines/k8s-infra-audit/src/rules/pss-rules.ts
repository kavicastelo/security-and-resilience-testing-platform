import {
  K8sRule,
  K8sWorkloadDocument,
  RuleEvaluationContext,
  K8sAuditRuleFinding,
  K8sContainer,
} from '../types.js';
import { extractPodSpec, findLineNumber } from '../manifest-parser.js';

const SENSITIVE_HOST_PATHS = [
  '/',
  '/etc',
  '/var/run/docker.sock',
  '/run/containerd/containerd.sock',
  '/var/run',
  '/proc',
  '/sys',
  '/dev',
  '/boot',
  '/root',
  '//./pipe/docker_engine',
];

const DANGEROUS_CAPABILITIES = new Set([
  'SYS_ADMIN',
  'CAP_SYS_ADMIN',
  'NET_ADMIN',
  'CAP_NET_ADMIN',
  'SYS_PTRACE',
  'CAP_SYS_PTRACE',
  'SYS_RAWIO',
  'CAP_SYS_RAWIO',
  'DAC_OVERRIDE',
  'CAP_DAC_OVERRIDE',
  'NET_RAW',
  'CAP_NET_RAW',
  'ALL',
  'CAP_ALL',
]);

/**
 * Rule K8S-001: Privileged container execution.
 */
export const privilegedContainerRule: K8sRule = {
  id: 'K8S-001-PRIVILEGED-CONTAINER',
  name: 'Privileged Container Execution Forbidden',
  severity: 'critical',
  category: 'cloud_native_security',
  description:
    'Containers running with securityContext.privileged: true possess full administrative access to the underlying host node, bypassing container isolation boundaries.',
  evaluate(doc: K8sWorkloadDocument, _context: RuleEvaluationContext): K8sAuditRuleFinding[] {
    const findings: K8sAuditRuleFinding[] = [];
    const podSpec = extractPodSpec(doc);
    if (!podSpec) return findings;

    const allContainers: Array<{ container: K8sContainer; isInit: boolean }> = [
      ...(podSpec.containers || []).map((c) => ({ container: c, isInit: false })),
      ...(podSpec.initContainers || []).map((c) => ({ container: c, isInit: true })),
    ];

    const raw = doc.rawText || '';

    for (const { container } of allContainers) {
      if (container.securityContext?.privileged === true) {
        const line = findLineNumber(raw, `name: ${container.name}`) || doc.startLine || 1;
        findings.push({
          ruleId: this.id,
          title: `Privileged Container Execution Detected (${container.name})`,
          description: `Container "${container.name}" in ${doc.kind} "${doc.metadata?.name || 'unnamed'}" specifies "privileged: true", allowing potential host breakout.`,
          severity: this.severity,
          category: this.category,
          resourceKind: doc.kind,
          resourceName: doc.metadata?.name,
          containerName: container.name,
          filePath: doc.filePath,
          lineNumber: line,
          violatingSnippet: `container: ${container.name}\nsecurityContext:\n  privileged: true`,
          recommendation:
            'Set "securityContext.privileged: false" or omit the field. Grant only specific Linux capabilities if required.',
        });
      }
    }

    return findings;
  },
};

/**
 * Rule K8S-002: Container running as root.
 */
export const rootContainerExecutionRule: K8sRule = {
  id: 'K8S-002-ROOT-CONTAINER',
  name: 'Container Execution as Root User Forbidden',
  severity: 'high',
  category: 'cloud_native_security',
  description:
    'Containers must not execute as root (UID 0) and should enforce securityContext.runAsNonRoot: true to protect against container breakout vulnerabilities.',
  evaluate(doc: K8sWorkloadDocument, _context: RuleEvaluationContext): K8sAuditRuleFinding[] {
    const findings: K8sAuditRuleFinding[] = [];
    const podSpec = extractPodSpec(doc);
    if (!podSpec) return findings;

    const podRunAsNonRoot = podSpec.securityContext?.runAsNonRoot === true;
    const podRunAsUser = podSpec.securityContext?.runAsUser;

    const allContainers = [
      ...(podSpec.containers || []),
      ...(podSpec.initContainers || []),
    ];

    const raw = doc.rawText || '';

    for (const container of allContainers) {
      const cSec = container.securityContext;
      const explicitRootUser = cSec?.runAsUser === 0 || (!cSec?.runAsUser && podRunAsUser === 0);
      const enforcesNonRoot = cSec?.runAsNonRoot === true || (cSec?.runAsNonRoot === undefined && podRunAsNonRoot);

      if (explicitRootUser) {
        const line = findLineNumber(raw, `name: ${container.name}`) || doc.startLine || 1;
        findings.push({
          ruleId: this.id,
          title: `Container Explicitly Running as Root UID 0 (${container.name})`,
          description: `Container "${container.name}" in ${doc.kind} "${doc.metadata?.name || 'unnamed'}" explicitly configures "runAsUser: 0".`,
          severity: 'high',
          category: this.category,
          resourceKind: doc.kind,
          resourceName: doc.metadata?.name,
          containerName: container.name,
          filePath: doc.filePath,
          lineNumber: line,
          violatingSnippet: `container: ${container.name}\nsecurityContext:\n  runAsUser: 0`,
          recommendation:
            'Assign a non-zero UID (e.g. runAsUser: 10001) and set runAsNonRoot: true in the pod or container securityContext.',
        });
      } else if (!enforcesNonRoot) {
        const line = findLineNumber(raw, `name: ${container.name}`) || doc.startLine || 1;
        findings.push({
          ruleId: this.id,
          title: `Container Missing runAsNonRoot Enforcement (${container.name})`,
          description: `Container "${container.name}" in ${doc.kind} "${doc.metadata?.name || 'unnamed'}" does not enforce "runAsNonRoot: true", allowing image default root execution.`,
          severity: 'high',
          category: this.category,
          resourceKind: doc.kind,
          resourceName: doc.metadata?.name,
          containerName: container.name,
          filePath: doc.filePath,
          lineNumber: line,
          violatingSnippet: `container: ${container.name}\nsecurityContext: runAsNonRoot missing`,
          recommendation:
            'Set "securityContext.runAsNonRoot: true" on the container or pod level to mandate non-root execution.',
        });
      }
    }

    return findings;
  },
};

/**
 * Rule K8S-003: Sensitive hostPath mounts.
 */
export const sensitiveHostPathRule: K8sRule = {
  id: 'K8S-003-SENSITIVE-HOSTPATH',
  name: 'Sensitive HostPath Volume Mount Forbidden',
  severity: 'critical',
  category: 'cloud_native_security',
  description:
    'Mounting host directories (especially /, /etc, or the Docker socket /var/run/docker.sock) grants containers direct control over the host node file system and daemon.',
  evaluate(doc: K8sWorkloadDocument, context: RuleEvaluationContext): K8sAuditRuleFinding[] {
    const findings: K8sAuditRuleFinding[] = [];
    const podSpec = extractPodSpec(doc);
    if (!podSpec || !podSpec.volumes) return findings;

    const raw = doc.rawText || '';

    for (const volume of podSpec.volumes) {
      if (volume.hostPath?.path) {
        const path = volume.hostPath.path.trim();
        const isSensitive = SENSITIVE_HOST_PATHS.some((p) => {
          if (p === '/') return path === '/';
          return path === p || path.startsWith(p + '/');
        });

        const line = findLineNumber(raw, path) || doc.startLine || 1;

        if (isSensitive) {
          findings.push({
            ruleId: this.id,
            title: `Critical Sensitive HostPath Mount Detected (${volume.name}: "${path}")`,
            description: `Volume "${volume.name}" in ${doc.kind} "${doc.metadata?.name || 'unnamed'}" mounts critical host directory "${path}". Containers mounting this volume can inspect or manipulate host resources.`,
            severity: 'critical',
            category: this.category,
            resourceKind: doc.kind,
            resourceName: doc.metadata?.name,
            filePath: doc.filePath,
            lineNumber: line,
            violatingSnippet: `volume: ${volume.name}\nhostPath:\n  path: "${path}"`,
            recommendation:
              'Remove hostPath volume mounts. Use Kubernetes native ConfigMaps, Secrets, emptyDir, or PersistentVolumeClaims instead.',
          });
        } else if (context.policyLevel === 'restricted') {
          // In restricted PSS mode, all hostPath mounts are prohibited
          findings.push({
            ruleId: this.id,
            title: `HostPath Volume Forbidden under PSS Restricted Policy (${volume.name})`,
            description: `Volume "${volume.name}" in ${doc.kind} "${doc.metadata?.name || 'unnamed'}" uses hostPath "${path}", which is prohibited by Pod Security Standards Restricted profile.`,
            severity: 'high',
            category: this.category,
            resourceKind: doc.kind,
            resourceName: doc.metadata?.name,
            filePath: doc.filePath,
            lineNumber: line,
            violatingSnippet: `volume: ${volume.name}\nhostPath:\n  path: "${path}"`,
            recommendation:
              'Replace hostPath with an emptyDir volume or a persistent network storage claim.',
          });
        }
      }
    }

    return findings;
  },
};

/**
 * Rule K8S-004: Missing capability drop ALL.
 */
export const missingCapabilityDropRule: K8sRule = {
  id: 'K8S-004-MISSING-CAPABILITY-DROP',
  name: 'Containers Must Drop ALL Linux Capabilities',
  severity: 'medium',
  category: 'cloud_native_security',
  description:
    'Pod Security Standards require dropping all default Linux kernel capabilities (capabilities.drop: ["ALL"]) to establish a minimal privilege execution context.',
  evaluate(doc: K8sWorkloadDocument, _context: RuleEvaluationContext): K8sAuditRuleFinding[] {
    const findings: K8sAuditRuleFinding[] = [];
    const podSpec = extractPodSpec(doc);
    if (!podSpec) return findings;

    const allContainers = [
      ...(podSpec.containers || []),
      ...(podSpec.initContainers || []),
    ];

    const raw = doc.rawText || '';

    for (const container of allContainers) {
      const dropList = container.securityContext?.capabilities?.drop || [];
      const dropsAll = dropList.some((cap) => cap.toUpperCase() === 'ALL');

      if (!dropsAll) {
        const line = findLineNumber(raw, `name: ${container.name}`) || doc.startLine || 1;
        findings.push({
          ruleId: this.id,
          title: `Container Does Not Drop ALL Linux Capabilities (${container.name})`,
          description: `Container "${container.name}" in ${doc.kind} "${doc.metadata?.name || 'unnamed'}" does not configure "capabilities.drop: ["ALL"]".`,
          severity: this.severity,
          category: this.category,
          resourceKind: doc.kind,
          resourceName: doc.metadata?.name,
          containerName: container.name,
          filePath: doc.filePath,
          lineNumber: line,
          violatingSnippet: `container: ${container.name}\nsecurityContext:\n  capabilities:\n    drop: ${JSON.stringify(dropList)}`,
          recommendation:
            'Add "capabilities.drop: ["ALL"]" to the container securityContext and only selectively add required capabilities such as NET_BIND_SERVICE.',
        });
      }
    }

    return findings;
  },
};

/**
 * Rule K8S-005: Dangerous Linux capability added.
 */
export const dangerousCapabilityAddedRule: K8sRule = {
  id: 'K8S-005-DANGEROUS-CAPABILITY-ADDED',
  name: 'Dangerous Linux Kernel Capabilities Added',
  severity: 'critical',
  category: 'cloud_native_security',
  description:
    'Adding dangerous capabilities such as SYS_ADMIN, NET_ADMIN, or SYS_PTRACE allows containers to manipulate node kernel objects or sniff host network traffic.',
  evaluate(doc: K8sWorkloadDocument, _context: RuleEvaluationContext): K8sAuditRuleFinding[] {
    const findings: K8sAuditRuleFinding[] = [];
    const podSpec = extractPodSpec(doc);
    if (!podSpec) return findings;

    const allContainers = [
      ...(podSpec.containers || []),
      ...(podSpec.initContainers || []),
    ];

    const raw = doc.rawText || '';

    for (const container of allContainers) {
      const added = container.securityContext?.capabilities?.add || [];
      const dangerousFound = added.filter((c) => DANGEROUS_CAPABILITIES.has(c.toUpperCase()));

      if (dangerousFound.length > 0) {
        const line = findLineNumber(raw, `name: ${container.name}`) || doc.startLine || 1;
        findings.push({
          ruleId: this.id,
          title: `Dangerous Linux Capabilities Added (${container.name}: ${dangerousFound.join(', ')})`,
          description: `Container "${container.name}" in ${doc.kind} "${doc.metadata?.name || 'unnamed'}" adds high-risk kernel capabilities: [${dangerousFound.join(', ')}].`,
          severity: 'critical',
          category: this.category,
          resourceKind: doc.kind,
          resourceName: doc.metadata?.name,
          containerName: container.name,
          filePath: doc.filePath,
          lineNumber: line,
          violatingSnippet: `container: ${container.name}\ncapabilities:\n  add: ${JSON.stringify(dangerousFound)}`,
          recommendation:
            'Remove dangerous capabilities (SYS_ADMIN, NET_ADMIN, SYS_PTRACE). Refactor workloads to run without root privileges or kernel hooks.',
        });
      }
    }

    return findings;
  },
};

/**
 * Rule K8S-006: Host network, PID, or IPC namespaces shared.
 */
export const hostNamespacesRule: K8sRule = {
  id: 'K8S-006-HOST-NAMESPACE-SHARED',
  name: 'Sharing Host Namespaces (Network, PID, IPC) Forbidden',
  severity: 'high',
  category: 'cloud_native_security',
  description:
    'Pods configuring hostNetwork: true, hostPID: true, or hostIPC: true bypass container namespace isolation, allowing network snooping and process manipulation on the node.',
  evaluate(doc: K8sWorkloadDocument, _context: RuleEvaluationContext): K8sAuditRuleFinding[] {
    const findings: K8sAuditRuleFinding[] = [];
    const podSpec = extractPodSpec(doc);
    if (!podSpec) return findings;

    const raw = doc.rawText || '';

    const checks: Array<{ key: string; val?: boolean; desc: string }> = [
      { key: 'hostNetwork', val: podSpec.hostNetwork, desc: 'host network namespace' },
      { key: 'hostPID', val: podSpec.hostPID, desc: 'host PID process namespace' },
      { key: 'hostIPC', val: podSpec.hostIPC, desc: 'host IPC namespace' },
    ];

    for (const check of checks) {
      if (check.val === true) {
        const line = findLineNumber(raw, `${check.key}: true`) || doc.startLine || 1;
        findings.push({
          ruleId: this.id,
          title: `Pod Shares Host Namespace (${check.key}: true)`,
          description: `Workload ${doc.kind} "${doc.metadata?.name || 'unnamed'}" specifies "${check.key}: true", granting access to the ${check.desc}.`,
          severity: 'high',
          category: this.category,
          resourceKind: doc.kind,
          resourceName: doc.metadata?.name,
          filePath: doc.filePath,
          lineNumber: line,
          violatingSnippet: `${check.key}: true`,
          recommendation:
            `Set "${check.key}: false" or omit it to isolate the container within its own Kubernetes namespace.`,
        });
      }
    }

    return findings;
  },
};

/**
 * Rule K8S-007: Missing resource limits.
 */
export const missingResourceLimitsRule: K8sRule = {
  id: 'K8S-007-MISSING-RESOURCE-LIMITS',
  name: 'Container Resource Limits Must Be Configured',
  severity: 'medium',
  category: 'cloud_native_security',
  description:
    'Omitting CPU and memory limits allows a single rogue or compromised container to exhaust node resources, inducing a denial of service (OOM killer, starvation) on other workloads.',
  evaluate(doc: K8sWorkloadDocument, _context: RuleEvaluationContext): K8sAuditRuleFinding[] {
    const findings: K8sAuditRuleFinding[] = [];
    const podSpec = extractPodSpec(doc);
    if (!podSpec) return findings;

    const containers = podSpec.containers || [];
    const raw = doc.rawText || '';

    for (const container of containers) {
      const limits = container.resources?.limits;
      const missingCpu = !limits?.cpu;
      const missingMemory = !limits?.memory;

      if (missingCpu || missingMemory) {
        const line = findLineNumber(raw, `name: ${container.name}`) || doc.startLine || 1;
        const missingParts = [missingCpu ? 'CPU limit' : null, missingMemory ? 'Memory limit' : null]
          .filter(Boolean)
          .join(' and ');

        findings.push({
          ruleId: this.id,
          title: `Container Missing Resource Limits (${container.name}: ${missingParts})`,
          description: `Container "${container.name}" in ${doc.kind} "${doc.metadata?.name || 'unnamed'}" does not define ${missingParts}.`,
          severity: 'medium',
          category: this.category,
          resourceKind: doc.kind,
          resourceName: doc.metadata?.name,
          containerName: container.name,
          filePath: doc.filePath,
          lineNumber: line,
          violatingSnippet: `container: ${container.name}\nresources:\n  limits: ${JSON.stringify(limits || {})}`,
          recommendation:
            'Define explicit "resources.limits.cpu" and "resources.limits.memory" for all production containers to enforce resource governance.',
        });
      }
    }

    return findings;
  },
};

/**
 * Rule K8S-008: Mutable root filesystem.
 */
export const mutableRootFilesystemRule: K8sRule = {
  id: 'K8S-008-MUTABLE-ROOT-FILESYSTEM',
  name: 'Container Must Enforce Read-Only Root Filesystem',
  severity: 'low',
  category: 'cloud_native_security',
  description:
    'Configuring readOnlyRootFilesystem: true prevents attackers from writing malicious binaries, scripts, or implants to the container filesystem.',
  evaluate(doc: K8sWorkloadDocument, _context: RuleEvaluationContext): K8sAuditRuleFinding[] {
    const findings: K8sAuditRuleFinding[] = [];
    const podSpec = extractPodSpec(doc);
    if (!podSpec) return findings;

    const allContainers = [
      ...(podSpec.containers || []),
      ...(podSpec.initContainers || []),
    ];

    const raw = doc.rawText || '';

    for (const container of allContainers) {
      if (container.securityContext?.readOnlyRootFilesystem !== true) {
        const line = findLineNumber(raw, `name: ${container.name}`) || doc.startLine || 1;
        findings.push({
          ruleId: this.id,
          title: `Container Root Filesystem is Mutable (${container.name})`,
          description: `Container "${container.name}" in ${doc.kind} "${doc.metadata?.name || 'unnamed'}" does not set "readOnlyRootFilesystem: true".`,
          severity: 'low',
          category: this.category,
          resourceKind: doc.kind,
          resourceName: doc.metadata?.name,
          containerName: container.name,
          filePath: doc.filePath,
          lineNumber: line,
          violatingSnippet: `container: ${container.name}\nsecurityContext:\n  readOnlyRootFilesystem: false/missing`,
          recommendation:
            'Configure "securityContext.readOnlyRootFilesystem: true" and mount writable directories (/tmp, /var/log) as emptyDir volumes.',
        });
      }
    }

    return findings;
  },
};

/**
 * Rule K8S-009: Allow privilege escalation.
 */
export const allowPrivilegeEscalationRule: K8sRule = {
  id: 'K8S-009-ALLOW-PRIVILEGE-ESCALATION',
  name: 'Privilege Escalation Must Be Disabled',
  severity: 'high',
  category: 'cloud_native_security',
  description:
    'Setting allowPrivilegeEscalation: false ensures that no child process can gain more privileges than its parent, neutralizing SUID/SGID binaries.',
  evaluate(doc: K8sWorkloadDocument, _context: RuleEvaluationContext): K8sAuditRuleFinding[] {
    const findings: K8sAuditRuleFinding[] = [];
    const podSpec = extractPodSpec(doc);
    if (!podSpec) return findings;

    const allContainers = [
      ...(podSpec.containers || []),
      ...(podSpec.initContainers || []),
    ];

    const raw = doc.rawText || '';

    for (const container of allContainers) {
      if (container.securityContext?.allowPrivilegeEscalation !== false) {
        const line = findLineNumber(raw, `name: ${container.name}`) || doc.startLine || 1;
        findings.push({
          ruleId: this.id,
          title: `Container Permits Privilege Escalation (${container.name})`,
          description: `Container "${container.name}" in ${doc.kind} "${doc.metadata?.name || 'unnamed'}" does not explicitly set "allowPrivilegeEscalation: false".`,
          severity: 'high',
          category: this.category,
          resourceKind: doc.kind,
          resourceName: doc.metadata?.name,
          containerName: container.name,
          filePath: doc.filePath,
          lineNumber: line,
          violatingSnippet: `container: ${container.name}\nsecurityContext:\n  allowPrivilegeEscalation: true/missing`,
          recommendation:
            'Set "securityContext.allowPrivilegeEscalation: false" on all container definitions.',
        });
      }
    }

    return findings;
  },
};

export const ALL_K8S_RULES: K8sRule[] = [
  privilegedContainerRule,
  rootContainerExecutionRule,
  sensitiveHostPathRule,
  missingCapabilityDropRule,
  dangerousCapabilityAddedRule,
  hostNamespacesRule,
  missingResourceLimitsRule,
  mutableRootFilesystemRule,
  allowPrivilegeEscalationRule,
];
