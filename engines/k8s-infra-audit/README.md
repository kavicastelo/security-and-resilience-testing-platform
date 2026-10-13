# Kubernetes & Cloud-Native Infrastructure Security Audit (`@security-lab/k8s-infra-audit`)

## 1. Overview
The **Kubernetes & Cloud-Native Infrastructure Security Audit Engine** provides static analysis, Pod Security Standards (PSS) evaluation, and CIS Kubernetes Benchmark policy enforcement for Kubernetes workload manifests, Helm chart templates, and container Dockerfiles without requiring a live Kubernetes cluster or external CLI binaries.

While container image scanners like Trivy inspect package vulnerabilities (CVEs), critical cloud-native security compromises typically occur at the workload configuration layer: running containers as root, mounting host paths (`/var/run/docker.sock`), missing memory limits, or adding dangerous Linux capabilities (`SYS_ADMIN`). This engine identifies these misconfigurations before deployment.

---

## 2. Capabilities

| Capability ID | Name | Category | Description |
|---|---|---|---|
| `k8s_manifest_audit` | Kubernetes Manifest & Workload Security Static Audit | `passive_analysis` | Statically audits Kubernetes Deployments, StatefulSets, DaemonSets, Pods, and Jobs against CIS Benchmarks and Pod Security Standards. |
| `k8s_pss_enforcement` | Pod Security Standards (PSS) & CIS Benchmark Enforcement | `compliance_check` | Verifies container securityContext invariants including non-root execution, capability drop ALL, read-only root filesystems, and prohibited hostPath volumes. |
| `dockerfile_security_audit` | Dockerfile Static Configuration & Secret Ingestion Audit | `passive_analysis` | Audits Dockerfiles for unpinned base images, hardcoded ENV secrets, and root user directives. |

---

## 3. Evaluated Security Policies & Rules

### A. Kubernetes Pod Security Standards (PSS) & CIS Benchmark Rules
1. **`K8S-001-PRIVILEGED-CONTAINER`** (`CRITICAL`): Flags containers configuring `securityContext.privileged: true`.
2. **`K8S-002-ROOT-CONTAINER`** (`HIGH`): Flags containers running as root UID 0 or failing to enforce `runAsNonRoot: true`.
3. **`K8S-003-SENSITIVE-HOSTPATH`** (`CRITICAL`): Flags volumes mounting sensitive host paths (`/`, `/etc`, `/var/run/docker.sock`, `/run/containerd/containerd.sock`, `/proc`, `/sys`).
4. **`K8S-004-MISSING-CAPABILITY-DROP`** (`MEDIUM`): Flags containers that do not drop `ALL` capabilities (`capabilities.drop: ["ALL"]`).
5. **`K8S-005-DANGEROUS-CAPABILITY-ADDED`** (`CRITICAL`): Flags additions of high-risk capabilities (`SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, `SYS_RAWIO`, `DAC_OVERRIDE`).
6. **`K8S-006-HOST-NAMESPACE-SHARED`** (`HIGH`): Flags workloads sharing host namespaces (`hostNetwork: true`, `hostPID: true`, `hostIPC: true`).
7. **`K8S-007-MISSING-RESOURCE-LIMITS`** (`MEDIUM`): Flags containers omitting CPU or Memory limits, leaving workloads vulnerable to DoS.
8. **`K8S-008-MUTABLE-ROOT-FILESYSTEM`** (`LOW`): Flags containers without `securityContext.readOnlyRootFilesystem: true`.
9. **`K8S-009-ALLOW-PRIVILEGE-ESCALATION`** (`HIGH`): Flags containers allowing privilege escalation (`allowPrivilegeEscalation: false` missing or true).

### B. Dockerfile Hardening Rules
1. **`DOCKER-001-ROOT-USER`** (`HIGH`): Flags Dockerfiles with missing `USER` directive or explicit `USER root`.
2. **`DOCKER-002-HARDCODED-SECRET`** (`CRITICAL`): Flags `ENV` or `ARG` instructions embedding API keys, passwords, or secret tokens.
3. **`DOCKER-003-UNPINNED-BASE-IMAGE`** (`MEDIUM`): Flags `FROM` instructions using `:latest` or omitting version tags/digests.
4. **`DOCKER-004-PRIVILEGE-ESCALATION-TOOL`** (`HIGH`): Flags `RUN` instructions installing `sudo` or setting SUID bits (`chmod +s`).
5. **`DOCKER-005-SENSITIVE-PORT`** (`MEDIUM`): Flags `EXPOSE` instructions exposing SSH (port 22) or Docker daemon (ports 2375/2376).

---

## 4. Usage Example

```typescript
import { K8sInfraAuditEngine } from '@security-lab/k8s-infra-audit';

const engine = new K8sInfraAuditEngine();

const result = await engine.execute(
  {
    targetUrl: 'k8s://local-manifests',
    options: {
      manifestYaml: `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:latest
          securityContext:
            privileged: true
      volumes:
        - name: dockersock
          hostPath:
            path: /var/run/docker.sock
`,
      dockerfileContent: `
FROM alpine:latest
ENV API_KEY=secret_live_abcdef123456
RUN apt-get update && apt-get install -y sudo
`,
      policyLevel: 'restricted',
    },
  },
  {
    executionId: 'exec-k8s-001',
    testRunId: 'run-k8s-001',
    target: {
      id: 'target-k8s',
      baseUrl: 'k8s://local-manifests',
      scope: {
        allowedHosts: ['localhost'],
        allowedPorts: [80],
        allowPrivateIps: true,
        excludedPaths: [],
      },
    },
  }
);

console.log(result.findings);
```
