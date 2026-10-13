import { describe, it, expect } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  K8sInfraAuditEngine,
  k8sInfraAuditEngine,
  parseKubernetesManifests,
  parseDockerfile,
} from '../src/index.js';
import { WorkerRunner } from '@security-lab/engine-sdk';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe('Phase 13: Kubernetes & Cloud-Native Infrastructure Security Audit', () => {
  const dummyContext = {
    correlationId: 'test-k8s-corr-001',
    executionId: 'exec-k8s-001',
    testRunId: 'run-k8s-001',
    target: {
      id: 'target-k8s-01',
      name: 'Local K8s Manifests',
      baseUrl: 'k8s://local-cluster',
      scope: {
        allowedHosts: ['localhost', '127.0.0.1'],
        allowedPorts: [80, 443],
        allowPrivateIps: true,
        excludedPaths: [],
      },
    },
    reportProgress: () => {},
  };

  describe('1. Kubernetes Manifest Parsing & AST Extraction', () => {
    it('parses multi-document Kubernetes YAML manifests preserving workload attributes', () => {
      const multiDocYaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-api
spec:
  template:
    spec:
      containers:
        - name: api
          image: mycorp/api:1.0.0
---
apiVersion: v1
kind: Pod
metadata:
  name: standalone-worker
spec:
  containers:
    - name: worker
      image: mycorp/worker:1.0.0
`;
      const result = parseKubernetesManifests(multiDocYaml, 'test-manifest.yaml');
      expect(result.errors).toHaveLength(0);
      expect(result.documents).toHaveLength(2);
      expect(result.documents[0]?.kind).toBe('Deployment');
      expect(result.documents[0]?.metadata?.name).toBe('web-api');
      expect(result.documents[1]?.kind).toBe('Pod');
      expect(result.documents[1]?.metadata?.name).toBe('standalone-worker');
    });

    it('gracefully handles malformed YAML syntax without throwing fatal exceptions', () => {
      const invalidYaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: [broken-unclosed-array
spec:
  foo: bar: baz
`;
      const result = parseKubernetesManifests(invalidYaml, 'invalid.yaml');
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0]?.message).toMatch(/YAML syntax error/i);
    });
  });

  describe('2. CIS Kubernetes & Pod Security Standards (PSS) Rule Evaluation', () => {
    it('detects privileged containers as CRITICAL (K8S-001)', async () => {
      const privilegedYaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: privileged-pod
spec:
  template:
    spec:
      containers:
        - name: escape-artist
          image: alpine:latest
          securityContext:
            privileged: true
`;
      const engine = new K8sInfraAuditEngine();
      const res = await engine.execute(
        {
          targetUrl: 'k8s://local-cluster',
          options: { manifestYaml: privilegedYaml },
        },
        dummyContext,
      );

      expect(res.success).toBe(true);
      const privFinding = res.findings.find((f) => f.title.includes('Privileged Container'));
      expect(privFinding).toBeDefined();
      expect(privFinding?.severity).toBe('critical');
      expect(privFinding?.recommendation).toMatch(/privileged: false/);
    });

    it('detects root user execution and missing runAsNonRoot as HIGH (K8S-002)', async () => {
      const rootYaml = `
apiVersion: v1
kind: Pod
metadata:
  name: root-pod
spec:
  containers:
    - name: app
      image: nginx:1.25.0
      securityContext:
        runAsUser: 0
`;
      const engine = new K8sInfraAuditEngine();
      const res = await engine.execute(
        {
          targetUrl: 'k8s://local-cluster',
          options: { manifestYaml: rootYaml },
        },
        dummyContext,
      );

      const rootFinding = res.findings.find((f) => f.title.includes('Root UID 0'));
      expect(rootFinding).toBeDefined();
      expect(rootFinding?.severity).toBe('high');
    });

    it('detects critical sensitive hostPath mounts (K8S-003)', async () => {
      const hostPathYaml = `
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: host-dumper
spec:
  template:
    spec:
      containers:
        - name: agent
          image: monitoring:v1
      volumes:
        - name: docker-socket
          hostPath:
            path: /var/run/docker.sock
        - name: host-root
          hostPath:
            path: /
`;
      const engine = new K8sInfraAuditEngine();
      const res = await engine.execute(
        {
          targetUrl: 'k8s://local-cluster',
          options: { manifestYaml: hostPathYaml },
        },
        dummyContext,
      );

      const hostPathFindings = res.findings.filter((f) => f.title.includes('HostPath'));
      expect(hostPathFindings.length).toBeGreaterThanOrEqual(2);
      expect(hostPathFindings.some((f) => f.severity === 'critical')).toBe(true);
    });

    it('detects missing capability drop ALL and dangerous capabilities (K8S-004 & K8S-005)', async () => {
      const capYaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cap-violator
spec:
  template:
    spec:
      containers:
        - name: net-sniffer
          image: sniffer:1.0
          securityContext:
            capabilities:
              add: ["SYS_ADMIN", "NET_ADMIN"]
              drop: ["KILL"]
`;
      const engine = new K8sInfraAuditEngine();
      const res = await engine.execute(
        {
          targetUrl: 'k8s://local-cluster',
          options: { manifestYaml: capYaml },
        },
        dummyContext,
      );

      const dangerousCapFinding = res.findings.find((f) => f.title.includes('Dangerous Linux Capabilities'));
      expect(dangerousCapFinding).toBeDefined();
      expect(dangerousCapFinding?.severity).toBe('critical');

      const dropAllFinding = res.findings.find((f) => f.title.includes('Drop ALL Linux Capabilities'));
      expect(dropAllFinding).toBeDefined();
      expect(dropAllFinding?.severity).toBe('medium');
    });

    it('detects shared host namespaces (K8S-006) and missing resource limits (K8S-007)', async () => {
      const namespaceYaml = `
apiVersion: v1
kind: Pod
metadata:
  name: host-network-app
spec:
  hostNetwork: true
  hostPID: true
  containers:
    - name: proxy
      image: envoy:v1.28.0
`;
      const engine = new K8sInfraAuditEngine();
      const res = await engine.execute(
        {
          targetUrl: 'k8s://local-cluster',
          options: { manifestYaml: namespaceYaml },
        },
        dummyContext,
      );

      const netFinding = res.findings.find((f) => f.title.includes('hostNetwork: true'));
      expect(netFinding).toBeDefined();
      expect(netFinding?.severity).toBe('high');

      const pidFinding = res.findings.find((f) => f.title.includes('hostPID: true'));
      expect(pidFinding).toBeDefined();

      const resFinding = res.findings.find((f) => f.title.includes('Missing Resource Limits'));
      expect(resFinding).toBeDefined();
      expect(resFinding?.severity).toBe('medium');
    });

    it('verifies that hardened production manifest (infrastructure/k8s/agent.yaml) produces zero critical findings', async () => {
      const agentYamlPath = path.resolve(__dirname, '../../../infrastructure/k8s/agent.yaml');
      expect(fs.existsSync(agentYamlPath)).toBe(true);

      const engine = new K8sInfraAuditEngine();
      const res = await engine.execute(
        {
          targetUrl: `file://${agentYamlPath}`,
          options: { filePaths: [agentYamlPath], policyLevel: 'baseline' },
        },
        dummyContext,
      );

      expect(res.success).toBe(true);
      // Hardened agent manifest has rootless, drop ALL, read-only rootfs, and no privileged
      const criticalOrHigh = res.findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
      expect(criticalOrHigh).toHaveLength(0);
    });
  });

  describe('3. Dockerfile Security Auditor', () => {
    it('parses multi-line Dockerfiles and extracts instructions accurately', () => {
      const dockerfileContent = `
FROM node:20-alpine AS build
WORKDIR /app
COPY . .
RUN npm ci \\
    && npm run build
USER node
EXPOSE 3000
CMD ["npm", "start"]
`;
      const parsed = parseDockerfile(dockerfileContent, 'Dockerfile');
      expect(parsed.instructions.length).toBeGreaterThanOrEqual(7);
      const userInst = parsed.instructions.find((i) => i.instruction === 'USER');
      expect(userInst?.args).toBe('node');
      expect(userInst?.lineNumber).toBe(7);
    });

    it('detects unpinned base image (DOCKER-003) and missing USER directive (DOCKER-001)', async () => {
      const badDockerfile = `
FROM alpine:latest
RUN apk update && apk add curl
EXPOSE 8080
CMD ["sh"]
`;
      const engine = new K8sInfraAuditEngine();
      const res = await engine.execute(
        {
          targetUrl: 'k8s://local-cluster',
          options: { dockerfileContent: badDockerfile },
        },
        dummyContext,
      );

      const unpinnedFinding = res.findings.find((f) => f.title.includes('Unpinned or Latest'));
      expect(unpinnedFinding).toBeDefined();
      expect(unpinnedFinding?.severity).toBe('medium');

      const userFinding = res.findings.find((f) => f.title.includes('Missing USER'));
      expect(userFinding).toBeDefined();
      expect(userFinding?.severity).toBe('high');
    });

    it('detects hardcoded secrets in ENV instructions (DOCKER-002) and sudo installation (DOCKER-004)', async () => {
      const secretDockerfile = `
FROM debian:12-slim
ENV API_KEY="live_sk_94829482934892348"
ENV DATABASE_PASSWORD=SuperSecretPass123!
RUN apt-get update && apt-get install -y sudo
USER root
EXPOSE 22
`;
      const engine = new K8sInfraAuditEngine();
      const res = await engine.execute(
        {
          targetUrl: 'k8s://local-cluster',
          options: { dockerfileContent: secretDockerfile },
        },
        dummyContext,
      );

      const secretFindings = res.findings.filter((f) => f.title.includes('Hardcoded Secret'));
      expect(secretFindings.length).toBeGreaterThanOrEqual(2);
      expect(secretFindings[0]?.severity).toBe('critical');

      const sudoFinding = res.findings.find((f) => f.title.includes('Sudo Installed'));
      expect(sudoFinding).toBeDefined();
      expect(sudoFinding?.severity).toBe('high');

      const sshFinding = res.findings.find((f) => f.title.includes('SSH Port 22'));
      expect(sshFinding).toBeDefined();
      expect(sshFinding?.severity).toBe('medium');
    });
  });

  describe('4. Input Validation & Capabilities', () => {
    it('declares passive_analysis and compliance_check capabilities', () => {
      const caps = k8sInfraAuditEngine.capabilities();
      expect(caps.some((c) => c.id === 'k8s_manifest_audit')).toBe(true);
      expect(caps.some((c) => c.id === 'k8s_pss_enforcement')).toBe(true);
      expect(caps.some((c) => c.id === 'dockerfile_security_audit')).toBe(true);
    });

    it('rejects execution when no manifests, Dockerfiles, or file paths are provided', () => {
      const validation = k8sInfraAuditEngine.validate({
        targetUrl: 'https://example.com',
        options: {},
      });
      expect(validation.valid).toBe(false);
      expect(validation.errors?.[0]?.message).toMatch(/K8s Infra Audit requires/);
    });
  });

  describe('5. Worker Sandboxing Execution (Phase 03 Integration)', () => {
    it('executes k8s-infra-audit engine inside isolated V8 worker thread harness', async () => {
      const vulnerableYaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sandbox-test-workload
spec:
  template:
    spec:
      containers:
        - name: root-app
          image: redis:latest
          securityContext:
            privileged: true
            runAsUser: 0
`;
      const runner = new WorkerRunner();
      const result = await runner.execute(
        'engine-k8s-infra-audit',
        {
          targetUrl: 'k8s://local-cluster',
          options: { manifestYaml: vulnerableYaml },
        },
        dummyContext,
        { enabled: true, timeoutMs: 10000 },
      );

      expect(result.success).toBe(true);
      expect(result.engineId).toBe('engine-k8s-infra-audit');
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.findings.some((f) => f.title.includes('Privileged Container'))).toBe(true);
    });
  });
});
