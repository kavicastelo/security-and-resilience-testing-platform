import { describe, it, expect } from 'vitest';
import {
  SAMPLE_FLEET_NODES,
  SAMPLE_JOB_LEASES,
  fetchAgentFleet,
  fetchAgentJobLeases,
  generateEnrollmentToken,
  drainAgent,
  revokeAgent,
  cancelAgentJobLease,
} from '../src/api/agents.js';

describe('Phase UI-12: Enterprise Distributed Agent Fleet Command Console & mTLS Radar', () => {
  describe('Agent Fleet Node Topology & Status Breakdown', () => {
    it('provides multi-region distributed nodes with valid status distribution', async () => {
      const { agents, summary } = await fetchAgentFleet();

      expect(agents.length).toBeGreaterThanOrEqual(5);
      expect(summary.totalAgents).toBe(agents.length);
      expect(summary.onlineCount + summary.busyCount + summary.drainingCount + summary.offlineCount).toBe(
        summary.totalAgents
      );

      // Verify node states exist
      expect(agents.some((a) => a.status === 'online')).toBe(true);
      expect(agents.some((a) => a.status === 'busy')).toBe(true);
      expect(agents.some((a) => a.status === 'draining')).toBe(true);
      expect(agents.some((a) => a.status === 'offline')).toBe(true);
    });

    it('aggregates fleet compute pool (total vCPUs, RAM GB, and cluster utilization)', async () => {
      const { summary } = await fetchAgentFleet();

      expect(summary.totalCpuCores).toBeGreaterThan(40);
      expect(summary.totalMemoryGb).toBeGreaterThan(64);
      expect(summary.clusterUtilizationPercent).toBeGreaterThanOrEqual(0);
      expect(summary.clusterUtilizationPercent).toBeLessThanOrEqual(100);
    });

    it('verifies node system architecture, OS, and runtime environments', () => {
      const usEastNode = SAMPLE_FLEET_NODES.find((n) => n.id === 'agt-us-east-prod-01');
      expect(usEastNode).toBeDefined();
      expect(usEastNode!.os).toContain('Linux');
      expect(usEastNode!.arch).toBe('x86_64');
      expect(usEastNode!.nodeVersion).toBe('v22.13.5');
      expect(usEastNode!.cpuCount).toBe(16);
      expect(usEastNode!.totalMemoryMb).toBe(32768);

      const armNode = SAMPLE_FLEET_NODES.find((n) => n.id === 'agt-dev-macos-arm64');
      expect(armNode).toBeDefined();
      expect(armNode!.arch).toContain('arm64');
      expect(armNode!.os).toContain('Darwin');
    });
  });

  describe('Real-Time Telemetry & Heartbeat Gauges', () => {
    it('reports live CPU and memory utilization within bounds', () => {
      for (const node of SAMPLE_FLEET_NODES) {
        if (node.status !== 'offline') {
          expect(node.currentCpuUsagePercent).toBeGreaterThanOrEqual(0);
          expect(node.currentCpuUsagePercent).toBeLessThanOrEqual(100);
          expect(node.currentMemoryUsageMb).toBeGreaterThan(0);
          expect(node.currentMemoryUsageMb).toBeLessThanOrEqual(node.totalMemoryMb);
          expect(node.secondsSinceHeartbeat).toBeLessThanOrEqual(60);
        }
      }
    });

    it('identifies active running job details on busy nodes', () => {
      const busyNode = SAMPLE_FLEET_NODES.find((n) => n.status === 'busy');
      expect(busyNode).toBeDefined();
      expect(busyNode!.activeJob).toBeDefined();
      expect(busyNode!.activeJob!.jobId).toBeDefined();
      expect(busyNode!.activeJob!.targetUrl).toBeDefined();
      expect(busyNode!.activeJob!.progressPercent).toBeGreaterThanOrEqual(0);
      expect(busyNode!.activeJob!.progressPercent).toBeLessThanOrEqual(100);
      expect(busyNode!.activeJob!.engines.length).toBeGreaterThan(0);
    });
  });

  describe('mTLS Cryptographic Attestation & Capabilities', () => {
    it('verifies asymmetric Ed25519 public key fingerprints and mTLS certificate validity', () => {
      const prodNodes = SAMPLE_FLEET_NODES.filter((n) => n.authMode === 'asymmetric');
      expect(prodNodes.length).toBeGreaterThanOrEqual(4);

      for (const node of prodNodes) {
        expect(node.publicKeyFingerprint).toMatch(/^SHA256:Ed25519:/);
        if (node.certificate) {
          expect(node.certificate.tlsVersion).toContain('TLSv1.3');
          expect(node.certificate.daysRemaining).toBeGreaterThan(0);
          expect(node.certificate.issuer).toContain('Security Lab Fleet Intermediate CA');
        }
      }
    });

    it('contains capability tags for engine routing (docker, native-load, zap, k8s, db-security)', () => {
      const allCaps = new Set<string>();
      SAMPLE_FLEET_NODES.forEach((n) => n.capabilities.forEach((c) => allCaps.add(c)));

      expect(allCaps.has('docker')).toBe(true);
      expect(allCaps.has('native-load')).toBe(true);
      expect(allCaps.has('zap')).toBe(true);
      expect(allCaps.has('k8s')).toBe(true);
      expect(allCaps.has('db-security')).toBe(true);
    });
  });

  describe('Agent Enrollment Wizard & Multi-Format Command Snippets', () => {
    it('generates valid Tenant Enrollment Key and deployment command snippets', async () => {
      const commands = await generateEnrollmentToken({
        name: 'runner-test-cluster',
        expiresInDays: 30,
        tags: ['vpc-test', 'high-concurrency'],
      });

      expect(commands.token).toMatch(/^tek_runner-test-cluster_/);
      expect(commands.keyPrefix).toBeDefined();
      expect(new Date(commands.expiresAt).getTime()).toBeGreaterThan(Date.now());

      // Docker command check
      expect(commands.dockerCommand).toContain('docker run -d');
      expect(commands.dockerCommand).toContain('--name security-lab-agent');
      expect(commands.dockerCommand).toContain(`AGENT_TOKEN="${commands.token}"`);
      expect(commands.dockerCommand).toContain('security-lab/agent:latest');

      // Kubernetes manifest check
      expect(commands.k8sSnippet).toContain('apiVersion: apps/v1');
      expect(commands.k8sSnippet).toContain('kind: Deployment');
      expect(commands.k8sSnippet).toContain('security-lab-agent');

      // Node CLI check
      expect(commands.nodeCliCommand).toContain('npx security-lab-agent start');
      expect(commands.nodeCliCommand).toContain(`--token "${commands.token}"`);

      // systemd check
      expect(commands.systemdSnippet).toContain('[Unit]');
      expect(commands.systemdSnippet).toContain('[Service]');
      expect(commands.systemdSnippet).toContain('ExecStart=/usr/bin/security-lab-agent start');
    });
  });

  describe('Job Lease Lifecycle & Node Management Actions', () => {
    it('queries active and completed job leases per agent node', async () => {
      const allLeases = await fetchAgentJobLeases();
      expect(allLeases.length).toBeGreaterThanOrEqual(3);

      const runningLease = allLeases.find((l) => l.status === 'running');
      expect(runningLease).toBeDefined();
      expect(runningLease!.leaseId).toBeDefined();
      expect(runningLease!.progressPercent).toBeGreaterThan(0);

      const agentLeases = await fetchAgentJobLeases('agt-us-east-prod-01');
      expect(agentLeases.length).toBe(1);
      expect(agentLeases[0].assignedAgentId).toBe('agt-us-east-prod-01');
    });

    it('cancels job lease gracefully', async () => {
      const res = await cancelAgentJobLease('job-perf-8412-checkout');
      expect(res.success).toBe(true);
    });

    it('executes node drain action to finish existing leases and reject new jobs', async () => {
      const res = await drainAgent('agt-us-east-prod-01');
      expect(res.success).toBe(true);
      expect(res.message).toContain('draining');
    });

    it('revokes agent cryptographic identity', async () => {
      const res = await revokeAgent('agt-stale-node-offline', 'Operator decommissioned node');
      expect(res.success).toBe(true);
      expect(res.message).toContain('revoked');
    });
  });
});
