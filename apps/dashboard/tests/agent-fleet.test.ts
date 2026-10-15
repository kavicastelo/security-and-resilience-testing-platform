import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  fetchAgentFleet,
  fetchAgentJobLeases,
  generateEnrollmentToken,
  drainAgent,
  revokeAgent,
  cancelAgentJobLease,
} from '../src/api/agents.js';

describe('Phase UI-12: Enterprise Distributed Agent Fleet Command Console & mTLS Radar', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    globalThis.fetch = vi.fn();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe('Truthful Zero-Agent Empty Fleet State', () => {
    it('returns empty array and zero-count summary when no agents are registered in backend', async () => {
      // Mock /api/v1/agents returning empty list and /api/v1/agents/leases returning empty list
      (globalThis.fetch as any).mockImplementation((url: string) => {
        if (url.includes('/api/v1/agents/leases')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({ success: true, data: [] }),
          });
        }
        return Promise.resolve({
          ok: true,
          json: async () => ({ success: true, data: [] }),
        });
      });

      const { agents, summary } = await fetchAgentFleet();

      expect(agents).toEqual([]);
      expect(summary.totalAgents).toBe(0);
      expect(summary.onlineCount).toBe(0);
      expect(summary.busyCount).toBe(0);
      expect(summary.drainingCount).toBe(0);
      expect(summary.offlineCount).toBe(0);
      expect(summary.activeJobsCount).toBe(0);
      expect(summary.totalCpuCores).toBe(0);
      expect(summary.totalMemoryGb).toBe(0);
      expect(summary.clusterUtilizationPercent).toBe(0);
    });
  });

  describe('Real Agent Fleet Mapping & Dynamic Status Attestation', () => {
    const mockDbAgents = [
      {
        id: 'agt-us-east-prod-01',
        name: 'runner-us-east-1a-prod',
        status: 'online',
        ipAddress: '10.100.4.12',
        tags: ['vpc-prod', 'high-throughput', 'pci-dss'],
        capabilities: ['docker', 'native-load', 'zap', 'k8s', 'db-security'],
        authMode: 'asymmetric',
        fingerprint: 'SHA256:Ed25519:8f3c7e1a902b4d5e6f7a8b9c0d1e2f3a4b5c6d7e',
        lastHeartbeatAt: new Date(Date.now() - 5000).toISOString(),
        systemInfo: {
          os: 'Linux 6.5.0-generic',
          arch: 'x86_64',
          nodeVersion: 'v22.13.5',
          cpuCount: 16,
          totalMemoryMb: 32768,
          cpuPercent: 42.5,
          memoryUsageMb: 12000,
          region: 'us-east-1 (N. Virginia)',
          environment: 'VPC-Production-Isolated',
          totalJobsCompleted: 142,
          totalJobsFailed: 3,
        },
      },
      {
        id: 'agt-eu-central-prod-02',
        name: 'runner-eu-central-1-appsec',
        status: 'online',
        ipAddress: '10.200.8.44',
        tags: ['vpc-eu', 'gdpr-zone'],
        capabilities: ['docker', 'zap', 'k8s'],
        authMode: 'asymmetric',
        fingerprint: 'SHA256:Ed25519:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b',
        lastHeartbeatAt: new Date(Date.now() - 10000).toISOString(),
        systemInfo: {
          os: 'Linux 6.1.0-18-amd64',
          arch: 'x86_64',
          nodeVersion: 'v20.18.0',
          cpuCount: 8,
          totalMemoryMb: 16384,
          cpuPercent: 15.0,
          memoryUsageMb: 4000,
          region: 'eu-central-1 (Frankfurt)',
          environment: 'VPC-Production-GDPR',
          totalJobsCompleted: 98,
          totalJobsFailed: 1,
        },
      },
      {
        id: 'agt-stale-node-offline',
        name: 'runner-offline-legacy',
        status: 'online', // backend recorded status is online, but heartbeat > 30s ago
        ipAddress: '10.50.12.8',
        tags: ['legacy'],
        capabilities: ['headers'],
        authMode: 'token',
        lastHeartbeatAt: new Date(Date.now() - 120000).toISOString(), // 2 minutes ago
        systemInfo: {
          os: 'Debian 11',
          arch: 'x86_64',
          nodeVersion: 'v20.11.0',
          cpuCount: 4,
          totalMemoryMb: 8192,
          cpuPercent: 0,
          memoryUsageMb: 0,
        },
      },
    ];

    const mockDbLeases = [
      {
        leaseId: 'lease-8801',
        jobId: 'job-perf-8412',
        testRunId: 'run-9f82b1c4',
        targetName: 'Core Ingress Gateway',
        targetUrl: 'https://api.production.internal/v1/checkout',
        engines: ['engine-native-load'],
        assignedAgentId: 'agt-us-east-prod-01',
        assignedAgentName: 'runner-us-east-1a-prod',
        status: 'running',
        startedAt: new Date(Date.now() - 30000).toISOString(),
        leaseExpiresAt: new Date(Date.now() + 60000).toISOString(),
        progressPercent: 50,
        lastLogMessage: 'Scanning checkout endpoints',
      },
    ];

    it('maps real database agents, marks busy on active lease, and detects stale offline nodes', async () => {
      (globalThis.fetch as any).mockImplementation((url: string) => {
        if (url.includes('/api/v1/agents/leases')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({ success: true, data: mockDbLeases }),
          });
        }
        return Promise.resolve({
          ok: true,
          json: async () => ({ success: true, data: mockDbAgents }),
        });
      });

      const { agents, summary } = await fetchAgentFleet();

      expect(agents.length).toBe(3);
      expect(summary.totalAgents).toBe(3);

      const busyAgent = agents.find((a) => a.id === 'agt-us-east-prod-01');
      expect(busyAgent).toBeDefined();
      expect(busyAgent!.status).toBe('busy'); // Active lease marks it busy
      expect(busyAgent!.activeJob).toBeDefined();
      expect(busyAgent!.activeJob!.jobId).toBe('job-perf-8412');
      expect(busyAgent!.cpuCount).toBe(16);
      expect(busyAgent!.totalMemoryMb).toBe(32768);
      expect(busyAgent!.secondsSinceHeartbeat).toBeLessThan(30);
      expect(busyAgent!.publicKeyFingerprint).toBe('SHA256:Ed25519:8f3c7e1a902b4d5e6f7a8b9c0d1e2f3a4b5c6d7e');

      const onlineAgent = agents.find((a) => a.id === 'agt-eu-central-prod-02');
      expect(onlineAgent).toBeDefined();
      expect(onlineAgent!.status).toBe('online');
      expect(onlineAgent!.secondsSinceHeartbeat).toBeLessThan(30);

      const staleAgent = agents.find((a) => a.id === 'agt-stale-node-offline');
      expect(staleAgent).toBeDefined();
      expect(staleAgent!.status).toBe('offline'); // Heartbeat > 30s ago forces offline status
      expect(staleAgent!.secondsSinceHeartbeat).toBeGreaterThan(60);

      // Verify aggregate compute metrics
      expect(summary.totalCpuCores).toBe(16 + 8 + 4);
      expect(summary.totalMemoryGb).toBe(Math.round((32768 + 16384 + 8192) / 1024));
      expect(summary.activeJobsCount).toBe(1);
    });
  });

  describe('Agent Job Leases API', () => {
    it('queries active job leases from /api/v1/agents/leases', async () => {
      const mockLeases = [
        {
          leaseId: 'lease-101',
          jobId: 'job-101',
          testRunId: 'run-1',
          targetName: 'Auth Service',
          targetUrl: 'https://auth.internal',
          engines: ['engine-authz-matrix'],
          assignedAgentId: 'agt-1',
          assignedAgentName: 'Worker 1',
          status: 'running',
          startedAt: new Date().toISOString(),
          leaseExpiresAt: new Date(Date.now() + 120000).toISOString(),
          progressPercent: 30,
          lastLogMessage: 'Testing tenant isolation',
        },
      ];

      (globalThis.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ success: true, data: mockLeases }),
      });

      const leases = await fetchAgentJobLeases('agt-1');
      expect(leases.length).toBe(1);
      expect(leases[0].leaseId).toBe('lease-101');
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/agents/leases?agentId=agt-1'),
        expect.anything()
      );
    });
  });

  describe('Agent Enrollment Wizard & Multi-Format Command Snippets', () => {
    it('generates valid Tenant Enrollment Key and deployment command snippets', async () => {
      (globalThis.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          success: true,
          data: {
            key: 'tek_runner-test-cluster_abcdef123456',
            keyPrefix: 'tek_runner-t',
            expiresAt: new Date(Date.now() + 30 * 86400000).toISOString(),
          },
        }),
      });

      const commands = await generateEnrollmentToken({
        name: 'runner-test-cluster',
        expiresInDays: 30,
        tags: ['vpc-test', 'high-concurrency'],
      });

      expect(commands.token).toContain('tek_runner-test-cluster_');
      expect(commands.keyPrefix).toBeDefined();

      // Docker command check
      expect(commands.dockerCommand).toContain('docker run -d');
      expect(commands.dockerCommand).toContain('--name security-lab-agent');
      expect(commands.dockerCommand).toContain(`AGENT_TOKEN="${commands.token}"`);

      // Kubernetes manifest check
      expect(commands.k8sSnippet).toContain('apiVersion: apps/v1');
      expect(commands.k8sSnippet).toContain('kind: Deployment');
      expect(commands.k8sSnippet).toContain('security-lab-agent');

      // Node CLI check
      expect(commands.nodeCliCommand).toContain('npx @security-lab/agent start');
      expect(commands.nodeCliCommand).toContain(`--token "${commands.token}"`);

      // systemd check
      expect(commands.systemdSnippet).toContain('[Unit]');
      expect(commands.systemdSnippet).toContain('[Service]');
      expect(commands.systemdSnippet).toContain('ExecStart=/usr/bin/security-lab-agent start');
    });
  });

  describe('Lifecycle Node Management Actions', () => {
    it('cancels job lease gracefully', async () => {
      (globalThis.fetch as any).mockResolvedValueOnce({ ok: true });
      const res = await cancelAgentJobLease('job-perf-8412');
      expect(res.success).toBe(true);
    });

    it('executes node drain action to finish existing leases and reject new jobs', async () => {
      (globalThis.fetch as any).mockResolvedValueOnce({ ok: true });
      const res = await drainAgent('agt-us-east-prod-01');
      expect(res.success).toBe(true);
      expect(res.message).toContain('draining');
    });

    it('revokes agent cryptographic identity', async () => {
      (globalThis.fetch as any).mockResolvedValueOnce({ ok: true });
      const res = await revokeAgent('agt-stale-node-offline', 'Operator decommissioned node');
      expect(res.success).toBe(true);
      expect(res.message).toContain('revoked');
    });
  });
});
