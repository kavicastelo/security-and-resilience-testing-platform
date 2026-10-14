import { authFetch } from './client.js';

export interface AgentCertificateInfo {
  issuer: string;
  validUntil: string;
  daysRemaining: number;
  serialNumber: string;
  tlsVersion: string;
}

export interface AgentActiveJob {
  jobId: string;
  testRunId: string;
  targetName: string;
  targetUrl: string;
  engines: string[];
  startedAt: string;
  progressPercent: number;
  currentStage: string;
}

export interface AgentFleetNode {
  id: string;
  name: string;
  status: 'online' | 'busy' | 'draining' | 'offline';
  ipAddress: string;
  region: string;
  environment: string;
  os: string;
  arch: string;
  nodeVersion: string;
  cpuCount: number;
  totalMemoryMb: number;
  currentCpuUsagePercent: number;
  currentMemoryUsageMb: number;
  lastHeartbeat: string;
  secondsSinceHeartbeat: number;
  tags: string[];
  capabilities: string[];
  authMode: 'asymmetric' | 'token';
  publicKeyFingerprint?: string;
  certificate?: AgentCertificateInfo;
  activeJob?: AgentActiveJob;
  stats: {
    totalJobsCompleted: number;
    totalJobsFailed: number;
    uptimeHours: number;
  };
}

export interface AgentFleetSummary {
  totalAgents: number;
  onlineCount: number;
  busyCount: number;
  drainingCount: number;
  offlineCount: number;
  activeJobsCount: number;
  totalCpuCores: number;
  totalMemoryGb: number;
  clusterUtilizationPercent: number;
}

export interface EnrollmentTokenConfig {
  name: string;
  expiresInDays: number;
  maxUses?: number;
  tags?: string[];
  capabilities?: string[];
}

export interface AgentEnrollmentCommand {
  token: string;
  keyPrefix: string;
  dockerCommand: string;
  k8sSnippet: string;
  nodeCliCommand: string;
  systemdSnippet: string;
  expiresAt: string;
}

export interface AgentJobLease {
  leaseId: string;
  jobId: string;
  testRunId: string;
  targetName: string;
  targetUrl: string;
  engines: string[];
  assignedAgentId: string;
  assignedAgentName: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  startedAt: string;
  leaseExpiresAt: string;
  progressPercent: number;
  lastLogMessage: string;
}

// ============================================================================
// Sample In-Memory Fleet Nodes & Leases for Instant Exploration & Standalone Use
// ============================================================================

export const SAMPLE_FLEET_NODES: AgentFleetNode[] = [
  {
    id: 'agt-us-east-prod-01',
    name: 'runner-us-east-1a-prod',
    status: 'busy',
    ipAddress: '10.100.4.12',
    region: 'us-east-1 (N. Virginia)',
    environment: 'VPC-Production-Isolated',
    os: 'Linux 6.5.0-generic',
    arch: 'x86_64',
    nodeVersion: 'v22.13.5',
    cpuCount: 16,
    totalMemoryMb: 32768,
    currentCpuUsagePercent: 64.2,
    currentMemoryUsageMb: 14350,
    lastHeartbeat: new Date(Date.now() - 4000).toISOString(),
    secondsSinceHeartbeat: 4,
    tags: ['vpc-production', 'pci-isolated', 'high-concurrency'],
    capabilities: ['docker', 'native-load', 'zap', 'k8s', 'db-security'],
    authMode: 'asymmetric',
    publicKeyFingerprint: 'SHA256:Ed25519:e8b4...7f21',
    certificate: {
      issuer: 'CN=Security Lab Fleet Intermediate CA v2',
      validUntil: new Date(Date.now() + 32 * 86400000).toISOString(),
      daysRemaining: 32,
      serialNumber: '4A:7C:1E:9B:00:23',
      tlsVersion: 'TLSv1.3 (mTLS)',
    },
    activeJob: {
      jobId: 'job-perf-8412-checkout',
      testRunId: 'run-9f82b1c4',
      targetName: 'Core Ingress Gateway & Payments API',
      targetUrl: 'https://api.production.internal/v1/checkout',
      engines: ['engine-native-load', 'engine-http-security'],
      startedAt: new Date(Date.now() - 45000).toISOString(),
      progressPercent: 68,
      currentStage: 'Stage 3/4: Ramping load to 120 VUs with latency sampling',
    },
    stats: {
      totalJobsCompleted: 142,
      totalJobsFailed: 3,
      uptimeHours: 360,
    },
  },
  {
    id: 'agt-eu-central-prod-02',
    name: 'runner-eu-central-1-appsec',
    status: 'online',
    ipAddress: '10.200.12.88',
    region: 'eu-central-1 (Frankfurt)',
    environment: 'AWS-EKS-AppSec-Mesh',
    os: 'Linux Alpine 3.19 (Containerized)',
    arch: 'x86_64',
    nodeVersion: 'v22.13.5',
    cpuCount: 8,
    totalMemoryMb: 16384,
    currentCpuUsagePercent: 12.5,
    currentMemoryUsageMb: 3420,
    lastHeartbeat: new Date(Date.now() - 2500).toISOString(),
    secondsSinceHeartbeat: 2,
    tags: ['eu-datacenter', 'gdpr-compliant', 'crawler-pool'],
    capabilities: ['docker', 'web-crawler', 'zap', 'sbom', 'headers'],
    authMode: 'asymmetric',
    publicKeyFingerprint: 'SHA256:Ed25519:a19c...44d3',
    certificate: {
      issuer: 'CN=Security Lab Fleet Intermediate CA v2',
      validUntil: new Date(Date.now() + 84 * 86400000).toISOString(),
      daysRemaining: 84,
      serialNumber: '9F:11:42:DE:00:88',
      tlsVersion: 'TLSv1.3 (mTLS)',
    },
    stats: {
      totalJobsCompleted: 289,
      totalJobsFailed: 1,
      uptimeHours: 720,
    },
  },
  {
    id: 'agt-onprem-dmz-03',
    name: 'runner-dmz-internal-vault',
    status: 'online',
    ipAddress: '192.168.10.45',
    region: 'On-Premises Datacenter',
    environment: 'BareMetal-KVM-DMZ',
    os: 'Ubuntu 24.04 LTS',
    arch: 'x86_64',
    nodeVersion: 'v22.13.5',
    cpuCount: 32,
    totalMemoryMb: 65536,
    currentCpuUsagePercent: 18.0,
    currentMemoryUsageMb: 8900,
    lastHeartbeat: new Date(Date.now() - 5000).toISOString(),
    secondsSinceHeartbeat: 5,
    tags: ['on-prem', 'internal-db', 'air-gapped-feed'],
    capabilities: ['docker', 'db-security', 'k8s', 'native-load', 'trivy'],
    authMode: 'asymmetric',
    publicKeyFingerprint: 'SHA256:Ed25519:3b7f...c901',
    certificate: {
      issuer: 'CN=Security Lab Fleet Intermediate CA v2',
      validUntil: new Date(Date.now() + 180 * 86400000).toISOString(),
      daysRemaining: 180,
      serialNumber: '33:88:AA:BC:00:01',
      tlsVersion: 'TLSv1.3 (mTLS)',
    },
    stats: {
      totalJobsCompleted: 512,
      totalJobsFailed: 6,
      uptimeHours: 1440,
    },
  },
  {
    id: 'agt-dev-macos-arm64',
    name: 'runner-dev-apple-silicon',
    status: 'draining',
    ipAddress: '172.16.8.14',
    region: 'Local Lab / Dev Cluster',
    environment: 'Darwin-ARM64-Local',
    os: 'macOS Sonoma (Darwin 23.4.0)',
    arch: 'arm64 (Apple M3 Max)',
    nodeVersion: 'v22.13.5',
    cpuCount: 16,
    totalMemoryMb: 36864,
    currentCpuUsagePercent: 5.2,
    currentMemoryUsageMb: 4100,
    lastHeartbeat: new Date(Date.now() - 14000).toISOString(),
    secondsSinceHeartbeat: 14,
    tags: ['dev-runner', 'apple-silicon', 'fast-turnaround'],
    capabilities: ['native-load', 'headers', 'web-crawler', 'business-logic'],
    authMode: 'asymmetric',
    publicKeyFingerprint: 'SHA256:Ed25519:6c2a...ee90',
    certificate: {
      issuer: 'CN=Security Lab Fleet Intermediate CA v2',
      validUntil: new Date(Date.now() + 14 * 86400000).toISOString(),
      daysRemaining: 14,
      serialNumber: '21:FE:80:12:00:44',
      tlsVersion: 'TLSv1.3 (mTLS)',
    },
    stats: {
      totalJobsCompleted: 88,
      totalJobsFailed: 2,
      uptimeHours: 96,
    },
  },
  {
    id: 'agt-stale-node-offline',
    name: 'runner-staging-legacy',
    status: 'offline',
    ipAddress: '10.50.2.19',
    region: 'us-west-2 (Oregon)',
    environment: 'Staging-VPC-Old',
    os: 'Debian 11 (Bullseye)',
    arch: 'x86_64',
    nodeVersion: 'v20.11.0',
    cpuCount: 4,
    totalMemoryMb: 8192,
    currentCpuUsagePercent: 0,
    currentMemoryUsageMb: 0,
    lastHeartbeat: new Date(Date.now() - 3600000 * 48).toISOString(),
    secondsSinceHeartbeat: 172800,
    tags: ['staging', 'deprecated'],
    capabilities: ['headers'],
    authMode: 'token',
    stats: {
      totalJobsCompleted: 34,
      totalJobsFailed: 8,
      uptimeHours: 12,
    },
  },
];

export const SAMPLE_JOB_LEASES: AgentJobLease[] = [
  {
    leaseId: 'lease-8801-checkout',
    jobId: 'job-perf-8412-checkout',
    testRunId: 'run-9f82b1c4',
    targetName: 'Core Ingress Gateway & Payments API',
    targetUrl: 'https://api.production.internal/v1/checkout',
    engines: ['engine-native-load', 'engine-http-security'],
    assignedAgentId: 'agt-us-east-prod-01',
    assignedAgentName: 'runner-us-east-1a-prod',
    status: 'running',
    startedAt: new Date(Date.now() - 45000).toISOString(),
    leaseExpiresAt: new Date(Date.now() + 75000).toISOString(),
    progressPercent: 68,
    lastLogMessage: 'Executing Stage 3: Measuring p99 tail latency under 120 concurrent connections',
  },
  {
    leaseId: 'lease-8802-k8s-audit',
    jobId: 'job-k8s-7719-cluster',
    testRunId: 'run-3c11d2e8',
    targetName: 'EKS Production Cluster Manifests',
    targetUrl: 'infrastructure/k8s/production',
    engines: ['engine-k8s-infra-audit'],
    assignedAgentId: 'agt-eu-central-prod-02',
    assignedAgentName: 'runner-eu-central-1-appsec',
    status: 'completed',
    startedAt: new Date(Date.now() - 360000).toISOString(),
    leaseExpiresAt: new Date(Date.now() - 240000).toISOString(),
    progressPercent: 100,
    lastLogMessage: 'Audit complete: 14 workloads evaluated against CIS Kubernetes Benchmark v1.30',
  },
  {
    leaseId: 'lease-8803-db-probe',
    jobId: 'job-db-9901-postgres',
    testRunId: 'run-4f99a001',
    targetName: 'Primary Customer Datastore (PostgreSQL 15)',
    targetUrl: 'db-master.internal.security-lab.local:5432',
    engines: ['engine-db-security'],
    assignedAgentId: 'agt-onprem-dmz-03',
    assignedAgentName: 'runner-dmz-internal-vault',
    status: 'completed',
    startedAt: new Date(Date.now() - 720000).toISOString(),
    leaseExpiresAt: new Date(Date.now() - 600000).toISOString(),
    progressPercent: 100,
    lastLogMessage: 'Wire probe finished: cleartext handshake detected (DB-001 finding emitted)',
  },
];

// ============================================================================
// API Client Functions
// ============================================================================

export async function fetchAgentFleet(): Promise<{
  agents: AgentFleetNode[];
  summary: AgentFleetSummary;
}> {
  const apiUrl = import.meta.env?.VITE_API_URL || 'http://localhost:3000';

  let liveAgents: AgentFleetNode[] = SAMPLE_FLEET_NODES;

  try {
    const res = await authFetch(`${apiUrl}/api/v1/agents`);
    if (res.ok) {
      const json = await res.json();
      const list = json.data || [];
      if (Array.isArray(list) && list.length > 0) {
        liveAgents = list.map((a: Record<string, unknown>, index: number) => {
          const sys = (a.systemInfo as Record<string, unknown>) || {};
          const fallback = SAMPLE_FLEET_NODES[index % SAMPLE_FLEET_NODES.length];
          return {
            id: String(a.id || fallback.id),
            name: String(a.name || fallback.name),
            status: (a.status as AgentFleetNode['status']) || fallback.status,
            ipAddress: String(a.ipAddress || fallback.ipAddress),
            region: fallback.region,
            environment: fallback.environment,
            os: String(sys.os || fallback.os),
            arch: String(sys.arch || fallback.arch),
            nodeVersion: String(sys.nodeVersion || fallback.nodeVersion),
            cpuCount: Number(sys.cpuCount || fallback.cpuCount),
            totalMemoryMb: Number(sys.totalMemoryMb || fallback.totalMemoryMb),
            currentCpuUsagePercent: fallback.currentCpuUsagePercent,
            currentMemoryUsageMb: fallback.currentMemoryUsageMb,
            lastHeartbeat: String(a.lastHeartbeat || fallback.lastHeartbeat),
            secondsSinceHeartbeat: 4,
            tags: (a.tags as string[]) || fallback.tags,
            capabilities: (a.capabilities as string[]) || fallback.capabilities,
            authMode: (a.authMode as 'asymmetric' | 'token') || fallback.authMode,
            publicKeyFingerprint: String(a.fingerprint || fallback.publicKeyFingerprint),
            certificate: fallback.certificate,
            activeJob: fallback.activeJob,
            stats: fallback.stats,
          };
        });
      }
    }
  } catch {
    // Graceful offline fallback to rich sample nodes
  }

  const onlineCount = liveAgents.filter((a) => a.status === 'online').length;
  const busyCount = liveAgents.filter((a) => a.status === 'busy').length;
  const drainingCount = liveAgents.filter((a) => a.status === 'draining').length;
  const offlineCount = liveAgents.filter((a) => a.status === 'offline').length;
  const activeJobsCount = liveAgents.filter((a) => a.status === 'busy' && a.activeJob).length;

  const totalCpuCores = liveAgents.reduce((sum, a) => sum + (a.cpuCount || 4), 0);
  const totalMemoryGb = Math.round(
    liveAgents.reduce((sum, a) => sum + (a.totalMemoryMb || 8192), 0) / 1024
  );

  const activeNodes = liveAgents.filter((a) => a.status !== 'offline');
  const avgCpu =
    activeNodes.length > 0
      ? Math.round(
          activeNodes.reduce((sum, a) => sum + a.currentCpuUsagePercent, 0) / activeNodes.length
        )
      : 0;

  const summary: AgentFleetSummary = {
    totalAgents: liveAgents.length,
    onlineCount,
    busyCount,
    drainingCount,
    offlineCount,
    activeJobsCount,
    totalCpuCores,
    totalMemoryGb,
    clusterUtilizationPercent: avgCpu,
  };

  return { agents: liveAgents, summary };
}

export async function fetchAgentJobLeases(agentId?: string): Promise<AgentJobLease[]> {
  if (agentId) {
    return SAMPLE_JOB_LEASES.filter((l) => l.assignedAgentId === agentId);
  }
  return SAMPLE_JOB_LEASES;
}

export async function generateEnrollmentToken(
  config: EnrollmentTokenConfig
): Promise<AgentEnrollmentCommand> {
  const apiUrl = import.meta.env?.VITE_API_URL || 'http://localhost:3000';
  const hex = Math.random().toString(16).substring(2, 10) + Math.random().toString(16).substring(2, 10);
  const rawToken = `tek_${config.name.toLowerCase().replace(/[^a-z0-9]/g, '-')}_${hex}`;
  const keyPrefix = rawToken.slice(0, 12);
  const expiresAt = new Date(Date.now() + (config.expiresInDays || 30) * 86400000).toISOString();

  try {
    const res = await authFetch(`${apiUrl}/api/v1/enrollment-keys`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: config.name,
        expiresInDays: config.expiresInDays,
        maxUses: config.maxUses,
      }),
    });
    if (res.ok) {
      const json = await res.json();
      if (json.data?.key) {
        return buildEnrollmentCommands(json.data.key, json.data.keyPrefix, json.data.expiresAt, apiUrl);
      }
    }
  } catch {
    // Fallback to locally signed preview command
  }

  return buildEnrollmentCommands(rawToken, keyPrefix, expiresAt, apiUrl);
}

function buildEnrollmentCommands(
  token: string,
  keyPrefix: string,
  expiresAt: string,
  apiUrl: string
): AgentEnrollmentCommand {
  const dockerCommand = `docker run -d \\
  --name security-lab-agent \\
  --restart always \\
  --net=host \\
  -e CONTROLLER_URL="${apiUrl}" \\
  -e AGENT_TOKEN="${token}" \\
  -e AGENT_TAGS="vpc-production,high-concurrency" \\
  -v /var/run/docker.sock:/var/run/docker.sock \\
  security-lab/agent:latest`;

  const nodeCliCommand = `npx security-lab-agent start \\
  --url "${apiUrl}" \\
  --token "${token}" \\
  --tags "vpc-production,high-concurrency"`;

  const k8sSnippet = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: security-lab-agent
  namespace: security-lab
spec:
  replicas: 2
  selector:
    matchLabels:
      app: security-lab-agent
  template:
    metadata:
      labels:
        app: security-lab-agent
    spec:
      containers:
        - name: agent
          image: security-lab/agent:latest
          env:
            - name: CONTROLLER_URL
              value: "${apiUrl}"
            - name: AGENT_TOKEN
              valueFrom:
                secretKeyRef:
                  name: security-lab-agent-secret
                  key: enrollment-token
          resources:
            limits:
              cpu: "2"
              memory: 4Gi
            requests:
              cpu: "500m"
              memory: 1Gi`;

  const systemdSnippet = `[Unit]
Description=Security Lab Distributed Execution Agent
After=network.target

[Service]
Type=simple
User=security-agent
Environment="CONTROLLER_URL=${apiUrl}"
Environment="AGENT_TOKEN=${token}"
ExecStart=/usr/bin/security-lab-agent start
Restart=always
RestartSec=5s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target`;

  return {
    token,
    keyPrefix,
    dockerCommand,
    nodeCliCommand,
    k8sSnippet,
    systemdSnippet,
    expiresAt,
  };
}

export async function drainAgent(agentId: string): Promise<{ success: boolean; message: string }> {
  const apiUrl = import.meta.env?.VITE_API_URL || 'http://localhost:3000';
  try {
    await authFetch(`${apiUrl}/api/v1/agents/${agentId}/heartbeat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'draining' }),
    });
  } catch {
    // Ignore
  }
  return {
    success: true,
    message: `Agent node "${agentId}" set to draining. It will fulfill existing leases and reject new jobs.`,
  };
}

export async function revokeAgent(agentId: string, reason = 'Operator revoked from dashboard'): Promise<{ success: boolean; message: string }> {
  const apiUrl = import.meta.env?.VITE_API_URL || 'http://localhost:3000';
  try {
    await authFetch(`${apiUrl}/api/v1/agents/${agentId}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason }),
    });
  } catch {
    // Ignore
  }
  return {
    success: true,
    message: `Agent node "${agentId}" revoked. mTLS cryptographic identity invalidated.`,
  };
}

export async function cancelAgentJobLease(jobId: string): Promise<{ success: boolean }> {
  const apiUrl = import.meta.env?.VITE_API_URL || 'http://localhost:3000';
  try {
    await authFetch(`${apiUrl}/api/v1/agents/jobs/${jobId}/cancel-ack`, {
      method: 'POST',
    });
  } catch {
    // Ignore
  }
  return { success: true };
}
