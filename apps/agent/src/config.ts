import os from 'node:os';

export interface AgentConfig {
  controllerUrl: string;
  agentId?: string;
  agentToken?: string;
  tenantId?: string;
  name: string;
  tags: string[];
  capabilities: string[];
  pollIntervalMs: number;
  heartbeatIntervalMs: number;
}

export function loadAgentConfig(overrides: Partial<AgentConfig> = {}): AgentConfig {
  const env = process.env;

  const defaultCapabilities = [
    'engine-native-headers',
    'engine-native-cors',
    'engine-native-tls',
    'engine-native-auth',
    'engine-native-resilience',
    'declarative',
    'engine-zap',
    'engine-trivy',
    'engine-k6',
  ];

  const rawTags = overrides.tags || env.AGENT_TAGS || env.SECURITY_LAB_AGENT_TAGS;
  const tags = Array.isArray(rawTags)
    ? rawTags
    : rawTags
      ? rawTags.split(',').map((t) => t.trim())
      : ['default', 'local'];

  const rawCaps = overrides.capabilities || env.AGENT_CAPABILITIES || env.SECURITY_LAB_AGENT_CAPABILITIES;
  const capabilities = Array.isArray(rawCaps)
    ? rawCaps
    : rawCaps
      ? rawCaps.split(',').map((c) => c.trim())
      : defaultCapabilities;

  const rawPoll = env.POLL_INTERVAL_MS || env.SECURITY_LAB_AGENT_POLL_INTERVAL_MS;
  const rawHeartbeat = env.HEARTBEAT_INTERVAL_MS || env.SECURITY_LAB_AGENT_HEARTBEAT_INTERVAL_MS;

  return {
    controllerUrl: (
      overrides.controllerUrl ||
      env.CONTROLLER_URL ||
      env.SECURITY_LAB_CONTROLLER_URL ||
      'http://localhost:4000'
    ).replace(/\/+$/, ''),
    agentId: overrides.agentId || env.AGENT_ID || env.SECURITY_LAB_AGENT_ID,
    agentToken: overrides.agentToken || env.AGENT_TOKEN || env.SECURITY_LAB_AGENT_TOKEN,
    tenantId: overrides.tenantId || env.TENANT_ID || env.SECURITY_LAB_TENANT_ID,
    name:
      overrides.name ||
      env.AGENT_NAME ||
      env.SECURITY_LAB_AGENT_NAME ||
      `agent-${os.hostname().toLowerCase().replace(/[^a-z0-9-]/g, '-')}`,
    tags,
    capabilities,
    pollIntervalMs: overrides.pollIntervalMs || (rawPoll ? parseInt(rawPoll, 10) : 2000),
    heartbeatIntervalMs:
      overrides.heartbeatIntervalMs || (rawHeartbeat ? parseInt(rawHeartbeat, 10) : 10000),
  };
}
