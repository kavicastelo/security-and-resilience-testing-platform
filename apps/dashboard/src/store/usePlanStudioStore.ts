import { create } from 'zustand';

export type EngineCategory = 'web' | 'api' | 'auth' | 'resilience' | 'infra';
export type EngineComplexity = 'low' | 'medium' | 'high';

export interface EngineDescriptor {
  id: string;
  name: string;
  category: EngineCategory;
  complexity: EngineComplexity;
  disruptive: boolean;
  description: string;
  defaultOptions: Record<string, any>;
}

export interface PlanStep {
  id: string;
  engineId: string;
  name: string;
  category: EngineCategory;
  disruptive: boolean;
  enabled: boolean;
  options: Record<string, any>;
}

export interface PlanPreset {
  id: string;
  name: string;
  description: string;
  category: EngineCategory;
  disruptive: boolean;
  engineIds: string[];
}

export const REGISTERED_ENGINES: EngineDescriptor[] = [
  {
    id: 'engine-native-headers',
    name: 'Security Headers Analyzer',
    category: 'web',
    complexity: 'low',
    disruptive: false,
    description: 'Inspects strict transport security (HSTS), CSP, X-Frame-Options, and referrer policies.',
    defaultOptions: { checkHsts: true, checkCsp: true, checkXFrame: true },
  },
  {
    id: 'engine-native-tls',
    name: 'TLS & Cipher Suite Auditor',
    category: 'web',
    complexity: 'low',
    disruptive: false,
    description: 'Validates certificate validity, deprecation of SSLv3/TLS 1.0/1.1, and weak cipher suites.',
    defaultOptions: { minTlsVersion: '1.2', checkRevocation: true },
  },
  {
    id: 'engine-native-cors',
    name: 'CORS Misconfiguration Checker',
    category: 'web',
    complexity: 'low',
    disruptive: false,
    description: 'Evaluates wildcard Access-Control-Allow-Origin with credentials reflections and null origins.',
    defaultOptions: { testNullOrigin: true, testArbitraryOrigin: true },
  },
  {
    id: 'engine-native-crawler',
    name: 'DAST Attack Surface Spider',
    category: 'web',
    complexity: 'medium',
    disruptive: false,
    description: 'Deep recursive link extractor and form explorer mapping endpoints and input vectors.',
    defaultOptions: { maxDepth: 3, maxEndpoints: 50, crawlForms: true },
  },
  {
    id: 'engine-native-auth',
    name: 'Stateful Auth & MFA Flow',
    category: 'auth',
    complexity: 'medium',
    disruptive: false,
    description: 'Authenticates with session cookies, OAuth2 client tokens, or TOTP MFA before downstream tests.',
    defaultOptions: { authType: 'OAUTH2', tokenEndpoint: '/oauth/token' },
  },
  {
    id: 'engine-native-fuzzer',
    name: 'Injection & Fuzzing Engine',
    category: 'api',
    complexity: 'high',
    disruptive: true,
    description: 'Fuzzes parameters with SQLi, command injection, and path traversal payloads.',
    defaultOptions: { attackTypes: ['sqli', 'cmdi', 'traversal'], wordlistSize: 'standard', delayMs: 50 },
  },
  {
    id: 'engine-native-graphql',
    name: 'GraphQL Security Auditor',
    category: 'api',
    complexity: 'medium',
    disruptive: false,
    description: 'Checks introspection exposure, query depth ceilings, circular aliases, and batch attacks.',
    defaultOptions: { maxDepth: 6, testIntrospection: true, testBatching: true },
  },
  {
    id: 'engine-native-authz-matrix',
    name: 'RBAC & BOLA Access Matrix',
    category: 'auth',
    complexity: 'high',
    disruptive: true,
    description: 'Replays high-privilege administrative requests with low-privilege tokens to detect BOLA/BFLA.',
    defaultOptions: { matrixRoles: ['admin', 'engineer', 'auditor'], detectBola: true },
  },
  {
    id: 'engine-native-business-logic',
    name: 'Business Logic & Race Prober',
    category: 'api',
    complexity: 'high',
    disruptive: true,
    description: 'Tests state-machine order bypasses, coupon stacking, and concurrent multi-flight requests.',
    defaultOptions: { concurrentFlights: 5, testNegativeValues: true },
  },
  {
    id: 'engine-native-resilience',
    name: 'Rate-Limit & Circuit Breaker Prober',
    category: 'resilience',
    complexity: 'medium',
    disruptive: true,
    description: 'Verifies 429 Too Many Requests response behavior and sliding 5xx circuit-breaker cooldowns.',
    defaultOptions: { burstRps: 150, expectedStatusCode: 429 },
  },
  {
    id: 'engine-worker-k6',
    name: 'Distributed Load Generator (k6)',
    category: 'resilience',
    complexity: 'high',
    disruptive: true,
    description: 'Executes high-concurrency Virtual User (VU) stress load tests measuring P95/P99 latency SLAs.',
    defaultOptions: { vus: 10, durationSec: 15, maxP95Ms: 500 },
  },
  {
    id: 'engine-native-chaos',
    name: 'Chaos MITM & Network Faults',
    category: 'resilience',
    complexity: 'high',
    disruptive: true,
    description: 'Simulates socket drops, packet corruption, jitter latency, and partial response aborts.',
    defaultOptions: { latencyJitterMs: 200, packetDropRate: 0.1 },
  },
  {
    id: 'engine-native-smuggling',
    name: 'HTTP Request Smuggling (CL.TE/TE.CL)',
    category: 'resilience',
    complexity: 'high',
    disruptive: true,
    description: 'Dispatches desync canary probes to identify reverse proxy desynchronization flaws.',
    defaultOptions: { probeVariants: ['CL.TE', 'TE.CL'], timeoutMs: 5000 },
  },
  {
    id: 'engine-db-security',
    name: 'Database Security & Protocol Audit',
    category: 'infra',
    complexity: 'medium',
    disruptive: false,
    description: 'Direct protocol verification for Redis, PostgreSQL, and MongoDB authorization boundaries.',
    defaultOptions: { dbType: 'REDIS', checkAuth: true },
  },
  {
    id: 'engine-sbom-supply-chain',
    name: 'SBOM & Dependency Vulnerability Analyzer',
    category: 'infra',
    complexity: 'medium',
    disruptive: false,
    description: 'Scans software bill of materials (CycloneDX / SPDX) against known CVEs and license violations.',
    defaultOptions: { failOnSeverity: 'high', checkLicenses: true },
  },
  {
    id: 'engine-k8s-infra',
    name: 'Kubernetes Cluster & Pod Security Audit',
    category: 'infra',
    complexity: 'high',
    disruptive: false,
    description: 'Audits pod security admission, hostPID/hostNetwork leaks, and excessive RBAC permissions.',
    defaultOptions: { namespace: 'default', enforcePodStandards: true },
  },
  {
    id: 'engine-container-trivy',
    name: 'Container Image Security (Trivy)',
    category: 'infra',
    complexity: 'medium',
    disruptive: false,
    description: 'Inspects base container layers for critical vulnerabilities, misconfigurations, and leaked secrets.',
    defaultOptions: { scanSecrets: true, severityThreshold: 'HIGH,CRITICAL' },
  },
  {
    id: 'engine-container-zap',
    name: 'OWASP ZAP Dynamic Scanner',
    category: 'web',
    complexity: 'high',
    disruptive: true,
    description: 'Automated dynamic application security scanner exploring web vulnerabilities.',
    defaultOptions: { scanPolicy: 'Standard', spiderFirst: true },
  },
];

export const CURATED_PRESETS: PlanPreset[] = [
  {
    id: 'quick-web',
    name: 'Quick Web & TLS Hygiene',
    description: 'Rapid baseline audit inspecting HTTP headers, TLS certificate expiry, and CORS permissions.',
    category: 'web',
    disruptive: false,
    engineIds: ['engine-native-headers', 'engine-native-tls', 'engine-native-cors'],
  },
  {
    id: 'api-bola',
    name: 'Full API, GraphQL & BOLA Penetration',
    description: 'Comprehensive API security assessment testing broken object level auth, injection, and GraphQL depth.',
    category: 'api',
    disruptive: true,
    engineIds: ['engine-native-auth', 'engine-native-graphql', 'engine-native-authz-matrix', 'engine-native-fuzzer'],
  },
  {
    id: 'resilience-chaos',
    name: 'Resilience & Chaos Laboratory',
    description: 'High-concurrency stress test combined with simulated network latency and proxy desync probes.',
    category: 'resilience',
    disruptive: true,
    engineIds: ['engine-worker-k6', 'engine-native-resilience', 'engine-native-chaos', 'engine-native-smuggling'],
  },
  {
    id: 'supply-chain-infra',
    name: 'Supply Chain & Container Security',
    description: 'Inspects software dependencies, SBOM vulnerabilities, container images, and cluster policies.',
    category: 'infra',
    disruptive: false,
    engineIds: ['engine-sbom-supply-chain', 'engine-container-trivy', 'engine-k8s-infra'],
  },
  {
    id: 'production-safe',
    name: 'Production-Safe Non-Disruptive Check',
    description: 'Passive probing strictly guaranteed not to degrade application performance or mutate data.',
    category: 'web',
    disruptive: false,
    engineIds: ['engine-native-headers', 'engine-native-tls', 'engine-native-cors', 'engine-native-crawler'],
  },
];

export interface PlanStudioState {
  isOpen: boolean;
  setIsOpen: (open: boolean) => void;
  planName: string;
  setPlanName: (name: string) => void;
  planDescription: string;
  setPlanDescription: (desc: string) => void;
  selectedTargetId: string;
  setSelectedTargetId: (targetId: string) => void;
  targetEndpoint: string;
  setTargetEndpoint: (endpoint: string) => void;
  steps: PlanStep[];
  activeConfigStepId: string | null;
  setActiveConfigStepId: (stepId: string | null) => void;
  activePresetId: string | null;
  hazardAcknowledged: boolean;
  setHazardAcknowledged: (ack: boolean) => void;
  viewMode: 'visual' | 'yaml';
  setViewMode: (mode: 'visual' | 'yaml') => void;

  // Step Actions
  addStep: (engineId: string) => void;
  removeStep: (stepId: string) => void;
  reorderStep: (fromIndex: number, toIndex: number) => void;
  toggleStep: (stepId: string) => void;
  updateStepOptions: (stepId: string, options: Record<string, any>) => void;
  applyPreset: (presetId: string) => void;
  resetPlan: () => void;
  exportToYaml: () => string;
}

export const usePlanStudioStore = create<PlanStudioState>((set, get) => ({
  isOpen: false,
  setIsOpen: (open) => set({ isOpen: open }),
  planName: 'Enterprise Security & Resilience Pipeline',
  setPlanName: (planName) => set({ planName }),
  planDescription: 'Multi-stage defense in depth assessment across web, API, and resilience boundaries.',
  setPlanDescription: (planDescription) => set({ planDescription }),
  selectedTargetId: '',
  setSelectedTargetId: (selectedTargetId) => set({ selectedTargetId }),
  targetEndpoint: '/',
  setTargetEndpoint: (targetEndpoint) => set({ targetEndpoint }),
  steps: [
    {
      id: 'step-1',
      engineId: 'engine-native-headers',
      name: 'Security Headers Analyzer',
      category: 'web',
      disruptive: false,
      enabled: true,
      options: { checkHsts: true, checkCsp: true, checkXFrame: true },
    },
    {
      id: 'step-2',
      engineId: 'engine-native-tls',
      name: 'TLS & Cipher Suite Auditor',
      category: 'web',
      disruptive: false,
      enabled: true,
      options: { minTlsVersion: '1.2', checkRevocation: true },
    },
    {
      id: 'step-3',
      engineId: 'engine-native-cors',
      name: 'CORS Misconfiguration Checker',
      category: 'web',
      disruptive: false,
      enabled: true,
      options: { testNullOrigin: true, testArbitraryOrigin: true },
    },
  ],
  activeConfigStepId: null,
  setActiveConfigStepId: (stepId) => set({ activeConfigStepId: stepId }),
  activePresetId: 'quick-web',
  hazardAcknowledged: false,
  setHazardAcknowledged: (hazardAcknowledged) => set({ hazardAcknowledged }),
  viewMode: 'visual',
  setViewMode: (viewMode) => set({ viewMode }),

  addStep: (engineId) => {
    const descriptor = REGISTERED_ENGINES.find((e) => e.id === engineId);
    if (!descriptor) return;

    const newStep: PlanStep = {
      id: `step-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      engineId: descriptor.id,
      name: descriptor.name,
      category: descriptor.category,
      disruptive: descriptor.disruptive,
      enabled: true,
      options: { ...descriptor.defaultOptions },
    };

    set((state) => ({
      steps: [...state.steps, newStep],
      activePresetId: null,
    }));
  },

  removeStep: (stepId) => {
    set((state) => ({
      steps: state.steps.filter((s) => s.id !== stepId),
      activeConfigStepId: state.activeConfigStepId === stepId ? null : state.activeConfigStepId,
      activePresetId: null,
    }));
  },

  reorderStep: (fromIndex, toIndex) => {
    set((state) => {
      if (fromIndex < 0 || fromIndex >= state.steps.length) return state;
      if (toIndex < 0 || toIndex >= state.steps.length) return state;
      const updated = [...state.steps];
      const [moved] = updated.splice(fromIndex, 1);
      updated.splice(toIndex, 0, moved);
      return { steps: updated, activePresetId: null };
    });
  },

  toggleStep: (stepId) => {
    set((state) => ({
      steps: state.steps.map((s) => (s.id === stepId ? { ...s, enabled: !s.enabled } : s)),
    }));
  },

  updateStepOptions: (stepId, options) => {
    set((state) => ({
      steps: state.steps.map((s) =>
        s.id === stepId ? { ...s, options: { ...s.options, ...options } } : s,
      ),
    }));
  },

  applyPreset: (presetId) => {
    const preset = CURATED_PRESETS.find((p) => p.id === presetId);
    if (!preset) return;

    const newSteps: PlanStep[] = preset.engineIds
      .map((engineId, idx) => {
        const desc = REGISTERED_ENGINES.find((e) => e.id === engineId);
        if (!desc) return null;
        return {
          id: `step-${idx + 1}-${Date.now().toString().slice(-4)}`,
          engineId: desc.id,
          name: desc.name,
          category: desc.category,
          disruptive: desc.disruptive,
          enabled: true,
          options: { ...desc.defaultOptions },
        };
      })
      .filter((s): s is PlanStep => s !== null);

    set({
      planName: preset.name,
      planDescription: preset.description,
      steps: newSteps,
      activePresetId: preset.id,
      activeConfigStepId: null,
      hazardAcknowledged: false,
    });
  },

  resetPlan: () => {
    get().applyPreset('quick-web');
  },

  exportToYaml: () => {
    const state = get();
    const activeSteps = state.steps.filter((s) => s.enabled);

    let yaml = `# Security Lab Declarative Test Plan V2\n`;
    yaml += `version: '2.0'\n`;
    yaml += `name: '${state.planName.replace(/'/g, "''")}'\n`;
    yaml += `description: '${state.planDescription.replace(/'/g, "''")}'\n`;
    yaml += `target:\n`;
    yaml += `  targetId: '${state.selectedTargetId || 'TARGET_ID_PLACEHOLDER'}'\n`;
    yaml += `  endpoint: '${state.targetEndpoint || '/'}'\n`;
    yaml += `pipeline:\n`;

    activeSteps.forEach((step, index) => {
      yaml += `  - stage: ${index + 1}\n`;
      yaml += `    engineId: '${step.engineId}'\n`;
      yaml += `    name: '${step.name.replace(/'/g, "''")}'\n`;
      yaml += `    disruptive: ${step.disruptive}\n`;
      yaml += `    options:\n`;
      for (const [key, value] of Object.entries(step.options)) {
        if (typeof value === 'object' && value !== null) {
          yaml += `      ${key}: ${JSON.stringify(value)}\n`;
        } else {
          yaml += `      ${key}: ${value}\n`;
        }
      }
    });

    return yaml;
  },
}));
