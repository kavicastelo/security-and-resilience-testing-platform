import React from 'react';
import {
  FileCode2,
  KeyRound,
  Grid,
  Zap,
  Gauge,
  Boxes,
  Radio,
  FileSpreadsheet,
  ShieldCheck,
  GitBranch,
  ArrowRight,
  Shield,
  Sparkles,
} from 'lucide-react';
import { useAppStore, NavTab } from '../store/useAppStore.js';

interface DomainMeta {
  title: string;
  subtitle: string;
  description: string;
  phaseId: string;
  phaseTitle: string;
  engineCapabilities: string[];
  icon: React.ElementType;
  quickActionTab: NavTab;
  quickActionLabel: string;
}

const domainRegistry: Partial<Record<NavTab, DomainMeta>> = {
  'api-security': {
    title: 'API Security & GraphQL Introspection',
    subtitle: 'Contract validation, circular query recursion & mutation fuzzing',
    description:
      'Native engine testing REST OpenAPI 3.0 schemas, deep GraphQL query recursion bounds, and field suggestion information leaks.',
    phaseId: 'Phase UI-06',
    phaseTitle: 'API & GraphQL Security Explorer',
    engineCapabilities: ['OpenAPI 3.0', 'GraphQL Introspection', 'Circular Depth Defense', 'Field Leaks'],
    icon: FileCode2,
    quickActionTab: 'targets',
    quickActionLabel: 'Configure API Targets',
  },
  'auth-vault': {
    title: 'Stateful Authentication & Secrets Vault',
    subtitle: 'Multi-step login flows, session cookies, and TOTP 2FA simulation',
    description:
      'Encrypted credential vault backed by AES-256-GCM envelope encryption. Handles OAuth2 code grants, automated TOTP passcode generation, and session re-authentication.',
    phaseId: 'Phase UI-07',
    phaseTitle: 'Stateful Auth & Secrets Vault',
    engineCapabilities: ['AES-256-GCM Vault', 'OAuth2 / OIDC Grants', 'RFC 6238 TOTP', 'Session Refresh'],
    icon: KeyRound,
    quickActionTab: 'targets',
    quickActionLabel: 'Manage Target Credentials',
  },
  'authz-matrix': {
    title: 'BOLA / BFLA Access Matrix & Access Graph',
    subtitle: 'Automated dual-identity access verification and IDOR prevention',
    description:
      'Tests whether User A can access User B resources (BOLA/IDOR) or whether unprivileged roles can execute administrative actions (BFLA/Privilege Escalation).',
    phaseId: 'Phase UI-08',
    phaseTitle: 'Access Matrix & BOLA Visualizer',
    engineCapabilities: ['Dual-Identity Probes', 'IDOR Detection', 'Cross-Tenant Leakage', 'BFLA Matrix'],
    icon: Grid,
    quickActionTab: 'findings',
    quickActionLabel: 'View Authorization Findings',
  },
  resilience: {
    title: 'Resilience Laboratory & Chaos MITM',
    subtitle: 'Controlled fault injection, packet drops, and business logic state machines',
    description:
      'Simulates upstream dependency brownouts, latency degradation, packet drops, and HTTP 5xx faults with automatic safety circuit-breaker trips.',
    phaseId: 'Phase UI-09',
    phaseTitle: 'Business Logic & Chaos Workbench',
    engineCapabilities: ['MITM Chaos Proxy', 'Latency Injection', 'Packet Drop Simulation', 'Circuit Breakers'],
    icon: Zap,
    quickActionTab: 'runs',
    quickActionLabel: 'Trigger Resilience Run',
  },
  performance: {
    title: 'Native Performance & Capacity Studio',
    subtitle: 'High-throughput load generation, percentile histograms & bottleneck detection',
    description:
      'Zero-dependency native load generator delivering thousands of requests per second. Generates p50, p90, p95, and p99 latency distributions and identifies saturation inflection points.',
    phaseId: 'Phase UI-10',
    phaseTitle: 'Performance & Capacity Studio',
    engineCapabilities: ['High-Concurrency VUs', 'p99 Latency Histograms', 'Saturation Knee', 'RPS Waterfalls'],
    icon: Gauge,
    quickActionTab: 'runs',
    quickActionLabel: 'Execute Load Benchmark',
  },
  'infra-supply-chain': {
    title: 'Kubernetes Audit & SBOM Supply Chain',
    subtitle: 'Pod Security Standards, CycloneDX/SPDX dependencies, and HTTP smuggling',
    description:
      'Scans Kubernetes workloads against Pod Security Standards, ingests CycloneDX SBOMs with real-time OSV/NVD CVE feeds, and verifies HTTP request smuggling desyncs.',
    phaseId: 'Phase UI-11',
    phaseTitle: 'Infra K8s & SBOM Supply Chain',
    engineCapabilities: ['K8s Pod Security', 'CycloneDX 1.5 SBOM', 'OSV / NVD CVE Feeds', 'Request Smuggling'],
    icon: Boxes,
    quickActionTab: 'findings',
    quickActionLabel: 'Inspect Supply Chain Risks',
  },
  'agent-fleet': {
    title: 'Distributed Enterprise Agent Fleet',
    subtitle: 'Private worker topology, mTLS attestation, and heartbeat telemetry',
    description:
      'Connects distributed test runners deployed inside customer private VPCs. Employs mutual TLS certificates, cryptographic attestation, and isolated job leasing.',
    phaseId: 'Phase UI-12',
    phaseTitle: 'Agent Fleet Command Console',
    engineCapabilities: ['mTLS Attestation', 'Ephemeral Job Leases', 'Heartbeat Telemetry', 'VPC Isolation'],
    icon: Radio,
    quickActionTab: 'management',
    quickActionLabel: 'View Active Agents',
  },
  compliance: {
    title: 'Compliance Center & Reporting Hub',
    subtitle: 'OWASP Top 10, ASVS 4.0, PCI-DSS scorecards, and zero-dependency PDF 1.4',
    description:
      'Maps test findings against industry security frameworks. Exports verifiable zero-dependency PDF 1.4 documents, interactive standalone HTML audits, and SARIF 2.1.0 scan feeds.',
    phaseId: 'Phase UI-15',
    phaseTitle: 'Compliance Center & Reports Hub',
    engineCapabilities: ['OWASP Top 10 2021', 'OWASP ASVS 4.0', 'PCI-DSS 4.0', 'PDF 1.4 / SARIF 2.1'],
    icon: FileSpreadsheet,
    quickActionTab: 'management',
    quickActionLabel: 'Generate Compliance Report',
  },
  governance: {
    title: 'Enterprise Workspaces, SSO & Governance',
    subtitle: 'SAML 2.0, OIDC, SCIM 2.0 directory sync, and Stripe usage metering',
    description:
      'Provides multi-tenant organization hierarchy, enterprise single sign-on with Okta/AzureAD, SCIM 2.0 automated provisioning, and tier quota guards.',
    phaseId: 'Phase UI-02',
    phaseTitle: 'Workspace RBAC & Governance',
    engineCapabilities: ['SAML 2.0 / OIDC SSO', 'SCIM 2.0 Sync', 'RBAC Role Hierarchy', 'Stripe Quota Guard'],
    icon: ShieldCheck,
    quickActionTab: 'management',
    quickActionLabel: 'Manage Organizations',
  },
  integrations: {
    title: 'CI/CD Integrations & Webhooks Hub',
    subtitle: 'HMAC-SHA256 signed webhooks, GitHub Actions, and Jira 2-way sync',
    description:
      'Dispatches cryptographically signed webhook notifications with exponential backoff queues. Syncs finding statuses bi-directionally with GitHub Issues and Jira.',
    phaseId: 'Phase UI-16',
    phaseTitle: 'CI/CD Integrations & Webhooks',
    engineCapabilities: ['HMAC-SHA256 Webhooks', 'Exponential Backoff', 'GitHub / Jira Sync', 'Action Workflows'],
    icon: GitBranch,
    quickActionTab: 'policies',
    quickActionLabel: 'Review Release Gates',
  },
};

export const DomainWorkbenchPlaceholder: React.FC<{ tab: NavTab }> = ({ tab }) => {
  const { setActiveTab } = useAppStore();
  const meta = domainRegistry[tab];

  if (!meta) return null;
  const Icon = meta.icon;

  return (
    <div className="space-y-6 animate-fade-in max-w-5xl mx-auto py-4">
      {/* Header Banner */}
      <div className="p-6 sm:p-8 rounded-2xl bg-card border border-border glass-panel relative overflow-hidden glow-blue">
        <div className="absolute right-0 top-0 translate-x-8 -translate-y-8 w-64 h-64 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 relative z-10">
          <div className="flex items-start space-x-4">
            <div className="p-3.5 rounded-2xl bg-primary/20 border border-primary/30 text-blue-400 shrink-0">
              <Icon className="w-8 h-8" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-xl sm:text-2xl font-bold text-foreground tracking-tight">
                  {meta.title}
                </h1>
                <span className="text-[10px] font-mono uppercase bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 rounded-full">
                  Backend Verified
                </span>
              </div>
              <p className="text-sm text-muted-foreground mt-1">{meta.subtitle}</p>
            </div>
          </div>

          <div className="flex items-center space-x-2 shrink-0">
            <button
              type="button"
              onClick={() => setActiveTab(meta.quickActionTab)}
              className="flex items-center space-x-2 px-4 py-2 rounded-xl bg-primary text-primary-foreground font-medium text-xs hover:bg-blue-600 transition-colors shadow-md"
            >
              <span>{meta.quickActionLabel}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Capabilities & Roadmap Notice */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Left 2 Cols: Capabilities */}
        <div className="md:col-span-2 p-6 rounded-2xl bg-card border border-border/80 glass-card space-y-4">
          <div className="flex items-center space-x-2 text-foreground font-semibold text-sm">
            <Shield className="w-4 h-4 text-blue-400" />
            <span>Verified Engine Capabilities</span>
          </div>
          <p className="text-xs text-muted-foreground leading-relaxed">{meta.description}</p>

          <div className="pt-2">
            <div className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground mb-2">
              Underlying Verified Subsystems
            </div>
            <div className="flex flex-wrap gap-2">
              {meta.engineCapabilities.map((cap) => (
                <span
                  key={cap}
                  className="px-2.5 py-1 rounded-lg text-xs font-mono bg-accent/60 text-blue-300 border border-border"
                >
                  ✓ {cap}
                </span>
              ))}
            </div>
          </div>
        </div>

        {/* Right Col: Roadmap Phase Notice */}
        <div className="p-6 rounded-2xl bg-card border border-border/80 glass-card space-y-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center space-x-2 text-foreground font-semibold text-sm">
              <Sparkles className="w-4 h-4 text-purple-400" />
              <span>UI Modernization Phase</span>
            </div>
            <p className="text-xs text-muted-foreground mt-2">
              This domain is scheduled for dedicated interactive visual workbench implementation under:
            </p>
            <div className="mt-3 p-3 rounded-xl bg-accent/40 border border-border text-xs font-mono text-purple-300">
              <div className="font-bold">{meta.phaseId}</div>
              <div className="text-[11px] text-muted-foreground">{meta.phaseTitle}</div>
            </div>
          </div>

          <div className="pt-2">
            <button
              type="button"
              onClick={() => setActiveTab('overview')}
              className="w-full flex items-center justify-center space-x-1.5 px-3 py-2 rounded-xl text-xs font-medium bg-accent/60 hover:bg-accent text-muted-foreground hover:text-foreground transition-colors border border-border"
            >
              <span>Return to Overview</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
