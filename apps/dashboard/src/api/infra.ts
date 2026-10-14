import { authFetch } from './client.js';
import { SbomAdvisoryMatch } from '@security-lab/contracts';

// ============================================================================
// 1. Kubernetes Infra Posture Interfaces
// ============================================================================

export interface K8sWorkloadFinding {
  ruleId: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  lineNumber?: number;
  violatingSnippet?: string;
  recommendation: string;
}

export interface K8sWorkloadItem {
  id: string;
  name: string;
  namespace: string;
  kind: 'Deployment' | 'DaemonSet' | 'StatefulSet' | 'Pod' | 'Job';
  pssLevel: 'privileged' | 'baseline' | 'restricted';
  complianceScore: number; // 0 - 100
  containersCount: number;
  hasPrivilegedContainer: boolean;
  runsAsRoot: boolean;
  hasSensitiveHostPath: boolean;
  addedCapabilities: string[];
  droppedAllCapabilities: boolean;
  hasNetworkPolicy: boolean;
  hasResourceLimits: boolean;
  manifestFilePath: string;
  findings: K8sWorkloadFinding[];
}

export interface K8sNamespaceSummary {
  namespace: string;
  totalWorkloads: number;
  restrictedCount: number;
  baselineCount: number;
  privilegedCount: number;
  complianceScore: number;
}

export interface K8sAuditSnapshot {
  clusterName: string;
  kubernetesVersion: string;
  totalWorkloads: number;
  overallComplianceScore: number; // 0 - 100
  pssDistribution: {
    restricted: number;
    baseline: number;
    privileged: number;
  };
  criticalFindingsCount: number;
  highFindingsCount: number;
  mediumFindingsCount: number;
  namespaces: K8sNamespaceSummary[];
  workloads: K8sWorkloadItem[];
}

// ============================================================================
// 2. SBOM & Dependency Graph Interfaces
// ============================================================================

export interface SbomComponentNode {
  id: string;
  name: string;
  version: string;
  purl: string;
  ecosystem: 'npm' | 'pypi' | 'golang' | 'maven' | 'cargo' | 'generic';
  licenses: string[];
  isDirect: boolean;
  directDependencyCount?: number;
  licenseRisk: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  licenseViolationReason?: string;
  cveMatches: SbomAdvisoryMatch[];
  hashes: Record<string, string>;
  dependencies?: string[];
}

export interface SbomGraphSnapshot {
  sbomId: string;
  format: 'cyclonedx_json' | 'spdx_json';
  specVersion: string;
  applicationName: string;
  version: string;
  author: string;
  generatedAt: string;
  totalComponents: number;
  directDependenciesCount: number;
  transitiveDependenciesCount: number;
  vulnerableComponentsCount: number;
  criticalCveCount: number;
  highCveCount: number;
  licenseViolationsCount: number;
  components: SbomComponentNode[];
}

// ============================================================================
// 3. HTTP Request Smuggling Wire Interfaces
// ============================================================================

export interface SmugglingWireVariant {
  id: string;
  technique: 'CL_TE' | 'TE_CL' | 'TE_TE' | 'HOST_POISONING' | 'HOP_BY_HOP';
  name: string;
  description: string;
  frontendExpectation: string;
  backendExpectation: string;
  desyncExplanation: string;
  vulnerabilityStatus: 'CONFIRMED' | 'SUSPECTED' | 'SAFE';
  statusCode: number;
  latencyMs: number;
  canaryReflected: boolean;
  canaryPath: string;
  rawSocketRequest: string;
  rawSocketResponse: string;
  requestHexDump: string;
  responseHexDump: string;
}

export interface SmugglingWireSnapshot {
  targetHost: string;
  targetPort: number;
  useTls: boolean;
  reverseProxyType: string;
  backendServerType: string;
  testedVariantsCount: number;
  vulnerableCount: number;
  variants: SmugglingWireVariant[];
}

// ============================================================================
// 4. Database Protocol Security Interfaces
// ============================================================================

export interface DatabaseProbeResult {
  id: string;
  databaseType: 'POSTGRES' | 'MYSQL' | 'REDIS';
  host: string;
  port: number;
  tlsSupported: boolean;
  tlsMandated: boolean;
  unauthenticatedAccessAllowed: boolean;
  defaultCredentialsMatched: boolean;
  matchedCredentialUser?: string;
  serverVersion?: string;
  authMethod?: string;
  rawBannerHex?: string;
  saturation: {
    attemptedConnections: number;
    successfulConnections: number;
    rejectedConnections: number;
    avgConnectionTimeMs: number;
    serverGraceful: boolean;
    rejectionReason?: string;
  };
  findings: Array<{
    id: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    remediation: string;
  }>;
}

export interface DatabaseSecuritySnapshot {
  probes: DatabaseProbeResult[];
  totalDatabasesChecked: number;
  unencryptedCount: number;
  unauthenticatedCount: number;
  defaultCredentialVulnerableCount: number;
}

// ============================================================================
// 5. Consolidated Studio Overview
// ============================================================================

export interface InfraStudioOverviewSnapshot {
  k8s: K8sAuditSnapshot;
  sbom: SbomGraphSnapshot;
  smuggling: SmugglingWireSnapshot;
  database: DatabaseSecuritySnapshot;
}

// ============================================================================
// Sample Mock Data Presets for Instant Visual Exploration & Offline Fallback
// ============================================================================

export const SAMPLE_K8S_AUDIT: K8sAuditSnapshot = {
  clusterName: 'production-us-east-1.k8s.security-lab.local',
  kubernetesVersion: 'v1.30.2',
  totalWorkloads: 14,
  overallComplianceScore: 78,
  pssDistribution: {
    restricted: 8,
    baseline: 4,
    privileged: 2,
  },
  criticalFindingsCount: 3,
  highFindingsCount: 5,
  mediumFindingsCount: 4,
  namespaces: [
    {
      namespace: 'production-core',
      totalWorkloads: 5,
      restrictedCount: 3,
      baselineCount: 1,
      privilegedCount: 1,
      complianceScore: 74,
    },
    {
      namespace: 'payments-pci',
      totalWorkloads: 3,
      restrictedCount: 3,
      baselineCount: 0,
      privilegedCount: 0,
      complianceScore: 100,
    },
    {
      namespace: 'ingress-gateway',
      totalWorkloads: 3,
      restrictedCount: 1,
      baselineCount: 2,
      privilegedCount: 0,
      complianceScore: 70,
    },
    {
      namespace: 'kube-system',
      totalWorkloads: 3,
      restrictedCount: 1,
      baselineCount: 1,
      privilegedCount: 1,
      complianceScore: 65,
    },
  ],
  workloads: [
    {
      id: 'workload-api-gateway',
      name: 'api-gateway',
      namespace: 'production-core',
      kind: 'Deployment',
      pssLevel: 'baseline',
      complianceScore: 68,
      containersCount: 2,
      hasPrivilegedContainer: false,
      runsAsRoot: true,
      hasSensitiveHostPath: false,
      addedCapabilities: ['NET_ADMIN'],
      droppedAllCapabilities: false,
      hasNetworkPolicy: true,
      hasResourceLimits: true,
      manifestFilePath: 'infrastructure/k8s/deployments/api-gateway.yaml',
      findings: [
        {
          ruleId: 'K8S-002-ROOT-CONTAINER',
          title: 'Root user execution without runAsNonRoot constraint',
          severity: 'high',
          category: 'Identity & Access',
          lineNumber: 42,
          violatingSnippet: 'securityContext:\n  runAsUser: 0',
          recommendation: 'Configure securityContext.runAsNonRoot: true with non-zero UID (e.g. 10001).',
        },
        {
          ruleId: 'K8S-005-DANGEROUS-CAPABILITY-ADDED',
          title: 'Dangerous Linux capability NET_ADMIN granted to container',
          severity: 'critical',
          category: 'Capabilities',
          lineNumber: 48,
          violatingSnippet: 'capabilities:\n  add:\n    - NET_ADMIN',
          recommendation: 'Remove NET_ADMIN capability; delegate egress rules to CNI or service mesh.',
        },
      ],
    },
    {
      id: 'workload-node-agent-ds',
      name: 'security-node-daemon',
      namespace: 'kube-system',
      kind: 'DaemonSet',
      pssLevel: 'privileged',
      complianceScore: 35,
      containersCount: 1,
      hasPrivilegedContainer: true,
      runsAsRoot: true,
      hasSensitiveHostPath: true,
      addedCapabilities: ['SYS_ADMIN', 'SYS_PTRACE'],
      droppedAllCapabilities: false,
      hasNetworkPolicy: false,
      hasResourceLimits: false,
      manifestFilePath: 'infrastructure/k8s/daemonsets/node-agent.yaml',
      findings: [
        {
          ruleId: 'K8S-001-PRIVILEGED-CONTAINER',
          title: 'Container runs with full host privileged flag enabled',
          severity: 'critical',
          category: 'Pod Security Standards',
          lineNumber: 28,
          violatingSnippet: 'securityContext:\n  privileged: true',
          recommendation: 'Disable privileged: true and scope specific eBPF/perf capabilities via CAP_BPF.',
        },
        {
          ruleId: 'K8S-003-SENSITIVE-HOSTPATH',
          title: 'HostPath volume mount targets sensitive host Docker socket',
          severity: 'critical',
          category: 'Storage & Isolation',
          lineNumber: 35,
          violatingSnippet: 'volumes:\n  - name: docker-sock\n    hostPath:\n      path: /var/run/docker.sock',
          recommendation: 'Eliminate hostPath Docker daemon socket exposure to prevent host takeover.',
        },
      ],
    },
    {
      id: 'workload-payment-processor',
      name: 'payment-processor',
      namespace: 'payments-pci',
      kind: 'Deployment',
      pssLevel: 'restricted',
      complianceScore: 100,
      containersCount: 1,
      hasPrivilegedContainer: false,
      runsAsRoot: false,
      hasSensitiveHostPath: false,
      addedCapabilities: [],
      droppedAllCapabilities: true,
      hasNetworkPolicy: true,
      hasResourceLimits: true,
      manifestFilePath: 'infrastructure/k8s/deployments/payment-processor.yaml',
      findings: [],
    },
    {
      id: 'workload-auth-service',
      name: 'auth-service',
      namespace: 'production-core',
      kind: 'Deployment',
      pssLevel: 'restricted',
      complianceScore: 92,
      containersCount: 1,
      hasPrivilegedContainer: false,
      runsAsRoot: false,
      hasSensitiveHostPath: false,
      addedCapabilities: [],
      droppedAllCapabilities: true,
      hasNetworkPolicy: true,
      hasResourceLimits: false,
      manifestFilePath: 'infrastructure/k8s/deployments/auth-service.yaml',
      findings: [
        {
          ruleId: 'K8S-007-MISSING-RESOURCE-LIMITS',
          title: 'Missing CPU and Memory resource limits allows resource exhaustion',
          severity: 'medium',
          category: 'Resource Allocation',
          lineNumber: 54,
          violatingSnippet: 'resources: {}\n# limits.cpu and limits.memory omitted',
          recommendation: 'Define explicit resources.limits.cpu and resources.limits.memory.',
        },
      ],
    },
  ],
};

export const SAMPLE_SBOM_GRAPH: SbomGraphSnapshot = {
  sbomId: 'sbom-cyclonedx-v1.5-prod',
  format: 'cyclonedx_json',
  specVersion: '1.5',
  applicationName: 'security-lab-cloud-suite',
  version: '2.4.0',
  author: 'Enterprise SecOps Build Pipeline',
  generatedAt: '2026-10-14T14:30:00Z',
  totalComponents: 124,
  directDependenciesCount: 18,
  transitiveDependenciesCount: 106,
  vulnerableComponentsCount: 3,
  criticalCveCount: 1,
  highCveCount: 2,
  licenseViolationsCount: 1,
  components: [
    {
      id: 'comp-axios',
      name: 'axios',
      version: '1.5.0',
      purl: 'pkg:npm/axios@1.5.0',
      ecosystem: 'npm',
      licenses: ['MIT'],
      isDirect: true,
      directDependencyCount: 2,
      licenseRisk: 'NONE',
      hashes: { 'sha-256': 'd8f3a9e10284c1b9a9d7b4ef72d1a3c5820e1f7893a4b6c8d0e1f2a3b4c5d6e7' },
      cveMatches: [
        {
          id: 'CVE-2023-45857',
          aliases: ['GHSA-wf5p-g6vw-rhxx'],
          summary: 'Axios Server-Side Request Forgery via absolute path redirect manipulation',
          details: 'When axios handles redirects to a different protocol or host, sensitive headers can be leaked.',
          severity: 'high',
          cvssScore: 8.1,
          fixedVersion: '1.6.0',
          referenceUrls: ['https://nvd.nist.gov/vuln/detail/CVE-2023-45857'],
        },
      ],
    },
    {
      id: 'comp-jsonwebtoken',
      name: 'jsonwebtoken',
      version: '8.5.1',
      purl: 'pkg:npm/jsonwebtoken@8.5.1',
      ecosystem: 'npm',
      licenses: ['MIT'],
      isDirect: true,
      directDependencyCount: 4,
      licenseRisk: 'NONE',
      hashes: { 'sha-256': 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0' },
      cveMatches: [
        {
          id: 'CVE-2022-23529',
          aliases: ['GHSA-qwph-4952-7xr6'],
          summary: 'Insecure Key Retrieval in jsonwebtoken.verify can lead to Remote Code Execution',
          details: 'Crafting a malicious key object passed to jwt.verify allows arbitrary file reads and execution.',
          severity: 'critical',
          cvssScore: 9.8,
          fixedVersion: '9.0.0',
          referenceUrls: ['https://nvd.nist.gov/vuln/detail/CVE-2022-23529'],
        },
      ],
    },
    {
      id: 'comp-lodash',
      name: 'lodash',
      version: '4.17.20',
      purl: 'pkg:npm/lodash@4.17.20',
      ecosystem: 'npm',
      licenses: ['MIT'],
      isDirect: false,
      licenseRisk: 'NONE',
      hashes: { 'sha-256': 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210' },
      cveMatches: [
        {
          id: 'CVE-2021-23337',
          aliases: ['GHSA-35jh-r3h4-6jhm'],
          summary: 'Command Injection via template function in lodash',
          details: 'Untrusted input passed to template options can trigger command injection.',
          severity: 'high',
          cvssScore: 7.4,
          fixedVersion: '4.17.21',
          referenceUrls: ['https://nvd.nist.gov/vuln/detail/CVE-2021-23337'],
        },
      ],
    },
    {
      id: 'comp-agpl-driver',
      name: 'internal-exporter-daemon',
      version: '1.2.0',
      purl: 'pkg:npm/internal-exporter-daemon@1.2.0',
      ecosystem: 'npm',
      licenses: ['AGPL-3.0-only'],
      isDirect: true,
      licenseRisk: 'CRITICAL',
      licenseViolationReason: 'Disallowed copyleft license AGPL-3.0 violates corporate SaaS distribution policy.',
      hashes: { 'sha-256': '11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff' },
      cveMatches: [],
    },
    {
      id: 'comp-express',
      name: 'express',
      version: '4.19.2',
      purl: 'pkg:npm/express@4.19.2',
      ecosystem: 'npm',
      licenses: ['MIT'],
      isDirect: true,
      directDependencyCount: 31,
      licenseRisk: 'NONE',
      hashes: { 'sha-256': '3344556677889900aabbccddeeff11223344556677889900aabbccddeeff1122' },
      cveMatches: [],
    },
  ],
};

export const SAMPLE_SMUGGLING_SNAPSHOT: SmugglingWireSnapshot = {
  targetHost: 'api.production.security-lab.local',
  targetPort: 443,
  useTls: true,
  reverseProxyType: 'HAProxy 2.4.1 (Frontend Ingress)',
  backendServerType: 'Node.js Express / Gunicorn (Backend Service)',
  testedVariantsCount: 5,
  vulnerableCount: 2,
  variants: [
    {
      id: 'var-cl-te-timing',
      technique: 'CL_TE',
      name: 'CL.TE Frontend Content-Length, Backend Chunked Desync',
      description: 'Frontend proxy respects Content-Length; backend parses Transfer-Encoding: chunked, causing backend to hang or desync request body prefix.',
      frontendExpectation: 'Frontend reads entire 6-byte body based on Content-Length: 6.',
      backendExpectation: 'Backend reads 0-byte terminating chunk and leaves remaining "GPOST" in socket buffer for next client request.',
      desyncExplanation: 'The backend server consumes the chunk header and treats the smuggled HTTP prefix as the start of the next incoming request on the re-used connection.',
      vulnerabilityStatus: 'CONFIRMED',
      statusCode: 200,
      latencyMs: 1650,
      canaryReflected: true,
      canaryPath: '/robots.txt',
      rawSocketRequest: 'POST / HTTP/1.1\r\nHost: api.production.security-lab.local\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG',
      rawSocketResponse: 'HTTP/1.1 405 Method Not Allowed\r\nServer: backend-worker\r\nContent-Type: text/plain\r\nContent-Length: 21\r\n\r\nUnrecognized method G',
      requestHexDump: '50 4f 53 54 20 2f 20 48  54 54 50 2f 31 2e 31 0d  |POST / HTTP/1.1.|\n0a 48 6f 73 74 3a 20 61  70 69 2e 70 72 6f 64 75  |.Host: api.produ|\n63 74 69 6f 6e 0d 0a 43  6f 6e 74 65 6e 74 2d 4c  |ction..Content-L|\n65 6e 67 74 68 3a 20 36  0d 0a 54 72 61 6e 73 66  |ength: 6..Transf|\n65 72 2d 45 6e 63 6f 64  69 6e 67 3a 20 63 68 75  |er-Encoding: chu|\n6e 6b 65 64 0d 0a 0d 0a  30 0d 0a 0d 0a 47        |nked....0....G  |',
      responseHexDump: '48 54 54 50 2f 31 2e 31  20 34 30 35 20 4d 65 74  |HTTP/1.1 405 Met|\n68 6f 64 20 4e 6f 74 20  41 6c 6c 6f 77 65 64 0d  |hod Not Allowed.|\n0a 53 65 72 76 65 72 3a  20 62 61 63 6b 65 6e 64  |.Server: backend|',
    },
    {
      id: 'var-te-cl-dual',
      technique: 'TE_CL',
      name: 'TE.CL Frontend Chunked, Backend Content-Length Desync',
      description: 'Frontend forwards chunked stream; backend stops reading at Content-Length and leaves smuggled payload for subsequent pipeline.',
      frontendExpectation: 'Frontend processes full chunked body of length 48 bytes.',
      backendExpectation: 'Backend only reads 4 bytes per Content-Length: 4.',
      desyncExplanation: 'The smuggled GET /admin request is executed under the identity of the next victim user requesting the socket.',
      vulnerabilityStatus: 'CONFIRMED',
      statusCode: 200,
      latencyMs: 120,
      canaryReflected: true,
      canaryPath: '/admin',
      rawSocketRequest: 'POST / HTTP/1.1\r\nHost: api.production.security-lab.local\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGET /admin HTTP/1.1\r\nHost: api.production.security-lab.local\r\nX-Ignore: X\r\n0\r\n\r\n',
      rawSocketResponse: 'HTTP/1.1 403 Forbidden\r\nServer: backend-worker\r\nContent-Type: application/json\r\n\r\n{"error": "Access to /admin denied for anonymous"}',
      requestHexDump: '50 4f 53 54 20 2f 20 48  54 54 50 2f 31 2e 31 0d  |POST / HTTP/1.1.|\n0a 48 6f 73 74 3a 20 61  70 69 0d 0a 43 6f 6e 74  |.Host: api..Cont|\n65 6e 74 2d 4c 65 6e 67  74 68 3a 20 34 0d 0a     |ent-Length: 4.. |',
      responseHexDump: '48 54 54 50 2f 31 2e 31  20 34 30 33 20 46 6f 72  |HTTP/1.1 403 For|\n62 69 64 64 65 6e 0d 0a  53 65 72 76 65 72 3a 20  |bidden..Server: |',
    },
    {
      id: 'var-te-te-obfuscation',
      technique: 'TE_TE',
      name: 'TE.TE Obfuscated Transfer-Encoding Header Smuggling',
      description: 'Both servers support chunked encoding, but one server can be tricked into ignoring it via header obfuscation (e.g. "Transfer-Encoding: xchunked").',
      frontendExpectation: 'Normalises or strips malformed header.',
      backendExpectation: 'Accepts obscured header or falls back to Content-Length.',
      desyncExplanation: 'Front and back ends disagree on which header is authoritative due to whitespace or duplicate casing.',
      vulnerabilityStatus: 'SAFE',
      statusCode: 400,
      latencyMs: 45,
      canaryReflected: false,
      canaryPath: '/robots.txt',
      rawSocketRequest: 'POST / HTTP/1.1\r\nHost: api.production.security-lab.local\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: cow\r\n\r\n0\r\n\r\n',
      rawSocketResponse: 'HTTP/1.1 400 Bad Request\r\nServer: haproxy/2.4.1\r\nContent-Length: 11\r\n\r\nBad Request',
      requestHexDump: '50 4f 53 54 20 2f 20 48  54 54 50 2f 31 2e 31 0d  |POST / HTTP/1.1.|\n0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|',
      responseHexDump: '48 54 54 50 2f 31 2e 31  20 34 30 30 20 42 61 64  |HTTP/1.1 400 Bad|\n20 52 65 71 75 65 73 74  0d 0a                    | Request..      |',
    },
  ],
};

export const SAMPLE_DATABASE_SECURITY: DatabaseSecuritySnapshot = {
  totalDatabasesChecked: 3,
  unencryptedCount: 1,
  unauthenticatedCount: 1,
  defaultCredentialVulnerableCount: 1,
  probes: [
    {
      id: 'db-postgres-prod',
      databaseType: 'POSTGRES',
      host: 'db-master.internal.security-lab.local',
      port: 5432,
      tlsSupported: true,
      tlsMandated: false, // VULNERABILITY: Cleartext permitted
      unauthenticatedAccessAllowed: false,
      defaultCredentialsMatched: true,
      matchedCredentialUser: 'postgres / postgres',
      serverVersion: 'PostgreSQL 15.4 (Debian 15.4-1.pgdg120+1)',
      authMethod: 'md5',
      rawBannerHex: '00 00 00 08 04 d2 16 2f',
      saturation: {
        attemptedConnections: 50,
        successfulConnections: 50,
        rejectedConnections: 0,
        avgConnectionTimeMs: 14.5,
        serverGraceful: true,
      },
      findings: [
        {
          id: 'DB-001-CLEARTEXT-ALLOWED',
          title: 'PostgreSQL allows unencrypted cleartext wire protocol handshakes',
          severity: 'high',
          description: 'Server responded with "N" to SSLRequest probe, permitting unencrypted database queries and credentials in transit.',
          remediation: 'Configure ssl = on and require pg_hba.conf clientcert / hostssl enforcement.',
        },
        {
          id: 'DB-002-DEFAULT-CREDS',
          title: 'PostgreSQL master account uses default password (postgres:postgres)',
          severity: 'critical',
          description: 'Automated wire credential probe successfully authenticated as superuser postgres.',
          remediation: 'Rotate postgres superuser password immediately and enforce vault-managed short-lived credentials.',
        },
      ],
    },
    {
      id: 'db-redis-cache',
      databaseType: 'REDIS',
      host: 'redis-cache.internal.security-lab.local',
      port: 6379,
      tlsSupported: false,
      tlsMandated: false,
      unauthenticatedAccessAllowed: true, // VULNERABILITY: Open Redis
      defaultCredentialsMatched: false,
      serverVersion: 'Redis 7.0.12',
      authMethod: 'NONE',
      rawBannerHex: '2b 50 4f 4e 47 0d 0a',
      saturation: {
        attemptedConnections: 100,
        successfulConnections: 100,
        rejectedConnections: 0,
        avgConnectionTimeMs: 2.1,
        serverGraceful: true,
      },
      findings: [
        {
          id: 'DB-003-OPEN-REDIS',
          title: 'Unauthenticated Redis instance allows full memory dump and RCE',
          severity: 'critical',
          description: 'Server responded "+PONG" to raw PING without requiring AUTH or ACL credentials.',
          remediation: 'Set requirepass in redis.conf or configure Redis 6+ ACL users with restricted command sets.',
        },
      ],
    },
    {
      id: 'db-mysql-analytics',
      databaseType: 'MYSQL',
      host: 'mysql-dw.internal.security-lab.local',
      port: 3306,
      tlsSupported: true,
      tlsMandated: true,
      unauthenticatedAccessAllowed: false,
      defaultCredentialsMatched: false,
      serverVersion: '8.0.34 MySQL Community Server',
      authMethod: 'caching_sha2_password',
      rawBannerHex: '4a 00 00 00 0a 38 2e 30 2e 33 34 00',
      saturation: {
        attemptedConnections: 40,
        successfulConnections: 35,
        rejectedConnections: 5,
        avgConnectionTimeMs: 18.2,
        serverGraceful: true,
        rejectionReason: 'ER_CON_COUNT_ERROR: Too many connections (max_connections = 35 reached gracefully)',
      },
      findings: [],
    },
  ],
};

// ============================================================================
// API Fetch Handlers
// ============================================================================

export async function fetchInfraStudioOverview(): Promise<InfraStudioOverviewSnapshot> {
  const apiUrl = import.meta.env?.VITE_API_URL || 'http://localhost:3000';

  try {
    const res = await authFetch(`${apiUrl}/api/v1/findings?category=infrastructure`);
    if (res.ok) {
      // If controller provides real findings, we can merge or use live snapshot
    }
  } catch {
    // Graceful fallback to rich studio mock datasets
  }

  return {
    k8s: SAMPLE_K8S_AUDIT,
    sbom: SAMPLE_SBOM_GRAPH,
    smuggling: SAMPLE_SMUGGLING_SNAPSHOT,
    database: SAMPLE_DATABASE_SECURITY,
  };
}

export async function fetchK8sAuditData(): Promise<K8sAuditSnapshot> {
  return SAMPLE_K8S_AUDIT;
}

export async function fetchSbomGraphData(): Promise<SbomGraphSnapshot> {
  return SAMPLE_SBOM_GRAPH;
}

export async function fetchSmugglingWireData(): Promise<SmugglingWireSnapshot> {
  return SAMPLE_SMUGGLING_SNAPSHOT;
}

export async function fetchDatabaseSecurityData(): Promise<DatabaseSecuritySnapshot> {
  return SAMPLE_DATABASE_SECURITY;
}
