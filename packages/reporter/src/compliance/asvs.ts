import { AsvsMapping } from './types.js';

export const ASVS_CATEGORIES: Record<string, AsvsMapping> = {
  V2: {
    sectionId: 'V2',
    sectionName: 'Authentication Verification Standard',
    chapterId: 'V2',
    chapterName: 'Authentication Verification Standard',
    requirementId: 'V2.1.1',
    level: 1,
    description: 'Verify that user set passwords are at least 12 characters in length and strong credential policies are enforced.',
  },
  V3: {
    sectionId: 'V3',
    sectionName: 'Session Management Verification Standard',
    chapterId: 'V3',
    chapterName: 'Session Management Verification Standard',
    requirementId: 'V3.2.1',
    level: 1,
    description: 'Verify that session tokens are generated using cryptographically secure pseudorandom generators and bound to secure cookie flags.',
  },
  V4: {
    sectionId: 'V4',
    sectionName: 'Access Control Verification Standard',
    chapterId: 'V4',
    chapterName: 'Access Control Verification Standard',
    requirementId: 'V4.1.1',
    level: 1,
    description: 'Verify that the principle of least privilege exists and access control decisions are enforced on every request and API route.',
  },
  V5: {
    sectionId: 'V5',
    sectionName: 'Validation, Sanitization and Encoding Verification Standard',
    chapterId: 'V5',
    chapterName: 'Validation, Sanitization and Encoding Verification Standard',
    requirementId: 'V5.1.1',
    level: 1,
    description: 'Verify that the application validates, filters, and sanitizes all untrusted user inputs before processing or rendering.',
  },
  V8: {
    sectionId: 'V8',
    sectionName: 'Data Protection Verification Standard',
    chapterId: 'V8',
    chapterName: 'Data Protection Verification Standard',
    requirementId: 'V8.1.1',
    level: 1,
    description: 'Verify that sensitive data is protected at rest and in transit, and confidential tokens or credentials are not leaked.',
  },
  V9: {
    sectionId: 'V9',
    sectionName: 'Communications Verification Standard',
    chapterId: 'V9',
    chapterName: 'Communications Verification Standard',
    requirementId: 'V9.1.1',
    level: 1,
    description: 'Verify that all communication between client and server is encrypted using strong TLS protocol configurations and HSTS is enforced.',
  },
  V10: {
    sectionId: 'V10',
    sectionName: 'Malicious Code & Supply Chain Search Standard',
    chapterId: 'V10',
    chapterName: 'Malicious Code & Supply Chain Search Standard',
    requirementId: 'V10.2.1',
    level: 1,
    description: 'Verify that third-party components and open-source libraries are audited and have no known critical vulnerabilities (CVEs).',
  },
  V13: {
    sectionId: 'V13',
    sectionName: 'API and Web Service Verification Standard',
    chapterId: 'V13',
    chapterName: 'API and Web Service Verification Standard',
    requirementId: 'V13.1.1',
    level: 1,
    description: 'Verify that REST, GraphQL, and microservice APIs enforce granular authentication, rate limiting, and schema validation.',
  },
  V14: {
    sectionId: 'V14',
    sectionName: 'Configuration Verification Standard',
    chapterId: 'V14',
    chapterName: 'Configuration Verification Standard',
    requirementId: 'V14.4.1',
    level: 1,
    description: 'Verify that defensive HTTP response headers (CSP, X-Content-Type-Options, X-Frame-Options) are configured on all endpoints.',
  },
};

/**
 * Maps a platform finding to its corresponding OWASP ASVS 4.0 standard requirement.
 */
export function mapRuleToAsvs(ruleOrCweId: string, category = '', title = ''): AsvsMapping {
  const normalized = `${ruleOrCweId} ${category} ${title}`.toLowerCase();

  // Access Control (V4)
  if (
    normalized.includes('bola') ||
    normalized.includes('bfla') ||
    normalized.includes('idor') ||
    normalized.includes('access control') ||
    normalized.includes('privilege') ||
    normalized.includes('cors') ||
    normalized.includes('step-skipping')
  ) {
    return ASVS_CATEGORIES['V4']!;
  }

  // Communications & Transport (V9)
  if (
    normalized.includes('hsts') ||
    normalized.includes('tls') ||
    normalized.includes('ssl') ||
    normalized.includes('cipher') ||
    normalized.includes('cleartext')
  ) {
    return ASVS_CATEGORIES['V9']!;
  }

  // Validation & Encoding / Injection (V5)
  if (
    normalized.includes('sqli') ||
    normalized.includes('sql injection') ||
    normalized.includes('xss') ||
    normalized.includes('injection') ||
    normalized.includes('command') ||
    normalized.includes('validation')
  ) {
    return ASVS_CATEGORIES['V5']!;
  }

  // Supply Chain & Outdated Components (V10)
  if (
    normalized.includes('sbom') ||
    normalized.includes('cve') ||
    normalized.includes('vulnerable component') ||
    normalized.includes('dependency') ||
    normalized.includes('supply chain')
  ) {
    return ASVS_CATEGORIES['V10']!;
  }

  // Authentication (V2) & Session (V3)
  if (
    normalized.includes('auth') ||
    normalized.includes('password') ||
    normalized.includes('brute force') ||
    normalized.includes('credential')
  ) {
    return ASVS_CATEGORIES['V2']!;
  }

  if (normalized.includes('session') || normalized.includes('token') || normalized.includes('jwt')) {
    return ASVS_CATEGORIES['V3']!;
  }

  // API & Web Services (V13)
  if (
    normalized.includes('graphql') ||
    normalized.includes('rate limit') ||
    normalized.includes('business logic') ||
    normalized.includes('race condition') ||
    normalized.includes('toctou') ||
    normalized.includes('api')
  ) {
    return ASVS_CATEGORIES['V13']!;
  }

  // Configuration & Headers (V14)
  return ASVS_CATEGORIES['V14']!;
}
