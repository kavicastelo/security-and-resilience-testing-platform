import { OwaspTop10Mapping } from './types.js';

export const OWASP_TOP_10_2021: Record<string, OwaspTop10Mapping> = {
  'A01:2021': {
    id: 'A01:2021',
    name: 'Broken Access Control',
    cweList: ['CWE-200', 'CWE-284', 'CWE-285', 'CWE-639', 'CWE-862', 'CWE-863'],
    description: 'Failures that lead to unauthorized information disclosure, modification, or destruction of data, or performing a business function outside user limits.',
  },
  'A02:2021': {
    id: 'A02:2021',
    name: 'Cryptographic Failures',
    cweList: ['CWE-259', 'CWE-319', 'CWE-326', 'CWE-327', 'CWE-330'],
    description: 'Failures related to cryptography (or lack thereof) leading to sensitive data exposure or system compromise.',
  },
  'A03:2021': {
    id: 'A03:2021',
    name: 'Injection',
    cweList: ['CWE-79', 'CWE-89', 'CWE-94', 'CWE-77', 'CWE-918'],
    description: 'User-supplied data is not validated, filtered, or sanitized by the application before being executed as part of a command or query.',
  },
  'A04:2021': {
    id: 'A04:2021',
    name: 'Insecure Design',
    cweList: ['CWE-209', 'CWE-256', 'CWE-362', 'CWE-501', 'CWE-657'],
    description: 'Risks related to design and architectural flaws, calling for more pre-design threat modeling, secure design patterns, and reference architectures.',
  },
  'A05:2021': {
    id: 'A05:2021',
    name: 'Security Misconfiguration',
    cweList: ['CWE-16', 'CWE-209', 'CWE-611', 'CWE-1004'],
    description: 'Missing appropriate security hardening across the application stack, improperly configured cloud permissions, or default accounts/passwords.',
  },
  'A06:2021': {
    id: 'A06:2021',
    name: 'Vulnerable and Outdated Components',
    cweList: ['CWE-1104', 'CWE-1035', 'CWE-937'],
    description: 'Using unsupported, out-of-date software libraries, containers, and OS dependencies with known vulnerabilities (CVEs).',
  },
  'A07:2021': {
    id: 'A07:2021',
    name: 'Identification and Authentication Failures',
    cweList: ['CWE-297', 'CWE-287', 'CWE-384', 'CWE-798'],
    description: 'Confirmation of the user identity, authentication, and session management is critical to protect against authentication-related attacks.',
  },
  'A08:2021': {
    id: 'A08:2021',
    name: 'Software and Data Integrity Failures',
    cweList: ['CWE-444', 'CWE-494', 'CWE-502', 'CWE-829'],
    description: 'Code and infrastructure that does not protect against integrity violations, including HTTP request smuggling, untrusted plugins, and insecure CI/CD.',
  },
  'A09:2021': {
    id: 'A09:2021',
    name: 'Security Logging and Monitoring Failures',
    cweList: ['CWE-117', 'CWE-223', 'CWE-532', 'CWE-778'],
    description: 'Without logging and monitoring, breaches cannot be detected, investigated, or mitigated in a timely manner.',
  },
  'A10:2021': {
    id: 'A10:2021',
    name: 'Server-Side Request Forgery (SSRF)',
    cweList: ['CWE-918'],
    description: 'SSRF flaws occur whenever a web application fetches a remote resource without validating the user-supplied URL.',
  },
};

/**
 * Maps a platform finding to its corresponding OWASP Top 10 2021 category.
 */
export function mapRuleToOwasp(ruleOrCweId: string, category = '', title = ''): OwaspTop10Mapping {
  const normalized = `${ruleOrCweId} ${category} ${title}`.toLowerCase();

  // 1. Broken Access Control (A01)
  if (
    normalized.includes('bola') ||
    normalized.includes('bfla') ||
    normalized.includes('idor') ||
    normalized.includes('access control') ||
    normalized.includes('privilege') ||
    normalized.includes('cors') ||
    normalized.includes('path traversal') ||
    normalized.includes('step-skipping') ||
    normalized.includes('step skipping') ||
    normalized.includes('directory listing') ||
    normalized.includes('cwe-639') ||
    normalized.includes('cwe-284') ||
    normalized.includes('cwe-285') ||
    normalized.includes('cwe-862') ||
    normalized.includes('cwe-863')
  ) {
    return OWASP_TOP_10_2021['A01:2021']!;
  }

  // 2. Cryptographic Failures (A02)
  if (
    normalized.includes('hsts') ||
    normalized.includes('tls') ||
    normalized.includes('ssl') ||
    normalized.includes('cipher') ||
    normalized.includes('cleartext') ||
    normalized.includes('cryptograph') ||
    normalized.includes('cwe-319') ||
    normalized.includes('cwe-326') ||
    normalized.includes('cwe-327')
  ) {
    return OWASP_TOP_10_2021['A02:2021']!;
  }

  // 3. Injection (A03)
  if (
    normalized.includes('sqli') ||
    normalized.includes('sql injection') ||
    normalized.includes('xss') ||
    normalized.includes('cross-site scripting') ||
    normalized.includes('command injection') ||
    normalized.includes('nosql') ||
    normalized.includes('ldap') ||
    normalized.includes('template injection') ||
    normalized.includes('cwe-89') ||
    normalized.includes('cwe-79') ||
    normalized.includes('cwe-77')
  ) {
    return OWASP_TOP_10_2021['A03:2021']!;
  }

  // 4. Insecure Design (A04)
  if (
    normalized.includes('race condition') ||
    normalized.includes('toctou') ||
    normalized.includes('rate limit') ||
    normalized.includes('rate-limit') ||
    normalized.includes('business logic') ||
    normalized.includes('parameter tampering') ||
    normalized.includes('concurrency') ||
    normalized.includes('cwe-362')
  ) {
    return OWASP_TOP_10_2021['A04:2021']!;
  }

  // 5. Security Misconfiguration (A05)
  if (
    normalized.includes('header') ||
    normalized.includes('x-content-type-options') ||
    normalized.includes('x-frame-options') ||
    normalized.includes('content-security-policy') ||
    normalized.includes('csp') ||
    normalized.includes('clickjacking') ||
    normalized.includes('cookie') ||
    normalized.includes('k8s') ||
    normalized.includes('kubernetes') ||
    normalized.includes('dockerfile') ||
    normalized.includes('misconfiguration') ||
    normalized.includes('verbose error') ||
    normalized.includes('fingerprint disclosure') ||
    normalized.includes('cwe-16') ||
    normalized.includes('cwe-209') ||
    normalized.includes('cwe-1004')
  ) {
    return OWASP_TOP_10_2021['A05:2021']!;
  }

  // 6. Vulnerable and Outdated Components (A06)
  if (
    normalized.includes('sbom') ||
    normalized.includes('cve') ||
    normalized.includes('vulnerable component') ||
    normalized.includes('outdated') ||
    normalized.includes('dependency') ||
    normalized.includes('supply chain') ||
    normalized.includes('trivy') ||
    normalized.includes('cwe-1104') ||
    normalized.includes('cwe-1035') ||
    normalized.includes('cwe-937')
  ) {
    return OWASP_TOP_10_2021['A06:2021']!;
  }

  // 7. Identification and Authentication Failures (A07)
  if (
    normalized.includes('auth') ||
    normalized.includes('password') ||
    normalized.includes('brute force') ||
    normalized.includes('session') ||
    normalized.includes('token') ||
    normalized.includes('jwt') ||
    normalized.includes('credential') ||
    normalized.includes('mfa') ||
    normalized.includes('cwe-287') ||
    normalized.includes('cwe-384') ||
    normalized.includes('cwe-798')
  ) {
    return OWASP_TOP_10_2021['A07:2021']!;
  }

  // 8. Software and Data Integrity Failures (A08)
  if (
    normalized.includes('smuggling') ||
    normalized.includes('cl.te') ||
    normalized.includes('te.cl') ||
    normalized.includes('deserialization') ||
    normalized.includes('integrity') ||
    normalized.includes('cwe-444') ||
    normalized.includes('cwe-502')
  ) {
    return OWASP_TOP_10_2021['A08:2021']!;
  }

  // 9. Logging & Monitoring (A09)
  if (
    normalized.includes('audit log') ||
    normalized.includes('logging') ||
    normalized.includes('monitoring') ||
    normalized.includes('cwe-778') ||
    normalized.includes('cwe-117')
  ) {
    return OWASP_TOP_10_2021['A09:2021']!;
  }

  // 10. SSRF (A10)
  if (
    normalized.includes('ssrf') ||
    normalized.includes('server-side request forgery') ||
    normalized.includes('metadata service') ||
    normalized.includes('169.254.169.254') ||
    normalized.includes('cwe-918')
  ) {
    return OWASP_TOP_10_2021['A10:2021']!;
  }

  // Default fallback to A05: Security Misconfiguration
  return OWASP_TOP_10_2021['A05:2021']!;
}
