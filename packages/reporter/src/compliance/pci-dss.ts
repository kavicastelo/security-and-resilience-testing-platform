import { PciDssMapping } from './types.js';

export const PCI_DSS_REQUIREMENTS: Record<string, PciDssMapping> = {
  '6.2.4': {
    requirementId: '6.2.4',
    section: 'Requirement 6: Develop and Maintain Secure Systems and Software',
    title: 'Software Development & Vulnerability Prevention',
    description: 'Custom software is developed securely to prevent vulnerabilities including improper error handling, insecure direct object references, and data leaks.',
  },
  '6.3.1': {
    requirementId: '6.3.1',
    section: 'Requirement 6: Develop and Maintain Secure Systems and Software',
    title: 'Software Vulnerabilities Identification & Patching',
    description: 'Security vulnerabilities in third-party software components and operating systems are identified and remediated through patching.',
  },
  '6.4.1': {
    requirementId: '6.4.1',
    section: 'Requirement 6: Develop and Maintain Secure Systems and Software',
    title: 'Public-Facing Web Applications Defense',
    description: 'Public-facing web applications are protected against web-based attacks via continuous automated dynamic testing or web application firewalls.',
  },
  '6.4.3': {
    requirementId: '6.4.3',
    section: 'Requirement 6: Develop and Maintain Secure Systems and Software',
    title: 'Client-Side Script & Header Integrity',
    description: 'All payment page scripts and HTTP security headers are authorized and ensured tamper-proof to prevent script injection and clickjacking.',
  },
  '6.5.1': {
    requirementId: '6.5.1',
    section: 'Requirement 6: Develop and Maintain Secure Systems and Software',
    title: 'Injection Flaws Prevention',
    description: 'Prevent injection flaws, particularly SQL injection, LDAP injection, OS command injection, and template injection.',
  },
  '6.5.7': {
    requirementId: '6.5.7',
    section: 'Requirement 6: Develop and Maintain Secure Systems and Software',
    title: 'Cross-Site Scripting (XSS) Prevention',
    description: 'Prevent Cross-Site Scripting (XSS) vulnerabilities through context-aware output encoding and strict Content Security Policies (CSP).',
  },
  '6.5.8': {
    requirementId: '6.5.8',
    section: 'Requirement 6: Develop and Maintain Secure Systems and Software',
    title: 'Improper Access Control (BOLA, IDOR, Privilege Escalation)',
    description: 'Prevent improper access control including broken object-level authorization (BOLA), forced browsing, and privilege escalation.',
  },
  '6.5.10': {
    requirementId: '6.5.10',
    section: 'Requirement 6: Develop and Maintain Secure Systems and Software',
    title: 'Authentication & Session Integrity',
    description: 'Prevent broken authentication, weak credentials, and compromised session tokens across payment workflows and APIs.',
  },
};

/**
 * Maps a platform finding to its corresponding PCI-DSS 4.0 requirement.
 */
export function mapRuleToPciDss(ruleOrCweId: string, category = '', title = ''): PciDssMapping {
  const normalized = `${ruleOrCweId} ${category} ${title}`.toLowerCase();

  // 1. Access Control (6.5.8)
  if (
    normalized.includes('bola') ||
    normalized.includes('bfla') ||
    normalized.includes('idor') ||
    normalized.includes('access control') ||
    normalized.includes('privilege') ||
    normalized.includes('cors') ||
    normalized.includes('step-skipping')
  ) {
    return PCI_DSS_REQUIREMENTS['6.5.8']!;
  }

  // 2. Injection (6.5.1)
  if (
    normalized.includes('sqli') ||
    normalized.includes('sql injection') ||
    normalized.includes('command') ||
    normalized.includes('nosql') ||
    normalized.includes('ldap')
  ) {
    return PCI_DSS_REQUIREMENTS['6.5.1']!;
  }

  // 3. XSS (6.5.7)
  if (normalized.includes('xss') || normalized.includes('cross-site scripting')) {
    return PCI_DSS_REQUIREMENTS['6.5.7']!;
  }

  // 4. Vulnerable Dependencies & SBOM (6.3.1)
  if (
    normalized.includes('sbom') ||
    normalized.includes('cve') ||
    normalized.includes('vulnerable component') ||
    normalized.includes('vulnerable') ||
    normalized.includes('vuln') ||
    normalized.includes('outdated') ||
    normalized.includes('dependency') ||
    normalized.includes('dependencies') ||
    normalized.includes('supply chain')
  ) {
    return PCI_DSS_REQUIREMENTS['6.3.1']!;
  }

  // 5. Authentication & Session (6.5.10)
  if (
    normalized.includes('auth') ||
    normalized.includes('password') ||
    normalized.includes('session') ||
    normalized.includes('token') ||
    normalized.includes('jwt') ||
    normalized.includes('brute force')
  ) {
    return PCI_DSS_REQUIREMENTS['6.5.10']!;
  }

  // 6. Defensive Headers & Clickjacking (6.4.3)
  if (
    normalized.includes('header') ||
    normalized.includes('x-frame-options') ||
    normalized.includes('clickjacking') ||
    normalized.includes('csp') ||
    normalized.includes('content-security-policy')
  ) {
    return PCI_DSS_REQUIREMENTS['6.4.3']!;
  }

  // Default: General Secure Software Engineering (6.2.4)
  return PCI_DSS_REQUIREMENTS['6.2.4']!;
}
