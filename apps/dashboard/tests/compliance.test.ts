import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  matchFindingToCategories,
  computeFrameworkAssessment,
  assembleComplianceReport,
  fetchComplianceAssessment,
  downloadReport,
  generateClientSyntheticHtml,
  generateClientSyntheticSarif,
  OWASP_TOP_10_CATALOG,
  OWASP_API_CATALOG,
  ASVS_CATALOG,
  PCI_DSS_CATALOG,
  COMPLIANCE_DISCLAIMER,
} from '../src/api/reports.js';

const TEST_VULNERABILITY_FINDINGS = [
  {
    id: 'f-authz-01',
    title: 'BOLA / IDOR in User Profile Endpoint (/api/v1/users/:id/billing)',
    category: 'Broken Access Control',
    severity: 'critical' as const,
    metadata: {
      ruleId: 'AUTHZ_BOLA_IDOR',
      cwe: 'CWE-639',
      endpoint: '/api/v1/users/:id/billing',
    },
  },
  {
    id: 'f-auth-02',
    title: 'Weak JWT Secret Key / Symmetric Algorithm Confusion',
    category: 'Identification and Authentication',
    severity: 'high' as const,
    metadata: {
      ruleId: 'AUTH_JWT_CONFUSION',
      cwe: 'CWE-327',
      endpoint: '/api/v1/auth/tokens',
    },
  },
  {
    id: 'f-sqli-03',
    title: 'SQL Injection in Search Query Parameter ($search)',
    category: 'Injection',
    severity: 'critical' as const,
    metadata: {
      ruleId: 'INJECT_SQLI_BLIND',
      cwe: 'CWE-89',
      endpoint: '/api/v1/catalog/search',
    },
  },
];

describe('Phase UI-15 / PR-02: Enterprise Compliance Center, Standards Mapping & Truthful Reports', () => {
  describe('Rule to Framework Mapping Engine', () => {
    it('correctly maps authorization flaws (BOLA/IDOR) to OWASP A01, API1, ASVS V4, and PCI-DSS 6.5.8', () => {
      const finding = {
        id: 'f-bola-01',
        title: 'Broken Object Level Authorization (IDOR) on Tenant Invoices',
        category: 'Broken Access Control',
        severity: 'critical' as const,
        metadata: {
          ruleId: 'AUTHZ_BOLA_IDOR',
          cwe: 'CWE-639',
          endpoint: '/api/v1/invoices/:id',
        },
      };

      const matches = matchFindingToCategories(finding);
      expect(matches.owaspId).toBe('A01:2021');
      expect(matches.apiId).toBe('API1:2023');
      expect(matches.asvsId).toBe('V4');
      expect(matches.pciId).toBe('6.5.8');
    });

    it('correctly maps injection flaws (SQLi) to OWASP A03, ASVS V5, and PCI-DSS 6.5.1', () => {
      const finding = {
        id: 'f-sqli-01',
        title: 'Blind SQL Injection in parameter order_by',
        category: 'Injection',
        severity: 'critical' as const,
        metadata: {
          ruleId: 'INJECT_SQLI_BLIND',
          cwe: 'CWE-89',
        },
      };

      const matches = matchFindingToCategories(finding);
      expect(matches.owaspId).toBe('A03:2021');
      expect(matches.asvsId).toBe('V5');
      expect(matches.pciId).toBe('6.5.1');
    });

    it('correctly maps vulnerable dependencies to OWASP A06, ASVS V10, and PCI-DSS 6.3.1', () => {
      const finding = {
        id: 'f-cve-01',
        title: 'Vulnerable Outdated Dependency (CVE-2023-26159) in follow-redirects',
        category: 'Vulnerable and Outdated Components',
        severity: 'high' as const,
        metadata: {
          ruleId: 'SUPPLY_CHAIN_CVE',
          cwe: 'CWE-1104',
        },
      };

      const matches = matchFindingToCategories(finding);
      expect(matches.owaspId).toBe('A06:2021');
      expect(matches.asvsId).toBe('V10');
      expect(matches.pciId).toBe('6.3.1');
    });

    it('correctly maps cryptographic and HSTS flaws to OWASP A02, ASVS V9, and PCI-DSS 6.2.4', () => {
      const finding = {
        id: 'f-crypto-01',
        title: 'Weak TLS Cipher Suite and Cleartext Communication',
        category: 'Cryptographic Failures',
        severity: 'medium' as const,
        metadata: {
          ruleId: 'CRYPTO_WEAK_CIPHER',
          cwe: 'CWE-326',
        },
      };

      const matches = matchFindingToCategories(finding);
      expect(matches.owaspId).toBe('A02:2021');
      expect(matches.asvsId).toBe('V9');
    });
  });

  describe('Framework Compliance Scorecard Assessment & Zero-Defect Posture', () => {
    it('truthfully computes 100% compliance with 0 violations when clean test run has zero findings', () => {
      const emptyFindings: any[] = [];
      const assessment = computeFrameworkAssessment(
        'OWASP_TOP_10_2021',
        OWASP_TOP_10_CATALOG,
        emptyFindings,
        'OWASP Top 10 (2021)',
        'v2021'
      );

      expect(assessment.compliancePercentage).toBe(100);
      expect(assessment.compliantControlsCount).toBe(OWASP_TOP_10_CATALOG.length);
      expect(assessment.nonCompliantControlsCount).toBe(0);
      expect(assessment.overallStatus).toBe('PASS');
      expect(assessment.categories.every((c) => c.status === 'COMPLIANT')).toBe(true);
      expect(assessment.categories.every((c) => c.findingsCount === 0)).toBe(true);
    });

    it('marks category as NON_COMPLIANT when critical or high findings are mapped', () => {
      const findings = [
        {
          id: 'f-1',
          title: 'Critical BOLA in API',
          category: 'Broken Access Control',
          severity: 'critical' as const,
          metadata: { ruleId: 'AUTHZ_BOLA', cwe: 'CWE-639' },
        },
      ];

      const assessment = computeFrameworkAssessment(
        'OWASP_TOP_10_2021',
        OWASP_TOP_10_CATALOG,
        findings,
        'OWASP Top 10 (2021)',
        'v2021'
      );

      const a01 = assessment.categories.find((c) => c.id === 'A01:2021');
      expect(a01).toBeDefined();
      expect(a01?.status).toBe('NON_COMPLIANT');
      expect(a01?.criticalCount).toBe(1);
      expect(a01?.findingsCount).toBe(1);
      expect(assessment.nonCompliantControlsCount).toBe(1);
      expect(assessment.compliantControlsCount).toBe(9);
      expect(assessment.compliancePercentage).toBe(90);
      expect(assessment.overallStatus).toBe('FAIL');
    });

    it('assembles multi-framework report covering OWASP Top 10, OWASP API, ASVS, and PCI-DSS', () => {
      const report = assembleComplianceReport(TEST_VULNERABILITY_FINDINGS, 'run-test-123', 'https://api.test.local');

      expect(report.testRunId).toBe('run-test-123');
      expect(report.targetUrl).toBe('https://api.test.local');
      expect(report.totalFindings).toBe(TEST_VULNERABILITY_FINDINGS.length);
      expect(report.frameworks.OWASP_TOP_10_2021).toBeDefined();
      expect(report.frameworks.OWASP_API_2023).toBeDefined();
      expect(report.frameworks.OWASP_ASVS_4_0).toBeDefined();
      expect(report.frameworks.PCI_DSS_4_0).toBeDefined();

      expect(report.countsBySeverity.critical).toBe(2);
      expect(report.countsBySeverity.high).toBe(1);
    });

    it('truthfully reports 100% compliance across all 4 frameworks when findings array is empty', () => {
      const cleanReport = assembleComplianceReport([], 'run-clean-01');

      expect(cleanReport.totalFindings).toBe(0);
      expect(cleanReport.countsBySeverity.critical).toBe(0);
      expect(cleanReport.countsBySeverity.high).toBe(0);

      expect(cleanReport.frameworks.OWASP_TOP_10_2021.compliancePercentage).toBe(100);
      expect(cleanReport.frameworks.OWASP_TOP_10_2021.nonCompliantControlsCount).toBe(0);
      expect(cleanReport.frameworks.OWASP_TOP_10_2021.overallStatus).toBe('PASS');

      expect(cleanReport.frameworks.OWASP_API_2023.compliancePercentage).toBe(100);
      expect(cleanReport.frameworks.OWASP_ASVS_4_0.compliancePercentage).toBe(100);
      expect(cleanReport.frameworks.PCI_DSS_4_0.compliancePercentage).toBe(100);
    });
  });

  describe('Truthful Auditing & Legal Disclaimer Invariant (Product Requirement 24.4)', () => {
    it('embeds mandatory disclaimer stating automated scans are technical evidence, not certification', () => {
      expect(COMPLIANCE_DISCLAIMER).toContain('Automated verification results provide technical testing evidence');
      expect(COMPLIANCE_DISCLAIMER).toContain('do not constitute formal legal certification');
      expect(COMPLIANCE_DISCLAIMER).toContain('Product Requirement 24.4');

      const report = assembleComplianceReport([]);
      expect(report.disclaimer).toBe(COMPLIANCE_DISCLAIMER);
    });

    it('enforces demonstration levels (DIRECT, SUPPORTING, RELATED) across all catalog controls', () => {
      for (const cat of OWASP_TOP_10_CATALOG) {
        expect(['DIRECT', 'SUPPORTING', 'RELATED']).toContain(cat.demonstrationLevel);
      }
      for (const cat of OWASP_API_CATALOG) {
        expect(['DIRECT', 'SUPPORTING', 'RELATED']).toContain(cat.demonstrationLevel);
      }
      for (const cat of ASVS_CATALOG) {
        expect(['DIRECT', 'SUPPORTING', 'RELATED']).toContain(cat.demonstrationLevel);
      }
      for (const cat of PCI_DSS_CATALOG) {
        expect(['DIRECT', 'SUPPORTING', 'RELATED']).toContain(cat.demonstrationLevel);
      }
    });
  });

  describe('Client-Server Controller Integration (PR-02)', () => {
    let originalFetch: typeof globalThis.fetch;

    beforeEach(() => {
      originalFetch = globalThis.fetch;
    });

    afterEach(() => {
      globalThis.fetch = originalFetch;
      vi.restoreAllMocks();
    });

    it('fetchComplianceAssessment queries /api/v1/findings and returns 100% compliant report for 0 findings', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ success: true, data: [] }),
      });

      const report = await fetchComplianceAssessment('run-clean-test');
      expect(report.totalFindings).toBe(0);
      expect(report.frameworks.OWASP_TOP_10_2021.compliancePercentage).toBe(100);
      expect(report.frameworks.OWASP_TOP_10_2021.nonCompliantControlsCount).toBe(0);
      expect(report.frameworks.OWASP_TOP_10_2021.overallStatus).toBe('PASS');
    });

    it('fetchComplianceAssessment maps real findings when returned by database', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ success: true, data: TEST_VULNERABILITY_FINDINGS }),
      });

      const report = await fetchComplianceAssessment('run-vuln-test');
      expect(report.totalFindings).toBe(3);
      expect(report.countsBySeverity.critical).toBe(2);
      expect(report.frameworks.OWASP_TOP_10_2021.nonCompliantControlsCount).toBeGreaterThan(0);
    });
  });

  describe('Report Generation & Live Previewers', () => {
    it('generates self-contained offline HTML audit report with clean status when findings is empty', () => {
      const html = generateClientSyntheticHtml('run-clean-456', {
        organizationName: 'Acme Global Defense',
        confidentialityNotice: 'RESTRICTED / STRICTLY CONFIDENTIAL',
      }, []);

      expect(html).toContain('<!DOCTYPE html>');
      expect(html).toContain('Acme Global Defense');
      expect(html).toContain('RESTRICTED / STRICTLY CONFIDENTIAL');
      expect(html).toContain('run-clean-456');
      expect(html).toContain(COMPLIANCE_DISCLAIMER);
      expect(html).toContain('100%');
      expect(html).toContain('badge-green');
      expect(html).not.toContain('http://cdn');
      expect(html).not.toContain('https://cdn');
    });

    it('generates valid SARIF 2.1 JSON artifact with compliance properties and disclaimer', () => {
      const sarifString = generateClientSyntheticSarif('run-sarif-789', {
        organizationName: 'CyberCorp Labs',
        confidentialityNotice: 'INTERNAL USE ONLY',
      }, TEST_VULNERABILITY_FINDINGS);

      const sarif = JSON.parse(sarifString);
      expect(sarif.version).toBe('2.1.0');
      expect(sarif.$schema).toContain('sarif-schema-2.1.0.json');
      expect(sarif.runs.length).toBe(1);

      const run = sarif.runs[0];
      expect(run.tool.driver.name).toBe('@security-lab/scanner');
      expect(run.invocations[0].properties.testRunId).toBe('run-sarif-789');
      expect(run.invocations[0].properties.organization).toBe('CyberCorp Labs');

      // Rules must carry compliance disclaimer
      expect(run.tool.driver.rules.length).toBe(TEST_VULNERABILITY_FINDINGS.length);
      expect(run.tool.driver.rules[0].properties.complianceDisclaimer).toBe(COMPLIANCE_DISCLAIMER);

      // Results must contain rule IDs and locations
      expect(run.results.length).toBe(TEST_VULNERABILITY_FINDINGS.length);
      expect(run.results[0].ruleId).toBeDefined();
      expect(run.results[0].locations[0].physicalLocation.artifactLocation.uri).toBeDefined();
    });
  });
});
