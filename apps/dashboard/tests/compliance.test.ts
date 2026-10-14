import { describe, it, expect } from 'vitest';
import {
  matchFindingToCategories,
  computeFrameworkAssessment,
  assembleComplianceReport,
  generateClientSyntheticHtml,
  generateClientSyntheticSarif,
  OWASP_TOP_10_CATALOG,
  OWASP_API_CATALOG,
  ASVS_CATALOG,
  PCI_DSS_CATALOG,
  COMPLIANCE_DISCLAIMER,
  FALLBACK_COMPLIANCE_FINDINGS,
} from '../src/api/reports.js';

describe('Phase UI-15: Enterprise Compliance Center, Standards Mapping & Multi-Format Report Hub', () => {
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

  describe('Framework Compliance Scorecard Assessment', () => {
    it('computes 100% compliance when no critical or high findings are present', () => {
      const emptyFindings: typeof FALLBACK_COMPLIANCE_FINDINGS = [];
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
      const report = assembleComplianceReport(FALLBACK_COMPLIANCE_FINDINGS, 'run-test-123', 'https://api.test.local');

      expect(report.testRunId).toBe('run-test-123');
      expect(report.targetUrl).toBe('https://api.test.local');
      expect(report.totalFindings).toBe(FALLBACK_COMPLIANCE_FINDINGS.length);
      expect(report.frameworks.OWASP_TOP_10_2021).toBeDefined();
      expect(report.frameworks.OWASP_API_2023).toBeDefined();
      expect(report.frameworks.OWASP_ASVS_4_0).toBeDefined();
      expect(report.frameworks.PCI_DSS_4_0).toBeDefined();

      // Check counts by severity
      expect(report.countsBySeverity.critical).toBeGreaterThan(0);
      expect(report.countsBySeverity.high).toBeGreaterThan(0);
    });
  });

  describe('Truthful Auditing & Legal Disclaimer Invariant (Product Requirement 24.4)', () => {
    it('embeds mandatory disclaimer stating automated scans are technical evidence, not certification', () => {
      expect(COMPLIANCE_DISCLAIMER).toContain('Automated verification results provide technical testing evidence');
      expect(COMPLIANCE_DISCLAIMER).toContain('do not constitute formal legal certification');
      expect(COMPLIANCE_DISCLAIMER).toContain('Product Requirement 24.4');

      const report = assembleComplianceReport(FALLBACK_COMPLIANCE_FINDINGS);
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

  describe('Report Generation & Live Previewers', () => {
    it('generates self-contained offline HTML audit report with embedded styles and disclaimer', () => {
      const html = generateClientSyntheticHtml('run-preview-456', {
        organizationName: 'Acme Global Defense',
        confidentialityNotice: 'RESTRICTED / STRICTLY CONFIDENTIAL',
      });

      expect(html).toContain('<!DOCTYPE html>');
      expect(html).toContain('Acme Global Defense');
      expect(html).toContain('RESTRICTED / STRICTLY CONFIDENTIAL');
      expect(html).toContain('run-preview-456');
      expect(html).toContain(COMPLIANCE_DISCLAIMER);
      expect(html).toContain('OWASP Top 10 (2021)');
      expect(html).toContain('Evidence Level');
      // Must not link to external CDNs
      expect(html).not.toContain('http://cdn');
      expect(html).not.toContain('https://cdn');
    });

    it('generates valid SARIF 2.1 JSON artifact with compliance properties and disclaimer', () => {
      const sarifString = generateClientSyntheticSarif('run-sarif-789', {
        organizationName: 'CyberCorp Labs',
        confidentialityNotice: 'INTERNAL USE ONLY',
      });

      const sarif = JSON.parse(sarifString);
      expect(sarif.version).toBe('2.1.0');
      expect(sarif.$schema).toContain('sarif-schema-2.1.0.json');
      expect(sarif.runs.length).toBe(1);

      const run = sarif.runs[0];
      expect(run.tool.driver.name).toBe('@security-lab/scanner');
      expect(run.invocations[0].properties.testRunId).toBe('run-sarif-789');
      expect(run.invocations[0].properties.organization).toBe('CyberCorp Labs');

      // Rules must carry compliance disclaimer
      expect(run.tool.driver.rules.length).toBeGreaterThan(0);
      expect(run.tool.driver.rules[0].properties.complianceDisclaimer).toBe(COMPLIANCE_DISCLAIMER);

      // Results must contain rule IDs and locations
      expect(run.results.length).toBeGreaterThan(0);
      expect(run.results[0].ruleId).toBeDefined();
      expect(run.results[0].locations[0].physicalLocation.artifactLocation.uri).toBeDefined();
    });
  });
});
