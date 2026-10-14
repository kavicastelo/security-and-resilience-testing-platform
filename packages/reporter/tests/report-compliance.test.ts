import { describe, it, expect } from 'vitest';
import { Finding, TestRun } from '@security-lab/domain';
import { ReportInput } from '@security-lab/contracts';
import {
  mapFindingToCompliance,
  mapRuleToOwasp,
  mapRuleToAsvs,
  mapRuleToPciDss,
  assessCompliance,
  generateStandaloneComplianceHtmlReport,
  generateExecutivePdfReport,
  generateEnrichedSarifReport,
  generateComplianceJsonReport,
  PdfDocumentBuilder,
} from '../src/index.js';

function createMockFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: overrides.id || 'f1111111-1111-1111-1111-111111111111',
    fingerprint: overrides.fingerprint || 'fp-mock-1',
    title: overrides.title || 'SQL Injection in /api/v1/users',
    category: overrides.category || 'injection',
    severity: overrides.severity || 'high',
    confidence: overrides.confidence || 'firm',
    status: overrides.status || 'open',
    description: overrides.description || 'Raw SQL statement executed without parameterization.',
    recommendation: overrides.recommendation || 'Use parameterized queries or ORM bindings.',
    testDefinitionId: overrides.testDefinitionId || 'sql-injection-check',
    testRunId: overrides.testRunId || 'r1111111-1111-1111-1111-111111111111',
    executionId: overrides.executionId || 'e1111111-1111-1111-1111-111111111111',
    targetId: overrides.targetId || 't1111111-1111-1111-1111-111111111111',
    occurrenceCount: overrides.occurrenceCount || 1,
    firstDetectedAt: overrides.firstDetectedAt || new Date('2026-10-14T00:00:00Z'),
    lastDetectedAt: overrides.lastDetectedAt || new Date('2026-10-14T01:00:00Z'),
    metadata: overrides.metadata || { ruleId: 'SQLI-001', cwe: 'CWE-89' },
    flappingScore: overrides.flappingScore || 0,
    isFlapping: overrides.isFlapping || false,
    triageHistory: overrides.triageHistory || [],
  };
}

function createMockTestRun(): TestRun {
  return {
    id: 'r1111111-1111-1111-1111-111111111111',
    targetId: 't1111111-1111-1111-1111-111111111111',
    status: 'completed',
    createdAt: new Date('2026-10-14T00:00:00Z'),
    startedAt: new Date('2026-10-14T00:00:05Z'),
    completedAt: new Date('2026-10-14T00:01:25Z'),
  };
}

describe('Enterprise Compliance Mapping Engine', () => {
  it('maps platform rule IDs and categories to OWASP Top 10 2021', () => {
    const sqli = mapRuleToOwasp('SQLI-001', 'injection', 'SQL Injection');
    expect(sqli.id).toBe('A03:2021');
    expect(sqli.name).toBe('Injection');
    expect(sqli.cweList).toContain('CWE-89');

    const bola = mapRuleToOwasp('BOLA-001', 'auth', 'Broken Object Level Authorization');
    expect(bola.id).toBe('A01:2021');
    expect(bola.name).toBe('Broken Access Control');

    const crypto = mapRuleToOwasp('CRYPTO-001', 'cryptography', 'Weak Cipher Suite');
    expect(crypto.id).toBe('A02:2021');
    expect(crypto.name).toBe('Cryptographic Failures');

    const ssrf = mapRuleToOwasp('SSRF-001', 'network', 'Server-Side Request Forgery');
    expect(ssrf.id).toBe('A10:2021');
    expect(ssrf.name).toBe('Server-Side Request Forgery (SSRF)');

    const cors = mapRuleToOwasp('CORS-001', 'headers', 'Overly Permissive CORS Origin');
    expect(cors.id).toBe('A01:2021');

    const logInjection = mapRuleToOwasp('LOG-INJECTION-001', 'logging', 'Log Injection Flaw');
    expect(logInjection.id).toBe('A09:2021');
  });

  it('maps platform rule IDs to OWASP ASVS 4.0 requirements', () => {
    const sqliAsvs = mapRuleToAsvs('SQLI-001', 'injection');
    expect(sqliAsvs.chapterId).toBe('V5');
    expect(sqliAsvs.sectionName).toContain('Validation');

    const authAsvs = mapRuleToAsvs('AUTH-001', 'authentication');
    expect(authAsvs.chapterId).toBe('V2');
    expect(authAsvs.sectionName).toContain('Authentication');

    const corsAsvs = mapRuleToAsvs('CORS-001', 'access_control');
    expect(corsAsvs.chapterId).toBe('V4');
    expect(corsAsvs.sectionName).toContain('Access Control');

    const configAsvs = mapRuleToAsvs('CONFIG-001', 'configuration');
    expect(configAsvs.chapterId).toBe('V14');
    expect(configAsvs.sectionName).toContain('Configuration');

    const tlsAsvs = mapRuleToAsvs('TLS-001', 'cryptography');
    expect(tlsAsvs.chapterId).toBe('V9');
    expect(tlsAsvs.sectionName).toContain('Communications');
  });

  it('maps platform rule IDs to PCI-DSS 4.0 Section 6 requirements', () => {
    const sqliPci = mapRuleToPciDss('SQLI-001', 'injection');
    expect(sqliPci.requirementId).toBe('6.5.1');
    expect(sqliPci.section).toContain('Requirement 6');

    const xssPci = mapRuleToPciDss('XSS-001', 'web');
    expect(xssPci.requirementId).toBe('6.5.7');

    const headerPci = mapRuleToPciDss('CSP-001', 'headers');
    expect(headerPci.requirementId).toBe('6.4.3');

    const vulnDepPci = mapRuleToPciDss('VULN-DEP-001', 'dependencies');
    expect(vulnDepPci.requirementId).toBe('6.3.1');
  });

  it('maps a complete Finding object to all 3 frameworks with CWE resolution', () => {
    const finding = createMockFinding({
      metadata: { ruleId: 'BOLA-001', cwe: 'CWE-284' },
      category: 'access_control',
    });

    const mapping = mapFindingToCompliance(finding);
    expect(mapping.owaspTop10.id).toBe('A01:2021');
    expect(mapping.asvs.chapterId).toBe('V4');
    expect(mapping.pciDss.requirementId).toBe('6.5.8');
    expect(mapping.cwe).toBe('CWE-284');
  });

  it('calculates comprehensive compliance scorecards across all frameworks', () => {
    const findings: Finding[] = [
      createMockFinding({
        id: 'f1',
        severity: 'critical',
        metadata: { ruleId: 'SQLI-001' },
      }),
      createMockFinding({
        id: 'f2',
        severity: 'high',
        metadata: { ruleId: 'BOLA-001' },
      }),
      createMockFinding({
        id: 'f3',
        severity: 'medium',
        metadata: { ruleId: 'CORS-001' },
      }),
    ];

    const report = assessCompliance(findings, 'test-run-123', 'https://api.example.com');
    expect(report.totalFindings).toBe(3);
    expect(report.countsBySeverity.critical).toBe(1);
    expect(report.countsBySeverity.high).toBe(1);
    expect(report.countsBySeverity.medium).toBe(1);
    expect(report.countsBySeverity.low).toBe(0);

    // OWASP assessment checks
    expect(report.frameworks.owaspTop10.categories.length).toBe(10);
    const a03 = report.frameworks.owaspTop10.categories.find((c) => c.id === 'A03:2021');
    expect(a03?.findingsCount).toBe(1);
    expect(a03?.status).toBe('NON_COMPLIANT');

    // ASVS assessment checks
    expect(report.frameworks.asvs.categories.length).toBeGreaterThan(5);

    // PCI-DSS assessment checks
    expect(report.frameworks.pciDss.categories.length).toBeGreaterThan(5);
    expect(report.frameworks.pciDss.compliancePercentage).toBeLessThan(100);
  });
});

describe('Standalone Interactive HTML Report Generator', () => {
  it('generates a 100% self-contained HTML report with embedded styles and charts', () => {
    const mockFinding = createMockFinding();
    const testRun = createMockTestRun();
    const reportInput: ReportInput = {
      testRun,
      target: { id: testRun.targetId, name: 'Production Gateway', baseUrl: 'https://gateway.internal' },
      executions: [],
      findings: [mockFinding],
      metrics: [],
      evidence: [],
    };

    const html = generateStandaloneComplianceHtmlReport(reportInput);

    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('<html lang="en">');
    expect(html).toContain('Production Gateway');
    expect(html).toContain('https://gateway.internal');
    expect(html).toContain('SQL Injection in /api/v1/users');

    // 100% self-contained check: no remote scripts or external CDNs
    expect(html).not.toMatch(/<script\s+[^>]*src=["']https?:\/\//i);
    expect(html).not.toMatch(/<link\s+[^>]*href=["']https?:\/\//i);

    // Embedded dark/light mode toggle
    expect(html).toContain('data-theme="dark"');
    expect(html).toContain('theme-toggle');

    // Inline SVG chart
    expect(html).toContain('class="donut-chart"');
    expect(html).toContain('viewBox="0 0 100 100"');

    // Interactive finding filter markup
    expect(html).toContain('filter-btn');
    expect(html).toContain('search-input');
    expect(html).toContain('data-severity="high"');

    // Compliance badges embedded
    expect(html).toContain('OWASP Top 10');
    expect(html).toContain('ASVS 4.0');
    expect(html).toContain('PCI-DSS');
  });

  it('sanitizes unsafe finding evidence against stored XSS attacks', () => {
    const xssFinding = createMockFinding({
      title: '<script>alert("XSS")</script> Parameter Tampering',
      description: 'Payload: <img src="x" onerror="stealTokens()"> and & special chars',
      recommendation: '<a href="javascript:void(0)">Fix this</a>',
    });

    const reportInput: ReportInput = {
      testRun: createMockTestRun(),
      target: { id: 't1', name: 'App', baseUrl: 'http://test' },
      executions: [],
      findings: [xssFinding],
      metrics: [],
      evidence: [],
    };

    const html = generateStandaloneComplianceHtmlReport(reportInput);

    // Verifies raw unescaped script tag is not present
    expect(html).not.toContain('<script>alert("XSS")</script>');
    expect(html).not.toContain('<img src="x" onerror="stealTokens()">');

    // Verifies escaped HTML entities are present
    expect(html).toContain('&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;');
    expect(html).toContain('&lt;img src=&quot;x&quot; onerror=&quot;stealTokens()&quot;&gt;');
  });
});

describe('Executive Headless PDF Generator', () => {
  it('generates a valid, multi-page vector PDF 1.4 buffer', () => {
    const findings: Finding[] = [
      createMockFinding({
        title: 'Critical Remote Code Execution',
        severity: 'critical',
        metadata: { ruleId: 'RCE-001' },
      }),
      createMockFinding({
        title: 'High Severity BOLA in /api/v1/orders',
        severity: 'high',
        metadata: { ruleId: 'BOLA-001' },
      }),
      createMockFinding({
        title: 'Medium CORS Wildcard',
        severity: 'medium',
        metadata: { ruleId: 'CORS-001' },
      }),
    ];

    const reportInput: ReportInput = {
      testRun: createMockTestRun(),
      target: { id: 't1', name: 'API Microservices Cluster', baseUrl: 'https://cluster.internal' },
      executions: [],
      findings,
      metrics: [],
      evidence: [],
    };

    const pdfBuffer = generateExecutivePdfReport(reportInput);

    expect(Buffer.isBuffer(pdfBuffer)).toBe(true);
    expect(pdfBuffer.length).toBeGreaterThan(1000);

    const pdfString = pdfBuffer.toString('binary');

    // Compliant PDF 1.4 Header and Trailer
    expect(pdfString.startsWith('%PDF-1.4')).toBe(true);
    expect(pdfString).toContain('%%EOF');

    // Structural PDF objects
    expect(pdfString).toContain('/Type /Catalog');
    expect(pdfString).toContain('/Type /Pages');
    expect(pdfString).toContain('/Type /Page');
    expect(pdfString).toContain('/Type /Font');
    expect(pdfString).toContain('/BaseFont /Helvetica');

    // Content verification
    expect(pdfString).toContain('SECURITY LAB & COMPLIANCE ASSESSMENT');
    expect(pdfString).toContain('EXECUTIVE PENETRATION TEST & AUDIT REPORT');
    expect(pdfString).toContain('API Microservices Cluster');
    expect(pdfString).toContain('OWASP Top 10');
    expect(pdfString).toContain('PCI-DSS');
    expect(pdfString).toContain('Critical Remote Code Execution');
  });

  it('PdfDocumentBuilder handles coordinate transformations and wrapped text gracefully', () => {
    const builder = new PdfDocumentBuilder();
    builder.startPage();
    builder.drawRect(50, 700, 200, 30, 0.1, 0.2, 0.3, true);
    builder.drawText('Sample Header Text', 55, 710, 12, true, { r: 1, g: 1, b: 1 });
    const nextY = builder.drawWrappedText(
      'This is a long test paragraph that will be automatically wrapped across multiple lines when drawing in the PDF document without overflowing the right margin.',
      50,
      680,
      300,
      10,
      12,
    );
    expect(nextY).toBeLessThan(680);

    const pdfBuf = builder.build();
    expect(pdfBuf.length).toBeGreaterThan(100);
    expect(pdfBuf.toString('binary')).toContain('%PDF-1.4');
  });
});

describe('SARIF 2.1.0 & Compliance JSON Reports', () => {
  it('enriches SARIF export with compliance taxonomies and rule properties', () => {
    const findings = [
      createMockFinding({
        metadata: { ruleId: 'SQLI-001', cwe: 'CWE-89' },
      }),
    ];

    const reportInput: ReportInput = {
      testRun: createMockTestRun(),
      target: { id: 't1', name: 'App', baseUrl: 'http://test' },
      executions: [],
      findings,
      metrics: [],
      evidence: [],
    };

    const sarif = generateEnrichedSarifReport(reportInput);

    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs.length).toBe(1);
    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe('Security & Resilience Testing Platform');

    // Verify compliance properties attached to rules
    const rule = run.tool.driver.rules[0];
    expect(rule.properties?.compliance?.owaspTop10?.id).toBe('A03:2021');
    expect(rule.properties?.compliance?.asvs?.chapterId).toBe('V5');
    expect(rule.properties?.compliance?.pciDss?.requirementId).toBe('6.5.1');
  });

  it('generates structured compliance JSON report with frameworks and scorecard summary', () => {
    const findings = [
      createMockFinding({ severity: 'critical', metadata: { ruleId: 'SQLI-001' } }),
      createMockFinding({ severity: 'low', metadata: { ruleId: 'HEADER-001' } }),
    ];

    const reportInput: ReportInput = {
      testRun: createMockTestRun(),
      target: { id: 't1', name: 'App', baseUrl: 'http://test' },
      executions: [],
      findings,
      metrics: [],
      evidence: [],
    };

    const json = generateComplianceJsonReport(reportInput);

    expect(json.testRunId).toBe(reportInput.testRun.id);
    expect(json.totalFindings).toBe(2);
    expect(json.countsBySeverity.critical).toBe(1);
    expect(json.countsBySeverity.low).toBe(1);
    expect(json.frameworks.owaspTop10).toBeDefined();
    expect(json.frameworks.asvs).toBeDefined();
    expect(json.frameworks.pciDss).toBeDefined();
  });
});
