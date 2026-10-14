import { Finding, FindingSeverity } from '@security-lab/domain';
import {
  ComplianceMapping,
  EnrichedComplianceFinding,
  OverallComplianceReport,
  FrameworkComplianceAssessment,
  CategoryComplianceScore,
} from './types.js';
import { mapRuleToOwasp, OWASP_TOP_10_2021 } from './owasp.js';
import { mapRuleToAsvs, ASVS_CATEGORIES } from './asvs.js';
import { mapRuleToPciDss, PCI_DSS_REQUIREMENTS } from './pci-dss.js';

export * from './types.js';
export * from './owasp.js';
export * from './asvs.js';
export * from './pci-dss.js';

/**
 * Maps a single finding to OWASP Top 10, ASVS 4.0, and PCI-DSS 4.0 standards.
 */
export function mapFindingToCompliance(finding: Finding): ComplianceMapping {
  let ruleOrCweId = finding.title;
  if (finding.metadata) {
    if (typeof finding.metadata.ruleId === 'string' && finding.metadata.ruleId.trim()) {
      ruleOrCweId = finding.metadata.ruleId.trim();
    } else if (typeof finding.metadata.cwe === 'string' && finding.metadata.cwe.trim()) {
      ruleOrCweId = finding.metadata.cwe.trim();
    }
  }

  const owasp = mapRuleToOwasp(ruleOrCweId, finding.category, finding.title);
  const asvs = mapRuleToAsvs(ruleOrCweId, finding.category, finding.title);
  const pciDss = mapRuleToPciDss(ruleOrCweId, finding.category, finding.title);

  const cwe =
    typeof finding.metadata?.cwe === 'string' && finding.metadata.cwe
      ? finding.metadata.cwe
      : owasp.cweList[0] || 'CWE-699';

  return {
    owaspTop10: owasp,
    asvs,
    pciDss,
    cwe,
  };
}

/**
 * Assesses an array of findings against all compliance frameworks,
 * returning detailed scorecards, category pass/fail counts, and enriched findings.
 */
export function assessCompliance(
  findings: Finding[],
  testRunId = 'unknown',
  targetUrl = 'unknown',
): OverallComplianceReport {
  const countsBySeverity: Record<FindingSeverity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  const enrichedFindings: EnrichedComplianceFinding[] = [];

  for (const f of findings) {
    countsBySeverity[f.severity] = (countsBySeverity[f.severity] || 0) + 1;
    const compliance = mapFindingToCompliance(f);
    enrichedFindings.push({
      ...f,
      compliance,
    });
  }

  // 1. OWASP Top 10 Assessment
  const owaspCategoriesMap = new Map<string, CategoryComplianceScore>();
  for (const [id, cat] of Object.entries(OWASP_TOP_10_2021)) {
    owaspCategoriesMap.set(id, {
      id: cat.id,
      name: cat.name,
      status: 'COMPLIANT',
      findingsCount: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      findingIds: [],
    });
  }

  for (const ef of enrichedFindings) {
    const cat = owaspCategoriesMap.get(ef.compliance.owaspTop10.id);
    if (cat) {
      cat.findingsCount++;
      cat.findingIds.push(ef.id);
      if (ef.severity === 'critical') cat.criticalCount++;
      else if (ef.severity === 'high') cat.highCount++;
      else if (ef.severity === 'medium') cat.mediumCount++;
      else if (ef.severity === 'low') cat.lowCount++;

      // Non-compliant if active critical or high flaw exists
      if (ef.status !== 'resolved' && ef.status !== 'false_positive') {
        cat.status = 'NON_COMPLIANT';
      }
    }
  }

  const owaspCategories = Array.from(owaspCategoriesMap.values());
  const owaspCompliant = owaspCategories.filter((c) => c.status === 'COMPLIANT').length;
  const owaspTotal = owaspCategories.length;
  const owaspPercentage = Math.round((owaspCompliant / owaspTotal) * 100);

  const owaspAssessment: FrameworkComplianceAssessment = {
    framework: 'OWASP_TOP_10_2021',
    frameworkName: 'OWASP Top 10:2021 Web Application Security Risks',
    totalControlsEvaluated: owaspTotal,
    compliantControlsCount: owaspCompliant,
    nonCompliantControlsCount: owaspTotal - owaspCompliant,
    compliancePercentage: owaspPercentage,
    overallStatus: owaspPercentage === 100 ? 'PASS' : owaspPercentage >= 80 ? 'NEEDS_REVIEW' : 'FAIL',
    categories: owaspCategories,
  };

  // 2. ASVS 4.0 Assessment
  const asvsCategoriesMap = new Map<string, CategoryComplianceScore>();
  for (const [id, sec] of Object.entries(ASVS_CATEGORIES)) {
    asvsCategoriesMap.set(id, {
      id: sec.sectionId,
      name: sec.sectionName,
      status: 'COMPLIANT',
      findingsCount: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      findingIds: [],
    });
  }

  for (const ef of enrichedFindings) {
    const sec = asvsCategoriesMap.get(ef.compliance.asvs.sectionId);
    if (sec) {
      sec.findingsCount++;
      sec.findingIds.push(ef.id);
      if (ef.severity === 'critical') sec.criticalCount++;
      else if (ef.severity === 'high') sec.highCount++;
      else if (ef.severity === 'medium') sec.mediumCount++;
      else if (ef.severity === 'low') sec.lowCount++;

      if (ef.status !== 'resolved' && ef.status !== 'false_positive') {
        sec.status = 'NON_COMPLIANT';
      }
    }
  }

  const asvsCategories = Array.from(asvsCategoriesMap.values());
  const asvsCompliant = asvsCategories.filter((c) => c.status === 'COMPLIANT').length;
  const asvsTotal = asvsCategories.length;
  const asvsPercentage = Math.round((asvsCompliant / asvsTotal) * 100);

  const asvsAssessment: FrameworkComplianceAssessment = {
    framework: 'OWASP_ASVS_4_0',
    frameworkName: 'OWASP Application Security Verification Standard (ASVS 4.0)',
    totalControlsEvaluated: asvsTotal,
    compliantControlsCount: asvsCompliant,
    nonCompliantControlsCount: asvsTotal - asvsCompliant,
    compliancePercentage: asvsPercentage,
    overallStatus: asvsPercentage === 100 ? 'PASS' : asvsPercentage >= 80 ? 'NEEDS_REVIEW' : 'FAIL',
    categories: asvsCategories,
  };

  // 3. PCI-DSS 4.0 Assessment
  const pciCategoriesMap = new Map<string, CategoryComplianceScore>();
  for (const [id, req] of Object.entries(PCI_DSS_REQUIREMENTS)) {
    pciCategoriesMap.set(id, {
      id: req.requirementId,
      name: `${req.requirementId} - ${req.title}`,
      status: 'COMPLIANT',
      findingsCount: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      findingIds: [],
    });
  }

  for (const ef of enrichedFindings) {
    const req = pciCategoriesMap.get(ef.compliance.pciDss.requirementId);
    if (req) {
      req.findingsCount++;
      req.findingIds.push(ef.id);
      if (ef.severity === 'critical') req.criticalCount++;
      else if (ef.severity === 'high') req.highCount++;
      else if (ef.severity === 'medium') req.mediumCount++;
      else if (ef.severity === 'low') req.lowCount++;

      if (ef.status !== 'resolved' && ef.status !== 'false_positive') {
        req.status = 'NON_COMPLIANT';
      }
    }
  }

  const pciCategories = Array.from(pciCategoriesMap.values());
  const pciCompliant = pciCategories.filter((c) => c.status === 'COMPLIANT').length;
  const pciTotal = pciCategories.length;
  const pciPercentage = Math.round((pciCompliant / pciTotal) * 100);

  const pciAssessment: FrameworkComplianceAssessment = {
    framework: 'PCI_DSS_4_0',
    frameworkName: 'PCI-DSS v4.0 Requirement 6 (Secure Systems & Software)',
    totalControlsEvaluated: pciTotal,
    compliantControlsCount: pciCompliant,
    nonCompliantControlsCount: pciTotal - pciCompliant,
    compliancePercentage: pciPercentage,
    overallStatus: pciPercentage === 100 ? 'PASS' : pciPercentage >= 80 ? 'NEEDS_REVIEW' : 'FAIL',
    categories: pciCategories,
  };

  return {
    testRunId,
    targetUrl,
    evaluatedAt: new Date().toISOString(),
    totalFindings: findings.length,
    countsBySeverity,
    owaspTop10: owaspAssessment,
    asvs: asvsAssessment,
    pciDss: pciAssessment,
    frameworks: {
      owaspTop10: owaspAssessment,
      asvs: asvsAssessment,
      pciDss: pciAssessment,
    },
    findings: enrichedFindings,
  };
}
