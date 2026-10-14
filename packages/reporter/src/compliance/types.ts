import { Finding, FindingSeverity } from '@security-lab/domain';

export interface OwaspTop10Mapping {
  id: string; // e.g. "A01:2021"
  name: string; // e.g. "Broken Access Control"
  cweList: string[];
  description: string;
}

export interface AsvsMapping {
  sectionId: string; // e.g. "V4"
  sectionName: string; // e.g. "Access Control Verification Standard"
  chapterId?: string; // e.g. "V4" (alias for sectionId)
  chapterName?: string; // alias for sectionName
  requirementId: string; // e.g. "V4.1.1"
  level: 1 | 2 | 3;
  description: string;
}

export interface PciDssMapping {
  requirementId: string; // e.g. "6.5.8"
  section: string; // e.g. "Requirement 6: Develop and Maintain Secure Systems and Software"
  title: string; // e.g. "Improper Access Control (BOLA, IDOR, Privilege Escalation)"
  description: string;
}

export interface ComplianceMapping {
  owaspTop10: OwaspTop10Mapping;
  asvs: AsvsMapping;
  pciDss: PciDssMapping;
  cwe: string;
}

export interface CategoryComplianceScore {
  id: string;
  name: string;
  status: 'COMPLIANT' | 'NON_COMPLIANT';
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  findingIds: string[];
}

export interface FrameworkComplianceAssessment {
  framework: 'OWASP_TOP_10_2021' | 'OWASP_ASVS_4_0' | 'PCI_DSS_4_0';
  frameworkName: string;
  totalControlsEvaluated: number;
  compliantControlsCount: number;
  nonCompliantControlsCount: number;
  compliancePercentage: number;
  overallStatus: 'PASS' | 'FAIL' | 'NEEDS_REVIEW';
  categories: CategoryComplianceScore[];
}

export interface EnrichedComplianceFinding extends Finding {
  compliance: ComplianceMapping;
}

export interface OverallComplianceReport {
  testRunId: string;
  targetUrl: string;
  evaluatedAt: string;
  totalFindings: number;
  countsBySeverity: Record<FindingSeverity, number>;
  owaspTop10: FrameworkComplianceAssessment;
  asvs: FrameworkComplianceAssessment;
  pciDss: FrameworkComplianceAssessment;
  frameworks: {
    owaspTop10: FrameworkComplianceAssessment;
    asvs: FrameworkComplianceAssessment;
    pciDss: FrameworkComplianceAssessment;
  };
  findings: EnrichedComplianceFinding[];
}
