import {
  SbomComponent,
  SbomFormat,
} from '@security-lab/contracts';

export * from '@security-lab/contracts';

export interface ParsedSbom {
  format: SbomFormat;
  specVersion?: string;
  metadata?: {
    timestamp?: string;
    tools?: string[];
    authors?: string[];
    component?: Partial<SbomComponent>;
  };
  components: SbomComponent[];
  rawText?: string;
  filePath?: string;
}

export interface SbomParserResult {
  sbom?: ParsedSbom;
  errors: string[];
}

export interface OsvPackageRef {
  name: string;
  ecosystem?: string;
  purl?: string;
}

export interface OsvQuery {
  package: OsvPackageRef;
  version?: string;
}

export interface OsvAffectedRange {
  type: string;
  repo?: string;
  events: Array<{ introduced?: string; fixed?: string; limit?: string }>;
}

export interface OsvSeverity {
  type: string;
  score: string;
}

export interface OsvVulnerabilityItem {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  published?: string;
  severity?: OsvSeverity[];
  affected?: Array<{
    package: OsvPackageRef;
    ranges?: OsvAffectedRange[];
    versions?: string[];
  }>;
  references?: Array<{ type: string; url: string }>;
}

export interface OsvBatchResponse {
  results: Array<{
    vulns?: OsvVulnerabilityItem[];
  }>;
}

export interface LicenseCheckResult {
  component: SbomComponent;
  disallowedLicense?: string;
  isViolation: boolean;
  message?: string;
}
