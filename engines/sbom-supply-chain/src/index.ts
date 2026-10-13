import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  TestEngine,
  TestCapability,
  ExecutionContext,
  TestInput,
  TestResult,
  ValidationResult,
  RawEngineFinding,
  RawEngineMetric,
  dynamicWorkerEngineRegistry,
} from '@security-lab/engine-sdk';
import { createLogger } from '@security-lab/logger';
import {
  SbomEngineOptions,
  SbomEngineOptionsSchema,
  SbomExecutionSummary,
  ParsedSbom,
  SbomParserResult,
} from './types.js';
import { parseCycloneDXJson } from './parsers/cyclonedx.js';
import { parseSpdxJson } from './parsers/spdx.js';
import { parsePackageLockJson } from './parsers/lockfile.js';
import { evaluateLicenseCompliance } from './license-checker.js';
import { OsvClient } from './osv-client.js';

export * from './types.js';
export * from './parsers/cyclonedx.js';
export * from './parsers/spdx.js';
export * from './parsers/lockfile.js';
export * from './license-checker.js';
export * from './osv-client.js';

const logger = createLogger({ name: 'engine-sbom-supply-chain' });

export class SbomSupplyChainEngine implements TestEngine {
  readonly id = 'engine-sbom-supply-chain';
  readonly version = '1.0.0';
  readonly executionClass = 'class_a_native' as const;

  capabilities(): TestCapability[] {
    return [
      {
        id: 'sbom_ingestion',
        name: 'CycloneDX & SPDX SBOM Document Parsing',
        category: 'passive_analysis',
        description:
          'Statically ingests and extracts software component inventories from standard CycloneDX 1.4/1.5 JSON, SPDX 2.2/2.3 JSON, and npm lockfiles.',
        isDisruptive: false,
      },
      {
        id: 'osv_vulnerability_mapping',
        name: 'Open Source Vulnerability (OSV) Advisory Matching',
        category: 'passive_analysis',
        description:
          'Correlates software components against OSV and GitHub Advisory databases to detect known CVEs, CVSS scores, and remediation upgrades.',
        isDisruptive: false,
      },
      {
        id: 'license_compliance_audit',
        name: 'Open Source Software (OSS) License Policy Audit',
        category: 'compliance_check',
        description:
          'Evaluates component SPDX license expressions against organizational license policies to flag copyleft (AGPL, GPL-3.0) and non-commercial restrictions.',
        isDisruptive: false,
      },
    ];
  }

  validate(input: TestInput): ValidationResult {
    const opts = (input.options || {}) as Record<string, unknown>;
    const hasSbomContent = typeof opts.sbomContent === 'string' && opts.sbomContent.trim().length > 0;
    const hasFilePath = typeof opts.sbomFilePath === 'string' && opts.sbomFilePath.trim().length > 0;
    const isFileUrl = typeof input.targetUrl === 'string' && input.targetUrl.startsWith('file://');
    const isSbomUrl = typeof input.targetUrl === 'string' && input.targetUrl.startsWith('sbom://');

    if (!hasSbomContent && !hasFilePath && !isFileUrl && !isSbomUrl) {
      return {
        valid: false,
        errors: [
          {
            path: 'options',
            message:
              'SBOM Engine requires either options.sbomContent, options.sbomFilePath, or a targetUrl with file:// or sbom:// protocol.',
          },
        ],
      };
    }

    return { valid: true };
  }

  async execute(input: TestInput, context: ExecutionContext): Promise<TestResult> {
    const startTime = Date.now();
    const rawOptions = (input.options || {}) as Record<string, unknown>;
    const options: SbomEngineOptions = SbomEngineOptionsSchema.parse(rawOptions);

    context.reportProgress?.(5, 'Initializing Software Supply Chain & SBOM Security Audit...');

    // 1. Ingest raw SBOM content from options or local file
    let rawContent: string | undefined = options.sbomContent;
    let sourceFilePath: string | undefined = options.sbomFilePath;

    if (!rawContent && options.sbomFilePath) {
      try {
        const resolved = path.resolve(options.sbomFilePath);
        if (fs.existsSync(resolved)) {
          rawContent = fs.readFileSync(resolved, 'utf8');
          sourceFilePath = resolved;
        }
      } catch (err: unknown) {
        logger.warn({ error: String(err), filePath: options.sbomFilePath }, 'Could not read sbomFilePath');
      }
    }

    if (!rawContent && typeof input.targetUrl === 'string' && input.targetUrl.startsWith('file://')) {
      try {
        const localPath = fileURLToPath(input.targetUrl);
        if (fs.existsSync(localPath)) {
          rawContent = fs.readFileSync(localPath, 'utf8');
          sourceFilePath = localPath;
        }
      } catch (err: unknown) {
        logger.warn({ error: String(err), targetUrl: input.targetUrl }, 'Could not read file from targetUrl');
      }
    }

    if (!rawContent || rawContent.trim().length === 0) {
      return {
        engineId: this.id,
        durationMs: Date.now() - startTime,
        success: false,
        findings: [],
        metrics: [],
        error: 'No SBOM content provided or accessible from input source.',
      };
    }

    // 2. Parse SBOM into normalized components
    context.reportProgress?.(20, 'Parsing SBOM components and dependency graph...');
    const parseResult = this.detectAndParseSbom(rawContent, options.format, sourceFilePath);

    const findings: RawEngineFinding[] = [];
    const metrics: RawEngineMetric[] = [];

    if (parseResult.errors.length > 0 && !parseResult.sbom) {
      const errHash = crypto.createHash('sha256').update(parseResult.errors.join(';')).digest('hex');
      findings.push({
        title: 'SBOM Parsing Failure',
        description: `Failed to parse SBOM document: ${parseResult.errors.join('; ')}`,
        severity: 'low',
        category: 'syntax_validation',
        recommendation: 'Ensure SBOM conforms to standard CycloneDX 1.4/1.5 or SPDX 2.2/2.3 JSON specification.',
        evidence: {
          request: { url: input.targetUrl, headers: { Host: 'localhost' }, method: 'SBOM_INGEST' },
          response: { statusCode: 0, headers: {}, body: rawContent.slice(0, 500) },
          immutableHash: errHash,
          metadata: { evidenceHash: errHash, errors: parseResult.errors },
        },
      });

      return {
        engineId: this.id,
        durationMs: Date.now() - startTime,
        success: true,
        findings,
        metrics: [{ name: 'sbom_components_total', value: 0, unit: 'count' }],
        rawOutput: JSON.stringify({ errors: parseResult.errors }, null, 2),
      };
    }

    const sbom = parseResult.sbom as ParsedSbom;
    const components = sbom.components;

    context.reportProgress?.(40, `Ingested ${components.length} components. Checking software license policies...`);

    // 3. License Compliance Policy Audit
    const licenseResults = evaluateLicenseCompliance(components, options.licensePolicy);
    for (const licRes of licenseResults) {
      const comp = licRes.component;
      const evidenceHash = crypto
        .createHash('sha256')
        .update(`license_violation:${comp.name}:${comp.version}:${licRes.disallowedLicense}`)
        .digest('hex');

      const loc = comp.location || `${comp.name}@${comp.version}`;

      findings.push({
        title: `Disallowed Software License (${comp.name}@${comp.version}: ${licRes.disallowedLicense || 'Unknown'})`,
        description: licRes.message || `Component "${comp.name}@${comp.version}" declares an unapproved license.`,
        severity: options.licensePolicy?.disallowedLicenseSeverity || 'high',
        category: 'compliance',
        recommendation: `Replace "${comp.name}" with an alternative library licensed under a permissive license (e.g. MIT, Apache-2.0, BSD), or obtain commercial waiver approval.`,
        evidence: {
          request: {
            url: input.targetUrl,
            headers: { Host: 'localhost', Component: `${comp.name}@${comp.version}` },
            method: 'LICENSE_AUDIT',
          },
          response: {
            statusCode: 0,
            headers: {},
            body: `Component: ${comp.name}@${comp.version}\nDeclared Licenses: ${comp.licenses.join(', ')}\nViolation: ${licRes.disallowedLicense}`,
          },
          immutableHash: evidenceHash,
          metadata: {
            componentName: comp.name,
            version: comp.version,
            license: licRes.disallowedLicense,
            location: loc,
            evidenceHash,
          },
        },
        metadata: {
          location: loc,
        },
      });
    }

    // 4. OSV Advisory Matching
    let vulnerableComponentsCount = 0;
    let totalVulnsCount = 0;

    if (options.enableOsvLookup !== false) {
      context.reportProgress?.(60, 'Correlating component inventory against OSV vulnerability advisories...');
      const osvClient = new OsvClient({ offlineMode: options.offlineMode });
      const advisoryMap = await osvClient.matchComponents(components);

      for (const [compKey, advisories] of advisoryMap.entries()) {
        if (advisories.length === 0) continue;
        vulnerableComponentsCount++;

        const comp = components.find((c) => `${c.name}@${c.version}` === compKey);
        const compName = comp?.name || compKey.split('@')[0] || compKey;
        const compVersion = comp?.version || compKey.split('@')[1] || 'unknown';
        const loc = comp?.location || compKey;

        for (const adv of advisories) {
          totalVulnsCount++;
          const vulnId = adv.aliases?.[0] || adv.id;
          const evidenceHash = crypto
            .createHash('sha256')
            .update(`osv_advisory:${compKey}:${adv.id}:${vulnId}`)
            .digest('hex');

          const fixedText = adv.fixedVersion ? ` Upgrade to version ${adv.fixedVersion} or higher.` : '';

          findings.push({
            title: `${vulnId} in ${compName}@${compVersion}: ${adv.summary || 'Known Vulnerability'}`,
            description:
              adv.details ||
              `Security advisory ${adv.id} affects ${compName}@${compVersion}.${adv.cvssScore ? ` (CVSS: ${adv.cvssScore})` : ''}`,
            severity: adv.severity,
            category: 'software_composition_analysis',
            recommendation: adv.fixedVersion
              ? `Upgrade ${compName} to version ${adv.fixedVersion} or higher to resolve ${vulnId}.`
              : `Review upstream vendor advisory at ${adv.referenceUrls?.[0] || 'https://osv.dev'} for remediation guidance.${fixedText}`,
            evidence: {
              request: {
                url: input.targetUrl,
                headers: { Host: 'localhost', Component: compKey },
                method: 'VULNERABILITY_LOOKUP',
              },
              response: {
                statusCode: 0,
                headers: {},
                body: `Vulnerability ID: ${adv.id}\nAliases: ${adv.aliases.join(', ')}\nSeverity: ${adv.severity} (CVSS: ${adv.cvssScore || 'N/A'})\nFixed In: ${adv.fixedVersion || 'N/A'}\nReferences: ${adv.referenceUrls.join(', ')}`,
              },
              immutableHash: evidenceHash,
              metadata: {
                vulnerabilityId: adv.id,
                aliases: adv.aliases,
                componentName: compName,
                version: compVersion,
                fixedVersion: adv.fixedVersion,
                cvssScore: adv.cvssScore,
                location: loc,
                evidenceHash,
              },
            },
            metadata: {
              location: loc,
              vulnerabilityId: adv.id,
            },
          });
        }
      }
    }

    // 5. Aggregate Metrics and Execution Summary
    const componentsByEcosystem: Record<string, number> = {};
    for (const c of components) {
      const eco = c.ecosystem || 'unknown';
      componentsByEcosystem[eco] = (componentsByEcosystem[eco] || 0) + 1;
    }

    const vulnerabilitiesBySeverity: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    for (const f of findings) {
      vulnerabilitiesBySeverity[f.severity] = (vulnerabilitiesBySeverity[f.severity] || 0) + 1;
    }

    const penalty =
      (vulnerabilitiesBySeverity.critical ?? 0) * 25 +
      (vulnerabilitiesBySeverity.high ?? 0) * 15 +
      (vulnerabilitiesBySeverity.medium ?? 0) * 5 +
      (vulnerabilitiesBySeverity.low ?? 0) * 1;
    const riskScore = Math.max(0, 100 - penalty);

    metrics.push(
      { name: 'sbom_components_total', value: components.length, unit: 'count' },
      { name: 'sbom_vulnerable_components_count', value: vulnerableComponentsCount, unit: 'count' },
      { name: 'sbom_vulnerabilities_total', value: totalVulnsCount, unit: 'count' },
      { name: 'sbom_license_violations_total', value: licenseResults.length, unit: 'count' },
      { name: 'sbom_risk_score', value: riskScore, unit: 'score' },
    );

    const durationMs = Date.now() - startTime;
    context.reportProgress?.(
      100,
      `SBOM audit complete in ${durationMs}ms. Analyzed ${components.length} components with ${findings.length} findings.`,
    );

    logger.info(
      {
        componentsCount: components.length,
        vulnerabilitiesCount: totalVulnsCount,
        licenseViolations: licenseResults.length,
        durationMs,
      },
      'SBOM Supply Chain Security audit completed successfully',
    );

    const summary: SbomExecutionSummary = {
      totalComponents: components.length,
      vulnerableComponents: vulnerableComponentsCount,
      totalVulnerabilities: totalVulnsCount,
      licenseViolations: licenseResults.length,
      componentsByEcosystem,
      vulnerabilitiesBySeverity,
      durationMs,
    };

    return {
      engineId: this.id,
      success: true,
      durationMs,
      findings,
      metrics,
      rawOutput: JSON.stringify(summary, null, 2),
    };
  }

  private detectAndParseSbom(raw: string, explicitFormat?: string, filePath?: string): SbomParserResult {
    let parsedJson: any;
    try {
      parsedJson = JSON.parse(raw);
    } catch (err: unknown) {
      return { errors: [`Invalid JSON in SBOM file: ${err instanceof Error ? err.message : String(err)}`] };
    }

    if (explicitFormat === 'cyclonedx_json' || parsedJson.bomFormat === 'CycloneDX') {
      return parseCycloneDXJson(raw, filePath);
    }

    if (explicitFormat === 'spdx_json' || String(parsedJson.spdxVersion || '').startsWith('SPDX')) {
      return parseSpdxJson(raw, filePath);
    }

    if (explicitFormat === 'package_lock' || parsedJson.lockfileVersion || (parsedJson.packages && parsedJson.name)) {
      return parsePackageLockJson(raw, filePath);
    }

    // Default heuristics: check for components or packages
    if (Array.isArray(parsedJson.components)) {
      return parseCycloneDXJson(raw, filePath);
    }

    if (Array.isArray(parsedJson.packages)) {
      return parseSpdxJson(raw, filePath);
    }

    return {
      errors: ['Unrecognized SBOM schema format. Expected CycloneDX JSON or SPDX JSON document.'],
    };
  }
}

export const sbomSupplyChainEngine = new SbomSupplyChainEngine();
export const sbomEngine = sbomSupplyChainEngine;
dynamicWorkerEngineRegistry.register(sbomSupplyChainEngine);
