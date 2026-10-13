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
  K8sAuditEngineOptions,
  K8sAuditEngineOptionsSchema,
  K8sAuditSummary,
  K8sWorkloadDocument,
  ParsedDockerfile,
  RuleEvaluationContext,
} from './types.js';
import { parseKubernetesManifests } from './manifest-parser.js';
import { parseDockerfile } from './dockerfile-parser.js';
import { ALL_K8S_RULES } from './rules/pss-rules.js';
import { ALL_DOCKERFILE_RULES } from './rules/dockerfile-rules.js';

export * from './types.js';
export * from './manifest-parser.js';
export * from './dockerfile-parser.js';
export * from './rules/pss-rules.js';
export * from './rules/dockerfile-rules.js';

const logger = createLogger({ name: 'engine-k8s-infra-audit' });

export class K8sInfraAuditEngine implements TestEngine {
  readonly id = 'engine-k8s-infra-audit';
  readonly version = '1.0.0';
  readonly executionClass = 'class_a_native' as const;

  capabilities(): TestCapability[] {
    return [
      {
        id: 'k8s_manifest_audit',
        name: 'Kubernetes Manifest & Workload Security Static Audit',
        category: 'passive_analysis',
        description:
          'Statically audits Kubernetes Deployments, StatefulSets, DaemonSets, Pods, and Jobs against CIS Benchmarks and Pod Security Standards.',
        isDisruptive: false,
      },
      {
        id: 'k8s_pss_enforcement',
        name: 'Pod Security Standards (PSS) & CIS Benchmark Enforcement',
        category: 'compliance_check',
        description:
          'Verifies workload securityContext invariants including runAsNonRoot, capability drops, and prohibited hostPath mounts.',
        isDisruptive: false,
      },
      {
        id: 'dockerfile_security_audit',
        name: 'Dockerfile Static Configuration & Secret Ingestion Audit',
        category: 'passive_analysis',
        description:
          'Audits container Dockerfiles for unpinned base images, hardcoded ENV secrets, and root user directives.',
        isDisruptive: false,
      },
    ];
  }

  validate(input: TestInput): ValidationResult {
    const opts = (input.options || {}) as Record<string, unknown>;
    const hasManifestYaml = typeof opts.manifestYaml === 'string' || typeof opts.yaml === 'string';
    const hasDockerfile = typeof opts.dockerfileContent === 'string' || typeof opts.dockerfile === 'string';
    const hasFilePaths = Array.isArray(opts.filePaths) && opts.filePaths.length > 0;
    const isFileUrl = typeof input.targetUrl === 'string' && input.targetUrl.startsWith('file://');
    const isK8sUrl = typeof input.targetUrl === 'string' && input.targetUrl.startsWith('k8s://');

    if (!hasManifestYaml && !hasDockerfile && !hasFilePaths && !isFileUrl && !isK8sUrl) {
      return {
        valid: false,
        errors: [
          {
            path: 'options',
            message:
              'K8s Infra Audit requires either options.manifestYaml, options.dockerfileContent, options.filePaths, or a targetUrl with file:// or k8s:// protocol.',
          },
        ],
      };
    }

    return { valid: true };
  }

  async execute(input: TestInput, context: ExecutionContext): Promise<TestResult> {
    const startTime = Date.now();
    const rawOptions = (input.options || {}) as Record<string, unknown>;
    const options: K8sAuditEngineOptions = K8sAuditEngineOptionsSchema.parse(rawOptions);

    context.reportProgress?.(5, 'Initializing Kubernetes & Cloud-Native Security Audit...');

    const k8sDocuments: K8sWorkloadDocument[] = [];
    const dockerfiles: ParsedDockerfile[] = [];
    const parseErrors: Array<{ message: string; line?: number; raw?: string }> = [];

    // 1. Ingest manifest YAML provided in options
    const manifestYamlString = options.manifestYaml || (rawOptions.yaml as string);
    if (manifestYamlString) {
      const parsed = parseKubernetesManifests(manifestYamlString, 'options.manifestYaml');
      k8sDocuments.push(...parsed.documents);
      parseErrors.push(...parsed.errors);
    }

    // 2. Ingest Dockerfile content provided in options
    const dockerfileString = options.dockerfileContent || (rawOptions.dockerfile as string);
    if (dockerfileString) {
      const parsed = parseDockerfile(dockerfileString, 'options.dockerfileContent');
      dockerfiles.push(parsed);
    }

    // 3. Ingest local files from targetUrl (file://) if applicable
    if (typeof input.targetUrl === 'string' && input.targetUrl.startsWith('file://')) {
      try {
        const localPath = fileURLToPath(input.targetUrl);
        if (fs.existsSync(localPath)) {
          const stat = fs.statSync(localPath);
          if (stat.isFile()) {
            this.ingestSingleFile(localPath, k8sDocuments, dockerfiles, parseErrors);
          }
        }
      } catch (err: unknown) {
        logger.warn({ error: String(err), targetUrl: input.targetUrl }, 'Could not read local file from targetUrl');
      }
    }

    // 4. Ingest explicit filePaths
    if (options.filePaths && Array.isArray(options.filePaths)) {
      for (const fPath of options.filePaths) {
        try {
          const resolvedPath = path.resolve(fPath);
          if (fs.existsSync(resolvedPath)) {
            const stat = fs.statSync(resolvedPath);
            if (stat.isFile()) {
              this.ingestSingleFile(resolvedPath, k8sDocuments, dockerfiles, parseErrors);
            }
          }
        } catch (err: unknown) {
          logger.warn({ error: String(err), filePath: fPath }, 'Could not read specified filePath');
        }
      }
    }

    context.reportProgress?.(25, `Ingested ${k8sDocuments.length} K8s documents and ${dockerfiles.length} Dockerfiles.`);

    const ignoredRules = new Set(options.ignoredRuleIds || []);
    const ruleContext: RuleEvaluationContext = {
      policyLevel: options.policyLevel || 'restricted',
    };

    const findings: RawEngineFinding[] = [];
    const metrics: RawEngineMetric[] = [];

    // Emit findings for YAML syntax errors
    for (const err of parseErrors) {
      const evidenceHash = crypto
        .createHash('sha256')
        .update(`yaml_parse_error:${err.line}:${err.message}`)
        .digest('hex');

      findings.push({
        title: 'Kubernetes YAML Syntax Error Detected',
        description: err.message,
        severity: 'low',
        category: 'syntax_validation',
        recommendation: 'Fix YAML syntax error to allow complete security analysis.',
        evidence: {
          request: { url: input.targetUrl, headers: { Host: 'localhost' }, method: 'STATIC_AUDIT' },
          response: { statusCode: 0, headers: {}, body: err.raw || err.message },
          immutableHash: evidenceHash,
          metadata: { evidenceHash, error: err.message, line: err.line, location: `manifest.yaml:${err.line || 1}` },
        },
        metadata: {
          location: `manifest.yaml:${err.line || 1}`,
        },
      });
    }

    // 5. Evaluate Kubernetes Pod Security Standards Rules
    let totalRulesEvaluated = 0;
    const passedRuleSet = new Set<string>();
    const failedRuleSet = new Set<string>();

    for (const doc of k8sDocuments) {
      for (const rule of ALL_K8S_RULES) {
        if (ignoredRules.has(rule.id)) continue;
        totalRulesEvaluated++;

        const ruleFindings = rule.evaluate(doc, { ...ruleContext, filePath: doc.filePath });
        if (ruleFindings.length > 0) {
          failedRuleSet.add(rule.id);
          for (const rf of ruleFindings) {
            const evidenceHash = crypto
              .createHash('sha256')
              .update(`${rf.ruleId}:${rf.resourceKind}:${rf.resourceName}:${rf.containerName}:${rf.lineNumber}`)
              .digest('hex');

            const locationStr = `${rf.filePath || doc.kind || 'manifest'}:${rf.resourceName || 'workload'}:${rf.lineNumber || 1}`;

            findings.push({
              title: rf.title,
              description: rf.description,
              severity: rf.severity,
              category: rf.category,
              recommendation: rf.recommendation,
              evidence: {
                request: {
                  url: input.targetUrl,
                  method: 'STATIC_AUDIT',
                  headers: {
                    Host: 'localhost',
                    ResourceKind: rf.resourceKind || 'Unknown',
                    ResourceName: rf.resourceName || 'Unknown',
                  },
                },
                response: {
                  statusCode: 0,
                  headers: {},
                  body: rf.violatingSnippet || rf.description,
                },
                immutableHash: evidenceHash,
                metadata: {
                  ruleId: rf.ruleId,
                  resourceKind: rf.resourceKind,
                  resourceName: rf.resourceName,
                  containerName: rf.containerName,
                  violatingSnippet: rf.violatingSnippet,
                  lineNumber: rf.lineNumber,
                  location: locationStr,
                  evidenceHash,
                },
              },
              metadata: {
                location: locationStr,
                lineNumber: rf.lineNumber,
              },
            });
          }
        } else {
          passedRuleSet.add(rule.id);
        }
      }
    }

    context.reportProgress?.(60, 'Evaluating Dockerfile security rules...');

    // 6. Evaluate Dockerfile Security Rules
    for (const dockerfile of dockerfiles) {
      for (const rule of ALL_DOCKERFILE_RULES) {
        if (ignoredRules.has(rule.id)) continue;
        totalRulesEvaluated++;

        const ruleFindings = rule.evaluate(dockerfile, { ...ruleContext, filePath: dockerfile.filePath });
        if (ruleFindings.length > 0) {
          failedRuleSet.add(rule.id);
          for (const rf of ruleFindings) {
            const evidenceHash = crypto
              .createHash('sha256')
              .update(`${rf.ruleId}:${dockerfile.filePath}:${rf.lineNumber}`)
              .digest('hex');

            const locationStr = `${rf.filePath || 'Dockerfile'}:${rf.lineNumber || 1}`;

            findings.push({
              title: rf.title,
              description: rf.description,
              severity: rf.severity,
              category: rf.category,
              recommendation: rf.recommendation,
              evidence: {
                request: { url: input.targetUrl, headers: { Host: 'localhost' }, method: 'STATIC_AUDIT' },
                response: {
                  statusCode: 0,
                  headers: {},
                  body: rf.violatingSnippet || rf.description,
                },
                immutableHash: evidenceHash,
                metadata: {
                  ruleId: rf.ruleId,
                  lineNumber: rf.lineNumber,
                  violatingSnippet: rf.violatingSnippet,
                  location: locationStr,
                  evidenceHash,
                },
              },
              metadata: {
                location: locationStr,
                lineNumber: rf.lineNumber,
              },
            });
          }
        } else {
          passedRuleSet.add(rule.id);
        }
      }
    }

    // 7. Calculate Metrics & Compliance Score
    const countsBySeverity: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    for (const f of findings) {
      countsBySeverity[f.severity] = (countsBySeverity[f.severity] || 0) + 1;
    }

    const totalViolations = findings.length;
    // Deduct points: Critical -25, High -15, Medium -5, Low -1
    const penalty =
      (countsBySeverity.critical ?? 0) * 25 +
      (countsBySeverity.high ?? 0) * 15 +
      (countsBySeverity.medium ?? 0) * 5 +
      (countsBySeverity.low ?? 0) * 1;
    const complianceScore = Math.max(0, 100 - penalty);

    metrics.push(
      { name: 'k8s_manifests_analyzed', value: k8sDocuments.length, unit: 'count' },
      { name: 'dockerfiles_analyzed', value: dockerfiles.length, unit: 'count' },
      { name: 'k8s_rules_evaluated', value: totalRulesEvaluated, unit: 'count' },
      { name: 'k8s_violations_count', value: totalViolations, unit: 'count' },
      { name: 'pss_compliance_score', value: complianceScore, unit: 'score' },
    );

    const durationMs = Date.now() - startTime;
    context.reportProgress?.(100, `Audit completed in ${durationMs}ms with ${findings.length} findings.`);

    logger.info(
      {
        k8sDocs: k8sDocuments.length,
        dockerfiles: dockerfiles.length,
        findingsCount: findings.length,
        durationMs,
        complianceScore,
      },
      'Kubernetes & Cloud-Native Infrastructure Security Audit completed successfully',
    );

    const summary: K8sAuditSummary = {
      totalFilesAnalyzed: k8sDocuments.length + dockerfiles.length,
      totalResourcesAudited: k8sDocuments.length,
      totalRulesEvaluated,
      findingsCount: findings.length,
      countsBySeverity,
      passedRuleCount: passedRuleSet.size,
      failedRuleCount: failedRuleSet.size,
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

  private ingestSingleFile(
    filePath: string,
    k8sDocs: K8sWorkloadDocument[],
    dockerfiles: ParsedDockerfile[],
    errors: Array<{ message: string; line?: number; raw?: string }>,
  ): void {
    const content = fs.readFileSync(filePath, 'utf8');
    const baseName = path.basename(filePath).toLowerCase();

    if (baseName.includes('dockerfile') || baseName.endsWith('.dockerfile')) {
      dockerfiles.push(parseDockerfile(content, filePath));
    } else if (filePath.endsWith('.yaml') || filePath.endsWith('.yml')) {
      const parsed = parseKubernetesManifests(content, filePath);
      k8sDocs.push(...parsed.documents);
      errors.push(...parsed.errors);
    }
  }
}

export const k8sInfraAuditEngine = new K8sInfraAuditEngine();
export const k8sAuditEngine = k8sInfraAuditEngine;
dynamicWorkerEngineRegistry.register(k8sInfraAuditEngine);
