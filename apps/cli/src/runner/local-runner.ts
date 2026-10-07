import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import pc from 'picocolors';
import {
  Finding,
  Metric,
  TestRun,
  TargetScope,
  validateUrlAgainstScope,
  Policy,
  Evidence,
  ReleaseGateDecision,
} from '@security-lab/domain';
import {
  HeadersSecurityEngine,
  CorsSecurityEngine,
  TlsSecurityEngine,
  DeclarativeTestEngine,
  AuthenticationSecurityEngine,
  AuthorizationSecurityEngine,
  SecurityContractEngine,
  TestEngine,
  ExecutionContext,
  RawEngineFinding,
} from '@security-lab/test-sdk';
import { evaluatePolicy, PolicyEvaluationResult } from '@security-lab/policy-engine';
import { calculatePostureScore, PostureScoreResult } from '@security-lab/scoring';
import {
  ProjectConfig,
  loadProjectConfigFile,
  generateCurlCommand,
  generateJUnitXml,
  generateSarifReport,
  generateHtmlExecutiveReport,
  ReportInput,
  TestExecutionRecord,
} from '@security-lab/contracts';
import { formatSuccess, formatError, formatWarning, formatInfo } from '../output/formatters.js';

export interface LocalRunnerOptions {
  configPath?: string;
  targetUrl?: string;
  engines?: string[];
  declarativeFiles?: string[];
  contractFiles?: string[];
  failOn?: 'failed' | 'warning' | 'never';
  format?: 'terminal' | 'sarif' | 'junit' | 'html' | 'json';
  outputFile?: string;
  outputPath?: string;
  silent?: boolean;
  scopeConfig?: {
    allowedHosts?: string[];
    allowedPorts?: number[];
    excludedPaths?: string[];
  };
}

export interface LocalExecutionRecord {
  engineId: string;
  status: 'completed' | 'failed';
  durationMs: number;
  findingsCount: number;
  errorMessage?: string;
}

export interface LocalRunnerResult {
  success: boolean;
  passed: boolean;
  decision: ReleaseGateDecision;
  policyVerdict: ReleaseGateDecision;
  score: PostureScoreResult & { overallScore: number };
  postureScore: PostureScoreResult & { overallScore: number };
  findings: Finding[];
  totalFindings: number;
  totalTests: number;
  metrics: Metric[];
  evidence: Evidence[];
  executions: LocalExecutionRecord[];
  gateResult: PolicyEvaluationResult;
  generatedReports: Record<string, string>;
  exitCode: number;
}


export class LocalRunner {
  /**
   * Resolves the effective project configuration from CLI options and disk.
   */
  resolveConfig(options: LocalRunnerOptions): { config: ProjectConfig; filePath?: string } {
    const loaded = loadProjectConfigFile(options.configPath);

    if (loaded) {
      const config = { ...loaded.config };
      if (options.targetUrl) {
        config.target.baseUrl = options.targetUrl;
        try {
          const parsed = new URL(options.targetUrl);
          const port = parsed.port ? parseInt(parsed.port, 10) : parsed.protocol === 'https:' ? 443 : 80;
          if (!config.target.allowedHosts || config.target.allowedHosts.length === 0) {
            config.target.allowedHosts = [parsed.hostname];
          } else if (!config.target.allowedHosts.includes(parsed.hostname)) {
            config.target.allowedHosts = [...config.target.allowedHosts, parsed.hostname];
          }
          if (!config.target.allowedPorts || config.target.allowedPorts.length === 0) {
            config.target.allowedPorts = [port];
          } else if (!config.target.allowedPorts.includes(port)) {
            config.target.allowedPorts = [...config.target.allowedPorts, port];
          }
        } catch {
          // Let validateUrlAgainstScope handle invalid URL
        }
      }
      if (options.engines && options.engines.length > 0) {
        config.definitions.engines = options.engines;
      }
      if (options.failOn) {
        config.policy.failOn = options.failOn;
      }
      if (options.scopeConfig) {
        if (options.scopeConfig.allowedHosts) {
          config.target.allowedHosts = options.scopeConfig.allowedHosts;
        }
        if (options.scopeConfig.allowedPorts) {
          config.target.allowedPorts = options.scopeConfig.allowedPorts;
        }
        if (options.scopeConfig.excludedPaths) {
          config.target.excludedPaths = options.scopeConfig.excludedPaths;
        }
      }
      return { config, filePath: loaded.filePath };
    }

    if (!options.targetUrl) {
      throw new Error(
        'No target URL specified and no .securitylab.yaml found.\n' +
          'Usage: security-lab run --local --target <url> [options] or create a .securitylab.yaml configuration file.',
      );
    }

    const defaultTargetConfig = {
      baseUrl: options.targetUrl,
      name: 'Standalone Target',
      allowedHosts: options.scopeConfig?.allowedHosts,
      allowedPorts: options.scopeConfig?.allowedPorts,
      excludedPaths: options.scopeConfig?.excludedPaths,
    };

    const config: ProjectConfig = {
      version: '1.0',
      name: 'Standalone CLI Scan',
      target: defaultTargetConfig,
      definitions: {
        engines: options.engines && options.engines.length > 0 ? options.engines : ['headers', 'cors', 'tls'],
        declarativeFiles: options.declarativeFiles,
        contractFiles: options.contractFiles,
      },
      policy: {
        name: 'Default Standalone Policy',
        maxAllowedSeverity: 'high',
        maxCriticalFindings: 0,
        maxHighFindings: 0,
        minPostureScore: 80,
        failOn: options.failOn || 'failed',
      },
      reporters: {
        formats: options.format ? [options.format] : ['terminal'],
        outputDir: './reports',
      },
    };

    return { config };
  }

  /**
   * Executes the standalone in-process test suite against the target.
   */
  async run(options: LocalRunnerOptions): Promise<LocalRunnerResult> {
    const { config, filePath } = this.resolveConfig(options);
    const targetUrl = config.target.baseUrl;
    const silent = options.silent ?? false;

    if (!silent) {
      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan('\n╔═══════════════════════════════════════════════════════════════════════╗')));
      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan('║  SECURITY LAB — Standalone Local Security QA Runner                   ║')));
      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan('╚═══════════════════════════════════════════════════════════════════════╝')));
      if (filePath) {
        // eslint-disable-next-line no-console
        console.log(formatInfo(`Loaded configuration from: ${pc.bold(filePath)}`));
      }
      // eslint-disable-next-line no-console
      console.log(formatInfo(`Target URL: ${pc.bold(pc.blue(targetUrl))}`));
    }

    // 1. Strict Target Scope Boundary Enforcement
    const parsedUrl = new URL(targetUrl);
    const scope: TargetScope = {
      allowedHosts: config.target.allowedHosts && config.target.allowedHosts.length > 0
        ? config.target.allowedHosts
        : [parsedUrl.hostname],
      allowedPorts: config.target.allowedPorts && config.target.allowedPorts.length > 0
        ? config.target.allowedPorts
        : [parsedUrl.port ? parseInt(parsedUrl.port, 10) : parsedUrl.protocol === 'https:' ? 443 : 80],
      excludedPaths: config.target.excludedPaths || [],
      testing: {
        activeScanning: true,
        loadTesting: false,
        chaosTesting: false,
      },
      limits: {
        maxRps: 100,
        maxConcurrency: 10,
        maxDuration: '5m',
      },
    };


    const scopeResult = validateUrlAgainstScope(targetUrl, scope);
    if (!scopeResult.valid) {
      throw new Error(
        `Scope boundary violation: Target URL "${targetUrl}" violates security boundary:\n` +
          scopeResult.violations.map((v) => `  - ${v}`).join('\n'),
      );
    }

    // 2. Instantiate Requested Class A Engines
    const engineMap: Record<string, TestEngine> = {
      headers: new HeadersSecurityEngine(),
      cors: new CorsSecurityEngine(),
      tls: new TlsSecurityEngine(),
      declarative: new DeclarativeTestEngine(),
      auth: new AuthenticationSecurityEngine(),
      bola: new AuthorizationSecurityEngine(),
      contract: new SecurityContractEngine(),
    };

    const enginesToRun: TestEngine[] = [];
    for (const name of config.definitions.engines) {
      const normalized = name.toLowerCase().trim();
      if (engineMap[normalized]) {
        enginesToRun.push(engineMap[normalized]);
      } else {
        if (!silent) {
          // eslint-disable-next-line no-console
          console.log(formatWarning(`Engine "${name}" is not supported in local offline mode; skipping.`));
        }
      }
    }

    if (enginesToRun.length === 0) {
      throw new Error('No valid local engines configured to run.');
    }

    // 3. In-Process Engine Execution Loop
    const allFindings: Finding[] = [];
    const allMetrics: Metric[] = [];
    const allEvidence: Evidence[] = [];
    const executionRecords: LocalExecutionRecord[] = [];
    const testRunId = crypto.randomUUID();

    const mockLogger = {
      info: () => {},
      warn: () => {},
      error: () => {},
      debug: () => {},
      trace: () => {},
      fatal: () => {},
      child: () => mockLogger,
    } as unknown as ExecutionContext['logger'];

    for (const engine of enginesToRun) {
      const executionId = crypto.randomUUID();
      const startTime = Date.now();

      if (!silent) {
        // eslint-disable-next-line no-console
        console.log(formatInfo(`Executing engine: ${pc.bold(engine.id)}...`));
      }

      const execContext: ExecutionContext = {
        correlationId: crypto.randomUUID(),
        testRunId,
        executionId,
        target: {
          id: 'local-target',
          name: config.target.name || parsedUrl.hostname,
          baseUrl: targetUrl,
          scope,
        },
        logger: mockLogger,
        abortSignal: new AbortController().signal,
        reportProgress: () => {},
      };

      try {
        const result = await engine.execute(
          {
            targetUrl,
            customHeaders: config.target.headers,
          },
          execContext,
        );

        const durationMs = Date.now() - startTime;

        // Map Raw Findings to Domain Findings
        const engineFindings: Finding[] = result.findings.map((rf: RawEngineFinding) => {
          const findingId = crypto.randomUUID();
          const fingerprint = crypto
            .createHash('sha256')
            .update(`${targetUrl}:${rf.category}:${rf.title}:${rf.severity}`)
            .digest('hex');

          let evidenceId: string | undefined;
          let reproductionCurl: string | undefined;

          if (rf.evidence?.request) {
            evidenceId = crypto.randomUUID();
            reproductionCurl = generateCurlCommand(rf.evidence.request);

            const evidenceRecord: Evidence = {
              id: evidenceId,
              testRunId,
              executionId,
              request: rf.evidence.request,
              response: rf.evidence.response,
              expected: rf.evidence.expected,
              actual: rf.evidence.actual,
              metadata: (rf.evidence.metadata as Record<string, unknown>) || {},
              timestamp: new Date(),
              environment: 'local',
              immutableHash: crypto
                .createHash('sha256')
                .update(JSON.stringify(rf.evidence.request))
                .digest('hex'),
            };

            allEvidence.push(evidenceRecord);
          }

          return {
            id: findingId,
            fingerprint,
            title: rf.title,
            category: rf.category,
            severity: rf.severity,
            confidence: 'firm',
            status: 'open',
            description: rf.description,
            risk: undefined,
            recommendation: rf.recommendation,
            testDefinitionId: engine.id,
            testRunId,
            executionId,
            targetId: 'local-target',
            occurrenceCount: 1,
            firstDetectedAt: new Date(),
            lastDetectedAt: new Date(),
            evidenceId,
            metadata: {
              ...(rf.metadata || {}),
              reproductionCurl,
            },
          };
        });

        allFindings.push(...engineFindings);

        // Map Metrics
        if (result.metrics) {
          for (const m of result.metrics) {
            allMetrics.push({
              id: crypto.randomUUID(),
              testRunId,
              executionId,
              name: m.name,
              value: m.value,
              unit: m.unit,
              tags: m.tags || {},
              timestamp: new Date(),
            });
          }
        }

        executionRecords.push({
          engineId: engine.id,
          status: result.success ? 'completed' : 'failed',
          durationMs,
          findingsCount: engineFindings.length,
          errorMessage: result.error,
        });

        if (!silent) {
          const statusIcon = result.success ? pc.green('✔') : pc.yellow('⚠');
          // eslint-disable-next-line no-console
          console.log(
            `  ${statusIcon} ${pc.bold(engine.id)} completed in ${durationMs}ms with ${
              engineFindings.length === 0
                ? pc.green('0 findings')
                : pc.red(`${engineFindings.length} findings`)
            }`,
          );
        }
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        executionRecords.push({
          engineId: engine.id,
          status: 'failed',
          durationMs: Date.now() - startTime,
          findingsCount: 0,
          errorMessage: errorMsg,
        });

        if (!silent) {
          // eslint-disable-next-line no-console
          console.log(formatError(`${engine.id} failed: ${errorMsg}`));
        }
      }
    }

    // 4. Policy Gate Evaluation & Posture Score
    const effectivePolicy: Policy = {
      id: 'local-policy',
      name: config.policy.name || 'Local CLI Policy',
      description: 'Enforced standalone by Security Lab CLI',
      rules: config.policy.rules || [
        {
          id: 'rule-max-severity',
          name: 'Allowed Severity Ceiling',
          condition: {
            maxAllowedSeverity: config.policy.maxAllowedSeverity,
            maxCountBySeverity: {
              critical: config.policy.maxCriticalFindings,
              high: config.policy.maxHighFindings,
            },
          },
          action: 'block_release',
        },
      ],
      waivers: config.policy.waivers || [],
      requiredProfiles: [],
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const gateResult = evaluatePolicy(effectivePolicy, allFindings, allMetrics, {
      executedEngines: enginesToRun.map((e) => e.id),
    });

    const rawScore = calculatePostureScore(allFindings);
    const score: PostureScoreResult & { overallScore: number } = {
      ...rawScore,
      overallScore: rawScore.score,
    };

    // 5. Determine Verdict and Exit Code
    const failOn = options.failOn || config.policy.failOn || 'failed';
    let passed = gateResult.passed;
    let decision: ReleaseGateDecision = gateResult.decision;

    const minScore = config.policy.minPostureScore ?? 80;
    if (
      score.findingCounts.critical > 0 ||
      (config.policy.maxHighFindings === 0 && score.findingCounts.high > 0) ||
      score.score < minScore
    ) {
      passed = false;
      decision = 'failed';
    }

    let exitCode = 0;
    if (failOn === 'failed' && !passed) {
      exitCode = 1;
    } else if (failOn === 'warning' && decision !== 'passed') {
      exitCode = 1;
    }

    // 6. Generate Reports
    const generatedReports: Record<string, string> = {};
    const requestedFormats = new Set<string>();

    if (options.format) {
      requestedFormats.add(options.format);
    }
    if (config.reporters?.formats) {
      for (const fmt of config.reporters.formats) {
        requestedFormats.add(fmt);
      }
    }

    const testRunRecord: TestRun = {
      id: testRunId,
      projectId: 'local-project',
      targetId: 'local-target',
      status: passed ? 'completed' : 'failed',
      triggeredBy: 'cli',
      summary: {
        totalTests: enginesToRun.length,
        passedTests: executionRecords.filter((e) => e.status === 'completed' && e.findingsCount === 0).length,
        failedTests: executionRecords.filter((e) => e.findingsCount > 0).length,
        errorTests: executionRecords.filter((e) => e.status === 'failed' && e.errorMessage).length,
        findingsCount: score.findingCounts,
      },
      metadata: {},
      createdAt: new Date(),
      updatedAt: new Date(),
    };


    const execRecordsForReport: TestExecutionRecord[] = executionRecords.map((e, idx) => ({
      id: `exec-${idx}`,
      engineId: e.engineId,
      executionClass: 'class_a_native',
      status: e.status,
      durationMs: e.durationMs,
      errorMessage: e.errorMessage,
    }));

    const reportInput: ReportInput = {
      testRun: testRunRecord,
      target: { id: 'local-target', name: config.target.name || parsedUrl.hostname, baseUrl: targetUrl },
      executions: execRecordsForReport,
      findings: allFindings,
      metrics: allMetrics,
      evidence: allEvidence,
      posture: score,
      releaseGate: gateResult,
    };

    // Output Directory Preparation
    const outputDir = path.resolve(process.cwd(), config.reporters.outputDir || './reports');

    if (requestedFormats.has('sarif')) {

      const sarif = generateSarifReport(reportInput);
      const sarifStr = JSON.stringify(sarif, null, 2);
      generatedReports['sarif'] = sarifStr;

      const explicitOutput = options.outputPath || options.outputFile;
      const sarifPath = explicitOutput && (options.format === 'sarif' || explicitOutput.endsWith('.sarif'))
        ? path.resolve(process.cwd(), explicitOutput)
        : config.reporters.sarifFile
          ? path.resolve(process.cwd(), config.reporters.sarifFile)
          : path.join(outputDir, 'security-lab.sarif');

      fs.mkdirSync(path.dirname(sarifPath), { recursive: true });
      fs.writeFileSync(sarifPath, sarifStr, 'utf-8');
      if (!silent) {
        // eslint-disable-next-line no-console
        console.log(formatSuccess(`Exported SARIF report to: ${pc.bold(sarifPath)}`));
      }
    }

    if (requestedFormats.has('junit')) {
      const junitXml = generateJUnitXml(reportInput);
      generatedReports['junit'] = junitXml;

      const explicitOutput = options.outputPath || options.outputFile;
      const junitPath = explicitOutput && (options.format === 'junit' || explicitOutput.endsWith('.xml'))
        ? path.resolve(process.cwd(), explicitOutput)
        : config.reporters.junitFile
          ? path.resolve(process.cwd(), config.reporters.junitFile)
          : path.join(outputDir, 'junit.xml');

      fs.mkdirSync(path.dirname(junitPath), { recursive: true });
      fs.writeFileSync(junitPath, junitXml, 'utf-8');
      if (!silent) {
        // eslint-disable-next-line no-console
        console.log(formatSuccess(`Exported JUnit report to: ${pc.bold(junitPath)}`));
      }
    }

    if (requestedFormats.has('html')) {
      const html = generateHtmlExecutiveReport(reportInput);
      generatedReports['html'] = html;

      const explicitOutput = options.outputPath || options.outputFile;
      const htmlPath = explicitOutput && (options.format === 'html' || explicitOutput.endsWith('.html') || explicitOutput.endsWith('.htm'))
        ? path.resolve(process.cwd(), explicitOutput)
        : config.reporters.htmlFile
          ? path.resolve(process.cwd(), config.reporters.htmlFile)
          : path.join(outputDir, 'executive-report.html');

      fs.mkdirSync(path.dirname(htmlPath), { recursive: true });
      fs.writeFileSync(htmlPath, html, 'utf-8');
      if (!silent) {
        // eslint-disable-next-line no-console
        console.log(formatSuccess(`Exported Executive HTML report to: ${pc.bold(htmlPath)}`));
      }
    }

    if (requestedFormats.has('json')) {
      const jsonStr = JSON.stringify(
        {
          success: true,
          targetUrl,
          decision,
          passed,
          score,
          findings: allFindings,
          gateResult,
        },
        null,
        2,
      );
      generatedReports['json'] = jsonStr;

      const explicitOutput = options.outputPath || options.outputFile;
      if (explicitOutput && options.format === 'json') {
        const jsonPath = path.resolve(process.cwd(), explicitOutput);
        fs.mkdirSync(path.dirname(jsonPath), { recursive: true });
        fs.writeFileSync(jsonPath, jsonStr, 'utf-8');
        if (!silent) {
          // eslint-disable-next-line no-console
          console.log(formatSuccess(`Exported JSON summary to: ${pc.bold(jsonPath)}`));
        }
      }
    }

    // 7. Interactive Terminal Output Polish
    if (!silent) {
      this.printTerminalSummary(score, gateResult, allFindings, decision);
    }

    // 8. Write GitHub Step Summary if running in GitHub Actions
    if (process.env.GITHUB_STEP_SUMMARY) {
      try {
        const markdown = this.generateMarkdownSummary(score, gateResult, allFindings, decision, targetUrl);
        fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown, 'utf-8');
      } catch {
        // Ignore failure to write step summary
      }
    }

    return {
      success: true,
      passed,
      decision,
      policyVerdict: decision,
      score,
      postureScore: score,
      findings: allFindings,
      totalFindings: allFindings.length,
      totalTests: executionRecords.length,
      metrics: allMetrics,
      evidence: allEvidence,
      executions: executionRecords,
      gateResult,
      generatedReports,
      exitCode,
    };
  }

  private generateMarkdownSummary(
    score: PostureScoreResult,
    gateResult: PolicyEvaluationResult,
    findings: Finding[],
    decision: ReleaseGateDecision,
    targetUrl: string,
  ): string {
    const verdictBadge =
      decision === 'passed'
        ? '✅ **PASSED (Compliant)**'
        : decision === 'warning'
          ? '⚠️ **WARNING (Manual Review Required)**'
          : '❌ **BLOCKED (Policy Violations Detected)**';

    const findingsTableRows = findings
      .map(
        (f) =>
          `| **${f.severity.toUpperCase()}** | ${f.title} | ${f.category} | ${f.recommendation || 'N/A'} |`,
      )
      .join('\n');

    const violationsList =
      gateResult.violations.length > 0
        ? `\n### Policy Violations (${gateResult.violations.length})\n` +
          gateResult.violations.map((v) => `- **${v.ruleName}**: ${v.reason}`).join('\n')
        : '';

    return `
## 🛡️ Security Lab — Release Gate Summary

**Target URL:** \`${targetUrl}\`  
**Verdict:** ${verdictBadge}  
**Posture Score:** **${score.score} / 100** (Grade **${score.grade}**)  
**Evaluated Rules:** ${gateResult.evaluatedRulesCount}
${violationsList}

### Severity Distribution
| Critical | High | Medium | Low | Total Findings |
| :---: | :---: | :---: | :---: | :---: |
| ${score.findingCounts.critical} | ${score.findingCounts.high} | ${score.findingCounts.medium} | ${score.findingCounts.low} | ${findings.length} |

${
  findings.length > 0
    ? `### Detected Vulnerabilities
| Severity | Title | Category | Remediation |
| :--- | :--- | :--- | :--- |
${findingsTableRows}
`
    : `\n> ✔ **Zero security defects detected. Target satisfies baseline security posture.**\n`
}
`;

  }


  private printTerminalSummary(
    score: PostureScoreResult,
    gateResult: PolicyEvaluationResult,
    findings: Finding[],
    decision: ReleaseGateDecision,
  ): void {

    // eslint-disable-next-line no-console
    console.log(pc.bold(pc.cyan('\n───────────────────────────────────────────────────────────────────────')));
    // eslint-disable-next-line no-console
    console.log(pc.bold('FINDINGS & VULNERABILITIES:'));

    if (findings.length === 0) {
      // eslint-disable-next-line no-console
      console.log(pc.green('  ✔ Zero security or resilience defects detected.'));
    } else {
      for (const f of findings) {
        const sevColor =
          f.severity === 'critical'
            ? pc.bgRed(pc.bold(' CRITICAL '))
            : f.severity === 'high'
              ? pc.red(pc.bold('[HIGH]'))
              : f.severity === 'medium'
                ? pc.yellow(pc.bold('[MEDIUM]'))
                : pc.blue(pc.bold('[LOW]'));

        // eslint-disable-next-line no-console
        console.log(`\n  ${sevColor} ${pc.bold(f.title)}`);
        // eslint-disable-next-line no-console
        console.log(`    Category:       ${f.category}`);
        // eslint-disable-next-line no-console
        console.log(`    Description:    ${f.description}`);
        if (f.recommendation) {
          // eslint-disable-next-line no-console
          console.log(`    ${pc.green('Remediation:   ')} ${pc.green(f.recommendation)}`);
        }
        const curlCmd = (f.metadata?.reproductionCurl as string) || '';
        if (curlCmd) {
          // eslint-disable-next-line no-console
          console.log(`    ${pc.cyan('Reproduction:')}`);
          // eslint-disable-next-line no-console
          console.log(`      ${pc.gray(curlCmd.split('\n').join('\n      '))}`);
        }
      }
    }

    // eslint-disable-next-line no-console
    console.log(pc.bold(pc.cyan('\n───────────────────────────────────────────────────────────────────────')));
    // eslint-disable-next-line no-console
    console.log(pc.bold('RELEASE GOVERNANCE VERDICT:'));
    // eslint-disable-next-line no-console
    console.log(`  Posture Score:    ${pc.bold(`${score.score} / 100`)} (Grade ${pc.bold(score.grade)})`);
    // eslint-disable-next-line no-console
    console.log(`  Severity Breakdown: Critical: ${score.findingCounts.critical} | High: ${score.findingCounts.high} | Medium: ${score.findingCounts.medium} | Low: ${score.findingCounts.low}`);

    if (decision === 'passed') {
      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.green(`\n✔ RELEASE GATE: PASSED (Compliant with ${gateResult.evaluatedRulesCount} evaluated rules)\n`)));
    } else if (decision === 'warning') {
      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.yellow(`\n⚠ RELEASE GATE: WARNING (${gateResult.violations.length} warnings detected)\n`)));
      for (const v of gateResult.violations) {
        // eslint-disable-next-line no-console
        console.log(`  ${pc.yellow('•')} ${v.ruleName}: ${v.reason}`);
      }
    } else {
      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.red(`\n✖ RELEASE GATE: BLOCKED (${gateResult.violations.length} policy violations)\n`)));
      for (const v of gateResult.violations) {
        // eslint-disable-next-line no-console
        console.log(`  ${pc.red('•')} ${v.ruleName}: ${v.reason}`);
      }
    }
  }
}

export const localRunner = new LocalRunner();
