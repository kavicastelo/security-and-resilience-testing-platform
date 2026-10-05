import crypto from 'node:crypto';
import { eq } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { testExecutions } from './db/schema.js';
import { testRunsService } from './test-runs.service.js';
import { targetsService } from './targets.service.js';
import { findingsService } from './findings.service.js';
import { evidenceService } from './evidence.service.js';
import {
  validateUrlAgainstScope,
  Finding,
  FindingSeverity,
  TestRun,
  TestRunSummary,
  HttpRequestEvidence,
  HttpResponseEvidence,
} from '@security-lab/domain';
import { createImmutableEvidence } from '@security-lab/evidence';
import {
  HeadersSecurityEngine,
  CorsSecurityEngine,
  TlsSecurityEngine,
  DeclarativeTestEngine,
  TestEngine,
  ExecutionContext,
} from '@security-lab/test-sdk';
import { logger } from '@security-lab/logger';

export interface ExecuteRunOptions {
  engineIds?: string[];
  definitionYaml?: string;
  customHeaders?: Record<string, string>;
  options?: Record<string, unknown>;
}

export interface TestRunExecutionResult {
  testRun: TestRun;
  executions: {
    id: string;
    engineId: string;
    status: string;
    durationMs?: number;
    error?: string;
  }[];
  findings: Finding[];
}

export class TestRunnerService {
  private readonly defaultEngines: TestEngine[] = [
    new HeadersSecurityEngine(),
    new CorsSecurityEngine(),
    new TlsSecurityEngine(),
  ];

  async executeTestRun(testRunId: string, options?: ExecuteRunOptions): Promise<TestRunExecutionResult> {
    const runLogger = logger.child({ testRunId });
    const { db } = getDatabase();

    // 1. Fetch TestRun and Target
    const testRun = await testRunsService.getTestRunById(testRunId);
    if (!testRun) {
      throw new Error(`TestRun "${testRunId}" not found`);
    }

    const target = await targetsService.getTargetById(testRun.targetId);
    if (!target) {
      throw new Error(`Target "${testRun.targetId}" not found for TestRun "${testRunId}"`);
    }

    // Mark test run as running
    await testRunsService.updateTestRunStatus(testRunId, 'running');
    runLogger.info(`Starting execution for test run ${testRunId} against target ${target.baseUrl}`);

    // 2. Enforce Security Scope Boundary
    const scopeCheck = validateUrlAgainstScope(target.baseUrl, target.scope);
    if (!scopeCheck.valid) {
      const scopeError = `Scope violation: ${scopeCheck.violations.join('; ')}`;
      runLogger.warn(`Execution aborted: ${scopeError}`);

      // Record failed execution due to boundary restriction
      const [failedExec] = await db
        .insert(testExecutions)
        .values({
          testRunId,
          engineId: 'scope-boundary-gate',
          executionClass: 'class_a_native',
          status: 'failed',
          startedAt: new Date(),
          completedAt: new Date(),
          durationMs: 0,
          errorMessage: scopeError,
        })
        .returning();

      const failedSummary: TestRunSummary = {
        totalTests: 1,
        passedTests: 0,
        failedTests: 1,
        errorTests: 1,
        findingsCount: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
      };

      const updatedRun = await testRunsService.updateTestRunStatus(testRunId, 'failed', failedSummary);

      return {
        testRun: updatedRun,
        executions: [
          {
            id: failedExec ? failedExec.id : crypto.randomUUID(),
            engineId: 'scope-boundary-gate',
            status: 'failed',
            error: scopeError,
          },
        ],
        findings: [],
      };
    }

    // 3. Resolve Engines to Execute
    let enginesToRun: TestEngine[] = [];
    const definitionYaml =
      options?.definitionYaml ||
      (testRun.metadata?.definitionYaml as string | undefined);

    if (definitionYaml || testRun.profileId === 'declarative') {
      enginesToRun = [new DeclarativeTestEngine()];
    } else if (options?.engineIds && options.engineIds.length > 0) {
      const requested = new Set(options.engineIds);
      const allKnown = [...this.defaultEngines, new DeclarativeTestEngine()];
      enginesToRun = allKnown.filter((e) => requested.has(e.id));
      if (enginesToRun.length === 0) {
        enginesToRun = this.defaultEngines;
      }
    } else {
      enginesToRun = this.defaultEngines;
    }

    const executionResults: {
      id: string;
      engineId: string;
      status: string;
      durationMs?: number;
      error?: string;
    }[] = [];

    const allFindings: Finding[] = [];
    let totalPassedTests = 0;
    let totalFailedTests = 0;

    // 4. Run Engines Sequentially
    for (const engine of enginesToRun) {
      runLogger.info(`Dispatching engine [${engine.id}]...`);

      const [executionRow] = await db
        .insert(testExecutions)
        .values({
          testRunId,
          engineId: engine.id,
          executionClass: 'class_a_native',
          status: 'running',
          startedAt: new Date(),
        })
        .returning();

      if (!executionRow) {
        throw new Error(`Failed to initialize execution record for engine ${engine.id}`);
      }

      const abortController = new AbortController();
      const context: ExecutionContext = {
        correlationId: crypto.randomUUID(),
        testRunId,
        executionId: executionRow.id,
        target: {
          id: target.id,
          name: target.name,
          baseUrl: target.baseUrl,
          scope: target.scope,
        },
        abortSignal: abortController.signal,
        reportProgress: (percent, msg) => {
          runLogger.debug(`[${engine.id}] Progress ${percent}%: ${msg}`);
        },
        logger: runLogger.child({ engineId: engine.id, executionId: executionRow.id }),
      };

      const engineInput = {
        targetUrl: target.baseUrl,
        customHeaders: options?.customHeaders,
        options: {
          ...options?.options,
          yaml: definitionYaml,
        },
      };

      const validation = engine.validate(engineInput);
      if (!validation.valid) {
        const errorMsg = validation.errors?.map((e) => `${e.path}: ${e.message}`).join('; ') || 'Validation failed';
        await db
          .update(testExecutions)
          .set({
            status: 'failed',
            completedAt: new Date(),
            durationMs: 0,
            errorMessage: errorMsg,
          })
          .where(eq(testExecutions.id, executionRow.id));

        executionResults.push({
          id: executionRow.id,
          engineId: engine.id,
          status: 'failed',
          error: errorMsg,
        });
        totalFailedTests++;
        continue;
      }

      try {
        const result = await engine.execute(engineInput, context);

        // Process findings and immutable forensic evidence
        for (const rawFinding of result.findings) {
          const fingerprint = crypto
            .createHash('sha256')
            .update(`${engine.id}:${target.id}:${rawFinding.title}:${rawFinding.category}:${rawFinding.severity}`)
            .digest('hex');

          let evidenceId: string | undefined;

          if (rawFinding.evidence) {
            const evidence = createImmutableEvidence({
              id: crypto.randomUUID(),
              testRunId,
              executionId: executionRow.id,
              request: rawFinding.evidence.request as HttpRequestEvidence | undefined,
              response: rawFinding.evidence.response as HttpResponseEvidence | undefined,
              expected: rawFinding.evidence.expected,
              actual: rawFinding.evidence.actual,
              environment: 'default',
              timestamp: new Date(),
            });

            await evidenceService.saveEvidence(evidence);
            evidenceId = evidence.id;
          }

          const savedFinding = await findingsService.saveFinding({
            fingerprint,
            title: rawFinding.title,
            category: rawFinding.category,
            severity: rawFinding.severity,
            description: rawFinding.description,
            recommendation: rawFinding.recommendation,
            testDefinitionId: engine.id,
            testRunId,
            executionId: executionRow.id,
            targetId: target.id,
            evidenceId,
            metadata: rawFinding.metadata || {},
          });

          allFindings.push(savedFinding);
        }

        const isSuccess = result.success && result.findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length === 0;
        if (isSuccess) {
          totalPassedTests++;
        } else {
          totalFailedTests++;
        }

        await db
          .update(testExecutions)
          .set({
            status: result.success ? 'completed' : 'failed',
            completedAt: new Date(),
            durationMs: result.durationMs,
            errorMessage: result.error,
            rawResult: (result.rawOutput as Record<string, unknown>) || null,
          })
          .where(eq(testExecutions.id, executionRow.id));

        executionResults.push({
          id: executionRow.id,
          engineId: engine.id,
          status: result.success ? 'completed' : 'failed',
          durationMs: result.durationMs,
          error: result.error,
        });
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        await db
          .update(testExecutions)
          .set({
            status: 'failed',
            completedAt: new Date(),
            errorMessage: errorMsg,
          })
          .where(eq(testExecutions.id, executionRow.id));

        executionResults.push({
          id: executionRow.id,
          engineId: engine.id,
          status: 'failed',
          error: errorMsg,
        });
        totalFailedTests++;
      }
    }

    // 5. Aggregate Findings and Complete TestRun
    const severityCounts: Record<FindingSeverity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    for (const f of allFindings) {
      severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
    }

    const summary: TestRunSummary = {
      totalTests: enginesToRun.length,
      passedTests: totalPassedTests,
      failedTests: totalFailedTests,
      errorTests: executionResults.filter((e) => e.status === 'failed' && e.error).length,
      findingsCount: severityCounts,
    };

    const finalStatus = severityCounts.critical > 0 ? 'failed' : 'completed';
    const updatedTestRun = await testRunsService.updateTestRunStatus(testRunId, finalStatus, summary);

    runLogger.info(`Test run ${testRunId} finished with status ${finalStatus}: ${allFindings.length} findings.`);

    return {
      testRun: updatedTestRun,
      executions: executionResults,
      findings: allFindings,
    };
  }
}

export const testRunnerService = new TestRunnerService();
