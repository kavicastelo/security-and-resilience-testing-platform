import crypto from 'node:crypto';
import { eq } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { testExecutions } from './db/schema.js';
import { testRunsService } from './test-runs.service.js';
import { targetsService } from './targets.service.js';
import {
  findingsService,
  computeHardenedFindingFingerprint,
  extractFindingComponents,
} from './findings.service.js';
import { evidenceService } from './evidence.service.js';
import { metricsService } from './metrics.service.js';
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
  engineRegistry,
  TestEngine,
  ExecutionContext,
  EngineExecutionClass,
} from '@security-lab/test-sdk';
import { logger } from '@security-lab/logger';

export interface ExecuteRunOptions {
  engineIds?: string[];
  definitionYaml?: string;
  customHeaders?: Record<string, string>;
  options?: Record<string, unknown>;
  wait?: boolean;
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
  async executeTestRun(testRunId: string, options?: ExecuteRunOptions): Promise<TestRunExecutionResult> {
    return this.executeTestRunInternal(testRunId, options);
  }

  async executeTestRunInternal(
    testRunId: string,
    options?: ExecuteRunOptions,
    abortSignal?: AbortSignal,
  ): Promise<TestRunExecutionResult> {
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

    // Check if run was aborted or already cancelled
    if (abortSignal?.aborted || testRun.status === 'cancelled') {
      runLogger.info(`Test run ${testRunId} was cancelled before starting execution.`);
      return {
        testRun,
        executions: [],
        findings: [],
      };
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

    // 3. Resolve Engines to Execute via EngineRegistry
    let enginesToRun: TestEngine[] = [];
    const definitionYaml =
      options?.definitionYaml ||
      (testRun.metadata?.definitionYaml as string | undefined);

    if (definitionYaml || testRun.profileId === 'declarative') {
      const decl = engineRegistry.get('engine-native-declarative');
      enginesToRun = decl ? [decl] : [];
    } else if (testRun.profileId === 'class-b-scanners' || testRun.profileId === 'container-scanners') {
      enginesToRun = engineRegistry.findByExecutionClass('class_b_container');
    } else if (testRun.profileId === 'zap') {
      const zap = engineRegistry.get('engine-container-zap');
      enginesToRun = zap ? [zap] : [];
    } else if (testRun.profileId === 'trivy') {
      const trivy = engineRegistry.get('engine-container-trivy');
      enginesToRun = trivy ? [trivy] : [];
    } else if (testRun.profileId === 'class-c-resilience' || testRun.profileId === 'resilience') {
      const k6 = engineRegistry.get('engine-worker-k6');
      const rl = engineRegistry.get('engine-native-resilience');
      enginesToRun = [k6, rl].filter((e): e is TestEngine => e !== undefined);
    } else if (testRun.profileId === 'k6' || testRun.profileId === 'load-sla') {
      const k6 = engineRegistry.get('engine-worker-k6');
      enginesToRun = k6 ? [k6] : [];
    } else if (testRun.profileId === 'rate-limit') {
      const rl = engineRegistry.get('engine-native-resilience');
      enginesToRun = rl ? [rl] : [];
    } else if (options?.engineIds && options.engineIds.length > 0) {
      enginesToRun = options.engineIds
        .map((id) => engineRegistry.get(id))
        .filter((e): e is TestEngine => e !== undefined);
      if (enginesToRun.length === 0) {
        enginesToRun = engineRegistry.findByExecutionClass('class_a_native');
      }
    } else {
      enginesToRun = engineRegistry.findByExecutionClass('class_a_native');
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

    // 4. Run Engines Sequentially with Cancellation Checks
    for (const engine of enginesToRun) {
      if (abortSignal?.aborted) {
        runLogger.warn(`Execution for test run ${testRunId} aborted before dispatching [${engine.id}].`);
        break;
      }

      runLogger.info(`Dispatching engine [${engine.id}]...`);

      const entry = engineRegistry.getEntry(engine.id);
      const executionClass: EngineExecutionClass =
        entry?.executionClass || engine.executionClass || 'class_a_native';

      const [executionRow] = await db
        .insert(testExecutions)
        .values({
          testRunId,
          engineId: engine.id,
          executionClass,
          status: 'running',
          startedAt: new Date(),
        })
        .returning();

      if (!executionRow) {
        throw new Error(`Failed to initialize execution record for engine ${engine.id}`);
      }

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
        abortSignal: abortSignal || new AbortController().signal,
        reportProgress: (percent, msg) => {
          runLogger.debug(`[${engine.id}] Progress ${percent}%: ${msg}`);
        },
        logger: runLogger.child({ engineId: engine.id, executionId: executionRow.id }),
      };

      const engineInput = {
        targetUrl: target.baseUrl,
        customHeaders: options?.customHeaders,
        options: {
          ...(testRun.metadata as Record<string, unknown> | undefined),
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

        if (abortSignal?.aborted) {
          await db
            .update(testExecutions)
            .set({
              status: 'cancelled',
              completedAt: new Date(),
              errorMessage: 'Execution aborted by cancellation request',
            })
            .where(eq(testExecutions.id, executionRow.id));

          executionResults.push({
            id: executionRow.id,
            engineId: engine.id,
            status: 'cancelled',
            error: 'Execution cancelled',
          });
          break;
        }

        // Process findings and immutable forensic evidence
        for (const rawFinding of result.findings) {
          const { ruleOrCweId, endpointPath, parameterName } = extractFindingComponents({
            category: rawFinding.category,
            title: rawFinding.title,
            location: (rawFinding as { location?: string }).location,
            evidence: rawFinding.evidence as { request?: { url?: string } } | undefined,
            metadata: rawFinding.metadata,
          });

          const fingerprint = computeHardenedFindingFingerprint({
            targetId: target.id,
            engineId: engine.id,
            category: rawFinding.category,
            ruleOrCweId,
            endpointPath,
            parameterName,
          });

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

        // Process quantitative metrics (e.g. Latency SLA, P95, P99, RPS)
        if (result.metrics && result.metrics.length > 0) {
          for (const m of result.metrics) {
            await metricsService.saveMetric({
              testRunId,
              executionId: executionRow.id,
              name: m.name,
              value: m.value,
              unit: m.unit,
              tags: m.tags,
            });
          }
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
        const isCancelled = abortSignal?.aborted || errorMsg.toLowerCase().includes('abort');
        const finalExecStatus = isCancelled ? 'cancelled' : 'failed';

        await db
          .update(testExecutions)
          .set({
            status: finalExecStatus,
            completedAt: new Date(),
            errorMessage: errorMsg,
          })
          .where(eq(testExecutions.id, executionRow.id));

        executionResults.push({
          id: executionRow.id,
          engineId: engine.id,
          status: finalExecStatus,
          error: errorMsg,
        });

        if (isCancelled) {
          break;
        }
        totalFailedTests++;
      }
    }

    // 5. Reconcile Findings (Transition unresolved findings to 'resolved' if not detected)
    const isCancelled = abortSignal?.aborted;
    if (!isCancelled) {
      try {
        const reconciliation = await findingsService.reconcileTestRunFindings(
          testRunId,
          target.id,
          enginesToRun.map((e) => e.id),
        );
        if (reconciliation.resolvedCount > 0) {
          runLogger.info(
            `Finding reconciliation: ${reconciliation.resolvedCount} previously open findings resolved on target ${target.id}.`,
          );
        }
      } catch (err: unknown) {
        runLogger.warn({ err }, 'Finding reconciliation encountered an error');
      }
    }

    // 6. Aggregate Findings and Complete TestRun
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

    const finalStatus = isCancelled
      ? 'cancelled'
      : severityCounts.critical > 0
        ? 'failed'
        : 'completed';

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
