import { AgentJobDispatch, AgentJobCompletionReport, RawFindingPayload } from '@security-lab/contracts';
import { AgentClient } from './client.js';
import { engineRegistry, ExecutionContext, TestInput } from '@security-lab/test-sdk';
import { logger } from '@security-lab/logger';

export class AgentWorker {
  private readonly client: AgentClient;

  constructor(client: AgentClient) {
    this.client = client;
  }

  async executeJob(job: AgentJobDispatch): Promise<void> {
    const workerLogger = logger.child({ jobId: job.jobId, testRunId: job.testRunId });
    workerLogger.info(`Agent worker starting execution for target ${job.target.baseUrl}`);

    const enginesToRun = job.engineIds.length > 0
      ? job.engineIds
      : ['engine-native-headers', 'engine-native-cors', 'engine-native-tls'];

    const allFindings: RawFindingPayload[] = [];
    const executionSummaries: { engineId: string; status: string; durationMs?: number; error?: string }[] = [];
    const metrics: { name: string; value: number; unit: string; tags?: Record<string, string> }[] = [];

    let executedCount = 0;
    const totalEngines = enginesToRun.length;

    try {
      for (const engineId of enginesToRun) {
        const percent = Math.round((executedCount / totalEngines) * 90);
        await this.client.reportProgress(
          job.jobId,
          job.testRunId,
          percent,
          `Agent executing engine ${engineId} against ${job.target.baseUrl}...`,
          engineId,
        );

        const engine = engineRegistry.get(engineId);
        if (!engine) {
          workerLogger.warn(`Engine "${engineId}" not found in local registry; skipping`);
          executionSummaries.push({
            engineId,
            status: 'failed',
            error: `Engine "${engineId}" not registered on agent`,
          });
          executedCount++;
          continue;
        }

        const startTime = Date.now();
        const context: ExecutionContext = {
          correlationId: crypto.randomUUID(),
          testRunId: job.testRunId,
          executionId: job.jobId,
          target: {
            id: job.target.id,
            name: job.target.name,
            baseUrl: job.target.baseUrl,
            scope: job.target.scope as unknown as ExecutionContext['target']['scope'],
          },
          logger: workerLogger,
          abortSignal: new AbortController().signal,
          reportProgress: (_percentage: number, _stepMessage: string) => {},
        };

        const testInput: TestInput = {
          targetUrl: job.target.baseUrl,
          options: job.options,
          customHeaders: job.customHeaders,
        };

        try {
          const result = await engine.execute(testInput, context);
          const durationMs = result.durationMs || Date.now() - startTime;
          const status = result.success ? 'completed' : 'failed';

          // Record engine metric
          metrics.push({
            name: `${engineId}_duration_ms`,
            value: durationMs,
            unit: 'ms',
            tags: { engineId, status },
          });

          executionSummaries.push({
            engineId,
            status,
            durationMs,
            error: result.error,
          });

          if (result.findings) {
            for (const f of result.findings) {
              allFindings.push({
                sourceEngine: engineId,
                title: f.title,
                description: f.description,
                rawSeverity: f.severity,
                evidenceData: f.evidence as Record<string, unknown> | undefined,
              });
            }
          }
        } catch (engineErr: unknown) {
          const errMsg = engineErr instanceof Error ? engineErr.message : String(engineErr);
          workerLogger.error({ err: engineErr, engineId }, `Engine execution error`);
          executionSummaries.push({
            engineId,
            status: 'failed',
            durationMs: Date.now() - startTime,
            error: errMsg,
          });
        }

        executedCount++;
      }

      await this.client.reportProgress(
        job.jobId,
        job.testRunId,
        100,
        `All ${totalEngines} engines completed by agent. Packaging results...`,
      );

      const completionReport: AgentJobCompletionReport = {
        jobId: job.jobId,
        testRunId: job.testRunId,
        status: executionSummaries.some((e) => e.status === 'failed') ? 'failed' : 'completed',
        findings: allFindings,
        metrics,
        executions: executionSummaries,
      };

      await this.client.reportCompletion(job.jobId, completionReport);
      workerLogger.info(
        { findingsCount: allFindings.length, executionsCount: executionSummaries.length },
        `Agent successfully completed job and submitted report`,
      );
    } catch (jobErr: unknown) {
      const msg = jobErr instanceof Error ? jobErr.message : String(jobErr);
      workerLogger.error({ err: jobErr }, 'Job failed catastrophically');
      await this.client.reportFailure(job.jobId, msg);
    }
  }
}
