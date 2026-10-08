import crypto from 'node:crypto';
import { AgentJobDispatch, AgentJobCompletionReport, RawFindingPayload } from '@security-lab/contracts';
import {
  TargetScope,
  isCloudMetadataHost,
  isCloudMetadataIp,
  isLinkLocalIp,
  isLoopbackIp,
  canonicalizeIp,
  validateUrlAgainstScope,
} from '@security-lab/domain';
import {
  computeFindingsHash,
  computeResultSignature,
  verifyScopeSignature,
} from '@security-lab/evidence';
import { AgentClient } from './client.js';
import { engineRegistry, ExecutionContext, TestInput } from '@security-lab/test-sdk';
import { logger } from '@security-lab/logger';

export class ScopeTamperingError extends Error {
  readonly code = 'SCOPE_TAMPERING_DETECTED';
  constructor(message: string) {
    super(message);
    this.name = 'ScopeTamperingError';
  }
}

export class SecurityBoundaryError extends Error {
  readonly code = 'SECURITY_BOUNDARY_VIOLATION';
  constructor(message: string) {
    super(message);
    this.name = 'SecurityBoundaryError';
  }
}

export class JobTimeoutError extends Error {
  readonly code = 'JOB_TIMEOUT_EXCEEDED';
  constructor(message: string) {
    super(message);
    this.name = 'JobTimeoutError';
  }
}

export class JobCancelledError extends Error {
  readonly code = 'JOB_CANCELLED';
  constructor(message: string) {
    super(message);
    this.name = 'JobCancelledError';
  }
}

export function parseDurationMs(duration: string | number | undefined, defaultMs = 15 * 60 * 1000): number {
  if (typeof duration === 'number') {
    return duration > 1000 ? duration : duration * 1000;
  }
  if (typeof duration === 'string') {
    const match = duration.trim().match(/^(\d+(?:\.\d+)?)\s*(ms|s|m|h)?$/i);
    if (match && match[1]) {
      const val = parseFloat(match[1]);
      const unit = (match[2] || 's').toLowerCase();
      if (unit === 'ms') return Math.round(val);
      if (unit === 's') return Math.round(val * 1000);
      if (unit === 'm') return Math.round(val * 60 * 1000);
      if (unit === 'h') return Math.round(val * 3600 * 1000);
    }
  }
  return defaultMs;
}

export interface AgentWorkerOptions {
  allowLocalTesting?: boolean;
  masterKey?: string;
}

export class AgentWorker {
  private readonly client: AgentClient;
  private readonly allowLocalTesting: boolean;
  private readonly masterKey?: string;

  constructor(client: AgentClient, options: AgentWorkerOptions = {}) {
    this.client = client;
    this.allowLocalTesting =
      options.allowLocalTesting ??
      (process.env.ALLOW_LOCAL_TESTING === 'true' ||
        process.env.SECURITY_LAB_ALLOW_LOCAL_TESTING === 'true' ||
        process.env.NODE_ENV === 'test' ||
        process.env.VITEST === 'true');
    this.masterKey = options.masterKey;
  }

  async executeJob(job: AgentJobDispatch, abortSignal?: AbortSignal): Promise<void> {
    const workerLogger = logger.child({ jobId: job.jobId, testRunId: job.testRunId });
    workerLogger.info(`Agent worker starting execution for target ${job.target.baseUrl}`);

    if (abortSignal?.aborted) {
      workerLogger.warn(
        { event: 'job.cancelled_propagated', jobId: job.jobId },
        'Job was already cancelled prior to execution start; aborting',
      );
      throw new JobCancelledError(`Job "${job.jobId}" cancelled before execution started`);
    }

    const executionController = new AbortController();
    let isTimedOut = false;
    let isCancelled = false;

    const onExternalAbort = () => {
      isCancelled = true;
      workerLogger.warn(
        { event: 'job.cancelled_propagated', jobId: job.jobId },
        'Cancellation signal received; aborting in-flight execution and active containers',
      );
      executionController.abort(abortSignal?.reason || new Error(`Job execution was cancelled`));
    };

    if (abortSignal) {
      abortSignal.addEventListener('abort', onExternalAbort, { once: true });
    }

    const maxDurationLimit = (job.target.scope as { limits?: { maxDuration?: string | number } })?.limits?.maxDuration;
    const timeoutMs = parseDurationMs(maxDurationLimit, 15 * 60 * 1000);

    const timeoutTimer = setTimeout(() => {
      isTimedOut = true;
      workerLogger.warn(
        { event: 'job.timeout_exceeded', jobId: job.jobId, timeoutMs },
        `Job execution exceeded maximum duration of ${timeoutMs}ms; aborting`,
      );
      executionController.abort(new JobTimeoutError(`Job execution timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    try {
      // 1. Verify Scope Attestation Signature (Rule 4, Rule 9, Rule 10)
      if (!job.target.scopeSignature) {
        workerLogger.warn(
          {
            event: 'security.scope_violation_blocked',
            reason: 'MISSING_SCOPE_SIGNATURE',
            jobId: job.jobId,
            targetId: job.target.id,
          },
          'Scope verification failed: missing cryptographic scope signature',
        );
        const err = new ScopeTamperingError(`Missing scope signature for target "${job.target.id}"`);
        await this.client.reportFailure(job.jobId, err.message);
        throw err;
      }

      const isScopeSignatureValid = verifyScopeSignature({
        targetId: job.target.id,
        baseUrl: job.target.baseUrl,
        scope: job.target.scope,
        signature: job.target.scopeSignature,
        masterKey: this.masterKey,
      });

      if (!isScopeSignatureValid) {
        workerLogger.warn(
          {
            event: 'security.scope_violation_blocked',
            reason: 'INVALID_SCOPE_SIGNATURE',
            jobId: job.jobId,
            targetId: job.target.id,
          },
          'Scope verification failed: cryptographic signature mismatch (target or scope tampering detected)',
        );
        const err = new ScopeTamperingError(
          `Cryptographic scope signature mismatch for target "${job.target.id}". Authorized target scope may have been tampered with.`,
        );
        await this.client.reportFailure(job.jobId, err.message);
        throw err;
      }

      // 2. In-Agent Defense-in-Depth SSRF & Cloud Metadata Guard (Rule 9, Rule 16)
      let parsedUrl: URL;
      try {
        parsedUrl = new URL(job.target.baseUrl);
      } catch {
        workerLogger.warn(
          { event: 'security.scope_violation_blocked', reason: 'INVALID_TARGET_URL', url: job.target.baseUrl },
          'Target base URL cannot be parsed',
        );
        const err = new SecurityBoundaryError(`Invalid target base URL: "${job.target.baseUrl}"`);
        await this.client.reportFailure(job.jobId, err.message);
        throw err;
      }

      const host = parsedUrl.hostname.replace(/^\[|\]$/g, '').toLowerCase().trim();
      const canonical = canonicalizeIp(host);

      // Hardcoded prohibition against cloud provider metadata services
      if (
        isCloudMetadataHost(host) ||
        (canonical && (isCloudMetadataIp(canonical) || isCloudMetadataHost(canonical) || isLinkLocalIp(canonical))) ||
        isLinkLocalIp(host)
      ) {
        workerLogger.warn(
          {
            event: 'security.scope_violation_blocked',
            reason: 'CLOUD_METADATA_PROHIBITED',
            host,
            url: job.target.baseUrl,
            jobId: job.jobId,
          },
          'Blocked attempt to target cloud provider metadata endpoint from agent',
        );
        const err = new SecurityBoundaryError(
          `Prohibited target: access to cloud provider metadata endpoint "${host}" is strictly forbidden.`,
        );
        await this.client.reportFailure(job.jobId, err.message);
        throw err;
      }

      // Hardcoded prohibition against scanning the agent host's own local loopback unless explicitly allowed
      if (!this.allowLocalTesting) {
        if (host === 'localhost' || (canonical && isLoopbackIp(canonical)) || isLoopbackIp(host)) {
          workerLogger.warn(
            {
              event: 'security.scope_violation_blocked',
              reason: 'LOCAL_LOOPBACK_PROHIBITED',
              host,
              url: job.target.baseUrl,
              jobId: job.jobId,
            },
            'Blocked attempt to target local loopback from agent host without --allow-local-testing flag',
          );
          const err = new SecurityBoundaryError(
            `Prohibited target: scanning agent host local loopback "${host}" is forbidden without explicit authorization (--allow-local-testing).`,
          );
          await this.client.reportFailure(job.jobId, err.message);
          throw err;
        }
      }

      // Check allowedHosts in scope does not contain cloud metadata
      const allowedHosts = (job.target.scope as { allowedHosts?: string[] })?.allowedHosts || [];
      for (const allowed of allowedHosts) {
        const cleanAllowed = allowed.replace(/^\[|\]$/g, '').toLowerCase().trim();
        const canonAllowed = canonicalizeIp(cleanAllowed);
        if (
          isCloudMetadataHost(cleanAllowed) ||
          (canonAllowed &&
            (isCloudMetadataIp(canonAllowed) ||
              isCloudMetadataHost(canonAllowed) ||
              isLinkLocalIp(canonAllowed))) ||
          isLinkLocalIp(cleanAllowed)
        ) {
          workerLogger.warn(
            {
              event: 'security.scope_violation_blocked',
              reason: 'SCOPE_ALLOWED_HOST_CLOUD_METADATA',
              host: cleanAllowed,
              jobId: job.jobId,
            },
            'Target scope allowedHosts contains prohibited cloud metadata endpoint',
          );
          const err = new SecurityBoundaryError(
            `Prohibited target scope: allowedHosts contains cloud metadata endpoint "${cleanAllowed}".`,
          );
          await this.client.reportFailure(job.jobId, err.message);
          throw err;
        }
      }

      // Validate target.baseUrl against target.scope using domain scope validator
      const scopeResult = validateUrlAgainstScope(
        job.target.baseUrl,
        job.target.scope as unknown as TargetScope,
        { allowUnresolvedDns: true },
      );
      if (!scopeResult.valid) {
        workerLogger.warn(
          {
            event: 'security.scope_violation_blocked',
            reason: 'SCOPE_VIOLATIONS',
            violations: scopeResult.violations,
            jobId: job.jobId,
          },
          'Target base URL violates authorized target scope',
        );
        const err = new SecurityBoundaryError(
          `Scope violation: ${scopeResult.violations.join('; ')}`,
        );
        await this.client.reportFailure(job.jobId, err.message);
        throw err;
      }

      const enginesToRun =
        job.engineIds.length > 0
          ? job.engineIds
          : ['engine-native-headers', 'engine-native-cors', 'engine-native-tls'];

      const allFindings: RawFindingPayload[] = [];
      const executionSummaries: { engineId: string; status: string; durationMs?: number; error?: string }[] = [];
      const metrics: { name: string; value: number; unit: string; tags?: Record<string, string> }[] = [];

      let executedCount = 0;
      const totalEngines = enginesToRun.length;

      for (const engineId of enginesToRun) {
        if (executionController.signal.aborted) {
          workerLogger.info({ engineId, jobId: job.jobId }, 'Execution aborted; breaking engine loop');
          break;
        }

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
          abortSignal: executionController.signal,
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
          if (executionController.signal.aborted) {
            workerLogger.info({ engineId, jobId: job.jobId }, 'Engine execution interrupted by abort signal');
            break;
          }
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

        if (executionController.signal.aborted) {
          break;
        }
      }

      // Check aborted state before reporting completion
      if (executionController.signal.aborted) {
        if (isTimedOut) {
          const timeoutErr = new JobTimeoutError(
            `Job execution timed out after exceeding maximum duration of ${timeoutMs}ms`,
          );
          await this.client.reportFailure(job.jobId, timeoutErr.message);
          throw timeoutErr;
        }
        if (isCancelled || abortSignal?.aborted) {
          workerLogger.info(
            { event: 'job.cancelled_propagated', jobId: job.jobId },
            'Job execution aborted due to cancellation; skipping completion submission',
          );
          throw new JobCancelledError(`Job "${job.jobId}" cancelled during execution`);
        }
        throw new JobCancelledError(`Job "${job.jobId}" execution was aborted`);
      }

      await this.client.reportProgress(
        job.jobId,
        job.testRunId,
        100,
        `All ${totalEngines} engines completed by agent. Packaging results...`,
      );

      let resultSignature: string | undefined;
      if (job.jobDispatchSecret) {
        const findingsHash = computeFindingsHash(allFindings, executionSummaries);
        resultSignature = computeResultSignature(job.jobDispatchSecret, job.jobId, findingsHash);
      }

      const completionReport: AgentJobCompletionReport = {
        jobId: job.jobId,
        leaseId: job.leaseId,
        testRunId: job.testRunId,
        status: executionSummaries.some((e) => e.status === 'failed') ? 'failed' : 'completed',
        findings: allFindings,
        metrics,
        executions: executionSummaries,
        resultSignature,
      };

      await this.client.reportCompletion(job.jobId, completionReport);
      workerLogger.info(
        { findingsCount: allFindings.length, executionsCount: executionSummaries.length },
        `Agent successfully completed job and submitted report`,
      );
    } catch (jobErr: unknown) {
      const msg = jobErr instanceof Error ? jobErr.message : String(jobErr);
      workerLogger.error({ err: jobErr }, 'Job execution failed');
      if (
        !(jobErr instanceof ScopeTamperingError) &&
        !(jobErr instanceof SecurityBoundaryError) &&
        !(jobErr instanceof JobCancelledError) &&
        !(jobErr instanceof JobTimeoutError)
      ) {
        await this.client.reportFailure(job.jobId, msg);
      }
      throw jobErr;
    } finally {
      clearTimeout(timeoutTimer);
      if (abortSignal) {
        abortSignal.removeEventListener('abort', onExternalAbort);
      }
    }
  }
}
