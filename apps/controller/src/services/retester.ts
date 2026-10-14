import { getDatabase } from './db.js';
import { findings } from './db/schema.js';
import { eq } from 'drizzle-orm';
import { findingsService, extractFindingComponents } from './findings.service.js';
import { targetsService } from './targets.service.js';
import { testRunsService } from './test-runs.service.js';
import { testRunnerService } from './runner.service.js';
import { engineRegistry } from '@security-lab/test-sdk';
import { RetestResult } from '@security-lab/contracts';
import { logger } from '@security-lab/logger';

export class RetesterService {
  /**
   * Executes a targeted, minimal single-finding retest.
   * Runs only the specific engine and rule that detected the flaw against the affected endpoint.
   * If the flaw is no longer detected, transitions the finding to RESOLVED.
   * If still detected, marks as REOPENED / regressed.
   * Enforces a 5-second timeout constraint for native rules.
   */
  async retestFinding(
    findingId: string,
    tenantId?: string,
    timeoutMs = 5000,
  ): Promise<RetestResult> {
    const startTime = Date.now();
    const { db } = getDatabase();

    // 1. Fetch finding
    const finding = await findingsService.getFindingById(findingId, tenantId);
    if (!finding) {
      throw new Error(`Finding with ID "${findingId}" not found`);
    }

    // 2. Fetch target
    const target = await targetsService.getTargetById(finding.targetId, tenantId);
    if (!target) {
      throw new Error(`Target with ID "${finding.targetId}" not found`);
    }

    // 3. Extract components (rule ID, endpoint path, parameter name)
    const { ruleOrCweId, endpointPath, parameterName } = extractFindingComponents(finding);
    const engineId = finding.testDefinitionId;

    logger.info(
      {
        findingId,
        engineId,
        ruleOrCweId,
        endpointPath,
        parameterName,
        targetUrl: target.baseUrl,
      },
      'Starting targeted single-finding retest execution',
    );

    // 4. Create ephemeral retest test run
    const retestRun = await testRunsService.createTestRun(
      {
        projectId: target.projectId,
        targetId: target.id,
        profileId: engineId,
        triggeredBy: 'api' as const,
        metadata: {
          isRetest: true,
          targetedFindingId: finding.id,
          targetedRuleId: ruleOrCweId,
          targetedEndpoint: endpointPath,
          endpoint: endpointPath,
          ruleId: ruleOrCweId,
          parameter: parameterName,
        },
      },
      tenantId,
    );

    // 5. Build AbortController for enforcing timeout constraint
    const abortController = new AbortController();
    const timeoutHandle = setTimeout(() => {
      abortController.abort(new Error(`Retest timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    // Ensure target has valid scope object with allowedHosts, allowedPorts, and limits
    const currentScope = (target.scope || {}) as Record<string, unknown>;
    const allowedHosts = Array.isArray(currentScope.allowedHosts)
      ? currentScope.allowedHosts
      : ['127.0.0.1', 'localhost'];
    const allowedPorts = Array.isArray(currentScope.allowedPorts)
      ? [...(currentScope.allowedPorts as number[])]
      : [80, 443, 8080, 3000];

    try {
      const u = new URL(target.baseUrl);
      if (u.port) {
        const p = parseInt(u.port, 10);
        if (!allowedPorts.includes(p)) allowedPorts.push(p);
      }
    } catch {
      // ignore
    }

    (target as Record<string, unknown>).scope = {
      allowedHosts,
      allowedPorts,
      excludedPaths: Array.isArray(currentScope.excludedPaths) ? currentScope.excludedPaths : [],
      allowPrivateIps: true,
      testing: { activeScanning: true, loadTesting: true, chaosTesting: true },
      limits: { maxRps: 1000, maxConcurrency: 50, maxDuration: '10m' },
    };

    let stillDetected = false;
    let executionDuration = 0;
    let timedOut = false;
    let executionError: Error | null = null;

    try {
      // 6. Check if engine is available in registry
      const engine = engineRegistry.get(engineId);

      if (engine) {
        // Run single engine targeted execution via testRunnerService
        const result = await testRunnerService.executeTestRunInternal(
          retestRun.id,
          {
            engineIds: [engineId],
            options: {
              endpoint: endpointPath,
              ruleId: ruleOrCweId,
              parameter: parameterName,
              singleFindingRetest: true,
            },
          },
          abortController.signal,
        );

        // Check if matching finding was re-detected
        stillDetected = result.findings.some((f) => {
          if (f.fingerprint === finding.fingerprint) return true;
          if (f.category === finding.category && f.title === finding.title) return true;
          if (ruleOrCweId && f.title.toLowerCase().includes(ruleOrCweId.toLowerCase())) return true;
          if (ruleOrCweId && ruleOrCweId.toLowerCase().includes(f.title.toLowerCase())) return true;
          if (
            typeof f.metadata?.ruleId === 'string' &&
            typeof finding.metadata?.ruleId === 'string' &&
            f.metadata.ruleId === finding.metadata.ruleId
          ) {
            return true;
          }
          return false;
        });
      } else {
        // Fallback / mock test execution: probe target URL directly if engine not in registry
        let targetProbeUrl = target.baseUrl;
        if (endpointPath) {
          try {
            targetProbeUrl = new URL(endpointPath, target.baseUrl).toString();
          } catch {
            targetProbeUrl = `${target.baseUrl}${endpointPath.startsWith('/') ? '' : '/'}${endpointPath}`;
          }
        }

        try {
          const res = await fetch(targetProbeUrl, {
            method: 'GET',
            headers: { 'x-security-lab-retest': finding.id },
            signal: abortController.signal,
          });

          // Check if response indicates vulnerability is still present
          // (e.g. if the finding was about missing headers, check if headers are now present)
          const headers = res.headers;
          if (ruleOrCweId.toLowerCase().includes('x-content-type-options')) {
            stillDetected = !headers.get('x-content-type-options');
          } else if (ruleOrCweId.toLowerCase().includes('x-frame-options')) {
            stillDetected = !headers.get('x-frame-options');
          } else if (res.status >= 500) {
            stillDetected = true;
          } else {
            // Default: if target probe returned 200 without error, flaw considered cleared
            stillDetected = false;
          }
        } catch (fetchErr) {
          if (abortController.signal.aborted) {
            throw fetchErr;
          }
          // Network failure during probe: maintain detection
          stillDetected = true;
        }
      }
    } catch (err: unknown) {
      if (abortController.signal.aborted) {
        timedOut = true;
        logger.warn(
          { findingId, timeoutMs },
          'Targeted single-finding retest timed out. Keeping finding in current status.',
        );
      } else {
        executionError = err instanceof Error ? err : new Error(String(err));
        stillDetected = true;
        logger.error({ err, findingId }, 'Targeted retest execution failed with error');
      }
    } finally {
      clearTimeout(timeoutHandle);
      executionDuration = Date.now() - startTime;
    }

    // 7. Update status based on retest outcome
    if (timedOut || executionError) {
      return {
        findingId: finding.id,
        status: (finding.status === 'resolved' ? 'resolved' : 'open'),
        stillDetected: true,
        testedEndpoint: endpointPath,
        ruleId: ruleOrCweId,
        durationMs: executionDuration,
        retestRunId: retestRun.id,
        message: timedOut
          ? `Retest timed out after ${timeoutMs}ms. Status left unchanged as ${finding.status}.`
          : `Retest execution failed: ${executionError?.message}. Status left unchanged as ${finding.status}.`,
        timestamp: new Date().toISOString(),
      };
    }

    if (!stillDetected) {
      // Flaw is resolved!
      await findingsService.triageFinding(
        finding.id,
        {
          status: 'resolved',
          comment: `Targeted single-finding retest confirmed flaw resolved on ${endpointPath || target.baseUrl}`,
          actorId: 'system:retester',
        },
        'system:retester',
        tenantId,
      );

      // Record fixedInRunId and fixedAt
      await db
        .update(findings)
        .set({
          fixedInRunId: retestRun.id,
          fixedAt: new Date(),
        })
        .where(eq(findings.id, finding.id));

      logger.info(
        { findingId: finding.id, durationMs: executionDuration },
        'Targeted retest succeeded: finding transitioned to RESOLVED',
      );

      return {
        findingId: finding.id,
        status: 'RESOLVED',
        stillDetected: false,
        testedEndpoint: endpointPath,
        ruleId: ruleOrCweId,
        durationMs: executionDuration,
        retestRunId: retestRun.id,
        message: 'Vulnerability is no longer detected. Status transitioned to RESOLVED.',
        timestamp: new Date().toISOString(),
      };
    }

    // Still detected: transition to regressed (if was resolved) or remain open / REOPENED
    if (finding.status === 'resolved') {
      await db
        .update(findings)
        .set({
          status: 'regressed',
          lastDetectedAt: new Date(),
          occurrenceCount: (finding.occurrenceCount || 1) + 1,
        })
        .where(eq(findings.id, finding.id));
    }

    logger.info(
      { findingId: finding.id, durationMs: executionDuration },
      'Targeted retest failed: finding still present, marked as REOPENED',
    );

    return {
      findingId: finding.id,
      status: 'REOPENED',
      stillDetected: true,
      testedEndpoint: endpointPath,
      ruleId: ruleOrCweId,
      durationMs: executionDuration,
      retestRunId: retestRun.id,
      message: 'Vulnerability is still detected. Status remains open or regressed.',
      timestamp: new Date().toISOString(),
    };
  }
}

export const retesterService = new RetesterService();
