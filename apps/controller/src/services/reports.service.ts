import { eq } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { testExecutions } from './db/schema.js';
import { testRunsService } from './test-runs.service.js';
import { targetsService } from './targets.service.js';
import { findingsService } from './findings.service.js';
import { metricsService } from './metrics.service.js';
import { evidenceService } from './evidence.service.js';
import { releasesService } from './releases.service.js';
import {
  generateJUnitXml,
  generateSarifReport,
  generateHtmlExecutiveReport,
  ReportInput,
  TestExecutionRecord,
} from '@security-lab/contracts';

export type ReportFormat = 'junit' | 'sarif' | 'html' | 'json';

export interface GeneratedReport {
  format: ReportFormat;
  content: string;
  contentType: string;
  filename: string;
}

export class ReportsService {
  async generateReport(
    testRunId: string,
    format: ReportFormat = 'html',
    policyId?: string,
  ): Promise<GeneratedReport> {
    const { db } = getDatabase();

    // 1. Fetch Test Run & Target
    const testRun = await testRunsService.getTestRunById(testRunId);
    if (!testRun) {
      throw new Error(`TestRun "${testRunId}" not found`);
    }

    const target = await targetsService.getTargetById(testRun.targetId);

    // 2. Fetch Executions
    const execRows = await db
      .select()
      .from(testExecutions)
      .where(eq(testExecutions.testRunId, testRunId));

    const executions: TestExecutionRecord[] = execRows.map((e) => ({
      id: e.id,
      engineId: e.engineId,
      executionClass: e.executionClass,
      status: e.status,
      durationMs: e.durationMs || undefined,
      errorMessage: e.errorMessage || undefined,
    }));

    // 3. Fetch Findings, Metrics, and Evidence
    const findings = await findingsService.listFindings({ testRunId });
    const metrics = await metricsService.listMetricsByTestRunId(testRunId);
    const evidenceList = await evidenceService.listEvidenceByTestRunId(testRunId);

    // 4. Evaluate Release Gate & Posture Score
    const gateEval = await releasesService.evaluateReleaseGate({
      testRunId,
      policyId,
    });

    const reportInput: ReportInput = {
      testRun,
      target: target ? { id: target.id, name: target.name, baseUrl: target.baseUrl } : undefined,
      executions,
      findings,
      metrics,
      evidence: evidenceList,
      posture: gateEval.score,
      releaseGate: gateEval.gateResult,
    };

    switch (format) {
      case 'junit': {
        const xml = generateJUnitXml(reportInput);
        return {
          format: 'junit',
          content: xml,
          contentType: 'application/xml',
          filename: `security-report-${testRunId}.xml`,
        };
      }
      case 'sarif': {
        const sarif = generateSarifReport(reportInput);
        return {
          format: 'sarif',
          content: JSON.stringify(sarif, null, 2),
          contentType: 'application/sarif+json',
          filename: `security-report-${testRunId}.sarif`,
        };
      }
      case 'html': {
        const html = generateHtmlExecutiveReport(reportInput);
        return {
          format: 'html',
          content: html,
          contentType: 'text/html; charset=utf-8',
          filename: `security-report-${testRunId}.html`,
        };
      }
      case 'json':
      default: {
        return {
          format: 'json',
          content: JSON.stringify(
            {
              success: true,
              data: {
                testRun,
                target,
                posture: gateEval.score,
                releaseGate: gateEval.gateResult,
                executions,
                findings,
                metrics,
              },
            },
            null,
            2,
          ),
          contentType: 'application/json',
          filename: `security-report-${testRunId}.json`,
        };
      }
    }
  }
}

export const reportsService = new ReportsService();
