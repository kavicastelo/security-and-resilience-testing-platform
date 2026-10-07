import { eq, and, ne, desc, or } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { testExecutions, testRuns, reports, findings as findingsTable } from './db/schema.js';
import { testRunsService } from './test-runs.service.js';
import { targetsService } from './targets.service.js';
import { findingsService } from './findings.service.js';
import { metricsService } from './metrics.service.js';
import { evidenceService } from './evidence.service.js';
import { releasesService } from './releases.service.js';
import { artifactStorageService } from './artifact-storage.service.js';
import {
  generateJUnitXml,
  generateSarifReport,
  generateHtmlExecutiveReport,
  ReportInput,
  TestExecutionRecord,
  FindingDiffSummary,
  FindingDiffItem,
} from '@security-lab/contracts';
import { Finding, TestRun } from '@security-lab/domain';
import { logger } from '@security-lab/logger';

export type ReportFormat = 'junit' | 'sarif' | 'html' | 'json';

export interface GeneratedReport {
  id?: string;
  format: ReportFormat;
  content: string;
  contentType: string;
  filename: string;
}

export interface StoredReportHeader {
  id: string;
  testRunId: string;
  format: string;
  filename: string;
  contentType: string;
  createdAt: Date;
}

export interface StoredReportRecord extends StoredReportHeader {
  content: string;
}

export class ReportsService {
  /**
   * Calculates finding diffs relative to the previous test run on the same target.
   * Categorizes findings into:
   * - NEW: Introduced in this run
   * - RECURRING: Previously seen and persisted
   * - FIXED: Resolved in this run
   */
  async calculateFindingDiff(
    currentTestRun: TestRun,
    currentFindings: Finding[],
  ): Promise<FindingDiffSummary> {
    const { db } = getDatabase();

    // 1. Find previous completed or failed test run on the same target
    const prevRuns = await db
      .select()
      .from(testRuns)
      .where(
        and(
          eq(testRuns.targetId, currentTestRun.targetId),
          ne(testRuns.id, currentTestRun.id),
          or(eq(testRuns.status, 'completed'), eq(testRuns.status, 'failed')),
        ),
      )
      .orderBy(desc(testRuns.createdAt))
      .limit(1);

    const prevRun = prevRuns[0];
    const details: FindingDiffItem[] = [];

    // 2. Query any findings fixed specifically in this run
    const fixedInThisRun = await db
      .select()
      .from(findingsTable)
      .where(
        and(
          eq(findingsTable.targetId, currentTestRun.targetId),
          eq(findingsTable.fixedInRunId, currentTestRun.id),
        ),
      );

    let newCount = 0;
    let recurringCount = 0;

    if (prevRun) {
      // Fetch findings from previous test run
      const prevFindings = await findingsService.listFindings({ testRunId: prevRun.id });
      const prevFingerprints = new Set(prevFindings.map((f) => f.fingerprint));

      for (const f of currentFindings) {
        const isRecurring =
          prevFingerprints.has(f.fingerprint) || (f.occurrenceCount && f.occurrenceCount > 1);

        if (isRecurring) {
          recurringCount++;
          details.push({
            fingerprint: f.fingerprint,
            title: f.title,
            severity: f.severity,
            category: f.category,
            diffStatus: 'RECURRING',
            findingId: f.id,
          });
        } else {
          newCount++;
          details.push({
            fingerprint: f.fingerprint,
            title: f.title,
            severity: f.severity,
            category: f.category,
            diffStatus: 'NEW',
            findingId: f.id,
          });
        }
      }

      // Check for findings resolved in this run from the previous run
      const currentFingerprints = new Set(currentFindings.map((f) => f.fingerprint));
      const fixedFingerprints = new Set(fixedInThisRun.map((f) => f.fingerprint));

      for (const pf of prevFindings) {
        if (!currentFingerprints.has(pf.fingerprint) && !fixedFingerprints.has(pf.fingerprint)) {
          fixedFingerprints.add(pf.fingerprint);
          details.push({
            fingerprint: pf.fingerprint,
            title: pf.title,
            severity: pf.severity,
            category: pf.category,
            diffStatus: 'FIXED',
            findingId: pf.id,
          });
        }
      }

      for (const ff of fixedInThisRun) {
        if (!details.some((d) => d.fingerprint === ff.fingerprint && d.diffStatus === 'FIXED')) {
          details.push({
            fingerprint: ff.fingerprint,
            title: ff.title,
            severity: ff.severity,
            category: ff.category,
            diffStatus: 'FIXED',
            findingId: ff.id,
          });
        }
      }

      const fixedCount = details.filter((d) => d.diffStatus === 'FIXED').length;

      return {
        newCount,
        recurringCount,
        fixedCount,
        previousTestRunId: prevRun.id,
        details,
      };
    }

    // No previous run: infer diff status from occurrenceCount
    for (const f of currentFindings) {
      if (f.occurrenceCount && f.occurrenceCount > 1) {
        recurringCount++;
        details.push({
          fingerprint: f.fingerprint,
          title: f.title,
          severity: f.severity,
          category: f.category,
          diffStatus: 'RECURRING',
          findingId: f.id,
        });
      } else {
        newCount++;
        details.push({
          fingerprint: f.fingerprint,
          title: f.title,
          severity: f.severity,
          category: f.category,
          diffStatus: 'NEW',
          findingId: f.id,
        });
      }
    }

    for (const ff of fixedInThisRun) {
      details.push({
        fingerprint: ff.fingerprint,
        title: ff.title,
        severity: ff.severity,
        category: ff.category,
        diffStatus: 'FIXED',
        findingId: ff.id,
      });
    }

    return {
      newCount,
      recurringCount,
      fixedCount: fixedInThisRun.length,
      details,
    };
  }

  /**
   * Generates a report in the specified format, persisting it to disk (via ArtifactStorageService)
   * and PostgreSQL (reports table).
   */
  async generateReport(
    testRunId: string,
    format: ReportFormat = 'html',
    policyId?: string,
    persist: boolean = true,
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

    // 3. Fetch Findings, Metrics, Evidence, and Diff Intelligence
    const findings = await findingsService.listFindings({ testRunId });
    const metrics = await metricsService.listMetricsByTestRunId(testRunId);
    const evidenceList = await evidenceService.listEvidenceByTestRunId(testRunId);
    const findingDiff = await this.calculateFindingDiff(testRun, findings);

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
      findingDiff,
    };

    let generated: GeneratedReport;

    switch (format) {
      case 'junit': {
        const xml = generateJUnitXml(reportInput);
        generated = {
          format: 'junit',
          content: xml,
          contentType: 'application/xml',
          filename: `security-report-${testRunId}.xml`,
        };
        break;
      }
      case 'sarif': {
        const sarif = generateSarifReport(reportInput);
        generated = {
          format: 'sarif',
          content: JSON.stringify(sarif, null, 2),
          contentType: 'application/sarif+json',
          filename: `security-report-${testRunId}.sarif`,
        };
        break;
      }
      case 'html': {
        const html = generateHtmlExecutiveReport(reportInput);
        generated = {
          format: 'html',
          content: html,
          contentType: 'text/html; charset=utf-8',
          filename: `security-report-${testRunId}.html`,
        };
        break;
      }
      case 'json':
      default: {
        generated = {
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
                findingDiff,
              },
            },
            null,
            2,
          ),
          contentType: 'application/json',
          filename: `security-report-${testRunId}.json`,
        };
        break;
      }
    }

    if (persist) {
      // 5. Persist to PostgreSQL reports table
      const [savedReport] = await db
        .insert(reports)
        .values({
          testRunId,
          format: generated.format,
          filename: generated.filename,
          contentType: generated.contentType,
          content: generated.content,
        })
        .returning();

      if (savedReport) {
        generated.id = savedReport.id;

        // 6. Persist report as immutable artifact on disk and in artifacts table
        try {
          await artifactStorageService.storeArtifact({
            testRunId,
            filename: generated.filename,
            content: generated.content,
            mimeType: generated.contentType,
            type: 'report',
            metadata: {
              reportId: savedReport.id,
              format: generated.format,
              targetId: testRun.targetId,
              generatedAt: new Date().toISOString(),
            },
          });
        } catch (err: unknown) {
          logger.warn({ err, testRunId, format }, 'Failed to persist report to disk artifact storage');
        }
      }
    }

    return generated;
  }

  /**
   * Persists all standard enterprise reports (JUnit XML, SARIF v2.1.0, HTML)
   * for a test run automatically upon completion.
   */
  async persistTestRunReports(
    testRunId: string,
    policyId?: string,
  ): Promise<{ junit: GeneratedReport; sarif: GeneratedReport; html: GeneratedReport }> {
    const [junit, sarif, html] = await Promise.all([
      this.generateReport(testRunId, 'junit', policyId, true),
      this.generateReport(testRunId, 'sarif', policyId, true),
      this.generateReport(testRunId, 'html', policyId, true),
    ]);

    logger.info(
      { testRunId, junitId: junit.id, sarifId: sarif.id, htmlId: html.id },
      'Persisted standard test run reports (JUnit, SARIF, HTML) in database and artifact storage',
    );

    return { junit, sarif, html };
  }

  /**
   * Lists stored reports for a given test run.
   */
  async listReports(testRunId: string): Promise<StoredReportHeader[]> {
    const { db } = getDatabase();
    const rows = await db
      .select({
        id: reports.id,
        testRunId: reports.testRunId,
        format: reports.format,
        filename: reports.filename,
        contentType: reports.contentType,
        createdAt: reports.createdAt,
      })
      .from(reports)
      .where(eq(reports.testRunId, testRunId))
      .orderBy(desc(reports.createdAt));

    return rows;
  }

  /**
   * Retrieves a specific stored report by ID, including its content.
   */
  async getReportById(reportId: string): Promise<StoredReportRecord | null> {
    const { db } = getDatabase();
    const [row] = await db.select().from(reports).where(eq(reports.id, reportId));

    if (!row) {
      return null;
    }

    return {
      id: row.id,
      testRunId: row.testRunId,
      format: row.format,
      filename: row.filename,
      contentType: row.contentType,
      content: row.content,
      createdAt: row.createdAt,
    };
  }
}

export const reportsService = new ReportsService();
