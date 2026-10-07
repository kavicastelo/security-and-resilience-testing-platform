import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { reportsService, ReportFormat } from '../services/reports.service.js';
import { artifactStorageService } from '../services/artifact-storage.service.js';
import { testRunsService } from '../services/test-runs.service.js';

export const reportsRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // 1. Generate & Return Report on demand in JUnit, SARIF, HTML, or JSON format
  fastify.get<{
    Params: { id: string };
    Querystring: { format?: ReportFormat; policyId?: string };
  }>('/api/v1/test-runs/:id/report', async (request, reply) => {
    const { id } = request.params;
    const format = request.query.format || 'html';
    const { policyId } = request.query;

    try {
      const report = await reportsService.generateReport(id, format, policyId);

      reply.header('Content-Type', report.contentType);
      reply.header('Content-Disposition', `inline; filename="${report.filename}"`);
      return reply.send(report.content);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to generate report';
      return reply.status(404).send({
        success: false,
        error: {
          code: 'REPORT_GENERATION_FAILED',
          message,
        },
      });
    }
  });

  // 2. List Persisted Reports for a TestRun
  fastify.get<{
    Params: { id: string };
  }>('/api/v1/test-runs/:id/reports', async (request, reply) => {
    const { id } = request.params;

    const testRun = await testRunsService.getTestRunById(id);
    if (!testRun) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'TESTRUN_NOT_FOUND',
          message: `TestRun with ID "${id}" not found`,
        },
      });
    }

    try {
      let storedReports = await reportsService.listReports(id);

      // If no stored reports yet, generate and persist standard set
      if (storedReports.length === 0) {
        await reportsService.persistTestRunReports(id);
        storedReports = await reportsService.listReports(id);
      }

      return reply.send({
        success: true,
        data: storedReports,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to list reports';
      return reply.status(500).send({
        success: false,
        error: {
          code: 'REPORT_LIST_FAILED',
          message,
        },
      });
    }
  });

  // 3. Download a Specific Stored Report by ID
  fastify.get<{
    Params: { id: string; reportId: string };
  }>('/api/v1/test-runs/:id/reports/:reportId/download', async (request, reply) => {
    const { id, reportId } = request.params;

    try {
      const report = await reportsService.getReportById(reportId);

      if (!report || report.testRunId !== id) {
        return reply.status(404).send({
          success: false,
          error: {
            code: 'REPORT_NOT_FOUND',
            message: `Report with ID "${reportId}" not found for test run "${id}"`,
          },
        });
      }

      reply.header('Content-Type', report.contentType);
      reply.header('Content-Disposition', `attachment; filename="${report.filename}"`);
      return reply.send(report.content);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to download report';
      return reply.status(500).send({
        success: false,
        error: {
          code: 'REPORT_DOWNLOAD_FAILED',
          message,
        },
      });
    }
  });

  // 4. List Stored Artifacts for a TestRun
  fastify.get<{
    Params: { id: string };
  }>('/api/v1/test-runs/:id/artifacts', async (request, reply) => {
    const { id } = request.params;

    try {
      const artifactList = await artifactStorageService.listArtifacts(id);
      return reply.send({
        success: true,
        data: artifactList,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to list artifacts';
      return reply.status(500).send({
        success: false,
        error: {
          code: 'ARTIFACT_LIST_FAILED',
          message,
        },
      });
    }
  });

  // 5. Download a Specific Artifact by ID
  fastify.get<{
    Params: { id: string; artifactId: string };
  }>('/api/v1/test-runs/:id/artifacts/:artifactId/download', async (request, reply) => {
    const { id, artifactId } = request.params;

    try {
      const result = await artifactStorageService.getArtifact(artifactId);

      if (!result || result.artifact.testRunId !== id) {
        return reply.status(404).send({
          success: false,
          error: {
            code: 'ARTIFACT_NOT_FOUND',
            message: `Artifact with ID "${artifactId}" not found for test run "${id}"`,
          },
        });
      }

      reply.header('Content-Type', result.artifact.mimeType);
      reply.header('Content-Disposition', `attachment; filename="${result.artifact.name}"`);
      reply.header('X-Artifact-SHA256', result.artifact.sha256);
      return reply.send(result.content);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to download artifact';
      return reply.status(500).send({
        success: false,
        error: {
          code: 'ARTIFACT_DOWNLOAD_FAILED',
          message,
        },
      });
    }
  });
};
