import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { reportsService, ReportFormat } from '../services/reports.service.js';

export const reportsRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // Generate & Download Report in JUnit, SARIF, HTML, or JSON format
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
};
