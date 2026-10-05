import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { CreateTestRunInputSchema } from '@security-lab/domain';
import { testRunsService } from '../services/test-runs.service.js';
import { testRunnerService, ExecuteRunOptions } from '../services/runner.service.js';
import { findingsService } from '../services/findings.service.js';
import { evidenceService } from '../services/evidence.service.js';
import { metricsService } from '../services/metrics.service.js';

export const testRunsRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // 1. Create & Queue TestRun
  fastify.post('/api/v1/test-runs', async (request, reply) => {
    const parseResult = CreateTestRunInputSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid TestRun input parameters',
          details: parseResult.error.format(),
        },
      });
    }

    try {
      const testRun = await testRunsService.createTestRun(parseResult.data);
      return reply.status(201).send({
        success: true,
        data: testRun,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to create TestRun';
      return reply.status(400).send({
        success: false,
        error: {
          code: 'TESTRUN_CREATION_FAILED',
          message,
        },
      });
    }
  });

  // 2. List TestRuns
  fastify.get<{
    Querystring: { projectId?: string; targetId?: string };
  }>('/api/v1/test-runs', async (request, reply) => {
    const { projectId, targetId } = request.query;
    const runs = await testRunsService.listTestRuns({ projectId, targetId });
    return reply.send({
      success: true,
      data: runs,
    });
  });

  // 3. Get TestRun by ID
  fastify.get<{ Params: { id: string } }>('/api/v1/test-runs/:id', async (request, reply) => {
    const run = await testRunsService.getTestRunById(request.params.id);
    if (!run) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'TESTRUN_NOT_FOUND',
          message: `TestRun with ID "${request.params.id}" not found`,
        },
      });
    }

    return reply.send({
      success: true,
      data: run,
    });
  });

  // 4. Execute TestRun
  fastify.post<{
    Params: { id: string };
    Body?: ExecuteRunOptions;
  }>('/api/v1/test-runs/:id/execute', async (request, reply) => {
    try {
      const result = await testRunnerService.executeTestRun(request.params.id, request.body);
      return reply.send({
        success: true,
        data: result,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Test run execution failed';
      return reply.status(500).send({
        success: false,
        error: {
          code: 'TESTRUN_EXECUTION_FAILED',
          message,
        },
      });
    }
  });

  // 5. Get TestRun Findings
  fastify.get<{ Params: { id: string } }>('/api/v1/test-runs/:id/findings', async (request, reply) => {
    const findingsList = await findingsService.listFindings({ testRunId: request.params.id });
    return reply.send({
      success: true,
      data: findingsList,
    });
  });

  // 6. Get TestRun Forensic Evidence Records
  fastify.get<{ Params: { id: string } }>('/api/v1/test-runs/:id/evidence', async (request, reply) => {
    const evidenceList = await evidenceService.listEvidenceByTestRunId(request.params.id);
    return reply.send({
      success: true,
      data: evidenceList,
    });
  });

  // 7. Get TestRun Quantitative Metrics
  fastify.get<{ Params: { id: string } }>('/api/v1/test-runs/:id/metrics', async (request, reply) => {
    const metricsList = await metricsService.listMetricsByTestRunId(request.params.id);
    return reply.send({
      success: true,
      data: metricsList,
    });
  });

  // 8. Delete TestRun
  fastify.delete<{ Params: { id: string } }>('/api/v1/test-runs/:id', async (request, reply) => {
    const { id } = request.params;
    const deleted = await testRunsService.deleteTestRun(id);
    if (!deleted) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'TESTRUN_NOT_FOUND',
          message: `TestRun with ID "${id}" not found`,
        },
      });
    }

    return reply.send({
      success: true,
      data: { id, deleted: true },
    });
  });
};
