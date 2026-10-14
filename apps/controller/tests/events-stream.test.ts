import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../src/app/index.js';
import { closeDatabase } from '../src/services/db.js';
import { testRunsService } from '../src/services/test-runs.service.js';
import { targetsService } from '../src/services/targets.service.js';
import { projectsService } from '../src/services/projects.service.js';
import { signJwt, DEFAULT_WORKSPACE_ID } from '../src/services/auth-token.service.js';

describe('Phase 18: Real-Time SSE Test Run Streaming & Operations Console Routes', () => {
  let app: FastifyInstance;
  let testToken: string;
  let projectId: string;
  let targetId: string;

  beforeAll(async () => {
    app = buildApp({
      disableLogging: true,
      enableReaper: false,
      bypassAuth: false,
    });
    await app.ready();

    testToken = signJwt({
      userId: 'test-auditor',
      workspaceId: DEFAULT_WORKSPACE_ID,
      role: 'auditor',
    });

    const project = await projectsService.createProject({
      name: `Operations Console Streaming Project ${Date.now()}`,
      description: 'Project for validating SSE streaming endpoints',
    });
    projectId = project.id;

    const target = await targetsService.createTarget({
      projectId,
      name: 'Streaming Target',
      baseUrl: 'https://operations.internal.test',
      allowedHosts: ['operations.internal.test'],
      allowedPorts: [443],
      excludedPaths: [],
    });
    targetId = target.id;
  });

  afterAll(async () => {
    await app.close();
    await closeDatabase();
  });

  it('rejects unauthenticated requests to the SSE stream', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/test-runs/nonexistent-run/stream',
    });
    expect(res.statusCode).toBe(401);
  });

  it('returns 404 when streaming a nonexistent test run', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/test-runs/00000000-0000-0000-0000-000000000000/stream',
      headers: {
        authorization: `Bearer ${testToken}`,
      },
    });
    expect(res.statusCode).toBe(404);
    const json = JSON.parse(res.payload);
    expect(json.error.code).toBe('TESTRUN_NOT_FOUND');
  });

  it('connects to SSE stream for completed test run and receives init and run_completed events', async () => {
    // 1. Create a test run
    const run = await testRunsService.createTestRun({
      projectId,
      targetId,
      profileId: 'header-security-baseline',
      triggeredBy: 'api',
    });

    // 2. Mark it completed
    await testRunsService.updateTestRunStatus(run.id, 'completed', {
      totalTests: 5,
      passedTests: 5,
      failedTests: 0,
      errorTests: 0,
      findingsCount: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    });

    // 3. Connect to SSE stream
    const res = await app.inject({
      method: 'GET',
      url: `/api/v1/test-runs/${run.id}/stream`,
      headers: {
        authorization: `Bearer ${testToken}`,
      },
    });

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/event-stream');
    expect(res.payload).toContain('event: init');
    expect(res.payload).toContain('event: run_completed');
    expect(res.payload).toContain(run.id);
  });

  it('authenticates via query parameter ?token= for EventSource browser compatibility', async () => {
    const run = await testRunsService.createTestRun({
      projectId,
      targetId,
      profileId: 'header-security-baseline',
      triggeredBy: 'api',
    });

    await testRunsService.updateTestRunStatus(run.id, 'completed', {
      totalTests: 1,
      passedTests: 1,
      failedTests: 0,
      errorTests: 0,
      findingsCount: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    });

    const res = await app.inject({
      method: 'GET',
      url: `/api/v1/test-runs/${run.id}/stream?token=${testToken}`,
    });

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/event-stream');
    expect(res.payload).toContain('event: init');
  });
});
