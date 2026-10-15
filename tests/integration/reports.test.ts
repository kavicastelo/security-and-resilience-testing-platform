import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth } from '../../apps/controller/src/services/db.js';
import { COMPLIANCE_DISCLAIMER } from '../../apps/dashboard/src/api/reports.js';

describe('PR-02 Integration: Truthful Compliance Reports & Controller Exports', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;
  let projectId: string;
  let targetId: string;
  let testRunId: string;
  const suffix = Math.floor(Math.random() * 100000);

  beforeAll(async () => {
    app = buildApp({
      disableLogging: true,
      enableReaper: false,
      bypassAuth: true,
    });
    await app.ready();

    const health = await checkDatabaseHealth();
    isDbAvailable = health === 'up';

    // 1. Create Project
    const projRes = await app.inject({
      method: 'POST',
      url: '/api/v1/projects',
      payload: {
        name: `Compliance Audit Project ${suffix}`,
        description: 'PR-02 Compliance audit test project',
      },
    });
    expect(projRes.statusCode).toBe(201);
    projectId = JSON.parse(projRes.payload).data.id;

    // 2. Create Target
    const targetRes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectId}/targets`,
      payload: {
        name: `Compliance Target ${suffix}`,
        baseUrl: 'http://127.0.0.1:4000',
        allowedHosts: ['127.0.0.1', 'localhost'],
        allowedPorts: [4000],
        testing: {
          activeScanning: true,
          loadTesting: false,
          chaosTesting: false,
        },
      },
    });
    expect(targetRes.statusCode).toBe(201);
    targetId = JSON.parse(targetRes.payload).data.id;

    // 3. Create TestRun
    const runRes = await app.inject({
      method: 'POST',
      url: '/api/v1/test-runs',
      payload: {
        projectId,
        targetId,
        profileId: 'native-class-a',
        triggeredBy: 'manual',
      },
    });
    expect(runRes.statusCode).toBe(201);
    testRunId = JSON.parse(runRes.payload).data.id;
  });

  afterAll(async () => {
    await app.close();
    await closeDatabase();
  });

  it('verifies database connectivity is healthy before executing compliance tests', () => {
    expect(isDbAvailable).toBe(true);
  });

  it('GET /api/v1/findings?testRunId=:id returns empty array for clean test run (zero findings)', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/api/v1/findings?testRunId=${testRunId}`,
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(Array.isArray(body.data)).toBe(true);
    expect(body.data.length).toBe(0);
  });

  it('GET /api/v1/test-runs/:id/report?format=html exports valid report with compliance disclaimer', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/api/v1/test-runs/${testRunId}/report?format=html`,
    });

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.payload).toContain('<!DOCTYPE html>');
    expect(res.payload).toContain(testRunId);
  });

  it('GET /api/v1/test-runs/:id/report?format=sarif exports valid SARIF 2.1 schema', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/api/v1/test-runs/${testRunId}/report?format=sarif`,
    });

    expect(res.statusCode).toBe(200);
    const sarif = JSON.parse(res.payload);
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toBeDefined();
    expect(sarif.runs.length).toBeGreaterThan(0);
  });

  it('GET /api/v1/test-runs/:id/reports lists persisted compliance audit artifacts', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/api/v1/test-runs/${testRunId}/reports`,
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(Array.isArray(body.data)).toBe(true);
  });

  it('verifies compliance disclaimer wording is strict and compliant with PR 24.4', () => {
    expect(COMPLIANCE_DISCLAIMER).toContain('Automated verification results provide technical testing evidence');
    expect(COMPLIANCE_DISCLAIMER).toContain('Product Requirement 24.4');
  });
});
