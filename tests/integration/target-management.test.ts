import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth } from '../../apps/controller/src/services/db.js';
import { FastifyInstance } from 'fastify';

describe('Target Management & Pre-Flight Scope Enforcement API', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;

  beforeAll(async () => {
    app = buildApp({ disableLogging: true });
    const health = await checkDatabaseHealth();
    isDbAvailable = health === 'up';
  });

  afterAll(async () => {
    await app.close();
    await closeDatabase();
  });

  it('verifies database connectivity before executing integration tests', () => {
    expect(isDbAvailable).toBe(true);
  });

  let createdProjectId: string;
  let createdTargetId: string;

  it('POST /api/v1/projects creates a new project', async () => {
    const randomSuffix = Math.floor(Math.random() * 100000);
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/projects',
      payload: {
        name: `Security Project ${randomSuffix}`,
        description: 'Integration test target project',
      },
    });

    expect(res.statusCode).toBe(201);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(body.data.id).toBeDefined();
    expect(body.data.name).toContain('Security Project');
    createdProjectId = body.data.id;
  });

  it('GET /api/v1/projects lists registered projects', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/projects',
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(Array.isArray(body.data)).toBe(true);
    expect(body.data.some((p: { id: string }) => p.id === createdProjectId)).toBe(true);
  });

  it('POST /api/v1/projects/:projectId/environments registers an environment', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${createdProjectId}/environments`,
      payload: {
        name: 'staging-us-east',
        type: 'staging',
        variables: { REGION: 'us-east-1' },
      },
    });

    expect(res.statusCode).toBe(201);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(body.data.type).toBe('staging');
  });

  it('POST /api/v1/projects/:projectId/targets registers a target with strict scope boundaries', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${createdProjectId}/targets`,
      payload: {
        name: 'Core Auth Gateway',
        baseUrl: 'https://staging.auth.example.com',
        allowedHosts: ['staging.auth.example.com'],
        allowedPorts: [443],
        excludedPaths: ['/oauth/revoke-all'],
        testing: {
          activeScanning: false, // passive only by default
          loadTesting: true,
          chaosTesting: false,
        },
        limits: {
          maxRps: 80,
          maxConcurrency: 15,
        },
      },
    });

    expect(res.statusCode).toBe(201);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(body.data.id).toBeDefined();
    expect(body.data.scope.allowedHosts).toContain('staging.auth.example.com');
    expect(body.data.scope.testing.activeScanning).toBe(false);
    expect(body.data.scope.testing.loadTesting).toBe(true);
    createdTargetId = body.data.id;
  });

  it('POST /api/v1/targets/:id/validate-scope permits valid in-scope requests', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/targets/${createdTargetId}/validate-scope`,
      payload: {
        candidateUrl: 'https://staging.auth.example.com/oauth/token',
      },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(body.data.valid).toBe(true);
    expect(body.data.violations).toHaveLength(0);
    expect(body.data.matchedHost).toBe('staging.auth.example.com');
  });

  it('POST /api/v1/targets/:id/validate-scope blocks out-of-scope targets and SSRF payloads', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/targets/${createdTargetId}/validate-scope`,
      payload: {
        candidateUrl: 'http://169.254.169.254/latest/meta-data/',
      },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(body.data.valid).toBe(false);
    expect(body.data.violations.some((v: string) => v.includes('cloud metadata IP/host'))).toBe(true);
  });

  it('POST /api/v1/targets/:id/validate-scope blocks excluded paths', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/targets/${createdTargetId}/validate-scope`,
      payload: {
        candidateUrl: 'https://staging.auth.example.com/oauth/revoke-all',
      },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(body.data.valid).toBe(false);
    expect(body.data.violations.some((v: string) => v.includes('matches excluded sensitive path'))).toBe(true);
  });

  it('POST /api/v1/targets/:id/validate-scope blocks active scanning when disabled on target', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/targets/${createdTargetId}/validate-scope`,
      payload: {
        candidateUrl: 'https://staging.auth.example.com/oauth/token',
        capability: 'activeScanning',
      },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(body.data.valid).toBe(false);
    expect(body.data.violations.some((v: string) => v.includes('activeScanning" is disabled'))).toBe(true);
  });

  it('POST /api/v1/test-runs creates a queued test session for the authorized target', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/test-runs',
      payload: {
        projectId: createdProjectId,
        targetId: createdTargetId,
        triggeredBy: 'manual',
        profileId: 'quick-security',
      },
    });

    expect(res.statusCode).toBe(201);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(body.data.id).toBeDefined();
    expect(body.data.status).toBe('queued');
    expect(body.data.targetId).toBe(createdTargetId);
  });
});
