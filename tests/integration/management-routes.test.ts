import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { getDatabase, closeDatabase } from '../../apps/controller/src/services/db.js';

describe('Remediation Prompt 06: Demo Data & Seed Isolation (REM-06)', () => {
  let app: FastifyInstance;
  const adminKey = 'test-admin-secret-key-32chars-long';
  const operatorKey = 'test-operator-api-key-32chars-long';
  const originalNodeEnv = process.env.NODE_ENV;

  beforeAll(async () => {
    app = buildApp({
      disableLogging: true,
      enableReaper: false,
      bypassAuth: false, // Strictly enforce authentication on protected endpoints
      apiKey: operatorKey,
      adminKey: adminKey,
    });
    await app.ready();
  });

  afterAll(async () => {
    process.env.NODE_ENV = originalNodeEnv;
    await app.close();
    await closeDatabase();
  });

  beforeEach(() => {
    process.env.NODE_ENV = 'development';
  });

  // ===========================================================================
  // 1. Production Environment Lockout Test
  // ===========================================================================
  describe('1. Production Environment Lockout', () => {
    it('returns 403 Forbidden with exact error payload when NODE_ENV=production', async () => {
      process.env.NODE_ENV = 'production';

      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/management/seed',
        headers: {
          authorization: `Bearer ${adminKey}`,
        },
        payload: { force: true },
      });

      expect(response.statusCode).toBe(403);
      const body = JSON.parse(response.payload);
      expect(body).toEqual({
        error: 'Forbidden',
        message: 'Demo data seeding is disabled in production environments.',
      });
    });

    it('rejects seeding in production when operator credentials are provided', async () => {
      process.env.NODE_ENV = 'production';

      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/management/seed',
        headers: {
          authorization: `Bearer ${operatorKey}`,
        },
      });

      expect(response.statusCode).toBe(403);
      const body = JSON.parse(response.payload);
      expect(body).toEqual({
        error: 'Forbidden',
        message: 'Demo data seeding is disabled in production environments.',
      });
    });
  });

  // ===========================================================================
  // 2. Authentication and Role-Based Authorization
  // ===========================================================================
  describe('2. Authentication & Admin Authorization Guards', () => {
    it('returns 401 Unauthorized when no credentials are provided in development', async () => {
      process.env.NODE_ENV = 'development';

      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/management/seed',
        payload: { force: true },
      });

      expect(response.statusCode).toBe(401);
      const body = JSON.parse(response.payload);
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('returns 403 Forbidden when operator (non-admin) credentials are provided in development', async () => {
      process.env.NODE_ENV = 'development';

      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/management/seed',
        headers: {
          authorization: `Bearer ${operatorKey}`,
        },
        payload: { force: true },
      });

      expect(response.statusCode).toBe(403);
      const body = JSON.parse(response.payload);
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.error.message).toMatch(/Administrative authorization required/);
    });
  });

  // ===========================================================================
  // 3. Admin Seeding, Synthetic Tagging & Distinct Demo Domains
  // ===========================================================================
  describe('3. Admin Seeding & Synthetic Tagging', () => {
    it('successfully seeds demo data with admin key in development and applies synthetic tags', async () => {
      process.env.NODE_ENV = 'development';

      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/management/seed',
        headers: {
          authorization: `Bearer ${adminKey}`,
        },
        payload: { force: true },
      });

      expect(response.statusCode).toBe(201);
      const body = JSON.parse(response.payload);
      expect(body.success).toBe(true);
      expect(body.data.projectId).toBeDefined();
      expect(body.data.projectName).toContain('Nova Banking');
      expect(body.data.targetsCreated).toBe(2);
      expect(body.data.findingsCreated).toBe(5);

      // Verify Database Entities & Synthetic Isolation
      const { sql } = getDatabase();

      // Check Targets use distinct demo domains
      const seededTargets = await sql.unsafe<{ id: string; name: string; base_url: string }[]>(
        `SELECT id, name, base_url FROM targets WHERE project_id = '${body.data.projectId}'`,
      );

      expect(seededTargets.length).toBe(2);
      const baseUrls = seededTargets.map((t) => t.base_url);
      expect(baseUrls).toContain('https://demo.local:8443');
      expect(baseUrls).toContain('https://mock-bank.internal:443');

      // Check Seeded Findings have explicit synthetic metadata
      const seededFindings = await sql.unsafe<{ id: string; metadata: any }[]>(
        `SELECT id, metadata FROM findings WHERE test_run_id = '${body.data.testRunId}'`,
      );

      expect(seededFindings.length).toBe(5);
      for (const f of seededFindings) {
        expect(f.metadata).toBeDefined();
        const meta = f.metadata as { synthetic?: boolean; environment?: string };
        expect(meta.synthetic).toBe(true);
        expect(meta.environment).toBe('demo');
      }
    });
  });

  // ===========================================================================
  // 4. Data Overwrite Protection
  // ===========================================================================
  describe('4. Data Overwrite Protection', () => {
    it('rejects seeding if real project exists and force: true is omitted', async () => {
      process.env.NODE_ENV = 'development';
      const { sql } = getDatabase();

      // Create a real (non-demo) project
      const realProjectName = `Customer Production Banking API-${Date.now()}`;
      const [realProject] = await sql.unsafe<{ id: string }[]>(
        `INSERT INTO projects (name, description) VALUES ('${realProjectName}', 'Legitimate customer production project') RETURNING id`,
      );

      try {
        // Attempt to seed without force: true
        const response = await app.inject({
          method: 'POST',
          url: '/api/v1/management/seed',
          headers: {
            authorization: `Bearer ${adminKey}`,
          },
          payload: {},
        });

        expect(response.statusCode).toBe(409);
        const body = JSON.parse(response.payload);
        expect(body.success).toBe(false);
        expect(body.error.code).toBe('PROJECTS_EXIST');
        expect(body.error.message).toContain('existing project(s) found in tenant');
        expect(body.error.message).toContain('Pass { force: true } to override');

        // Now attempt with force: true, which must succeed
        const forceResponse = await app.inject({
          method: 'POST',
          url: '/api/v1/management/seed',
          headers: {
            authorization: `Bearer ${adminKey}`,
          },
          payload: { force: true },
        });

        expect(forceResponse.statusCode).toBe(201);
        const forceBody = JSON.parse(forceResponse.payload);
        expect(forceBody.success).toBe(true);
      } finally {
        if (realProject) {
          await sql.unsafe(`DELETE FROM projects WHERE id = '${realProject.id}'`);
        }
      }
    });
  });
});
