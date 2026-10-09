import { describe, it, expect, afterAll, vi } from 'vitest';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase } from '../../apps/controller/src/services/db.js';
import { managementService } from '../../apps/controller/src/services/management.service.js';

describe('Universal Platform Management Integration Tests', () => {
  const app = buildApp({ disableLogging: true, enableReaper: false });

  afterAll(async () => {
    await app.close();
    await closeDatabase();
  });

  it('GET /api/v1/management/overview returns comprehensive system statistics', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/api/v1/management/overview',
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.payload);

    expect(body.success).toBe(true);
    expect(body.data).toBeDefined();

    // Verify Entity Counts
    expect(body.data.counts).toHaveProperty('projects');
    expect(body.data.counts).toHaveProperty('targets');
    expect(body.data.counts).toHaveProperty('testRuns');
    expect(body.data.counts).toHaveProperty('findings');
    expect(body.data.counts).toHaveProperty('evidenceRecords');
    expect(body.data.counts).toHaveProperty('metrics');
    expect(body.data.counts).toHaveProperty('policies');
    expect(body.data.counts).toHaveProperty('tenants');

    // Verify Storage Metrics
    expect(body.data.storage).toHaveProperty('totalDiskBytes');
    expect(body.data.storage).toHaveProperty('evidenceFileCount');
    expect(body.data.storage).toHaveProperty('artifactsFileCount');

    // Verify System & Database
    expect(body.data.system).toHaveProperty('nodeVersion');
    expect(body.data.system).toHaveProperty('platform');
    expect(body.data.system.memoryUsage).toHaveProperty('heapUsedMb');
    expect(body.data.database.status).toBe('up');
  });

  it('POST /api/v1/management/purge rejects invalid confirmation keywords', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/management/purge',
      payload: {
        mode: 'all',
        confirmation: 'accidental_click_no_confirm',
      },
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.payload);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('PURGE_FAILED');
  });

  it('POST /api/v1/management/seed generates realistic demo project, targets, and test runs', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/management/seed',
      payload: { force: true },
    });

    expect(response.statusCode).toBe(201);
    const body = JSON.parse(response.payload);

    expect(body.success).toBe(true);
    expect(body.data.projectId).toBeDefined();
    expect(body.data.projectName).toContain('Nova Banking');
    expect(body.data.targetsCreated).toBe(2);
    expect(body.data.findingsCreated).toBe(5);
    expect(body.data.evidenceCreated).toBe(5);
    expect(body.data.testRunId).toBeDefined();
  });

  it('POST /api/v1/management/reap-jobs executes watchdog lease reaper cleanly', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/management/reap-jobs',
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.payload);
    expect(body.success).toBe(true);
    expect(body.data).toHaveProperty('reapedCount');
  });

  it('POST /api/v1/management/purge validates payload and invokes purge handler successfully', async () => {
    const purgeSpy = vi.spyOn(managementService, 'purgeData').mockResolvedValueOnce({
      success: true,
      mode: 'all',
      cleared: { allTables: 19, storageFiles: 1 },
      retained: ['Default Tenant', 'Baseline Policy'],
      message: 'Factory Reset complete.',
      timestamp: new Date().toISOString(),
    });

    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/management/purge',
      payload: {
        mode: 'all',
        confirmation: 'CLEAR ALL DATA',
      },
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.payload);
    expect(body.success).toBe(true);
    expect(body.data.mode).toBe('all');
    expect(purgeSpy).toHaveBeenCalledWith('all', 'CLEAR ALL DATA', expect.any(String));

    purgeSpy.mockRestore();
  });

  it('GET /api/v1/management/audit-events returns list of system audit events', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/api/v1/management/audit-events',
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.payload);
    expect(body.success).toBe(true);
    expect(Array.isArray(body.data)).toBe(true);
  });

  describe('Backup and Disaster Recovery Operations', () => {
    let createdBackupId: string;

    it('POST /api/v1/management/backups creates a new platform snapshot with SHA-256 fingerprint', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/management/backups',
        payload: {
          description: 'Integration test automated snapshot',
          includeExecutions: true,
        },
      });

      expect(response.statusCode).toBe(201);
      const body = JSON.parse(response.payload);
      expect(body.success).toBe(true);
      expect(body.data).toBeDefined();
      expect(body.data.id).toBeDefined();
      expect(body.data.filename).toMatch(/^backup_.*\.json$/);
      expect(body.data.sha256).toMatch(/^[a-f0-9]{64}$/);
      expect(body.data.counts).toHaveProperty('projects');
      expect(body.data.counts).toHaveProperty('targets');
      expect(body.data.counts).toHaveProperty('policies');

      createdBackupId = body.data.id;
    });

    it('GET /api/v1/management/backups returns list of backups containing created snapshot', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/api/v1/management/backups',
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.payload);
      expect(body.success).toBe(true);
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.data.some((b: any) => b.id === createdBackupId)).toBe(true);
    });

    it('GET /api/v1/management/backups/:id/download downloads raw JSON backup snapshot', async () => {
      const response = await app.inject({
        method: 'GET',
        url: `/api/v1/management/backups/${createdBackupId}/download`,
      });

      expect(response.statusCode).toBe(200);
      expect(response.headers['content-type']).toContain('application/json');
      expect(response.headers['content-disposition']).toContain(`attachment; filename="backup_`);

      const payload = JSON.parse(response.payload);
      expect(payload).toHaveProperty('metadata');
      expect(payload).toHaveProperty('data');
      expect(payload.metadata.counts).toBeDefined();
      expect(payload.data.projects).toBeDefined();
    });

    it('POST /api/v1/management/backups/restore rejects replace mode without proper confirmation', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/management/backups/restore',
        payload: {
          backupId: createdBackupId,
          mode: 'replace',
          confirmation: 'WRONG_CONFIRMATION',
        },
      });

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.payload);
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('RESTORE_ERROR');
    });

    it('POST /api/v1/management/backups/restore validates and invokes restore handler cleanly', async () => {
      const restoreSpy = vi.spyOn(managementService, 'restoreBackup').mockResolvedValueOnce({
        success: true,
        mode: 'replace',
        restoredCounts: {
          tenants: 1,
          projects: 2,
          targets: 4,
          environments: 2,
          policies: 1,
          testRuns: 3,
          testExecutions: 3,
          findings: 5,
          evidenceRecords: 5,
          metrics: 3,
          releases: 1,
        },
        message: 'Platform state successfully restored (replace mode).',
        timestamp: new Date().toISOString(),
      });

      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/management/backups/restore',
        payload: {
          backupId: createdBackupId,
          mode: 'replace',
          confirmation: 'CONFIRM_RESTORE',
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.payload);
      expect(body.success).toBe(true);
      expect(body.data.mode).toBe('replace');
      expect(body.data.restoredCounts.findings).toBe(5);
      expect(restoreSpy).toHaveBeenCalledWith(
        {
          backupId: createdBackupId,
          mode: 'replace',
          confirmation: 'CONFIRM_RESTORE',
        },
        expect.any(String),
      );

      restoreSpy.mockRestore();
    });

    it('DELETE /api/v1/management/backups/:id removes the backup snapshot from disk', async () => {
      const response = await app.inject({
        method: 'DELETE',
        url: `/api/v1/management/backups/${createdBackupId}`,
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.payload);
      expect(body.success).toBe(true);
      expect(body.data.success).toBe(true);

      // Verify it is no longer in list
      const listResponse = await app.inject({
        method: 'GET',
        url: '/api/v1/management/backups',
      });
      const listBody = JSON.parse(listResponse.payload);
      expect(listBody.data.some((b: any) => b.id === createdBackupId)).toBe(false);
    });

    it('managementService.restoreBackup executes non-destructive merge mode directly with database tables', async () => {
      const backupMeta = await managementService.createBackup({
        description: 'Merge mode validation snapshot',
        includeExecutions: false,
      });

      const restoreResult = await managementService.restoreBackup({
        backupId: backupMeta.id,
        mode: 'merge',
      });

      expect(restoreResult.success).toBe(true);
      expect(restoreResult.mode).toBe('merge');
      expect(restoreResult.restoredCounts.tenants).toBeGreaterThanOrEqual(1);
      expect(restoreResult.restoredCounts.policies).toBeGreaterThanOrEqual(1);

      // Clean up backup file
      await managementService.deleteBackup(backupMeta.id);
    });
  });
});

