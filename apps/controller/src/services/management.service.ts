import fs from 'node:fs';
import path from 'node:path';
import {
  tenants,
  projects,
  targets,
  environments,
  policies,
  testRuns,
  testExecutions,
  findings,
  evidenceRecords,
  metrics,
  releases,
  agents,
  agentJobs,
  webhooks,
  webhookDeliveries,
  workspaces,
  contractSpecs,
} from './db/schema.js';
import { getDatabase } from './db.js';
import { config } from '../config/index.js';
import { logger } from '@security-lab/logger';
import {
  SystemOverviewStats,
  PurgeMode,
  PurgeDataResult,
  SeedDataResult,
  BackupMetadata,
  BackupPayload,
  CreateBackupRequest,
  RestoreBackupRequest,
  RestoreBackupResult,
} from '@security-lab/contracts';
import crypto from 'node:crypto';
import { TargetScope } from '@security-lab/domain';
import { tenantsService, DEFAULT_TENANT_ID } from './tenants.service.js';
import { policiesService, ENTERPRISE_DEFAULT_POLICY } from './policies.service.js';
import { agentDispatcherService } from './agent-dispatcher.service.js';
import { DEFAULT_WORKSPACE_ID } from './auth-token.service.js';
import { eq, like, or, inArray, sql } from 'drizzle-orm';

function sanitizeRecordForInsert(record: Record<string, any>): Record<string, any> {
  const result: Record<string, any> = {};
  for (const [key, val] of Object.entries(record)) {
    if (val === undefined) continue;
    if (
      typeof val === 'string' &&
      (key.endsWith('At') || key === 'timestamp') &&
      !isNaN(Date.parse(val))
    ) {
      result[key] = new Date(val);
    } else {
      result[key] = val;
    }
  }
  return result;
}

async function chunkedInsert(table: any, items: any[], chunkSize = 50): Promise<number> {
  if (!items || items.length === 0) return 0;
  const { db } = getDatabase();
  let inserted = 0;
  for (let i = 0; i < items.length; i += chunkSize) {
    const rawChunk = items.slice(i, i + chunkSize);
    const chunk = rawChunk.map(sanitizeRecordForInsert);
    if (chunk.length > 0) {
      try {
        await db.insert(table).values(chunk).onConflictDoNothing();
        inserted += chunk.length;
      } catch {
        // Fall back to row-by-row insertion if bulk conflict occurs
        for (const singleItem of chunk) {
          try {
            await db.insert(table).values(singleItem).onConflictDoNothing();
            inserted++;
          } catch {
            // Best effort insertion
          }
        }
      }
    }
  }
  return inserted;
}

function getDirectoryMetrics(dirPath: string): { fileCount: number; sizeBytes: number } {
  let fileCount = 0;
  let sizeBytes = 0;

  try {
    if (!fs.existsSync(dirPath)) {
      return { fileCount: 0, sizeBytes: 0 };
    }

    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      try {
        if (entry.isDirectory()) {
          const sub = getDirectoryMetrics(fullPath);
          fileCount += sub.fileCount;
          sizeBytes += sub.sizeBytes;
        } else if (entry.isFile()) {
          fileCount += 1;
          const stat = fs.statSync(fullPath);
          sizeBytes += stat.size;
        }
      } catch {
        // Skip unreadable files
      }
    }
  } catch {
    // Ignore top-level read errors
  }

  return { fileCount, sizeBytes };
}

function cleanDirectoryFiles(dirPath: string): number {
  let removedCount = 0;
  try {
    if (!fs.existsSync(dirPath)) return 0;
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      try {
        if (entry.isDirectory()) {
          removedCount += cleanDirectoryFiles(fullPath);
          fs.rmdirSync(fullPath);
        } else {
          fs.unlinkSync(fullPath);
          removedCount++;
        }
      } catch {
        // Best-effort removal
      }
    }
  } catch {
    // Best-effort cleanup
  }
  return removedCount;
}

export class ManagementService {
  async getSystemOverview(): Promise<SystemOverviewStats> {
    const { sql: sqlClient } = getDatabase();

    // 1. Table row counts query
    const [
      tenantsCount,
      projectsCount,
      targetsCount,
      environmentsCount,
      testRunsCount,
      testExecutionsCount,
      findingsCount,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      infoCount,
      evidenceCount,
      metricsCount,
      policiesCount,
      releasesCount,
      reportsCount,
      artifactsCount,
      agentsCount,
      agentJobsCount,
    ] = await Promise.all([
      sqlClient.unsafe<{ count: number }[]>('SELECT count(*)::int as count FROM tenants'),
      sqlClient.unsafe<{ count: number }[]>('SELECT count(*)::int as count FROM projects'),
      sqlClient.unsafe<{ count: number }[]>('SELECT count(*)::int as count FROM targets'),
      sqlClient.unsafe<{ count: number }[]>('SELECT count(*)::int as count FROM environments'),
      sqlClient.unsafe<{ count: number }[]>('SELECT count(*)::int as count FROM test_runs'),
      sqlClient.unsafe<{ count: number }[]>('SELECT count(*)::int as count FROM test_executions'),
      sqlClient.unsafe<{ count: number }[]>('SELECT count(*)::int as count FROM findings'),
      sqlClient.unsafe<{ count: number }[]>('SELECT count(*)::int as count FROM findings WHERE severity = \'critical\''),
      sqlClient.unsafe<{ count: number }[]>('SELECT count(*)::int as count FROM findings WHERE severity = \'high\''),
      sqlClient.unsafe<{ count: number }[]>('SELECT count(*)::int as count FROM findings WHERE severity = \'medium\''),
      sqlClient.unsafe<{ count: number }[]>('SELECT count(*)::int as count FROM findings WHERE severity = \'low\''),
      sqlClient.unsafe<{ count: number }[]>('SELECT count(*)::int as count FROM findings WHERE severity = \'info\''),
      sqlClient.unsafe<{ count: number }[]>('SELECT count(*)::int as count FROM evidence_records'),
      sqlClient.unsafe<{ count: number }[]>('SELECT count(*)::int as count FROM metrics'),
      sqlClient.unsafe<{ count: number }[]>('SELECT count(*)::int as count FROM policies'),
      sqlClient.unsafe<{ count: number }[]>('SELECT count(*)::int as count FROM releases'),
      sqlClient.unsafe<{ count: number }[]>('SELECT count(*)::int as count FROM reports'),
      sqlClient.unsafe<{ count: number }[]>('SELECT count(*)::int as count FROM artifacts'),
      sqlClient.unsafe<{ count: number }[]>('SELECT count(*)::int as count FROM agents'),
      sqlClient.unsafe<{ count: number }[]>('SELECT count(*)::int as count FROM agent_jobs'),
    ]);

    // 2. Agents & Jobs breakdown
    const [agentsByStatus, jobsByStatus] = await Promise.all([
      sqlClient.unsafe<{ status: string; count: number }[]>('SELECT status, count(*)::int as count FROM agents GROUP BY status'),
      sqlClient.unsafe<{ status: string; count: number }[]>('SELECT status, count(*)::int as count FROM agent_jobs GROUP BY status'),
    ]);

    const agentStatusMap: Record<string, number> = {};
    for (const row of agentsByStatus) {
      agentStatusMap[row.status] = Number(row.count) || 0;
    }

    const jobStatusMap: Record<string, number> = {};
    for (const row of jobsByStatus) {
      jobStatusMap[row.status] = Number(row.count) || 0;
    }

    // 3. Storage metrics
    const evidenceStorage = getDirectoryMetrics(config.EVIDENCE_DIR);
    const reportsStorage = getDirectoryMetrics(config.REPORTS_DIR);
    const artifactsStorage = getDirectoryMetrics(config.ARTIFACTS_DIR);
    const totalDiskBytes =
      evidenceStorage.sizeBytes + reportsStorage.sizeBytes + artifactsStorage.sizeBytes;

    // 4. Database ping test
    const pingStart = performance.now();
    let dbStatus: 'up' | 'down' = 'up';
    let pingMs = 0;
    try {
      await sqlClient`SELECT 1`;
      pingMs = Math.round((performance.now() - pingStart) * 100) / 100;
    } catch {
      dbStatus = 'down';
    }

    // 5. System metrics
    const mem = process.memoryUsage();

    return {
      counts: {
        projects: projectsCount[0]?.count ?? 0,
        targets: targetsCount[0]?.count ?? 0,
        environments: environmentsCount[0]?.count ?? 0,
        testRuns: testRunsCount[0]?.count ?? 0,
        testExecutions: testExecutionsCount[0]?.count ?? 0,
        findings: findingsCount[0]?.count ?? 0,
        criticalFindings: criticalCount[0]?.count ?? 0,
        highFindings: highCount[0]?.count ?? 0,
        mediumFindings: mediumCount[0]?.count ?? 0,
        lowFindings: lowCount[0]?.count ?? 0,
        infoFindings: infoCount[0]?.count ?? 0,
        evidenceRecords: evidenceCount[0]?.count ?? 0,
        metrics: metricsCount[0]?.count ?? 0,
        policies: policiesCount[0]?.count ?? 0,
        releases: releasesCount[0]?.count ?? 0,
        reports: reportsCount[0]?.count ?? 0,
        artifacts: artifactsCount[0]?.count ?? 0,
        agents: agentsCount[0]?.count ?? 0,
        agentJobs: agentJobsCount[0]?.count ?? 0,
        tenants: tenantsCount[0]?.count ?? 0,
      },
      storage: {
        evidenceSizeBytes: evidenceStorage.sizeBytes,
        evidenceFileCount: evidenceStorage.fileCount,
        reportsSizeBytes: reportsStorage.sizeBytes,
        reportsFileCount: reportsStorage.fileCount,
        artifactsSizeBytes: artifactsStorage.sizeBytes,
        artifactsFileCount: artifactsStorage.fileCount,
        totalDiskBytes,
      },
      system: {
        nodeVersion: process.version,
        platform: process.platform,
        environment: process.env.NODE_ENV || 'development',
        uptimeSeconds: Math.floor(process.uptime()),
        pid: process.pid,
        memoryUsage: {
          rssMb: Math.round((mem.rss / (1024 * 1024)) * 10) / 10,
          heapTotalMb: Math.round((mem.heapTotal / (1024 * 1024)) * 10) / 10,
          heapUsedMb: Math.round((mem.heapUsed / (1024 * 1024)) * 10) / 10,
          externalMb: Math.round((mem.external / (1024 * 1024)) * 10) / 10,
        },
      },
      database: {
        status: dbStatus,
        pingMs,
        poolMax: config.DB_MAX_CONNECTIONS,
        databaseName: 'security_lab',
      },
      agentSummary: {
        totalAgents: agentsCount[0]?.count ?? 0,
        onlineAgents: agentStatusMap['online'] ?? 0,
        offlineAgents: agentStatusMap['offline'] ?? 0,
        queuedJobs: jobStatusMap['queued'] ?? 0,
        activeJobs: (jobStatusMap['dispatched'] ?? 0) + (jobStatusMap['running'] ?? 0),
        completedJobs: jobStatusMap['completed'] ?? 0,
        failedJobs: (jobStatusMap['failed'] ?? 0) + (jobStatusMap['cancelled'] ?? 0),
      },
    };
  }

  async purgeData(mode: PurgeMode, confirmation: string, tenantId?: string): Promise<PurgeDataResult> {
    const validPhrases = [
      'CLEAR ALL DATA',
      'CONFIRM_PURGE',
      'CONFIRM-DELETE',
      'DELETE ALL',
      'PURGE-DEMO',
      'PURGE DEMO',
      'CONFIRM',
      mode.toUpperCase(),
    ];
    const normalized = (confirmation || '').trim().toUpperCase();

    if (!validPhrases.includes(normalized)) {
      throw new Error(
        `Invalid confirmation keyword. You must provide one of: ${validPhrases.slice(0, 3).join(', ')}`,
      );
    }

    const { sql: sqlClient } = getDatabase();
    const cleared: Record<string, number> = {};
    const retained: string[] = [];

    logger.warn({ mode, tenantId }, 'Universal Management: Commencing requested database purge operation');

    if (mode === 'all') {
      // 1. Factory Reset: Truncate all application data tables
      await sqlClient.unsafe(`
        TRUNCATE TABLE
          findings,
          evidence_records,
          metrics,
          test_executions,
          reports,
          artifacts,
          releases,
          agent_jobs,
          agent_audit_events,
          test_runs,
          targets,
          environments,
          projects,
          policies,
          tenant_enrollment_keys,
          credentials,
          identity_profiles,
          test_definitions,
          agents,
          tenants
        CASCADE;
      `);

      // 2. Clear all local forensic files
      cleanDirectoryFiles(config.ARTIFACTS_DIR);
      cleanDirectoryFiles(config.REPORTS_DIR);
      cleanDirectoryFiles(config.EVIDENCE_DIR);

      // 3. Re-initialize Default Tenant and Baseline Security Policy
      await tenantsService.ensureDefaultTenant();
      await policiesService.createPolicy(
        {
          id: ENTERPRISE_DEFAULT_POLICY.id,
          name: ENTERPRISE_DEFAULT_POLICY.name,
          description: ENTERPRISE_DEFAULT_POLICY.description,
          rules: ENTERPRISE_DEFAULT_POLICY.rules,
          requiredProfiles: ENTERPRISE_DEFAULT_POLICY.requiredProfiles,
          waivers: ENTERPRISE_DEFAULT_POLICY.waivers,
          isDefault: true,
        },
        DEFAULT_TENANT_ID,
      );

      cleared['allTables'] = 19;
      cleared['storageFiles'] = 1;
      retained.push('Default Tenant (00000000-0000-0000-0000-000000000000)');
      retained.push('Enterprise Security Baseline Gate Policy (00000000-0000-0000-0000-000000000001)');

      return {
        success: true,
        mode,
        cleared,
        retained,
        message: 'Factory Reset complete. All test data, targets, projects, and artifacts were successfully purged. System baseline reseeded.',
        timestamp: new Date().toISOString(),
      };
    }

    if (mode === 'executions') {
      // Truncate test execution tables only
      await sqlClient.unsafe(`
        TRUNCATE TABLE
          findings,
          evidence_records,
          metrics,
          test_executions,
          reports,
          artifacts,
          releases,
          agent_jobs,
          test_runs
        CASCADE;
      `);

      cleanDirectoryFiles(config.ARTIFACTS_DIR);
      cleanDirectoryFiles(config.REPORTS_DIR);
      cleanDirectoryFiles(config.EVIDENCE_DIR);

      cleared['testRuns'] = 1;
      cleared['testExecutions'] = 1;
      cleared['findings'] = 1;
      cleared['evidenceRecords'] = 1;
      cleared['metrics'] = 1;
      cleared['reports'] = 1;
      cleared['artifacts'] = 1;
      cleared['releases'] = 1;
      cleared['agentJobs'] = 1;

      retained.push('Projects');
      retained.push('Targets');
      retained.push('Environments');
      retained.push('Policies');
      retained.push('Registered Agents');

      return {
        success: true,
        mode,
        cleared,
        retained,
        message: 'Test executions, findings, forensic evidence, and artifacts cleared. Target scopes and policies preserved.',
        timestamp: new Date().toISOString(),
      };
    }

    if (mode === 'findings') {
      await sqlClient.unsafe(`
        TRUNCATE TABLE
          findings,
          evidence_records,
          metrics
        CASCADE;
      `);

      cleared['findings'] = 1;
      cleared['evidenceRecords'] = 1;
      cleared['metrics'] = 1;

      retained.push('Projects');
      retained.push('Targets');
      retained.push('Test Runs');
      retained.push('Policies');

      return {
        success: true,
        mode,
        cleared,
        retained,
        message: 'Findings, evidence records, and metrics successfully purged.',
        timestamp: new Date().toISOString(),
      };
    }

    if (mode === 'artifacts') {
      await sqlClient.unsafe(`
        TRUNCATE TABLE
          artifacts,
          reports
        CASCADE;
      `);

      cleanDirectoryFiles(config.ARTIFACTS_DIR);
      cleanDirectoryFiles(config.REPORTS_DIR);

      cleared['artifacts'] = 1;
      cleared['reports'] = 1;

      retained.push('Database records, Test Runs, Targets');

      return {
        success: true,
        mode,
        cleared,
        retained,
        message: 'Forensic artifacts and generated test reports cleared from database and local storage.',
        timestamp: new Date().toISOString(),
      };
    }

    if (mode === 'jobs') {
      await sqlClient.unsafe(`
        TRUNCATE TABLE
          agent_jobs,
          agent_audit_events
        CASCADE;
      `);

      cleared['agentJobs'] = 1;
      cleared['agentAuditEvents'] = 1;

      retained.push('Agents', 'Test Runs', 'Targets');

      return {
        success: true,
        mode,
        cleared,
        retained,
        message: 'Agent job queues and dispatch audit logs cleared.',
        timestamp: new Date().toISOString(),
      };
    }

    if (mode === 'demo') {
      const { db } = getDatabase();

      // Find demo projects
      const demoProjects = await db.select().from(projects).where(like(projects.name, '%(Demo%'));
      const demoProjectIds = demoProjects.map((p) => p.id);

      // Find demo targets
      const demoTargets = await db
        .select()
        .from(targets)
        .where(
          or(
            like(targets.name, '%(Demo%'),
            demoProjectIds.length > 0 ? inArray(targets.projectId, demoProjectIds) : sql`false`,
          ),
        );
      const demoTargetIds = demoTargets.map((t) => t.id);

      // Find demo test runs
      const demoRuns = await db
        .select()
        .from(testRuns)
        .where(
          or(
            demoProjectIds.length > 0 ? inArray(testRuns.projectId, demoProjectIds) : sql`false`,
            demoTargetIds.length > 0 ? inArray(testRuns.targetId, demoTargetIds) : sql`false`,
          ),
        );
      const demoRunIds = demoRuns.map((r) => r.id);

      // Find demo agents
      const demoAgents = await db
        .select()
        .from(agents)
        .where(or(like(agents.name, '%(Demo%'), sql`tags::text ILIKE '%demo%'`));
      const demoAgentIds = demoAgents.map((a) => a.id);

      // Find demo webhooks
      const demoWebhooks = await db
        .select()
        .from(webhooks)
        .where(or(like(webhooks.description, '%(Demo%'), like(webhooks.url, '%demo%')));
      const demoWebhookIds = demoWebhooks.map((w) => w.id);

      // Execute cascade cleanup safely
      if (demoWebhookIds.length > 0) {
        await db.delete(webhookDeliveries).where(inArray(webhookDeliveries.webhookId, demoWebhookIds));
        await db.delete(webhooks).where(inArray(webhooks.id, demoWebhookIds));
      }

      if (demoAgentIds.length > 0) {
        await db.delete(agentJobs).where(inArray(agentJobs.agentId, demoAgentIds));
        await db.delete(agents).where(inArray(agents.id, demoAgentIds));
      }

      if (demoRunIds.length > 0) {
        await db.delete(agentJobs).where(inArray(agentJobs.testRunId, demoRunIds));
        await db.delete(findings).where(inArray(findings.testRunId, demoRunIds));
        await db.delete(metrics).where(inArray(metrics.testRunId, demoRunIds));
        await db.delete(evidenceRecords).where(inArray(evidenceRecords.testRunId, demoRunIds));
        await db.delete(testExecutions).where(inArray(testExecutions.testRunId, demoRunIds));
        await db.delete(releases).where(inArray(releases.testRunId, demoRunIds));
        await db.delete(testRuns).where(inArray(testRuns.id, demoRunIds));
      }

      if (demoTargetIds.length > 0) {
        await db.delete(contractSpecs).where(inArray(contractSpecs.targetId, demoTargetIds));
        await db.delete(findings).where(inArray(findings.targetId, demoTargetIds));
        await db.delete(targets).where(inArray(targets.id, demoTargetIds));
      }

      if (demoProjectIds.length > 0) {
        await db.delete(environments).where(inArray(environments.projectId, demoProjectIds));
        await db.delete(releases).where(inArray(releases.projectId, demoProjectIds));
        await db.delete(projects).where(inArray(projects.id, demoProjectIds));
      }

      cleared['projects'] = demoProjects.length;
      cleared['targets'] = demoTargets.length;
      cleared['testRuns'] = demoRuns.length;
      cleared['agents'] = demoAgents.length;
      cleared['webhooks'] = demoWebhooks.length;

      retained.push('Non-demo Projects, Targets, Test Runs, Policies & Configurations');

      return {
        success: true,
        mode,
        cleared,
        retained,
        message: `Successfully purged ${demoProjects.length} demo project(s), ${demoTargets.length} demo target(s), and related synthetic records. Real projects remain untouched.`,
        timestamp: new Date().toISOString(),
      };
    }

    throw new Error(`Unsupported purge mode: ${mode}`);
  }

  async seedDemoData(
    tenantId: string = DEFAULT_TENANT_ID,
    options?: { force?: boolean },
  ): Promise<SeedDataResult> {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('Demo data seeding is disabled in production environments.');
    }

    const { db } = getDatabase();

    // 1. Data Overwrite Protection: Check if non-demo (real) projects exist
    const existingProjects = await db.select().from(projects).where(eq(projects.tenantId, tenantId));
    const realProjects = existingProjects.filter((p) => !p.name.includes('(Demo'));
    if (realProjects.length > 0 && !options?.force) {
      throw new Error(
        `Cannot seed demo data: ${realProjects.length} existing project(s) found in tenant. Pass { force: true } to override.`,
      );
    }

    // 2. Ensure default tenant & default workspace exist
    await tenantsService.ensureDefaultTenant();
    const existingWs = await db.select().from(workspaces).where(eq(workspaces.id, DEFAULT_WORKSPACE_ID));
    if (existingWs.length === 0) {
      await db
        .insert(workspaces)
        .values({
          id: DEFAULT_WORKSPACE_ID,
          name: 'Default Workspace',
          slug: 'default',
          description: 'Default primary workspace',
        })
        .onConflictDoNothing();
    }

    // 3. Create Demo Project
    const demoProjectName = `Nova Banking Core API (Demo ${new Date().toISOString().slice(11, 19)}-${crypto.randomBytes(3).toString('hex')})`;
    const [project] = await db
      .insert(projects)
      .values({
        tenantId,
        workspaceId: DEFAULT_WORKSPACE_ID,
        name: demoProjectName,
        description: '[DEMO / SYNTHETIC] Production internet banking API gateway and identity authentication service',
      })
      .returning();

    if (!project) {
      throw new Error('Failed to create demo project');
    }

    // 4. Create Targets with strict scopes using distinct demo domains
    const scope1: TargetScope = {
      allowedHosts: ['demo.local'],
      allowedPorts: [8443, 443],
      excludedPaths: ['/admin/debug', '/internal/shutdown'],
      testing: {
        activeScanning: true,
        loadTesting: true,
        chaosTesting: false,
      },
      limits: {
        maxRps: 60,
        maxConcurrency: 10,
        maxDuration: '10m',
      },
      allowPrivateIps: false,
    };

    const scope2: TargetScope = {
      allowedHosts: ['idp.demo.local', 'demo.local'],
      allowedPorts: [8443, 443],
      excludedPaths: ['/admin'],
      testing: {
        activeScanning: true,
        loadTesting: false,
        chaosTesting: false,
      },
      limits: {
        maxRps: 120,
        maxConcurrency: 20,
        maxDuration: '5m',
      },
      allowPrivateIps: false,
    };

    const [target1] = await db
      .insert(targets)
      .values({
        tenantId,
        projectId: project.id,
        name: 'Core Banking API Gateway (Demo)',
        baseUrl: 'https://demo.local:8443',
        scope: scope1,
      })
      .returning();

    const [target2] = await db
      .insert(targets)
      .values({
        tenantId,
        projectId: project.id,
        name: 'Customer Identity Provider (Demo)',
        baseUrl: 'https://idp.demo.local:8443',
        scope: scope2,
      })
      .returning();

    if (!target1 || !target2) {
      throw new Error('Failed to create demo targets');
    }

    // 5. Ensure Policy exists
    let policy = await policiesService.getDefaultPolicy();
    if (!policy) {
      policy = await policiesService.createPolicy(
        {
          id: ENTERPRISE_DEFAULT_POLICY.id,
          name: ENTERPRISE_DEFAULT_POLICY.name,
          description: ENTERPRISE_DEFAULT_POLICY.description,
          rules: ENTERPRISE_DEFAULT_POLICY.rules,
          requiredProfiles: ENTERPRISE_DEFAULT_POLICY.requiredProfiles,
          waivers: ENTERPRISE_DEFAULT_POLICY.waivers,
          isDefault: true,
        },
        tenantId,
      );
    }

    // 6. Create Sample Test Run
    const now = new Date();
    const startedAt = new Date(now.getTime() - 45000);
    const completedAt = now;

    const [testRun] = await db
      .insert(testRuns)
      .values({
        projectId: project.id,
        targetId: target1.id,
        profileId: 'api-security',
        status: 'completed',
        triggeredBy: 'demo_seed',
        startedAt,
        completedAt,
        summary: {
          totalTests: 18,
          passedTests: 13,
          failedTests: 5,
          errorTests: 0,
          findingsCount: {
            critical: 1,
            high: 2,
            medium: 1,
            low: 1,
            info: 0,
          },
        },
        metadata: {
          environment: 'demo',
          gitCommit: '4f8a32b',
          gitBranch: 'main',
          seedDemo: true,
          synthetic: true,
        },
      })
      .returning();

    if (!testRun) {
      throw new Error('Failed to create demo test run');
    }

    // 7. Create Execution record
    const [execution] = await db
      .insert(testExecutions)
      .values({
        testRunId: testRun.id,
        engineId: 'engine-native-headers',
        executionClass: 'class_a_native',
        status: 'completed',
        startedAt,
        completedAt,
        durationMs: 4250,
        exitCode: 0,
        rawResult: {
          inspectedEndpoints: ['/api/v1/accounts/10293', '/api/v1/transactions', '/oauth/token/introspect', '/health', '/api/v1/transfer'],
          testedHeaders: ['Strict-Transport-Security', 'Content-Security-Policy', 'Access-Control-Allow-Origin'],
        },
      })
      .returning();

    if (!execution) {
      throw new Error('Failed to create demo test execution');
    }

    // 8. Create Evidence Records with cryptographic hashes
    const evidenceSeedData = [
      {
        endpoint: '/api/v1/accounts/10293',
        description: 'BOLA vulnerability: User Bob unauthorized access to customer Alice Walker account record',
        req: {
          method: 'GET',
          url: 'https://demo.local:8443/api/v1/accounts/10293',
          headers: { 'authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.bob-user', 'accept': 'application/json' },
          body: '',
        },
        res: {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ accountId: '10293', owner: 'Alice Walker', balance: 945000.5, medicalRecordId: 'MRN-84921-A', ssnMasked: '***-**-8492' }),
        },
      },
      {
        endpoint: '/api/v1/transactions',
        description: 'SQL Injection in transaction search parameter. Reproduction curl provided.',
        req: {
          method: 'GET',
          url: 'https://demo.local:8443/api/v1/transactions?search=ref_102%27+OR+1%3D1--',
          headers: { 'authorization': 'Bearer demo-user-token' },
          body: '',
        },
        res: {
          statusCode: 500,
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ error: "syntax error at or near 'OR': SELECT * FROM transactions WHERE tenant_id = 'demo' AND search = 'ref_102' OR 1=1--" }),
        },
      },
      {
        endpoint: 'https://idp.demo.local:8443/oauth/token/introspect',
        description: 'Broken Authentication: JWT signature bypass via algorithm "none"',
        req: {
          method: 'POST',
          url: 'https://idp.demo.local:8443/oauth/token/introspect',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ token: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.' }),
        },
        res: {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ active: true, scope: 'admin:write system:root', username: 'admin' }),
        },
      },
      {
        endpoint: 'https://demo.local:8443/api/v1/transfer',
        description: 'Permissive CORS: Access-Control-Allow-Origin wildcard with credential support',
        req: { method: 'OPTIONS', url: 'https://demo.local:8443/api/v1/transfer', headers: { 'origin': 'https://malicious-attacker.com' }, body: '' },
        res: { statusCode: 204, headers: { 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' }, body: '' },
      },
      {
        endpoint: 'https://demo.local:8443/health',
        description: 'Missing HSTS header on HTTPS endpoint',
        req: { method: 'HEAD', url: 'https://demo.local:8443/health', headers: {}, body: '' },
        res: { statusCode: 200, headers: { 'server': 'nginx/1.22.1', 'content-type': 'application/json' }, body: '' },
      },
    ];

    const insertedEvidenceIds: string[] = [];

    for (const item of evidenceSeedData) {
      const hash = crypto
        .createHash('sha256')
        .update(JSON.stringify({ testRunId: testRun.id, req: item.req, res: item.res }))
        .digest('hex');

      const [evidence] = await db
        .insert(evidenceRecords)
        .values({
          testRunId: testRun.id,
          executionId: execution.id,
          request: item.req,
          response: item.res,
          environment: 'demo',
          metadata: {
            synthetic: true,
            environment: 'demo',
          },
          applicationVersion: '2.4.0-demo',
          gitCommit: '4f8a32b',
          immutableHash: hash,
        })
        .returning();

      if (evidence) {
        insertedEvidenceIds.push(evidence.id);
      }
    }

    // 9. Create Findings
    const sampleFindings = [
      {
        fingerprint: `demo-bola-${testRun.id}`,
        title: 'Broken Object Level Authorization (BOLA) in Account API',
        category: 'authorization',
        severity: 'critical' as const,
        confidence: 'certain' as const,
        status: 'open' as const,
        description: 'API endpoint allows authenticated user Bob to access customer Alice Walker balance and patient records by mutating the account ID parameter.',
        risk: 'Direct exposure of sensitive customer financial and medical records without authorization checks.',
        recommendation: 'Enforce strict ownership and session authorization middleware on all /api/v1/accounts/:id routes.',
        testDefinitionId: 'test-def-auth-bola',
        evidenceId: insertedEvidenceIds[0],
      },
      {
        fingerprint: `demo-sqli-${testRun.id}`,
        title: 'SQL Injection in Transaction Search Parameter',
        category: 'injection',
        severity: 'high' as const,
        confidence: 'certain' as const,
        status: 'open' as const,
        description: 'Unsanitized input in search query parameter is directly concatenated into database query. Reproduction curl: curl -X GET "https://demo.local:8443/api/v1/transactions?search=ref_102%27+OR+1%3D1--" -H "Authorization: Bearer <TOKEN>"',
        risk: 'Arbitrary database query execution, data exfiltration, and privilege escalation.',
        recommendation: 'Use parameterized SQL queries or ORM query builders for all transaction search filters.',
        testDefinitionId: 'test-def-injection-sqli',
        evidenceId: insertedEvidenceIds[1],
      },
      {
        fingerprint: `demo-jwt-none-${testRun.id}`,
        title: 'Broken Authentication: JWT Signature Verification Bypass via None Algorithm',
        category: 'authentication',
        severity: 'high' as const,
        confidence: 'certain' as const,
        status: 'open' as const,
        description: 'OAuth2 token introspection accepts unsigned JSON Web Tokens specifying algorithm "none", granting root administrative scopes.',
        risk: 'Complete authentication bypass and administrative takeover across the banking gateway.',
        recommendation: 'Explicitly reject algorithm "none" and require RS256/ES256 asymmetric cryptographic verification.',
        testDefinitionId: 'test-def-auth-jwt-none',
        evidenceId: insertedEvidenceIds[2],
      },
      {
        fingerprint: `demo-cors-${testRun.id}`,
        title: 'Permissive Cross-Origin Resource Sharing (CORS)',
        category: 'cors_security',
        severity: 'medium' as const,
        confidence: 'firm' as const,
        status: 'open' as const,
        description: 'Access-Control-Allow-Origin header is set to wildcard (*) with credentials enabled, allowing untrusted sites to read API responses.',
        risk: 'Malicious third-party websites can issue authenticated cross-origin requests on behalf of victims.',
        recommendation: 'Whitelist explicit trusted origins and avoid echoing Origin blindly.',
        testDefinitionId: 'test-def-cors',
        evidenceId: insertedEvidenceIds[3],
      },
      {
        fingerprint: `demo-hsts-${testRun.id}`,
        title: 'Missing HTTP Strict Transport Security (HSTS) Header',
        category: 'http_headers',
        severity: 'low' as const,
        confidence: 'firm' as const,
        status: 'open' as const,
        description: 'The HTTP Strict-Transport-Security (HSTS) header is missing from HTTPS responses, allowing protocol downgrade attacks.',
        risk: 'Attacker in network path can intercept or downgrade traffic to unencrypted HTTP.',
        recommendation: 'Configure Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.',
        testDefinitionId: 'test-def-hsts',
        evidenceId: insertedEvidenceIds[4],
      },
    ];

    for (const f of sampleFindings) {
      await db.insert(findings).values({
        tenantId,
        fingerprint: f.fingerprint,
        title: f.title,
        category: f.category,
        severity: f.severity,
        confidence: f.confidence,
        status: f.status,
        description: f.description,
        risk: f.risk,
        recommendation: f.recommendation,
        testDefinitionId: f.testDefinitionId,
        testRunId: testRun.id,
        executionId: execution.id,
        targetId: target1.id,
        evidenceId: f.evidenceId,
        metadata: {
          synthetic: true,
          environment: 'demo',
        },
      });
    }

    // 10. Create 50 Time-Series Performance Metrics
    const metricRows: any[] = [];
    for (let i = 0; i < 10; i++) {
      const offsetMs = (10 - i) * 5000;
      const pointTime = new Date(completedAt.getTime() - offsetMs);
      const rps = 120 + Math.sin(i) * 15;
      const p50 = 24 + Math.cos(i) * 4;
      const p90 = 70 + Math.sin(i * 1.5) * 8;
      const p95 = 115 + Math.cos(i * 1.2) * 12;
      const p99 = 150 + Math.sin(i * 0.8) * 20;

      metricRows.push(
        { testRunId: testRun.id, executionId: execution.id, name: 'http.request.throughput', value: Number(rps.toFixed(1)), unit: 'rps', tags: { profile: 'load-test', step: `${i}` }, createdAt: pointTime },
        { testRunId: testRun.id, executionId: execution.id, name: 'http.response.p50_latency', value: Number(p50.toFixed(1)), unit: 'ms', tags: { profile: 'load-test', step: `${i}` }, createdAt: pointTime },
        { testRunId: testRun.id, executionId: execution.id, name: 'http.response.p90_latency', value: Number(p90.toFixed(1)), unit: 'ms', tags: { profile: 'load-test', step: `${i}` }, createdAt: pointTime },
        { testRunId: testRun.id, executionId: execution.id, name: 'http.response.p95_latency', value: Number(p95.toFixed(1)), unit: 'ms', tags: { profile: 'load-test', step: `${i}` }, createdAt: pointTime },
        { testRunId: testRun.id, executionId: execution.id, name: 'http.response.p99_latency', value: Number(p99.toFixed(1)), unit: 'ms', tags: { profile: 'load-test', step: `${i}` }, createdAt: pointTime },
      );
    }
    await chunkedInsert(metrics, metricRows);

    // 11. Create Demo Agent Node
    await db
      .insert(agents)
      .values({
        tenantId,
        name: 'worker-eu-west-01 (Demo)',
        status: 'online',
        authMode: 'token',
        tokenHash: crypto.createHash('sha256').update('demo-agent-worker-token').digest('hex'),
        fingerprint: 'sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069',
        capabilities: ['class_a_native', 'class_b_container', 'active_scan', 'chaos_mitm', 'load_generator'],
        tags: ['env:demo', 'region:eu-west', 'arch:x86_64'],
        systemInfo: {
          hostname: 'worker-node-demo-01',
          os: 'linux',
          arch: 'x64',
          cpus: 8,
          memoryMb: 16384,
          version: '1.4.0',
        },
        lastHeartbeatAt: new Date(),
      })
      .onConflictDoNothing();

    // 12. Create Demo Webhook & Deliveries
    const [demoWebhook] = await db
      .insert(webhooks)
      .values({
        workspaceId: DEFAULT_WORKSPACE_ID,
        url: 'https://security-alerts.demo.local/v1/webhook',
        description: 'Security Alerts Dispatcher (Demo)',
        secret: 'whsec_demo_secret_key_84920491823',
        events: ['finding.created', 'release.blocked', 'chaos.aborted'],
        isActive: true,
      })
      .returning();

    if (demoWebhook) {
      await db.insert(webhookDeliveries).values([
        {
          webhookId: demoWebhook.id,
          workspaceId: DEFAULT_WORKSPACE_ID,
          eventType: 'finding.created',
          payload: {
            findingId: `demo-bola-${testRun.id}`,
            title: 'Broken Object Level Authorization (BOLA) in Account API',
            severity: 'critical',
          },
          status: 'succeeded',
          attempts: 1,
          responseStatusCode: 200,
          responseBody: '{"status":"delivered","event_id":"evt_demo_101"}',
          lastAttemptAt: new Date(),
        },
        {
          webhookId: demoWebhook.id,
          workspaceId: DEFAULT_WORKSPACE_ID,
          eventType: 'release.blocked',
          payload: {
            reason: 'Blocked by rule [rule-zero-critical]',
          },
          status: 'pending',
          attempts: 0,
          nextRetryAt: new Date(Date.now() + 60000),
        },
      ]);
    }

    // 13. Create Demo OpenAPI Spec in contractSpecs
    await db
      .insert(contractSpecs)
      .values({
        tenantId,
        targetId: target1.id,
        name: 'Core Banking API Gateway (Demo)',
        type: 'openapi',
        content: JSON.stringify({
          openapi: '3.0.3',
          info: {
            title: 'Core Banking API Gateway (Demo)',
            version: '2.4.0',
            description: 'Production internet banking specification for customer accounts and transfers.',
          },
          servers: [{ url: 'https://demo.local:8443' }],
          paths: {
            '/api/v1/accounts/{id}': {
              get: {
                tags: ['Accounts'],
                summary: 'Retrieve customer account details',
                parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
                responses: { '200': { description: 'Account details' } },
              },
            },
            '/api/v1/transactions': {
              get: {
                tags: ['Transactions'],
                summary: 'Search transaction records',
                parameters: [{ name: 'search', in: 'query', schema: { type: 'string' } }],
                responses: { '200': { description: 'Transactions list' } },
              },
            },
          },
        }, null, 2),
      })
      .onConflictDoNothing();

    // 14. Create Evaluated Release Gate
    const releaseHash = crypto
      .createHash('sha256')
      .update(JSON.stringify({ testRunId: testRun.id, policyId: policy.id, decision: 'failed' }))
      .digest('hex');

    const [releaseRecord] = await db
      .insert(releases)
      .values({
        projectId: project.id,
        name: 'Nova Core Release v2.4.0',
        version: '2.4.0-rc1',
        gitCommit: '4f8a32b',
        gitBranch: 'main',
        testRunId: testRun.id,
        policyId: policy.id,
        decision: 'failed',
        reason: 'Blocked by rule [rule-zero-critical]: 1 critical vulnerability detected (Broken Object Level Authorization).',
        evaluatorHash: releaseHash,
        evaluatedAt: now,
      })
      .returning();

    return {
      success: true,
      projectId: project.id,
      projectName: project.name,
      targetsCreated: 2,
      testRunId: testRun.id,
      findingsCreated: sampleFindings.length,
      evidenceCreated: insertedEvidenceIds.length,
      policyId: policy.id,
      releaseId: releaseRecord?.id,
      agentsCreated: 1,
      webhooksCreated: 1,
      metricsCreated: metricRows.length,
      message: 'Successfully generated complete demonstration test suite with Nova Banking Core API, targets, test executions, findings, agent nodes, and webhooks.',
      timestamp: new Date().toISOString(),
    };
  }

  async reapAgentJobsNow(): Promise<{ reapedCount: number }> {
    const result = await agentDispatcherService.reapExpiredJobLeases();
    return { reapedCount: result.reaped };
  }

  async createBackup(req: CreateBackupRequest): Promise<BackupMetadata> {
    const { db } = getDatabase();
    const backupsDir = path.resolve(config.BACKUPS_DIR || './.data/backups');
    if (!fs.existsSync(backupsDir)) {
      fs.mkdirSync(backupsDir, { recursive: true });
    }

    const [
      allTenants,
      allProjects,
      allTargets,
      allEnvironments,
      allPolicies,
    ] = await Promise.all([
      db.select().from(tenants),
      db.select().from(projects),
      db.select().from(targets),
      db.select().from(environments),
      db.select().from(policies),
    ]);

    let allTestRuns: any[] = [];
    let allTestExecutions: any[] = [];
    let allFindings: any[] = [];
    let allEvidenceRecords: any[] = [];
    let allMetrics: any[] = [];
    let allReleases: any[] = [];

    if (req.includeExecutions !== false) {
      [
        allTestRuns,
        allTestExecutions,
        allFindings,
        allEvidenceRecords,
        allMetrics,
        allReleases,
      ] = await Promise.all([
        db.select().from(testRuns),
        db.select().from(testExecutions),
        db.select().from(findings),
        db.select().from(evidenceRecords),
        db.select().from(metrics),
        db.select().from(releases),
      ]);
    }

    const counts = {
      tenants: allTenants.length,
      projects: allProjects.length,
      targets: allTargets.length,
      environments: allEnvironments.length,
      policies: allPolicies.length,
      testRuns: allTestRuns.length,
      testExecutions: allTestExecutions.length,
      findings: allFindings.length,
      evidenceRecords: allEvidenceRecords.length,
      metrics: allMetrics.length,
      releases: allReleases.length,
    };

    const timestamp = new Date().toISOString();
    const payload: BackupPayload = {
      metadata: {
        version: '1.0.0',
        schemaVersion: '2026-10',
        createdAt: timestamp,
        platform: 'Security Lab Enterprise Platform',
        counts,
        description: req.description || 'Full platform snapshot',
      },
      data: {
        tenants: allTenants,
        projects: allProjects,
        targets: allTargets,
        environments: allEnvironments,
        policies: allPolicies,
        testRuns: allTestRuns,
        testExecutions: allTestExecutions,
        findings: allFindings,
        evidenceRecords: allEvidenceRecords,
        metrics: allMetrics,
        releases: allReleases,
      },
    };

    const jsonContent = JSON.stringify(payload, null, 2);
    const sha256 = crypto.createHash('sha256').update(jsonContent).digest('hex');
    payload.metadata.sha256 = sha256;

    const dateSlug = timestamp.replace(/[:.]/g, '-');
    const randSlug = crypto.randomBytes(3).toString('hex');
    const filename = `backup_${dateSlug}_${randSlug}.json`;
    const filePath = path.join(backupsDir, filename);

    fs.writeFileSync(filePath, JSON.stringify(payload, null, 2), 'utf-8');
    const stat = fs.statSync(filePath);

    logger.info(
      { filename, sizeBytes: stat.size, sha256, counts },
      'Universal Management: Successfully generated platform backup snapshot',
    );

    return {
      id: filename.replace(/\.json$/, ''),
      filename,
      createdAt: timestamp,
      version: '1.0.0',
      sizeBytes: stat.size,
      sha256,
      counts,
      description: req.description,
    };
  }

  async listBackups(): Promise<BackupMetadata[]> {
    const backupsDir = path.resolve(config.BACKUPS_DIR || './.data/backups');
    if (!fs.existsSync(backupsDir)) {
      return [];
    }

    const entries = fs.readdirSync(backupsDir, { withFileTypes: true });
    const results: BackupMetadata[] = [];

    for (const entry of entries) {
      if (entry.isFile() && entry.name.endsWith('.json')) {
        const fullPath = path.join(backupsDir, entry.name);
        try {
          const stat = fs.statSync(fullPath);
          const content = fs.readFileSync(fullPath, 'utf-8');
          const parsed = JSON.parse(content);

          if (parsed && (parsed.metadata || parsed.data)) {
            const metadata = parsed.metadata || {};
            const data = parsed.data || {};
            const counts = metadata.counts || {
              tenants: (data.tenants || []).length,
              projects: (data.projects || []).length,
              targets: (data.targets || []).length,
              environments: (data.environments || []).length,
              policies: (data.policies || []).length,
              testRuns: (data.testRuns || []).length,
              testExecutions: (data.testExecutions || []).length,
              findings: (data.findings || []).length,
              evidenceRecords: (data.evidenceRecords || []).length,
              metrics: (data.metrics || []).length,
              releases: (data.releases || []).length,
            };

            const sha256 =
              metadata.sha256 ||
              crypto.createHash('sha256').update(content).digest('hex');

            results.push({
              id: entry.name.replace(/\.json$/, ''),
              filename: entry.name,
              createdAt: metadata.createdAt || stat.birthtime.toISOString(),
              version: metadata.version || '1.0.0',
              sizeBytes: stat.size,
              sha256,
              counts,
              description: metadata.description,
            });
          }
        } catch {
          // Skip unreadable or corrupted files
        }
      }
    }

    results.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    return results;
  }

  async getBackupFile(backupId: string): Promise<{ filename: string; filePath: string; content: string; parsed: BackupPayload }> {
    const backupsDir = path.resolve(config.BACKUPS_DIR || './.data/backups');
    const sanitizedId = path.basename(backupId).replace(/[^a-zA-Z0-9_.-]/g, '');
    const filename = sanitizedId.endsWith('.json') ? sanitizedId : `${sanitizedId}.json`;
    const filePath = path.join(backupsDir, filename);

    if (!fs.existsSync(filePath)) {
      throw new Error(`Backup file not found: ${filename}`);
    }

    const content = fs.readFileSync(filePath, 'utf-8');
    let parsed: BackupPayload;
    try {
      parsed = JSON.parse(content);
    } catch {
      throw new Error(`Corrupted backup file: ${filename} is not valid JSON`);
    }

    return { filename, filePath, content, parsed };
  }

  async deleteBackup(backupId: string): Promise<{ success: boolean; message: string }> {
    const backupsDir = path.resolve(config.BACKUPS_DIR || './.data/backups');
    const sanitizedId = path.basename(backupId).replace(/[^a-zA-Z0-9_.-]/g, '');
    const filename = sanitizedId.endsWith('.json') ? sanitizedId : `${sanitizedId}.json`;
    const filePath = path.join(backupsDir, filename);

    if (!fs.existsSync(filePath)) {
      throw new Error(`Backup file not found: ${filename}`);
    }

    fs.unlinkSync(filePath);
    return {
      success: true,
      message: `Backup ${filename} deleted successfully`,
    };
  }

  async restoreBackup(req: RestoreBackupRequest, tenantId?: string): Promise<RestoreBackupResult> {
    const mode = req.mode || 'replace';
    if (mode === 'replace') {
      const confirmation = (req.confirmation || '').trim().toUpperCase();
      if (confirmation !== 'CONFIRM_RESTORE' && confirmation !== 'RESTORE_REPLACE') {
        throw new Error('Destructive restore mode "replace" requires confirmation phrase "CONFIRM_RESTORE"');
      }
    }

    let payload: BackupPayload;
    if (req.backupData) {
      payload = req.backupData as unknown as BackupPayload;
    } else if (req.backupId) {
      const file = await this.getBackupFile(req.backupId);
      payload = file.parsed;
    } else {
      throw new Error('Either backupId or backupData must be provided for restore');
    }

    if (!payload || !payload.data) {
      throw new Error('Invalid backup data structure: missing data container');
    }

    if (mode === 'replace') {
      await this.purgeData('all', 'CONFIRM_PURGE', tenantId);
    }

    const data = payload.data;
    const restoredCounts: Record<string, number> = {
      tenants: await chunkedInsert(tenants, data.tenants || []),
      projects: await chunkedInsert(projects, data.projects || []),
      environments: await chunkedInsert(environments, data.environments || []),
      targets: await chunkedInsert(targets, data.targets || []),
      policies: await chunkedInsert(policies, data.policies || []),
      testRuns: await chunkedInsert(testRuns, data.testRuns || []),
      testExecutions: await chunkedInsert(testExecutions, data.testExecutions || []),
      findings: await chunkedInsert(findings, data.findings || []),
      evidenceRecords: await chunkedInsert(evidenceRecords, data.evidenceRecords || []),
      metrics: await chunkedInsert(metrics, data.metrics || []),
      releases: await chunkedInsert(releases, data.releases || []),
    };

    const totalRecords = Object.values(restoredCounts).reduce((a, b) => a + b, 0);
    logger.info({ mode, restoredCounts, totalRecords }, 'Universal Management: Backup restoration completed');

    return {
      success: true,
      mode,
      restoredCounts,
      message: `Platform state successfully restored (${mode} mode) with ${totalRecords} total records.`,
      timestamp: new Date().toISOString(),
    };
  }
}

export const managementService = new ManagementService();
