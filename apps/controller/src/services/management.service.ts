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
import { eq } from 'drizzle-orm';

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
    const validPhrases = ['CLEAR ALL DATA', 'CONFIRM_PURGE', 'CONFIRM-DELETE', 'DELETE ALL', mode.toUpperCase()];
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

    // 2. Ensure default tenant exists
    await tenantsService.ensureDefaultTenant();

    // 3. Create Demo Project
    const demoProjectName = `Nova Banking Core API (Demo ${new Date().toISOString().slice(11, 19)}-${crypto.randomBytes(3).toString('hex')})`;
    const [project] = await db
      .insert(projects)
      .values({
        tenantId,
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
      allowedHosts: ['mock-bank.internal'],
      allowedPorts: [443],
      excludedPaths: ['/internal'],
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
        name: 'Customer Identity & OAuth2 Provider (Demo)',
        baseUrl: 'https://mock-bank.internal:443',
        scope: scope2,
      })
      .returning();

    if (!target1 || !target2) {
      throw new Error('Failed to create demo targets');
    }

    // 4. Ensure Policy exists
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

    // 5. Create Sample Test Run
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
            high: 1,
            medium: 2,
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

    // 6. Create Execution record
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
          inspectedEndpoints: ['/api/v1/accounts/10293', '/health', '/api/v1/transfer'],
          testedHeaders: ['Strict-Transport-Security', 'Content-Security-Policy', 'Access-Control-Allow-Origin'],
        },
      })
      .returning();

    if (!execution) {
      throw new Error('Failed to create demo test execution');
    }

    // 7. Create Evidence Records with cryptographic hashes
    const evidenceSeedData = [
      {
        endpoint: '/api/v1/accounts/10293',
        description: 'BOLA vulnerability: Unauthorized access to arbitrary bank account without role check',
        req: { method: 'GET', url: 'https://demo.local:8443/api/v1/accounts/10293', headers: { 'authorization': 'Bearer demo-user-token' }, body: '' },
        res: { statusCode: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ accountId: '10293', balance: 945000.5, owner: 'Target Victim Corp' }) },
      },
      {
        endpoint: 'https://demo.local:8443',
        description: 'Missing HSTS header on HTTPS endpoint',
        req: { method: 'HEAD', url: 'https://demo.local:8443/health', headers: {}, body: '' },
        res: { statusCode: 200, headers: { 'server': 'nginx/1.22.1', 'content-type': 'application/json' }, body: '' },
      },
      {
        endpoint: 'https://demo.local:8443/api/v1/transfer',
        description: 'Permissive CORS: Access-Control-Allow-Origin wildcard with credential support',
        req: { method: 'OPTIONS', url: 'https://demo.local:8443/api/v1/transfer', headers: { 'origin': 'https://malicious-attacker.com' }, body: '' },
        res: { statusCode: 204, headers: { 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' }, body: '' },
      },
      {
        endpoint: 'https://demo.local:8443',
        description: 'Content-Security-Policy (CSP) header is completely absent',
        req: { method: 'GET', url: 'https://demo.local:8443/', headers: {}, body: '' },
        res: { statusCode: 200, headers: { 'content-type': 'text/html; charset=utf-8' }, body: '<html><body>Welcome</body></html>' },
      },
      {
        endpoint: 'https://demo.local:8443/health',
        description: 'Server banner leakage disclosing exact software version',
        req: { method: 'GET', url: 'https://demo.local:8443/health', headers: {}, body: '' },
        res: { statusCode: 200, headers: { 'server': 'nginx/1.22.1 (Ubuntu 22.04 LTS)', 'x-powered-by': 'Express/4.18.2' }, body: '{"status":"ok"}' },
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

    // 8. Create Findings
    const sampleFindings = [
      {
        fingerprint: `demo-bola-${testRun.id}`,
        title: 'Broken Object Level Authorization (BOLA) in Account API',
        category: 'authorization',
        severity: 'critical' as const,
        confidence: 'certain' as const,
        status: 'open' as const,
        description: 'API endpoint allows authenticated users to access other accounts by mutating the account ID parameter.',
        risk: 'Direct exposure of sensitive customer financial records and balance details.',
        recommendation: 'Enforce strict ownership and session authorization middleware on all /api/v1/accounts/:id routes.',
        testDefinitionId: 'test-def-auth-bola',
        evidenceId: insertedEvidenceIds[0],
      },
      {
        fingerprint: `demo-hsts-${testRun.id}`,
        title: 'Missing HTTP Strict Transport Security (HSTS) Header',
        category: 'http_headers',
        severity: 'high' as const,
        confidence: 'firm' as const,
        status: 'open' as const,
        description: 'The HTTP Strict-Transport-Security (HSTS) header is missing from HTTPS responses, allowing protocol downgrade attacks.',
        risk: 'Attacker in network path can intercept or downgrade traffic to unencrypted HTTP.',
        recommendation: 'Configure Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.',
        testDefinitionId: 'test-def-hsts',
        evidenceId: insertedEvidenceIds[1],
      },
      {
        fingerprint: `demo-cors-${testRun.id}`,
        title: 'Permissive Cross-Origin Resource Sharing (CORS)',
        category: 'cors_security',
        severity: 'medium' as const,
        confidence: 'firm' as const,
        status: 'open' as const,
        description: 'Access-Control-Allow-Origin header is set to wildcard (*) or reflects arbitrary origins with credentials enabled.',
        risk: 'Malicious third-party websites can issue authenticated cross-origin requests on behalf of victims.',
        recommendation: 'Whitelist explicit trusted origins and avoid echoing Origin blindly.',
        testDefinitionId: 'test-def-cors',
        evidenceId: insertedEvidenceIds[2],
      },
      {
        fingerprint: `demo-csp-${testRun.id}`,
        title: 'Missing Content-Security-Policy (CSP) Header',
        category: 'http_headers',
        severity: 'medium' as const,
        confidence: 'firm' as const,
        status: 'open' as const,
        description: 'No Content-Security-Policy header defined on web responses.',
        risk: 'Significantly elevated susceptibility to cross-site scripting (XSS) and code injection.',
        recommendation: 'Deploy robust Content-Security-Policy with default-src "self" directives.',
        testDefinitionId: 'test-def-csp',
        evidenceId: insertedEvidenceIds[3],
      },
      {
        fingerprint: `demo-banner-${testRun.id}`,
        title: 'Detailed Server Banner & Technology Leakage',
        category: 'information_disclosure',
        severity: 'low' as const,
        confidence: 'certain' as const,
        status: 'open' as const,
        description: 'Server response headers reveal exact versions of Nginx and Express framework.',
        risk: 'Aids attackers in reconnaissance for version-specific CVE vulnerabilities.',
        recommendation: 'Disable Server tokens and remove X-Powered-By header via server configuration.',
        testDefinitionId: 'test-def-headers',
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

    // 9. Create Metrics
    await db.insert(metrics).values([
      {
        testRunId: testRun.id,
        executionId: execution.id,
        name: 'http.response.p95_latency',
        value: 165.4,
        unit: 'ms',
        tags: { endpoint: '/api/v1/accounts' },
      },
      {
        testRunId: testRun.id,
        executionId: execution.id,
        name: 'http.request.throughput',
        value: 124.0,
        unit: 'rps',
        tags: { profile: 'api-security' },
      },
      {
        testRunId: testRun.id,
        executionId: execution.id,
        name: 'http.error_rate',
        value: 0.0,
        unit: 'percent',
        tags: { target: target1.name },
      },
    ]);

    // 10. Create Evaluated Release Gate
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
      message: 'Successfully generated complete demonstration test suite with Nova Banking Core API, targets, test executions, findings, and release gate decision.',
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
