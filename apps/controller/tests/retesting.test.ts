import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../src/app/index.js';
import { getDatabase, closeDatabase } from '../src/services/db.js';
import { findingsService, computeHardenedFindingFingerprint } from '../src/services/findings.service.js';
import { retesterService } from '../src/services/retester.js';
import { flappingService } from '../src/services/flapping.js';
import { workspacesService } from '../src/services/workspaces.service.js';
import { signJwt } from '../src/services/auth-token.service.js';
import { evaluatePolicy } from '@security-lab/policy-engine';
import { Policy, Finding } from '@security-lab/domain';

describe('Phase 16: Finding Lifecycle Intelligence, Retesting & Flapping Detection', () => {
  let app: FastifyInstance;
  let server: http.Server;
  let mockServerPort: number;
  let mockServerUrl: string;
  let headerNosniffEnabled = false;

  // Workspace, Project, Target, and Auth Tokens
  let workspaceId: string;
  let engineerUserId: string;
  let auditorUserId: string;
  let tokenEngineer: string;
  let tokenAuditor: string;
  let projectId: string;
  let targetId: string;
  let testRunId: string;
  let testExecId: string;

  beforeAll(async () => {
    // 1. Start ephemeral mock server to simulate vulnerable vs fixed endpoint
    await new Promise<void>((resolve) => {
      server = http.createServer((req, res) => {
        if (req.url === '/api/secure-endpoint' || req.url === '/api/vulnerable') {
          const headers: Record<string, string> = { 'Content-Type': 'application/json' };
          if (headerNosniffEnabled) {
            headers['X-Content-Type-Options'] = 'nosniff';
          }
          res.writeHead(200, headers);
          res.end(JSON.stringify({ status: 'ok', nosniff: headerNosniffEnabled }));
        } else {
          res.writeHead(404);
          res.end();
        }
      });
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address() as { port: number };
        mockServerPort = addr.port;
        mockServerUrl = `http://127.0.0.1:${mockServerPort}`;
        resolve();
      });
    });

    // 2. Initialize Fastify controller app
    app = buildApp({
      disableLogging: true,
      enableReaper: false,
      bypassAuth: false,
    });
    await app.ready();

    // 3. Create Workspace, Users, and Tokens
    const ws = await workspacesService.createWorkspace({
      name: `Triage Test Lab ${Date.now()}`,
      slug: `triage-lab-${Date.now()}`,
    });
    workspaceId = ws.id;

    const engineer = await workspacesService.createUser({
      email: `engineer-${Date.now()}@lab.local`,
      name: 'Security Engineer',
      password: 'StrongPassword123!',
      workspaceId,
      role: 'ENGINEER',
    });
    engineerUserId = engineer.id;
    tokenEngineer = signJwt({
      sub: engineerUserId,
      email: engineer.email,
      name: engineer.name,
      role: 'ENGINEER',
      workspaceId,
    });

    const auditor = await workspacesService.createUser({
      email: `auditor-${Date.now()}@lab.local`,
      name: 'Compliance Auditor',
      password: 'StrongPassword123!',
      workspaceId,
      role: 'AUDITOR',
    });
    auditorUserId = auditor.id;
    tokenAuditor = signJwt({
      sub: auditorUserId,
      email: auditor.email,
      name: auditor.name,
      role: 'AUDITOR',
      workspaceId,
    });

    // 4. Create Project, Target, TestRun in DB
    const { sql } = getDatabase();
    const [proj] = await sql`
      INSERT INTO projects (workspace_id, name, description)
      VALUES (${workspaceId}, ${`Project ${Date.now()}`}, 'Phase 16 Testing')
      RETURNING id
    `;
    projectId = proj.id;

    const [tgt] = await sql`
      INSERT INTO targets (project_id, name, base_url, scope, verification_status)
      VALUES (${projectId}, 'Local Mock Target', ${mockServerUrl}, ${JSON.stringify({ allowedHosts: ['127.0.0.1', 'localhost'], allowedPorts: [80, 443, mockServerPort], allowPrivateIps: true })}::jsonb, 'VERIFIED')
      RETURNING id
    `;
    targetId = tgt.id;

    const [tr] = await sql`
      INSERT INTO test_runs (project_id, target_id, profile_id, status)
      VALUES (${projectId}, ${targetId}, 'baseline', 'completed')
      RETURNING id
    `;
    testRunId = tr.id;

    const [te] = await sql`
      INSERT INTO test_executions (test_run_id, engine_id, status)
      VALUES (${testRunId}, 'engine-native-headers', 'completed')
      RETURNING id
    `;
    testExecId = te.id;
  });

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    await app.close();
    await closeDatabase();
  });

  // ===========================================================================
  // 1. Finding Triage State Machine
  // ===========================================================================
  describe('Finding Triage State Machine', () => {
    it('enforces valid transitions: OPEN -> CONFIRMED -> FALSE_POSITIVE / ACCEPTED_RISK', async () => {
      const fingerprint = computeHardenedFindingFingerprint({
        targetId,
        engineId: 'engine-native-headers',
        category: 'security-headers',
        ruleOrCweId: 'X-Content-Type-Options',
        endpointPath: '/api/vulnerable',
      });

      const finding = await findingsService.saveFinding({
        targetId,
        testRunId,
        executionId: testExecId,
        testDefinitionId: 'engine-native-headers',
        fingerprint,
        title: 'Missing X-Content-Type-Options Header',
        category: 'security-headers',
        severity: 'medium',
        description: 'Server response does not specify X-Content-Type-Options: nosniff',
        metadata: {
          ruleId: 'X-Content-Type-Options',
          endpoint: '/api/vulnerable',
        },
      });

      expect(finding.status).toBe('open');

      // Transition OPEN -> CONFIRMED
      const confirmed = await findingsService.triageFinding(
        finding.id,
        { status: 'confirmed', comment: 'Analyst verified flaw exists' },
        engineerUserId,
      );
      expect(confirmed?.status).toBe('confirmed');
      expect(confirmed?.triageHistory.length).toBe(1);
      expect(confirmed?.triageHistory[0].fromStatus).toBe('open');
      expect(confirmed?.triageHistory[0].toStatus).toBe('confirmed');

      // Attempt FALSE_POSITIVE without comment -> MUST FAIL
      await expect(
        findingsService.triageFinding(
          finding.id,
          { status: 'false_positive', comment: '' },
          engineerUserId,
        ),
      ).rejects.toThrow('Rationale comment is required');

      // Transition CONFIRMED -> FALSE_POSITIVE with comment -> MUST SUCCEED
      const fp = await findingsService.triageFinding(
        finding.id,
        { status: 'false_positive', comment: 'Endpoint only serves non-executable JSON, no MIME-sniffing risk' },
        engineerUserId,
      );
      expect(fp?.status).toBe('false_positive');
      expect(fp?.triageHistory.length).toBe(2);

      // Transition FALSE_POSITIVE -> OPEN (reopening) -> MUST SUCCEED
      const reopened = await findingsService.triageFinding(
        finding.id,
        { status: 'open', comment: 'Reopened by auditor review' },
        auditorUserId,
      );
      expect(reopened?.status).toBe('open');

      // Attempt ACCEPTED_RISK without expiresAt -> MUST FAIL
      await expect(
        findingsService.triageFinding(
          finding.id,
          { status: 'accepted_risk', comment: 'Accepted risk rationale' },
          engineerUserId,
        ),
      ).rejects.toThrow('Expiration date (expiresAt) is strictly required');

      // Attempt ACCEPTED_RISK with past expiresAt -> MUST FAIL
      await expect(
        findingsService.triageFinding(
          finding.id,
          {
            status: 'accepted_risk',
            comment: 'Accepted risk rationale',
            expiresAt: new Date(Date.now() - 3600000).toISOString(),
          },
          engineerUserId,
        ),
      ).rejects.toThrow('must be a valid future ISO timestamp');

      // Transition OPEN -> ACCEPTED_RISK with future date & rationale -> MUST SUCCEED
      const futureDate = new Date(Date.now() + 30 * 24 * 3600000).toISOString();
      const accepted = await findingsService.triageFinding(
        finding.id,
        {
          status: 'accepted_risk',
          comment: 'Accepted risk pending Q4 framework upgrade',
          expiresAt: futureDate,
        },
        engineerUserId,
      );
      expect(accepted?.status).toBe('accepted_risk');
      expect(accepted?.metadata.riskAcceptedExpiresAt).toBe(futureDate);
      expect(accepted?.triageHistory.length).toBe(4);

      // Verify audit event was recorded in audit_events table
      const { sql } = getDatabase();
      const auditRows = await sql`
        SELECT event_type, details
        FROM audit_events
        WHERE details->>'findingId' = ${finding.id}
      `;
      expect(auditRows.length).toBeGreaterThanOrEqual(1);
      expect(auditRows[0].event_type).toBe('finding.triaged');
    });
  });

  // ===========================================================================
  // 2. Targeted Single-Finding Retest Service
  // ===========================================================================
  describe('Targeted Single-Finding Retest Service', () => {
    it('runs targeted retest and verifies flaw resolution in < 5 seconds', async () => {
      headerNosniffEnabled = false; // Flaw is initially present

      const fingerprint = computeHardenedFindingFingerprint({
        targetId,
        engineId: 'engine-native-headers',
        category: 'security-headers',
        ruleOrCweId: 'X-Content-Type-Options',
        endpointPath: '/api/secure-endpoint',
      });

      const finding = await findingsService.saveFinding({
        targetId,
        testRunId,
        executionId: testExecId,
        testDefinitionId: 'engine-native-headers',
        fingerprint,
        title: 'Missing X-Content-Type-Options',
        category: 'security-headers',
        severity: 'medium',
        description: 'Vulnerable endpoint missing nosniff header',
        metadata: {
          ruleId: 'X-Content-Type-Options',
          endpoint: '/api/secure-endpoint',
        },
      });

      expect(finding.status).toBe('open');

      // 1. Retest while flaw is still present
      const retest1 = await retesterService.retestFinding(finding.id);
      expect(retest1.stillDetected).toBe(true);
      expect(retest1.status).toBe('REOPENED');
      expect(retest1.durationMs).toBeLessThan(5000);

      // 2. Fix the flaw on the target server
      headerNosniffEnabled = true;

      // 3. Retest again: flaw is now fixed!
      const startTime = Date.now();
      const retest2 = await retesterService.retestFinding(finding.id);
      const elapsedMs = Date.now() - startTime;

      expect(retest2.stillDetected).toBe(false);
      expect(retest2.status).toBe('RESOLVED');
      expect(elapsedMs).toBeLessThan(5000);

      // 4. Verify finding in database has transitioned to RESOLVED
      const reloaded = await findingsService.getFindingById(finding.id);
      expect(reloaded?.status).toBe('resolved');
      expect(reloaded?.fixedAt).toBeDefined();
      expect(reloaded?.fixedInRunId).toBeDefined();
    });
  });

  // ===========================================================================
  // 3. Flapping Score & Trend Analytics
  // ===========================================================================
  describe('Historical Flapping Analytics', () => {
    it('calculates flapping score over test runs and tags UNSTABLE_FLAPPING when score > 0.4', async () => {
      const { sql } = getDatabase();

      // Create dedicated target for flapping test
      const [flappingTarget] = await sql`
        INSERT INTO targets (project_id, name, base_url, scope, verification_status)
        VALUES (${projectId}, 'Dedicated Flapping Target', ${mockServerUrl}, '{"allowedHosts": ["127.0.0.1", "localhost"], "allowPrivateIps": true}'::jsonb, 'VERIFIED')
        RETURNING id
      `;
      const flappingTargetId = flappingTarget.id;

      // Create a finding with explicit run oscillation history
      const fingerprint = computeHardenedFindingFingerprint({
        targetId: flappingTargetId,
        engineId: 'engine-native-network',
        category: 'network',
        ruleOrCweId: 'Intermittent-Timeout',
        endpointPath: '/api/flapping',
      });

      // Simulate 5 completed test runs
      const runIds: string[] = [];
      for (let i = 0; i < 5; i++) {
        const [r] = await sql`
          INSERT INTO test_runs (project_id, target_id, profile_id, status, created_at)
          VALUES (${projectId}, ${flappingTargetId}, 'baseline', 'completed', ${new Date(Date.now() - (5 - i) * 60000).toISOString()})
          RETURNING id
        `;
        runIds.push(r.id);
      }

      // History alternates: PRESENT (run 0), ABSENT (run 1), PRESENT (run 2), ABSENT (run 3), PRESENT (run 4)
      // Transitions: run0->run1 (1), run1->run2 (2), run2->run3 (3), run3->run4 (4) = 4 transitions / 5 runs = 0.8
      const runHistory = [
        { runId: runIds[0], status: 'PRESENT' },
        { runId: runIds[1], status: 'ABSENT' },
        { runId: runIds[2], status: 'PRESENT' },
        { runId: runIds[3], status: 'ABSENT' },
        { runId: runIds[4], status: 'PRESENT' },
      ];

      const finding = await findingsService.saveFinding({
        targetId: flappingTargetId,
        testRunId: runIds[4],
        executionId: testExecId,
        testDefinitionId: 'engine-native-network',
        fingerprint,
        title: 'Intermittent Network Flap',
        category: 'network',
        severity: 'high',
        description: 'Oscillating network finding',
        metadata: {
          runHistory,
        },
      });

      // Calculate flapping score
      const analysis = await flappingService.calculateFlappingScore(finding.id);
      expect(analysis).not.toBeNull();
      expect(analysis!.totalRunsAnalyzed).toBe(5);
      expect(analysis!.transitionsCount).toBe(4);
      expect(analysis!.flappingScore).toBeGreaterThan(0.4);
      expect(analysis!.isFlapping).toBe(true);
      expect(analysis!.suppressReleaseGate).toBe(true);

      // Verify database record was updated with flapping tags
      const updatedInDb = await findingsService.getFindingById(finding.id);
      expect(updatedInDb?.isFlapping).toBe(true);
      expect(updatedInDb?.flappingScore).toBeGreaterThan(0.4);
      expect((updatedInDb?.metadata.tags as string[])).toContain('UNSTABLE_FLAPPING');
    });
  });

  // ===========================================================================
  // 4. Policy Engine Release Gate Suppression for Flapping Findings
  // ===========================================================================
  describe('Policy Engine Release Gate Flapping Suppression', () => {
    it('suppresses release gate blocking for flapping findings while blocking on stable critical findings', () => {
      const policy: Policy = {
        id: '11111111-1111-1111-1111-111111111111',
        name: 'Strict Release Gate Policy',
        description: 'Block all critical vulnerabilities',
        rules: [
          {
            id: 'no-criticals',
            name: 'No Critical Findings',
            severity: 'critical',
            action: 'block_release',
            condition: {
              maxAllowedSeverity: 'high',
            },
          },
        ],
        waivers: [],
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      // Finding A: Flapping finding (score = 0.6 > 0.4, isFlapping = true)
      const flappingFinding: Finding = {
        id: '22222222-2222-2222-2222-222222222222',
        fingerprint: 'fp-flapping-123',
        title: 'Flapping Intermittent Flaw',
        category: 'security',
        severity: 'critical',
        confidence: 'firm',
        status: 'open',
        description: 'Flapping flaw',
        testDefinitionId: 'engine-native-declarative',
        testRunId: testRunId,
        executionId: testExecId,
        targetId: targetId,
        firstDetectedAt: new Date(),
        lastDetectedAt: new Date(),
        occurrenceCount: 5,
        flappingScore: 0.6,
        isFlapping: true,
        metadata: {
          unstableFlapping: true,
          tags: ['UNSTABLE_FLAPPING'],
        },
        triageHistory: [],
      };

      // Evaluate policy with ONLY flapping finding -> release gate MUST NOT BLOCK (decision is warning, no block_release violations)
      const resultFlappingOnly = evaluatePolicy(policy, [flappingFinding]);
      expect(resultFlappingOnly.decision).not.toBe('failed');
      expect(resultFlappingOnly.violations.some((v) => v.action === 'block_release')).toBe(false);
      expect(resultFlappingOnly.waivedFindings.length).toBe(1);
      expect(resultFlappingOnly.violations.some((v) => v.ruleId === 'flapping-suppressed')).toBe(true);

      // Finding B: Stable critical finding (not flapping)
      const stableCriticalFinding: Finding = {
        ...flappingFinding,
        id: '33333333-3333-3333-3333-333333333333',
        fingerprint: 'fp-stable-critical-456',
        flappingScore: 0.0,
        isFlapping: false,
        metadata: {},
      };

      // Evaluate policy with stable critical finding -> MUST BLOCK RELEASE
      const resultWithStable = evaluatePolicy(policy, [stableCriticalFinding]);
      expect(resultWithStable.passed).toBe(false);
      expect(resultWithStable.decision).toBe('failed');
    });
  });

  // ===========================================================================
  // 5. REST API Endpoints Integration
  // ===========================================================================
  describe('REST API Endpoints (/retest, /triage, /flapping)', () => {
    let apiFindingId: string;

    beforeAll(async () => {
      const fingerprint = computeHardenedFindingFingerprint({
        targetId,
        engineId: 'engine-native-headers',
        category: 'security-headers',
        ruleOrCweId: 'X-Frame-Options',
        endpointPath: '/api/vulnerable',
      });

      const f = await findingsService.saveFinding({
        targetId,
        testRunId,
        executionId: testExecId,
        testDefinitionId: 'engine-native-headers',
        fingerprint,
        title: 'Missing X-Frame-Options',
        category: 'security-headers',
        severity: 'low',
        description: 'Clickjacking protection missing',
      });
      apiFindingId = f.id;
    });

    it('POST /api/v1/findings/:id/triage updates state and records history', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/findings/${apiFindingId}/triage`,
        headers: { authorization: `Bearer ${tokenEngineer}` },
        payload: {
          status: 'CONFIRMED',
          comment: 'Confirmed via developer test suite',
        },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.success).toBe(true);
      expect(body.data.status).toBe('confirmed');
      expect(body.data.triageHistory.length).toBeGreaterThanOrEqual(1);
    });

    it('POST /api/v1/findings/:id/retest executes targeted retest and returns result', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/findings/${apiFindingId}/retest`,
        headers: { authorization: `Bearer ${tokenEngineer}` },
        payload: { timeoutMs: 4000 },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.success).toBe(true);
      expect(body.data.findingId).toBe(apiFindingId);
      expect(body.data.durationMs).toBeLessThan(4000);
      expect(body.data.timestamp).toBeDefined();
    });

    it('GET /api/v1/findings/:id/flapping returns flapping analytics for auditor', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/findings/${apiFindingId}/flapping`,
        headers: { authorization: `Bearer ${tokenAuditor}` },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.success).toBe(true);
      expect(body.data.findingId).toBe(apiFindingId);
      expect(typeof body.data.flappingScore).toBe('number');
      expect(typeof body.data.isFlapping).toBe('boolean');
      expect(Array.isArray(body.data.history)).toBe(true);
    });
  });
});
