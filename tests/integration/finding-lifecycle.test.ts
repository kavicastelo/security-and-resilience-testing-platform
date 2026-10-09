import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import {
  canonicalizeJson,
  computeEvidenceHash,
  createImmutableEvidence,
  InMemoryEvidenceStore,
} from '@security-lab/evidence';
import {
  computeHardenedFindingFingerprint,
  extractFindingComponents,
  findingsService,
} from '../../apps/controller/src/services/findings.service.js';
import { getDatabase, closeDatabase } from '../../apps/controller/src/services/db.js';

describe('Phase 10 — Database Hardening, Finding Lifecycle & Regression Intelligence', () => {
  // ---------------------------------------------------------------------------
  // 1. RFC 8785 Canonical JSON Serialization & Evidence Immutability Hash
  // ---------------------------------------------------------------------------
  describe('RFC 8785 Canonical JSON Serializer', () => {
    it('serializes objects with sorted keys regardless of insertion order', () => {
      const obj1 = { z: 1, a: 2, m: 3 };
      const obj2 = { a: 2, m: 3, z: 1 };
      const obj3 = { m: 3, z: 1, a: 2 };

      const c1 = canonicalizeJson(obj1);
      const c2 = canonicalizeJson(obj2);
      const c3 = canonicalizeJson(obj3);

      expect(c1).toBe('{"a":2,"m":3,"z":1}');
      expect(c1).toBe(c2);
      expect(c2).toBe(c3);
    });

    it('recursively canonicalizes nested objects and arrays', () => {
      const nested1 = {
        outer: { delta: 'val4', alpha: 'val1', beta: { y: 2, x: 1 } },
        arr: [{ b: 2, a: 1 }, 'item'],
      };

      const nested2 = {
        arr: [{ a: 1, b: 2 }, 'item'],
        outer: { beta: { x: 1, y: 2 }, alpha: 'val1', delta: 'val4' },
      };

      expect(canonicalizeJson(nested1)).toBe(canonicalizeJson(nested2));
      expect(canonicalizeJson(nested1)).toBe(
        '{"arr":[{"a":1,"b":2},"item"],"outer":{"alpha":"val1","beta":{"x":1,"y":2},"delta":"val4"}}',
      );
    });

    it('omits undefined properties in objects and serializes null/dates predictably', () => {
      const date = new Date('2026-10-07T00:00:00.000Z');
      const obj = {
        present: 'yes',
        ignored: undefined,
        timestamp: date,
        empty: null,
      };

      const canonical = canonicalizeJson(obj);
      expect(canonical).toBe('{"empty":null,"present":"yes","timestamp":"2026-10-07T00:00:00.000Z"}');
    });

    it('produces identical evidence SHA-256 hash regardless of property order', () => {
      const timestamp = new Date('2026-10-07T01:00:00.000Z');

      const evidence1 = {
        id: 'ev-1',
        testRunId: '00000000-0000-0000-0000-000000000001',
        executionId: '00000000-0000-0000-0000-000000000002',
        request: {
          method: 'POST',
          url: 'https://api.example.com/login',
          headers: { 'user-agent': 'SecurityLab/1.0', authorization: 'Bearer token' },
          body: '{"b":2,"a":1}',
        },
        response: {
          statusCode: 200,
          headers: { 'content-type': 'application/json', server: 'nginx' },
          body: '{"ok":true}',
          responseTimeMs: 45,
        },
        expected: 'HTTP 401',
        actual: 'HTTP 200',
        environment: 'staging',
        timestamp,
        metadata: {},
      };

      const evidence2 = {
        id: 'ev-1',
        testRunId: '00000000-0000-0000-0000-000000000001',
        executionId: '00000000-0000-0000-0000-000000000002',
        request: {
          headers: { authorization: 'Bearer token', 'user-agent': 'SecurityLab/1.0' },
          url: 'https://api.example.com/login',
          method: 'POST',
          body: '{"b":2,"a":1}',
        },
        response: {
          responseTimeMs: 45,
          body: '{"ok":true}',
          headers: { server: 'nginx', 'content-type': 'application/json' },
          statusCode: 200,
        },
        actual: 'HTTP 200',
        expected: 'HTTP 401',
        timestamp,
        environment: 'staging',
        metadata: {},
      };

      const hash1 = computeEvidenceHash(evidence1);
      const hash2 = computeEvidenceHash(evidence2);

      expect(hash1).toBe(hash2);
      expect(hash1).toMatch(/^[a-f0-9]{64}$/);
    });

    it('InMemoryEvidenceStore strictly blocks overwriting existing evidence', async () => {
      const store = new InMemoryEvidenceStore();
      const evidence = createImmutableEvidence({
        id: '00000000-0000-0000-0000-000000000001',
        testRunId: '00000000-0000-0000-0000-000000000002',
        executionId: '00000000-0000-0000-0000-000000000003',
        environment: 'production',
        actual: 'Sample actual',
      });

      await store.save(evidence);
      const retrieved = await store.findById(evidence.id);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.immutableHash).toBe(evidence.immutableHash);

      // Attempting to overwrite existing immutable evidence throws an error
      await expect(store.save(evidence)).rejects.toThrow('Cannot overwrite immutable evidence record');
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Hardened Finding Fingerprint (Zero Collisions Guarantee)
  // ---------------------------------------------------------------------------
  describe('Hardened Finding Fingerprint', () => {
    const targetId = '00000000-0000-0000-0000-000000000010';
    const engineId = 'engine-native-headers';
    const category = 'headers';
    const ruleOrCweId = 'missing-content-type-options';

    it('generates distinct fingerprints for identical titles on different endpoints', () => {
      const fpEndpoint1 = computeHardenedFindingFingerprint({
        targetId,
        engineId,
        category,
        ruleOrCweId,
        endpointPath: '/api/v1/users',
      });

      const fpEndpoint2 = computeHardenedFindingFingerprint({
        targetId,
        engineId,
        category,
        ruleOrCweId,
        endpointPath: '/api/v1/orders',
      });

      expect(fpEndpoint1).not.toBe(fpEndpoint2);
      expect(fpEndpoint1).toMatch(/^[a-f0-9]{64}$/);
      expect(fpEndpoint2).toMatch(/^[a-f0-9]{64}$/);
    });

    it('generates distinct fingerprints for different parameters on the same endpoint', () => {
      const fpParam1 = computeHardenedFindingFingerprint({
        targetId,
        engineId: 'engine-native-contract',
        category: 'compliance',
        ruleOrCweId: 'no-sensitive-query-params',
        endpointPath: '/api/v1/auth',
        parameterName: 'access_token',
      });

      const fpParam2 = computeHardenedFindingFingerprint({
        targetId,
        engineId: 'engine-native-contract',
        category: 'compliance',
        ruleOrCweId: 'no-sensitive-query-params',
        endpointPath: '/api/v1/auth',
        parameterName: 'secret_key',
      });

      expect(fpParam1).not.toBe(fpParam2);
    });

    it('generates deterministic identical fingerprint for re-occurring findings', () => {
      const fpA = computeHardenedFindingFingerprint({
        targetId,
        engineId,
        category,
        ruleOrCweId,
        endpointPath: '/api/v1/users',
        parameterName: 'id',
      });

      const fpB = computeHardenedFindingFingerprint({
        targetId,
        engineId,
        category,
        ruleOrCweId,
        endpointPath: '/api/v1/users',
        parameterName: 'id',
      });

      expect(fpA).toBe(fpB);
    });

    it('extracts rule, endpoint, and parameter components from raw finding structures', () => {
      const rawFinding = {
        title: 'Sensitive Parameter in Query String: [api_key]',
        category: 'compliance',
        location: 'GET /api/v1/checkout',
        metadata: {
          ruleId: 'no-sensitive-query-params',
          endpoint: { path: '/api/v1/checkout', method: 'GET' },
          parameter: 'api_key',
        },
      };

      const extracted = extractFindingComponents(rawFinding);
      expect(extracted.ruleOrCweId).toBe('no-sensitive-query-params');
      expect(extracted.endpointPath).toBe('/api/v1/checkout');
      expect(extracted.parameterName).toBe('api_key');
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Database-Backed Finding Lifecycle State Machine & Regression Logic
  // ---------------------------------------------------------------------------
  describe('Database-Backed Finding Lifecycle & Regression State Machine', () => {
    const testTenantId = crypto.randomUUID();
    const testProjectId = crypto.randomUUID();
    const testTargetId = crypto.randomUUID();
    const testRun1Id = crypto.randomUUID();
    const testRun2Id = crypto.randomUUID();
    const testRun3Id = crypto.randomUUID();
    const testRun4Id = crypto.randomUUID();
    const testExec1Id = crypto.randomUUID();
    const testExec2Id = crypto.randomUUID();
    const testExec3Id = crypto.randomUUID();
    const testExec4Id = crypto.randomUUID();

    const sqlInjectionFingerprint = computeHardenedFindingFingerprint({
      targetId: testTargetId,
      engineId: 'zap-baseline',
      category: 'injection',
      ruleOrCweId: 'CWE-89',
      endpointPath: '/api/v1/users',
      parameterName: 'id',
    });

    const xssFingerprint = computeHardenedFindingFingerprint({
      targetId: testTargetId,
      engineId: 'zap-baseline',
      category: 'xss',
      ruleOrCweId: 'CWE-79',
      endpointPath: '/api/v1/search',
      parameterName: 'q',
    });

    beforeAll(async () => {
      const { sql } = getDatabase();

      // 1. Seed isolated tenant
      await sql`
        INSERT INTO tenants (id, name, slug)
        VALUES (${testTenantId}, 'Finding Lifecycle Tenant', ${'finding-lifecycle-' + testTenantId})
        ON CONFLICT (id) DO NOTHING;
      `;

      // 2. Seed project
      await sql`
        INSERT INTO projects (id, tenant_id, name, description)
        VALUES (${testProjectId}, ${testTenantId}, ${'Finding Lifecycle Project ' + testProjectId}, 'Test Project for finding lifecycle')
        ON CONFLICT (id) DO NOTHING;
      `;

      // 3. Seed target
      await sql`
        INSERT INTO targets (id, tenant_id, project_id, name, base_url, scope)
        VALUES (
          ${testTargetId},
          ${testTenantId},
          ${testProjectId},
          'Lifecycle Test Target',
          'https://lifecycle-target.local',
          ${JSON.stringify({ allowedHosts: ['lifecycle-target.local'], maxDepth: 2 })}
        )
        ON CONFLICT (id) DO NOTHING;
      `;

      // 4. Seed test runs and executions for runs 1 through 4
      const runs = [
        [testRun1Id, testExec1Id],
        [testRun2Id, testExec2Id],
        [testRun3Id, testExec3Id],
        [testRun4Id, testExec4Id],
      ];

      for (const [runId, execId] of runs) {
        await sql`
          INSERT INTO test_runs (id, project_id, target_id, status)
          VALUES (${runId}, ${testProjectId}, ${testTargetId}, 'completed')
          ON CONFLICT (id) DO NOTHING;
        `;

        await sql`
          INSERT INTO test_executions (id, test_run_id, engine_id, execution_class, status)
          VALUES (${execId}, ${runId}, 'zap-baseline', 'class_a_native', 'completed')
          ON CONFLICT (id) DO NOTHING;
        `;
      }
    });

    afterAll(async () => {
      const { sql } = getDatabase();
      try {
        await sql`DELETE FROM findings WHERE tenant_id = ${testTenantId}`;
        await sql`DELETE FROM test_executions WHERE test_run_id IN (${testRun1Id}, ${testRun2Id}, ${testRun3Id}, ${testRun4Id})`;
        await sql`DELETE FROM test_runs WHERE project_id = ${testProjectId}`;
        await sql`DELETE FROM targets WHERE id = ${testTargetId}`;
        await sql`DELETE FROM projects WHERE id = ${testProjectId}`;
        await sql`DELETE FROM tenants WHERE id = ${testTenantId}`;

        // Verify clean teardown with zero orphan records
        const remainingFindings = await sql`SELECT count(*)::int as count FROM findings WHERE tenant_id = ${testTenantId}`;
        expect(remainingFindings[0].count).toBe(0);
        const remainingTenants = await sql`SELECT count(*)::int as count FROM tenants WHERE id = ${testTenantId}`;
        expect(remainingTenants[0].count).toBe(0);
      } finally {
        await closeDatabase();
      }
    });

    it('persists initial finding discovery with status OPEN, occurrenceCount 1, and verifies real PostgreSQL columns and constraints', async () => {
      const { sql } = getDatabase();

      const created = await findingsService.saveFinding({
        tenantId: testTenantId,
        targetId: testTargetId,
        testRunId: testRun1Id,
        executionId: testExec1Id,
        testDefinitionId: 'zap-baseline',
        fingerprint: sqlInjectionFingerprint,
        title: 'SQL Injection in User Endpoint',
        category: 'injection',
        severity: 'high',
        confidence: 'confirmed',
        status: 'open',
        description: 'User input not sanitized in query string parameter id',
        risk: 'Potential full database compromise',
        recommendation: 'Use parameterized queries or ORM abstractions',
        metadata: {
          cwe: 'CWE-89',
          cve: 'CVE-2026-0001',
          cvss: 8.8,
          ruleId: 'sql-injection-rule',
        },
      });

      expect(created.status).toBe('open');
      expect(created.occurrenceCount).toBe(1);
      expect(created.fingerprint).toBe(sqlInjectionFingerprint);
      expect(created.targetId).toBe(testTargetId);
      expect(created.firstDetectedAt).toBeInstanceOf(Date);
      expect(created.lastDetectedAt).toBeInstanceOf(Date);

      // Verify PostgreSQL columns directly via SQL query
      const rows = await sql`
        SELECT id, tenant_id, fingerprint, title, severity, confidence, status, occurrence_count, metadata
        FROM findings
        WHERE id = ${created.id}
      `;
      expect(rows.length).toBe(1);
      const row = rows[0];
      expect(row.tenant_id).toBe(testTenantId);
      expect(row.fingerprint).toBe(sqlInjectionFingerprint);
      expect(row.severity).toBe('high');
      expect(row.confidence).toBe('confirmed');
      expect(row.status).toBe('open');
      expect(row.occurrence_count).toBe(1);
      expect(row.metadata.cwe).toBe('CWE-89');
      expect(row.metadata.cve).toBe('CVE-2026-0001');
      expect(row.metadata.cvss).toBe(8.8);
    });

    it('deduplicates recurring findings with identical fingerprint, incrementing occurrenceCount without duplicate rows', async () => {
      const { sql } = getDatabase();

      // Scan run 2 re-detects the exact same vulnerability
      const updated = await findingsService.saveFinding({
        tenantId: testTenantId,
        targetId: testTargetId,
        testRunId: testRun2Id,
        executionId: testExec2Id,
        testDefinitionId: 'zap-baseline',
        fingerprint: sqlInjectionFingerprint,
        title: 'SQL Injection in User Endpoint',
        category: 'injection',
        severity: 'high',
        description: 'User input not sanitized in query string parameter id',
      });

      expect(updated.status).toBe('open');
      expect(updated.occurrenceCount).toBe(2);
      expect(updated.testRunId).toBe(testRun2Id);
      expect(updated.executionId).toBe(testExec2Id);

      // Query database directly to assert exactly ONE row exists for this target + fingerprint
      const countRows = await sql`
        SELECT COUNT(*)::int as total
        FROM findings
        WHERE target_id = ${testTargetId} AND fingerprint = ${sqlInjectionFingerprint}
      `;
      expect(countRows[0].total).toBe(1);

      // Verify occurrence_count in database row is 2
      const dbRows = await sql`
        SELECT occurrence_count, test_run_id, execution_id
        FROM findings
        WHERE target_id = ${testTargetId} AND fingerprint = ${sqlInjectionFingerprint}
      `;
      expect(dbRows[0].occurrence_count).toBe(2);
      expect(dbRows[0].test_run_id).toBe(testRun2Id);
      expect(dbRows[0].execution_id).toBe(testExec2Id);
    });

    it('transitions absent finding to RESOLVED with fixedAt timestamp and fixedInRunId during reconciliation', async () => {
      const { sql } = getDatabase();

      // In testRun3, scan completed with zero detected findings for target
      const result = await findingsService.reconcileTestRunFindings(
        testRun3Id,
        testTargetId,
        ['zap-baseline'],
      );

      expect(result.resolvedCount).toBeGreaterThanOrEqual(1);

      // Query database directly to verify status is now 'resolved'
      const rows = await sql`
        SELECT id, status, fixed_at, fixed_in_run_id, metadata
        FROM findings
        WHERE target_id = ${testTargetId} AND fingerprint = ${sqlInjectionFingerprint}
      `;
      expect(rows.length).toBe(1);
      const row = rows[0];
      expect(row.status).toBe('resolved');
      expect(row.fixed_at).not.toBeNull();
      expect(row.fixed_in_run_id).toBe(testRun3Id);
      expect(row.metadata.resolvedInTestRunId).toBe(testRun3Id);
      expect(row.metadata.resolvedAt).toBeDefined();
    });

    it('transitions resolved finding to REGRESSED when re-detected in a subsequent run, clearing fixedAt and recording regression event', async () => {
      const { sql } = getDatabase();

      // Scan run 4 re-detects the previously resolved finding -> REGRESSION!
      const regressed = await findingsService.saveFinding({
        tenantId: testTenantId,
        targetId: testTargetId,
        testRunId: testRun4Id,
        executionId: testExec4Id,
        testDefinitionId: 'zap-baseline',
        fingerprint: sqlInjectionFingerprint,
        title: 'SQL Injection in User Endpoint',
        category: 'injection',
        severity: 'high',
        description: 'User input not sanitized in query string parameter id (reverted fix)',
      });

      expect(regressed.status).toBe('regressed');
      expect(regressed.occurrenceCount).toBe(3);
      expect(regressed.fixedAt).toBeUndefined();
      expect(regressed.fixedInRunId).toBeUndefined();

      // Verify regressionEvents array in metadata
      const metadata = regressed.metadata as {
        regressionEvents?: Array<{ regressedAt: string; testRunId: string; executionId: string }>;
      };
      expect(Array.isArray(metadata.regressionEvents)).toBe(true);
      expect(metadata.regressionEvents!.length).toBe(1);
      expect(metadata.regressionEvents![0].testRunId).toBe(testRun4Id);
      expect(metadata.regressionEvents![0].executionId).toBe(testExec4Id);

      // Directly verify in PostgreSQL
      const rows = await sql`
        SELECT status, occurrence_count, fixed_at, fixed_in_run_id, metadata
        FROM findings
        WHERE id = ${regressed.id}
      `;
      expect(rows.length).toBe(1);
      const row = rows[0];
      expect(row.status).toBe('regressed');
      expect(row.occurrence_count).toBe(3);
      expect(row.fixed_at).toBeNull();
      expect(row.fixed_in_run_id).toBeNull();
      expect(row.metadata.regressionEvents.length).toBe(1);
    });

    it('preserves analyst triage decision (false_positive) across recurring scan detections', async () => {
      const { sql } = getDatabase();

      // 1. Initial finding detected in testRun1
      const initial = await findingsService.saveFinding({
        tenantId: testTenantId,
        targetId: testTargetId,
        testRunId: testRun1Id,
        executionId: testExec1Id,
        testDefinitionId: 'zap-baseline',
        fingerprint: xssFingerprint,
        title: 'Reflected XSS in Search Query',
        category: 'xss',
        severity: 'medium',
        description: 'User input reflected without sanitization in HTML body',
      });
      expect(initial.status).toBe('open');

      // 2. Security analyst reviews and marks finding as false_positive
      const triaged = await findingsService.updateFindingStatus(
        initial.id,
        'false_positive',
        'Verified sanitized by upstream edge proxy and React JSX escaping',
        testTenantId,
      );
      expect(triaged?.status).toBe('false_positive');

      // 3. Subsequent scan run (testRun2) re-detects the same vulnerability fingerprint
      const recurring = await findingsService.saveFinding({
        tenantId: testTenantId,
        targetId: testTargetId,
        testRunId: testRun2Id,
        executionId: testExec2Id,
        testDefinitionId: 'zap-baseline',
        fingerprint: xssFingerprint,
        title: 'Reflected XSS in Search Query',
        category: 'xss',
        severity: 'medium',
        description: 'User input reflected without sanitization in HTML body',
      });

      // Triaged status must be preserved, but occurrenceCount increments
      expect(recurring.status).toBe('false_positive');
      expect(recurring.occurrenceCount).toBe(2);

      // Directly verify in PostgreSQL
      const rows = await sql`
        SELECT status, occurrence_count, metadata
        FROM findings
        WHERE id = ${initial.id}
      `;
      expect(rows.length).toBe(1);
      expect(rows[0].status).toBe('false_positive');
      expect(rows[0].occurrence_count).toBe(2);
      expect(rows[0].metadata.statusUpdatedNotes).toContain('upstream edge proxy');
    });

    it('enforces tenant isolation and prevents cross-tenant finding access or leakage', async () => {
      const otherTenantId = crypto.randomUUID();
      const { sql } = getDatabase();

      await sql`
        INSERT INTO tenants (id, name, slug)
        VALUES (${otherTenantId}, 'Other Tenant Ltd', ${'other-tenant-' + otherTenantId})
        ON CONFLICT (id) DO NOTHING;
      `;

      try {
        // Query findings with other tenant ID should return zero findings
        const otherFindings = await findingsService.listFindings({ tenantId: otherTenantId });
        expect(otherFindings.length).toBe(0);

        // Attempting to retrieve test tenant finding with other tenant ID returns null
        const testFindingId = (await sql`SELECT id FROM findings WHERE tenant_id = ${testTenantId} LIMIT 1`)[0]?.id;
        expect(testFindingId).toBeDefined();
        const candidate = await findingsService.getFindingById(testFindingId, otherTenantId);
        expect(candidate).toBeNull();
      } finally {
        await sql`DELETE FROM tenants WHERE id = ${otherTenantId}`;
      }
    });
  });

  // ---------------------------------------------------------------------------
  // 4. Migration 0004 DDL Integrity Verification
  // ---------------------------------------------------------------------------
  describe('Migration 0004 Schema & DDL Verification', () => {
    it('verifies SQL migration 0004 defines all required tables and constraints', async () => {
      const fs = await import('node:fs');
      const path = await import('node:path');
      const rootDir = fs.existsSync(path.resolve(process.cwd(), 'infrastructure'))
        ? process.cwd()
        : path.resolve(process.cwd(), '../..');
      const migrationPath = path.resolve(
        rootDir,
        'infrastructure/postgres/migrations/0004_finding_lifecycle_and_artifacts.sql',
      );

      expect(fs.existsSync(migrationPath)).toBe(true);
      const sqlContent = fs.readFileSync(migrationPath, 'utf-8');

      // Assert table creations
      expect(sqlContent).toContain('CREATE TABLE IF NOT EXISTS test_definitions');
      expect(sqlContent).toContain('CREATE TABLE IF NOT EXISTS reports');
      expect(sqlContent).toContain('CREATE TABLE IF NOT EXISTS artifacts');
      expect(sqlContent).toContain('CREATE TABLE IF NOT EXISTS identity_profiles');
      expect(sqlContent).toContain('CREATE TABLE IF NOT EXISTS credentials');

      // Assert column additions
      expect(sqlContent).toContain('occurrence_count INTEGER NOT NULL DEFAULT 1');
      expect(sqlContent).toContain('fixed_in_run_id UUID');

      // Assert indexes
      expect(sqlContent).toContain('CREATE INDEX IF NOT EXISTS idx_findings_status');
      expect(sqlContent).toContain('CREATE INDEX IF NOT EXISTS idx_findings_fixed_in_run_id');
      expect(sqlContent).toContain('CREATE INDEX IF NOT EXISTS idx_findings_target_fingerprint');

      // Assert Evidence Immutability Trigger
      expect(sqlContent).toContain('CREATE OR REPLACE FUNCTION prevent_evidence_tamper()');
      expect(sqlContent).toContain('EVIDENCE_TAMPER_PROTECTION');
      expect(sqlContent).toContain('BEFORE UPDATE OR DELETE ON evidence_records');
    });
  });
});
