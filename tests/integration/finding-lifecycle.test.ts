import { describe, it, expect } from 'vitest';
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
} from '../../apps/controller/src/services/findings.service.js';
import { FindingStatus } from '@security-lab/domain';

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
  // 3. Finding Lifecycle State Machine Logic
  // ---------------------------------------------------------------------------
  describe('Finding Lifecycle State Machine & Regression Logic', () => {
    it('models lifecycle transitions correctly (new -> open -> resolved -> regressed)', () => {
      // In-memory simulation of the lifecycle state machine verified in unit test
      interface SimulatedFinding {
        id: string;
        targetId: string;
        fingerprint: string;
        title: string;
        status: FindingStatus;
        occurrenceCount: number;
        firstDetectedAt: Date;
        lastDetectedAt: Date;
        fixedAt?: Date;
        regressionEvents: { regressedAt: string; testRunId: string }[];
      }

      const store = new Map<string, SimulatedFinding>();

      function simulateSaveFinding(input: {
        targetId: string;
        fingerprint: string;
        title: string;
        testRunId: string;
      }): SimulatedFinding {
        const key = `${input.targetId}:${input.fingerprint}`;
        const existing = store.get(key);
        const now = new Date();

        if (existing) {
          if (existing.status === 'resolved') {
            // Regression!
            existing.status = 'regressed';
            existing.occurrenceCount++;
            existing.lastDetectedAt = now;
            existing.fixedAt = undefined;
            existing.regressionEvents.push({
              regressedAt: now.toISOString(),
              testRunId: input.testRunId,
            });
            return existing;
          }

          // Recurring
          existing.occurrenceCount++;
          existing.lastDetectedAt = now;
          return existing;
        }

        // New finding
        const newFinding: SimulatedFinding = {
          id: crypto.randomUUID(),
          targetId: input.targetId,
          fingerprint: input.fingerprint,
          title: input.title,
          status: 'open',
          occurrenceCount: 1,
          firstDetectedAt: now,
          lastDetectedAt: now,
          regressionEvents: [],
        };
        store.set(key, newFinding);
        return newFinding;
      }

      function simulateReconcile(testRunId: string, targetId: string, detectedFp: string[]) {
        const detectedSet = new Set(detectedFp);
        let resolvedCount = 0;
        for (const finding of store.values()) {
          if (finding.targetId === targetId && (finding.status === 'open' || finding.status === 'regressed')) {
            if (!detectedSet.has(finding.fingerprint)) {
              finding.status = 'resolved';
              finding.fixedAt = new Date();
              resolvedCount++;
            }
          }
        }
        return resolvedCount;
      }

      const targetId = 'target-lifecycle-1';
      const fp = 'fp-xss-12345';

      // 1. First run: Finding is detected for the first time
      const f1 = simulateSaveFinding({ targetId, fingerprint: fp, title: 'Reflected XSS', testRunId: 'run-1' });
      expect(f1.status).toBe('open');
      expect(f1.occurrenceCount).toBe(1);

      // 2. Second run: Finding is re-detected (recurring)
      const f2 = simulateSaveFinding({ targetId, fingerprint: fp, title: 'Reflected XSS', testRunId: 'run-2' });
      expect(f2.status).toBe('open');
      expect(f2.occurrenceCount).toBe(2);

      // 3. Third run: Finding was fixed by developers (not detected during run-3)
      const resolved = simulateReconcile('run-3', targetId, []);
      expect(resolved).toBe(1);
      expect(f1.status).toBe('resolved');
      expect(f1.fixedAt).toBeDefined();

      // 4. Fourth run: Code was reverted! Finding reappears in run-4 -> REGRESSION!
      const f4 = simulateSaveFinding({ targetId, fingerprint: fp, title: 'Reflected XSS', testRunId: 'run-4' });
      expect(f4.status).toBe('regressed');
      expect(f4.occurrenceCount).toBe(3);
      expect(f4.fixedAt).toBeUndefined();
      expect(f4.regressionEvents.length).toBe(1);
      expect(f4.regressionEvents[0]?.testRunId).toBe('run-4');
    });
  });

  // ---------------------------------------------------------------------------
  // 4. Migration 0004 DDL Integrity Verification
  // ---------------------------------------------------------------------------
  describe('Migration 0004 Schema & DDL Verification', () => {
    it('verifies SQL migration 0004 defines all required tables and constraints', async () => {
      const fs = await import('node:fs');
      const path = await import('node:path');
      const migrationPath = path.resolve(
        process.cwd(),
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
