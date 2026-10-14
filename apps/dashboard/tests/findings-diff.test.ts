import { describe, it, expect } from 'vitest';
import {
  FindingItem,
  EvidenceRecord,
  calculateRunOverRunDiff,
  generateCanonicalHexDump,
  reconstructRawWireFrame,
  calculateWaiverCountdown,
  generateCurlSnippet,
} from '../src/api/findings.js';

describe('Phase UI-13: Forensic Evidence Wire Inspector, Run-over-Run Diffing & Vulnerability Flapping Console', () => {
  // Sample Findings fixtures
  const baselineFindings: FindingItem[] = [
    {
      id: 'f-baseline-01',
      fingerprint: 'fp-sql-injection-user-id',
      title: 'SQL Injection in User Search Parameter',
      category: 'injection',
      severity: 'critical',
      status: 'open',
      description: 'Blind Boolean-based SQL injection detected via parameter "q"',
      testDefinitionId: 'engine-sql-fuzz',
      testRunId: 'run-42',
      targetId: 'tgt-api-gateway',
      firstDetectedAt: '2026-10-10T10:00:00.000Z',
    },
    {
      id: 'f-baseline-02',
      fingerprint: 'fp-nosniff-header-missing',
      title: 'Missing X-Content-Type-Options Header',
      category: 'headers',
      severity: 'low',
      status: 'open',
      description: 'The response does not specify X-Content-Type-Options: nosniff',
      testDefinitionId: 'engine-native-declarative',
      testRunId: 'run-42',
      targetId: 'tgt-api-gateway',
      firstDetectedAt: '2026-10-10T10:00:00.000Z',
    },
    {
      id: 'f-baseline-03',
      fingerprint: 'fp-flapping-race-condition',
      title: 'Race Condition in Coupon Voucher Redemption',
      category: 'business-logic',
      severity: 'high',
      status: 'open',
      description: 'Oscillating race condition detected under concurrency stress',
      testDefinitionId: 'engine-concurrency-fuzz',
      testRunId: 'run-42',
      targetId: 'tgt-api-gateway',
      firstDetectedAt: '2026-10-10T10:00:00.000Z',
      isFlapping: true,
      flappingScore: 0.65,
    },
  ];

  const targetFindings: FindingItem[] = [
    // Persistent: fp-sql-injection-user-id still open
    {
      id: 'f-target-01',
      fingerprint: 'fp-sql-injection-user-id',
      title: 'SQL Injection in User Search Parameter',
      category: 'injection',
      severity: 'critical',
      status: 'open',
      description: 'Blind Boolean-based SQL injection detected via parameter "q"',
      testDefinitionId: 'engine-sql-fuzz',
      testRunId: 'run-48',
      targetId: 'tgt-api-gateway',
      firstDetectedAt: '2026-10-10T10:00:00.000Z',
    },
    // New: GraphQL circular depth vulnerability introduced in build 48
    {
      id: 'f-target-02',
      fingerprint: 'fp-graphql-circular-query-dos',
      title: 'Circular Query Depth Denial of Service',
      category: 'graphql',
      severity: 'high',
      status: 'open',
      description: 'GraphQL engine accepts recursion depth of 25 layers without truncation',
      testDefinitionId: 'engine-graphql-inspector',
      testRunId: 'run-48',
      targetId: 'tgt-api-gateway',
      firstDetectedAt: '2026-10-14T18:00:00.000Z',
    },
    // Flapping: still oscillating
    {
      id: 'f-target-03',
      fingerprint: 'fp-flapping-race-condition',
      title: 'Race Condition in Coupon Voucher Redemption',
      category: 'business-logic',
      severity: 'high',
      status: 'reopened',
      description: 'Oscillating race condition detected under concurrency stress',
      testDefinitionId: 'engine-concurrency-fuzz',
      testRunId: 'run-48',
      targetId: 'tgt-api-gateway',
      firstDetectedAt: '2026-10-10T10:00:00.000Z',
      isFlapping: true,
      flappingScore: 0.7,
    },
    // Notice: fp-nosniff-header-missing is absent in targetFindings => resolved!
  ];

  describe('Run-over-Run Diff Calculation Engine', () => {
    it('accurately categorizes New, Resolved, Persistent, and Flapping findings', () => {
      const diff = calculateRunOverRunDiff(baselineFindings, targetFindings, 'run-42', 'run-48');

      expect(diff.baseRunId).toBe('run-42');
      expect(diff.targetRunId).toBe('run-48');

      // 1. New Vulnerabilities
      expect(diff.summary.newCount).toBe(1);
      expect(diff.categories.newVulnerabilities[0].fingerprint).toBe('fp-graphql-circular-query-dos');
      expect(diff.categories.newVulnerabilities[0].diffCategory).toBe('new');

      // 2. Resolved Findings (fp-nosniff-header-missing was in base but absent in target)
      expect(diff.summary.resolvedCount).toBe(1);
      expect(diff.categories.resolvedFindings[0].fingerprint).toBe('fp-nosniff-header-missing');
      expect(diff.categories.resolvedFindings[0].diffCategory).toBe('resolved');

      // 3. Persistent Issues (fp-sql-injection-user-id present in both with active state)
      expect(diff.summary.persistentCount).toBe(1);
      expect(diff.categories.persistentIssues[0].fingerprint).toBe('fp-sql-injection-user-id');
      expect(diff.categories.persistentIssues[0].diffCategory).toBe('persistent');

      // 4. Flapping Anomalies (fp-flapping-race-condition isFlapping = true)
      expect(diff.summary.flappingCount).toBe(1);
      expect(diff.categories.flappingAnomalies[0].fingerprint).toBe('fp-flapping-race-condition');
      expect(diff.categories.flappingAnomalies[0].diffCategory).toBe('flapping');

      // Total differences = New + Resolved + Flapping
      expect(diff.summary.totalDifferences).toBe(3);
    });

    it('handles clean runs with zero regressions and zero differences', () => {
      const emptyBase: FindingItem[] = [];
      const emptyTarget: FindingItem[] = [];
      const cleanDiff = calculateRunOverRunDiff(emptyBase, emptyTarget, 'run-10', 'run-11');

      expect(cleanDiff.summary.newCount).toBe(0);
      expect(cleanDiff.summary.resolvedCount).toBe(0);
      expect(cleanDiff.summary.persistentCount).toBe(0);
      expect(cleanDiff.summary.flappingCount).toBe(0);
      expect(cleanDiff.summary.totalDifferences).toBe(0);
    });

    it('handles scenario where all findings in target run are new', () => {
      const diff = calculateRunOverRunDiff([], targetFindings, 'empty-base', 'run-48');

      // 2 new (one is flapping)
      expect(diff.summary.resolvedCount).toBe(0);
      expect(diff.summary.persistentCount).toBe(0);
      expect(diff.categories.newVulnerabilities.length).toBe(2);
      expect(diff.categories.flappingAnomalies.length).toBe(1);
    });

    it('recognizes findings with status=resolved in target run as resolved', () => {
      const base: FindingItem[] = [
        {
          id: 'f-1',
          fingerprint: 'fp-vuln-1',
          title: 'Vuln 1',
          category: 'auth',
          severity: 'high',
          status: 'open',
          description: 'Auth bypass',
          testDefinitionId: 'engine-auth',
          testRunId: 'run-1',
          targetId: 'tgt-1',
          firstDetectedAt: '2026-10-10T00:00:00Z',
        },
      ];

      const target: FindingItem[] = [
        {
          ...base[0],
          id: 'f-2',
          testRunId: 'run-2',
          status: 'resolved',
        },
      ];

      const diff = calculateRunOverRunDiff(base, target, 'run-1', 'run-2');
      expect(diff.summary.resolvedCount).toBe(1);
      expect(diff.summary.newCount).toBe(0);
      expect(diff.categories.resolvedFindings[0].diffCategory).toBe('resolved');
    });
  });

  describe('Canonical Hex Dump Generator', () => {
    it('formats string into 16-byte aligned lines with 8-character hex offsets', () => {
      const input = 'POST /api/v1/auth HTTP/1.1\r\nHost: api.sec.local\r\n';
      const hexDump = generateCanonicalHexDump(input);

      const lines = hexDump.split('\n');
      expect(lines.length).toBeGreaterThan(1);

      // Verify offset format: "00000000: "
      expect(lines[0]).toMatch(/^00000000: [0-9a-f]{2} /);

      // Verify second line offset: "00000010: "
      expect(lines[1]).toMatch(/^00000010: [0-9a-f]{2} /);

      // Verify ASCII section enclosed in pipes
      expect(lines[0]).toMatch(/\|.*\|$/);
      expect(lines[0]).toContain('POST');
    });

    it('handles empty and null inputs safely', () => {
      expect(generateCanonicalHexDump('')).toContain('(Empty Wire Buffer)');
      expect(generateCanonicalHexDump(null)).toContain('(Empty Wire Buffer)');
      expect(generateCanonicalHexDump(undefined)).toContain('(Empty Wire Buffer)');
    });

    it('replaces non-printable control characters with dots in ASCII preview', () => {
      const bufferWithControls = String.fromCharCode(0, 1, 2, 3, 4, 32, 65, 66); // NUL, SOH, ..., space, 'A', 'B'
      const dump = generateCanonicalHexDump(bufferWithControls);

      expect(dump).toContain('|..... AB|');
    });
  });

  describe('Raw Wire Socket Frame Reconstructor', () => {
    it('preserves exact CRLF protocol delimiters for request and response frames', () => {
      const sampleEvidence: EvidenceRecord = {
        id: 'ev-test-101',
        testRunId: 'run-48',
        request: {
          method: 'POST',
          url: 'https://gateway.sec.internal/api/v1/users',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer secret-token-xyz',
          },
          body: '{"username":"admin"}',
        },
        response: {
          statusCode: 201,
          headers: {
            'Content-Type': 'application/json',
            'X-Request-Id': 'req-98765',
          },
          body: '{"id":"usr-001","status":"created"}',
          responseTimeMs: 34,
        },
        immutableHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        timestamp: '2026-10-15T00:00:00Z',
      };

      const raw = reconstructRawWireFrame(sampleEvidence);

      // Verify CRLF present
      expect(raw).toContain('\r\n');
      expect(raw).toContain('POST /api/v1/users HTTP/1.1\r\n');
      expect(raw).toContain('Host: gateway.sec.internal\r\n');
      expect(raw).toContain('Content-Type: application/json\r\n');
      expect(raw).toContain('HTTP/1.1 201 Created\r\n');
      expect(raw).toContain('X-Request-Id: req-98765\r\n');
      expect(raw).toContain('{"username":"admin"}');
    });

    it('handles evidence with missing request or response gracefully', () => {
      expect(reconstructRawWireFrame(null)).toContain('No raw wire frame');
      expect(reconstructRawWireFrame({
        id: 'ev-empty',
        testRunId: 'run-empty',
        immutableHash: 'abc',
        timestamp: '2026-10-15T00:00:00Z',
      })).toContain('No HTTP socket frame available');
    });
  });

  describe('cURL Reproduction Generator', () => {
    it('generates multiline Bash cURL command with proper header and body escaping', () => {
      const curl = generateCurlSnippet({
        method: 'PUT',
        url: 'https://target.local/api/items/42',
        headers: {
          'Authorization': 'Bearer test-token',
          'X-Custom-Header': "O'Reilly",
        },
        body: '{"name":"gadget"}',
      });

      expect(curl).toContain("curl -i -X PUT 'https://target.local/api/items/42'");
      expect(curl).toContain("-H 'Authorization: Bearer test-token'");
      // Verify single quote escaping in header
      expect(curl).toContain("-H 'X-Custom-Header: O'\\''Reilly'");
      expect(curl).toContain("--data-raw '{\"name\":\"gadget\"}'");
    });
  });

  describe('SLA Timed Policy Waiver & Countdown Math', () => {
    it('computes days and hours accurately for active future waiver', () => {
      const futureDate = new Date(Date.now() + 30 * 86400000 + 4 * 3600000).toISOString();
      const countdown = calculateWaiverCountdown(futureDate);

      expect(countdown.isExpired).toBe(false);
      expect(countdown.days).toBe(30);
      expect(countdown.hours).toBeGreaterThanOrEqual(3);
      expect(countdown.label).toContain('30d');
      expect(countdown.label).toContain('left');
    });

    it('flags expired waivers correctly when timestamp is in past', () => {
      const pastDate = new Date(Date.now() - 100000).toISOString();
      const countdown = calculateWaiverCountdown(pastDate);

      expect(countdown.isExpired).toBe(true);
      expect(countdown.label).toBe('Waiver Expired');
    });

    it('handles null/undefined expiration gracefully', () => {
      const countdown = calculateWaiverCountdown(null);
      expect(countdown.isExpired).toBe(true);
      expect(countdown.label).toBe('No Waiver');
    });
  });
});
