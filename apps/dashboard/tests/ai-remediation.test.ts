import { describe, it, expect } from 'vitest';
import {
  parseGitDiffString,
  getConfidenceTier,
  generateGitHubPrMarkdown,
  AiRemediationProposal,
  VerifyRemediationResult,
} from '../src/api/remediation.js';

describe('Phase UI-14: AI Remediation Studio, Side-by-Side Code Diff Editor & Patch Verification Loop', () => {
  const sampleDiff = `diff --git a/server/routes/users.js b/server/routes/users.js
index e69de29..d95f3ad 100644
--- a/server/routes/users.js
+++ b/server/routes/users.js
@@ -12,6 +12,9 @@ router.get('/search', async (req, res) => {
   const { q } = req.query;
-  const query = "SELECT * FROM users WHERE username = '" + q + "'";
-  const users = await db.raw(query);
+  // Parameterized query prevents SQL injection
+  const query = "SELECT * FROM users WHERE username = $1";
+  const users = await db.query(query, [q]);
   res.json({ users });
 });
`;

  describe('Unified Git Diff Parser Engine', () => {
    it('parses standard git diff into structured file path, hunks, additions, and deletions', () => {
      const parsed = parseGitDiffString(sampleDiff);

      expect(parsed.filePath).toBe('server/routes/users.js');
      expect(parsed.additions).toBe(3);
      expect(parsed.deletions).toBe(2);
      expect(parsed.hunks.length).toBe(1);

      const hunk = parsed.hunks[0];
      expect(hunk.header).toContain('@@ -12,6 +12,9 @@');
      expect(hunk.oldStart).toBe(12);
      expect(hunk.newStart).toBe(12);

      // Verify line types
      const addedLines = hunk.lines.filter((l) => l.type === 'add');
      const deletedLines = hunk.lines.filter((l) => l.type === 'delete');
      const contextLines = hunk.lines.filter((l) => l.type === 'context');

      expect(addedLines.length).toBe(3);
      expect(deletedLines.length).toBe(2);
      expect(contextLines.length).toBeGreaterThan(0);

      // Verify addition content
      expect(addedLines[0].content).toContain('Parameterized query prevents SQL injection');
      expect(addedLines[1].content).toContain('SELECT * FROM users WHERE username = $1');

      // Verify line numbering increments
      expect(addedLines[0].newLineNumber).toBe(13);
      expect(deletedLines[0].oldLineNumber).toBe(13);
    });

    it('handles multi-hunk diffs accurately', () => {
      const multiHunkDiff = `diff --git a/app.js b/app.js
@@ -5,3 +5,4 @@ import express from 'express';
+import helmet from 'helmet';
 const app = express();
@@ -20,2 +21,3 @@ app.use(express.json());
+app.use(helmet());
 app.listen(3000);
`;

      const parsed = parseGitDiffString(multiHunkDiff);
      expect(parsed.filePath).toBe('app.js');
      expect(parsed.hunks.length).toBe(2);
      expect(parsed.additions).toBe(2);
      expect(parsed.deletions).toBe(0);
    });

    it('handles empty and null raw diff strings gracefully', () => {
      const emptyParsed = parseGitDiffString('');
      expect(emptyParsed.hunks).toEqual([]);
      expect(emptyParsed.additions).toBe(0);
      expect(emptyParsed.deletions).toBe(0);

      const whitespaceParsed = parseGitDiffString('   \n  ');
      expect(whitespaceParsed.hunks).toEqual([]);
    });

    it('parses diffs without standard git headers by generating fallback hunk', () => {
      const rawLines = `+const safe = escape(input);\n-const unsafe = input;\n const unchanged = true;`;
      const parsed = parseGitDiffString(rawLines);

      expect(parsed.hunks.length).toBe(1);
      expect(parsed.additions).toBe(1);
      expect(parsed.deletions).toBe(1);
    });
  });

  describe('Confidence Scoring Classification', () => {
    it('classifies confidence scores >= 0.85 as High tier', () => {
      const highTier = getConfidenceTier(0.92);
      expect(highTier.tier).toBe('High');
      expect(highTier.color).toContain('emerald');
      expect(highTier.description).toContain('Deterministic rule');
    });

    it('classifies confidence scores between 0.60 and 0.84 as Medium tier', () => {
      const medTier = getConfidenceTier(0.74);
      expect(medTier.tier).toBe('Medium');
      expect(medTier.color).toContain('amber');
      expect(medTier.description).toContain('Medium Confidence');
    });

    it('classifies confidence scores < 0.60 as Speculative tier', () => {
      const specTier = getConfidenceTier(0.45);
      expect(specTier.tier).toBe('Speculative');
      expect(specTier.color).toContain('rose');
      expect(specTier.description).toContain('Speculative');
    });
  });

  describe('GitHub Pull Request Draft Generator', () => {
    const finding = {
      title: 'SQL Injection in User Search Parameter',
      category: 'injection',
      severity: 'critical',
      fingerprint: 'fp-sql-inj-01',
    };

    const proposal: AiRemediationProposal = {
      id: 'e3b0c442-98fc-1c14-9afb-f4c8996fb924',
      findingId: '11111111-2222-3333-4444-555555555555',
      explanation: 'The parameter "q" was concatenated directly into raw SQL string without escaping.',
      gitDiff: sampleDiff,
      confidenceScore: 0.95,
      verifiedStatus: 'PASSED',
      model: 'Claude 3.5 Sonnet',
      createdAt: '2026-10-15T00:00:00Z',
    };

    it('generates standardized PR title and body with finding metadata and explanation', () => {
      const pr = generateGitHubPrMarkdown(finding, proposal);

      expect(pr.title).toBe('fix(security): remediate SQL Injection in User Search Parameter [CRITICAL]');
      expect(pr.body).toContain('SQL Injection in User Search Parameter');
      expect(pr.body).toContain('`injection`');
      expect(pr.body).toContain('CRITICAL');
      expect(pr.body).toContain('`fp-sql-inj-01`');
      expect(pr.body).toContain('concatenated directly into raw SQL string');
      expect(pr.body).toContain('```diff');
      expect(pr.body).toContain('Claude 3.5 Sonnet');
    });

    it('includes verified passed badge in PR description when verification succeeded', () => {
      const verification: VerifyRemediationResult = {
        remediationId: proposal.id,
        findingId: proposal.findingId,
        verifiedStatus: 'PASSED',
        retestSuccess: true,
        verificationDetails: 'Retest probe confirmed parameter "q" sanitized.',
        durationMs: 340,
        verifiedAt: '2026-10-15T00:00:00Z',
      };

      const pr = generateGitHubPrMarkdown(finding, proposal, verification);
      expect(pr.body).toContain('✅ **VERIFIED PASSED**');
      expect(pr.body).toContain('**Retest Duration**: `340ms`');
    });

    it('includes warning in PR description when verification failed', () => {
      const verification: VerifyRemediationResult = {
        remediationId: proposal.id,
        findingId: proposal.findingId,
        verifiedStatus: 'FAILED',
        retestSuccess: false,
        verificationDetails: 'Exploit probe still triggered SQL syntax error.',
        durationMs: 410,
        verifiedAt: '2026-10-15T00:00:00Z',
      };

      const pr = generateGitHubPrMarkdown(finding, proposal, verification);
      expect(pr.body).toContain('⚠️ **VERIFICATION FAILED**');
    });
  });
});
