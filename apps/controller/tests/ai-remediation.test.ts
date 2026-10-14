import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../src/app/index.js';
import { closeDatabase, getDatabase } from '../src/services/db.js';
import {
  remediationPromptBuilder,
  sanitizeHeaders,
  sanitizeText,
} from '../src/services/ai/prompt-builder.js';
import {
  llmClient,
  extractGitDiff,
  extractExplanation,
} from '../src/services/ai/client.js';
import {
  remediationVerifier,
  validateGitDiff,
} from '../src/services/ai/remediation-verifier.js';
import { remediationService } from '../src/services/ai/remediation.service.js';
import { findingsService, computeHardenedFindingFingerprint } from '../src/services/findings.service.js';
import { targetsService } from '../src/services/targets.service.js';
import { projectsService } from '../src/services/projects.service.js';
import { signJwt, DEFAULT_WORKSPACE_ID } from '../src/services/auth-token.service.js';
import { telemetryRegistry } from '../src/telemetry.js';

describe('Phase 20: AI-Assisted Security Analysis & Remediation', () => {
  let app: FastifyInstance;
  let tokenEngineer: string;
  let tokenAuditor: string;
  let testFindingId: string;
  let testTargetId: string;
  let testProjectId: string;

  beforeAll(async () => {
    app = buildApp({
      disableLogging: true,
      enableReaper: false,
      bypassAuth: false,
    });
    await app.ready();

    tokenEngineer = signJwt({
      userId: 'eng-01',
      workspaceId: DEFAULT_WORKSPACE_ID,
      role: 'engineer',
    });

    tokenAuditor = signJwt({
      userId: 'aud-01',
      workspaceId: DEFAULT_WORKSPACE_ID,
      role: 'auditor',
    });

    // 1. Create Project
    const project = await projectsService.createProject(
      {
        name: `AI Remediation Test Project ${crypto.randomBytes(4).toString('hex')}`,
        description: 'Test project for AI remediation and patch verification',
      },
      DEFAULT_WORKSPACE_ID,
    );
    testProjectId = project.id;

    // 2. Create Target
    const target = await targetsService.createTarget(
      {
        projectId: testProjectId,
        name: 'Vulnerable Web Service',
        baseUrl: 'http://127.0.0.1:8080',
        environment: 'staging',
        allowedHosts: ['127.0.0.1', 'localhost'],
        allowedPorts: [8080],
        excludedPaths: [],
        testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
      },
      DEFAULT_WORKSPACE_ID,
    );
    testTargetId = target.id;

    // 3. Create test_runs and test_executions to satisfy foreign keys
    const { sql } = getDatabase();
    const [tr] = await sql<{ id: string }[]>`
      INSERT INTO test_runs (project_id, target_id, profile_id, status)
      VALUES (${testProjectId}, ${testTargetId}, 'baseline', 'completed')
      RETURNING id
    `;
    const testRunId = tr.id;

    const [te] = await sql<{ id: string }[]>`
      INSERT INTO test_executions (test_run_id, engine_id, status)
      VALUES (${testRunId}, 'engine-native-cors', 'completed')
      RETURNING id
    `;
    const testExecId = te.id;

    // 4. Save sample security finding (CORS Misconfiguration)
    const fingerprint = computeHardenedFindingFingerprint({
      targetId: testTargetId,
      engineId: 'engine-native-cors',
      category: 'cors',
      ruleOrCweId: 'CWE-942',
      endpointPath: '/api/v1/profile',
    });

    const savedFinding = await findingsService.saveFinding({
      tenantId: DEFAULT_WORKSPACE_ID,
      fingerprint,
      title: 'Permissive Cross-Origin Resource Sharing (CORS) Policy',
      category: 'cors',
      severity: 'high',
      description:
        'The server reflects arbitrary Origin headers with Access-Control-Allow-Credentials: true, exposing user data.',
      testDefinitionId: 'engine-native-cors',
      testRunId,
      executionId: testExecId,
      targetId: testTargetId,
      metadata: {
        location: '/api/v1/profile',
        endpoint: '/api/v1/profile',
        cwe: 'CWE-942',
        ruleId: 'engine-native-cors',
        evidence: {
          request: {
            method: 'GET',
            url: 'http://127.0.0.1:8080/api/v1/profile',
            headers: {
              Origin: 'https://evil-attacker.com',
              Authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisToken',
              Cookie: 'session_id=secret-session-token-999; token=super-secret',
            },
          },
          response: {
            statusCode: 200,
            headers: {
              'Access-Control-Allow-Origin': 'https://evil-attacker.com',
              'Access-Control-Allow-Credentials': 'true',
            },
            body: '{"userId": "123", "email": "user@example.com"}',
          },
        },
      },
    });

    testFindingId = savedFinding.id;
  });

  afterAll(async () => {
    await app.close();
    await closeDatabase();
  });

  // ===========================================================================
  // 1. Contextual Prompt Builder & Secret Sanitization
  // ===========================================================================
  describe('Contextual Prompt Builder & Secret Sanitization', () => {
    it('sanitizes sensitive tokens, passwords, and JWTs from arbitrary text', () => {
      const dirty = 'User password is "password": "superSecret123" and JWT is eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature';
      const clean = sanitizeText(dirty);

      expect(clean).not.toContain('superSecret123');
      expect(clean).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
      expect(clean).toContain('[REDACTED_SECRET]');
    });

    it('redacts sensitive headers (Authorization, Cookie, X-Api-Key)', () => {
      const headers = {
        Authorization: 'Bearer secret-token-xyz',
        Cookie: 'session=abc1234',
        'X-Api-Key': 'sk-test-12345',
        'Content-Type': 'application/json',
        Host: '127.0.0.1',
      };

      const cleaned = sanitizeHeaders(headers);

      expect(cleaned.Authorization).toBe('[REDACTED]');
      expect(cleaned.Cookie).toBe('[REDACTED]');
      expect(cleaned['X-Api-Key']).toBe('[REDACTED]');
      expect(cleaned['Content-Type']).toBe('application/json');
      expect(cleaned.Host).toBe('127.0.0.1');
    });

    it('builds a structured prompt synthesizing finding metadata and HTTP evidence', async () => {
      const finding = await findingsService.getFindingById(testFindingId);
      expect(finding).toBeDefined();

      const built = remediationPromptBuilder.buildPrompt(finding!, null, {
        filePath: 'src/routes/profile.ts',
        sourceCodeSnippet: 'app.get("/api/v1/profile", (req, res) => res.json({ profile: true }));',
      });

      expect(built.systemPrompt).toContain('Principal Application Security Researcher');
      expect(built.systemPrompt).toContain('diff --git');
      expect(built.userPrompt).toContain(finding!.title);
      expect(built.userPrompt).toContain('src/routes/profile.ts');
      expect(built.userPrompt).toContain('### HTTP Request Evidence');
      expect(built.userPrompt).toContain('### HTTP Response Evidence');
      expect(built.userPrompt).not.toContain('doNotLeakThisToken');
      expect(built.userPrompt).not.toContain('secret-session-token-999');
      expect(built.sanitizedMetadata.redactedHeaderCount).toBeGreaterThanOrEqual(2);
      expect(built.sanitizedMetadata.hasSourceCode).toBe(true);
    });
  });

  // ===========================================================================
  // 2. Pluggable LLM Provider & Diff Parsing
  // ===========================================================================
  describe('Pluggable LLM Provider & Git Diff Extraction', () => {
    it('synthesizes context-aware remediation explanation and git diff for CORS', async () => {
      const finding = await findingsService.getFindingById(testFindingId);
      const prompt = remediationPromptBuilder.buildPrompt(finding!);

      const result = await llmClient.generateRemediation(prompt, { provider: 'mock' });

      expect(result.explanation).toContain('Root Cause Analysis');
      expect(result.explanation).toContain('CORS');
      expect(result.gitDiff).toContain('diff --git');
      expect(result.gitDiff).toContain('Access-Control-Allow-Origin');
      expect(result.confidenceScore).toBeGreaterThanOrEqual(0.85);
      expect(result.promptTokens).toBeGreaterThan(0);
      expect(result.completionTokens).toBeGreaterThan(0);
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });

    it('extracts and normalizes unified git diff blocks from LLM markdown', () => {
      const markdown = `
Here is the explanation of the fix.

\`\`\`diff
--- a/src/server.ts
+++ b/src/server.ts
@@ -1,3 +1,4 @@
-const x = 1;
+const x = 2;
\`\`\`

Hope this helps!
`;
      const diff = extractGitDiff(markdown, 'src/server.ts');
      expect(diff).toContain('diff --git a/src/server.ts b/src/server.ts');
      expect(diff).toContain('--- a/src/server.ts');
      expect(diff).toContain('+++ b/src/server.ts');
      expect(diff).toContain('+const x = 2;');
    });

    it('extracts explanation markdown stripping out code blocks', () => {
      const markdown = `### Root Cause\nThe service is vulnerable to SQL injection.\n\`\`\`diff\n- query\n+ paramQuery\n\`\`\`\nVerification passed.`;
      const explanation = extractExplanation(markdown);

      expect(explanation).toContain('### Root Cause');
      expect(explanation).toContain('Verification passed.');
      expect(explanation).not.toContain('```diff');
    });
  });

  // ===========================================================================
  // 3. Diff Syntax Validator
  // ===========================================================================
  describe('Git Diff Syntax Validator', () => {
    it('validates standard unified git diff structure with headers and hunks', () => {
      const validDiff = [
        'diff --git a/src/auth.ts b/src/auth.ts',
        '--- a/src/auth.ts',
        '+++ b/src/auth.ts',
        '@@ -10,4 +10,6 @@',
        ' const allowed = true;',
        '+if (!allowed) throw new Error("Forbidden");',
      ].join('\n');

      const result = validateGitDiff(validDiff);
      expect(result.valid).toBe(true);
      expect(result.files).toContain('src/auth.ts');
    });

    it('rejects malformed or empty git diffs', () => {
      expect(validateGitDiff('').valid).toBe(false);
      expect(validateGitDiff('just plain text explanation without diff headers').valid).toBe(false);
      expect(validateGitDiff('diff --git a/file.ts b/file.ts\n--- a/file.ts\n+++ b/file.ts').valid).toBe(false); // missing @@ hunk
    });
  });

  // ===========================================================================
  // 4. Remediation Service & Database Persistence
  // ===========================================================================
  describe('RemediationService Lifecycle & Database Persistence', () => {
    let createdRemediationId: string;

    it('generates and persists AI remediation proposal in database', async () => {
      const proposal = await remediationService.generateRemediation(
        testFindingId,
        {
          provider: 'mock',
          filePath: 'src/server.ts',
        },
        DEFAULT_WORKSPACE_ID,
      );

      expect(proposal.id).toBeDefined();
      expect(proposal.findingId).toBe(testFindingId);
      expect(proposal.explanation).toBeDefined();
      expect(proposal.gitDiff).toContain('diff --git');
      expect(proposal.verifiedStatus).toBe('UNVERIFIED');
      expect(proposal.confidenceScore).toBe(0.92);

      createdRemediationId = proposal.id;
    });

    it('retrieves existing remediation proposals for finding', async () => {
      const list = await remediationService.getRemediationsForFinding(testFindingId);
      expect(list.length).toBeGreaterThanOrEqual(1);
      expect(list[0]!.id).toBe(createdRemediationId);
    });

    it('retrieves remediation proposal by ID', async () => {
      const item = await remediationService.getRemediationById(createdRemediationId);
      expect(item).not.toBeNull();
      expect(item!.id).toBe(createdRemediationId);
      expect(item!.verifiedStatus).toBe('UNVERIFIED');
    });
  });

  // ===========================================================================
  // 5. Automated Patch Verification Loop
  // ===========================================================================
  describe('Automated Patch Verification Loop', () => {
    it('executes patch verification and updates status to PASSED on successful retest', async () => {
      const proposal = await remediationService.generateRemediation(
        testFindingId,
        { provider: 'mock' },
        DEFAULT_WORKSPACE_ID,
      );

      // Execute simulated verification
      const verifyResult = await remediationVerifier.verifyPatch(proposal.id, {
        simulateSuccess: true,
      });

      expect(verifyResult.verifiedStatus).toBe('PASSED');
      expect(verifyResult.retestSuccess).toBe(true);
      expect(verifyResult.verificationDetails).toContain('passed');
      expect(verifyResult.durationMs).toBeGreaterThanOrEqual(0);

      // Verify DB record was updated
      const updated = await remediationService.getRemediationById(proposal.id);
      expect(updated?.verifiedStatus).toBe('PASSED');
      expect(updated?.verificationOutput).toContain('passed');

      // Verify finding metadata was decorated
      const finding = await findingsService.getFindingById(testFindingId);
      expect((finding?.metadata as Record<string, unknown>)?.aiRemediationVerified).toBe(true);
    });

    it('marks remediation as FAILED if git diff syntax is invalid', async () => {
      const { db } = getDatabase();
      const proposal = await remediationService.generateRemediation(
        testFindingId,
        { provider: 'mock' },
        DEFAULT_WORKSPACE_ID,
      );

      // Intentionally corrupt git diff in DB
      const { aiRemediations } = await import('../src/services/db/schema.js');
      const { eq } = await import('drizzle-orm');
      await db
        .update(aiRemediations)
        .set({ gitDiff: 'corrupted non-diff text' })
        .where(eq(aiRemediations.id, proposal.id));

      const verifyResult = await remediationVerifier.verifyPatch(proposal.id);

      expect(verifyResult.verifiedStatus).toBe('FAILED');
      expect(verifyResult.retestSuccess).toBe(false);
      expect(verifyResult.verificationDetails).toContain('Git diff validation failed');

      const updated = await remediationService.getRemediationById(proposal.id);
      expect(updated?.verifiedStatus).toBe('FAILED');
    });
  });

  // ===========================================================================
  // 6. Fastify Controller REST API Endpoints
  // ===========================================================================
  describe('Fastify Controller REST API Routes', () => {
    it('POST /api/v1/findings/:id/remediate synthesizes proposal for engineer', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/findings/${testFindingId}/remediate`,
        headers: {
          authorization: `Bearer ${tokenEngineer}`,
        },
        payload: {
          provider: 'mock',
          filePath: 'src/app.ts',
        },
      });

      expect(res.statusCode).toBe(201);
      const json = JSON.parse(res.body);
      expect(json.success).toBe(true);
      expect(json.data.id).toBeDefined();
      expect(json.data.findingId).toBe(testFindingId);
      expect(json.data.gitDiff).toContain('diff --git');
    });

    it('GET /api/v1/findings/:id/remediation returns list of proposals', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/findings/${testFindingId}/remediation`,
        headers: {
          authorization: `Bearer ${tokenAuditor}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const json = JSON.parse(res.body);
      expect(json.success).toBe(true);
      expect(Array.isArray(json.data)).toBe(true);
      expect(json.data.length).toBeGreaterThan(0);
    });

    it('GET /api/v1/remediations/:id returns single proposal', async () => {
      const list = await remediationService.getRemediationsForFinding(testFindingId);
      const targetId = list[0]!.id;

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/remediations/${targetId}`,
        headers: {
          authorization: `Bearer ${tokenAuditor}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const json = JSON.parse(res.body);
      expect(json.data.id).toBe(targetId);
    });

    it('POST /api/v1/findings/:id/remediation/verify triggers automated verification', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/findings/${testFindingId}/remediation/verify`,
        headers: {
          authorization: `Bearer ${tokenEngineer}`,
        },
        payload: {
          timeoutMs: 5000,
        },
      });

      expect(res.statusCode).toBe(200);
      const json = JSON.parse(res.body);
      expect(json.success).toBe(true);
      expect(json.data.verifiedStatus).toBeDefined();
      expect(['PASSED', 'FAILED']).toContain(json.data.verifiedStatus);
    });

    it('POST /api/v1/findings/:id/remediate rejects auditor role with 403', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/findings/${testFindingId}/remediate`,
        headers: {
          authorization: `Bearer ${tokenAuditor}`,
        },
        payload: {},
      });

      expect(res.statusCode).toBe(403);
    });
  });

  // ===========================================================================
  // 7. Telemetry & Prometheus Observability
  // ===========================================================================
  describe('Telemetry & Prometheus Observability', () => {
    it('exports AI remediation metrics in Prometheus format', () => {
      const metrics = telemetryRegistry.exportPrometheus();

      expect(metrics).toContain('# HELP security_lab_ai_remediations_total');
      expect(metrics).toContain('# TYPE security_lab_ai_remediations_total counter');
      expect(metrics).toContain('security_lab_ai_remediations_total');

      expect(metrics).toContain('# HELP security_lab_ai_remediations_verified_total');
      expect(metrics).toContain('# TYPE security_lab_ai_remediations_verified_total counter');
      expect(metrics).toContain('security_lab_ai_remediations_verified_total{status="passed"}');
      expect(metrics).toContain('security_lab_ai_remediations_verified_total{status="failed"}');
    });
  });
});
