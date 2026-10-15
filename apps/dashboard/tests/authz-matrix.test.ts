import { describe, it, expect, vi } from 'vitest';
import {
  PRESET_MATRICES,
  generateMatrixMarkdown,
  formatGithubIssueBody,
  retestAuthzFinding,
  getAuthzMatrixDataset,
} from '../src/api/authz.js';

describe('Phase UI-08: Automated BOLA / BFLA Matrix & Privilege Escalation Visualizer', () => {
  describe('Preset Matrix Datasets & Schema Integrity', () => {
    it('provides multi-tenant financial SaaS dataset with complete persona and route topology', () => {
      const fin = PRESET_MATRICES.financialSaaS;
      expect(fin).toBeDefined();
      expect(fin.personas.length).toBeGreaterThanOrEqual(4);
      expect(fin.routes.length).toBeGreaterThanOrEqual(5);
      expect(fin.cells.length).toBe(fin.personas.length * fin.routes.length);
      expect(fin.isolationScore).toBe(68);

      // Verify personas contain Admin, Tenant Alpha, Tenant Beta, and Anonymous
      const personaIds = fin.personas.map((p) => p.id);
      expect(personaIds).toContain('admin');
      expect(personaIds).toContain('user_a');
      expect(personaIds).toContain('user_b');
      expect(personaIds).toContain('anon');
    });

    it('provides healthcare FHIR v4 dataset with HIPAA-critical clinical record routes', () => {
      const fhir = PRESET_MATRICES.healthcareFhir;
      expect(fhir).toBeDefined();
      expect(fhir.targetName).toContain('Clinical');
      expect(fhir.personas.some((p) => p.role === 'chief_medical_officer')).toBe(true);
      expect(fhir.routes.some((r) => r.path.includes('Patient'))).toBe(true);
      expect(fhir.crossTenantBreaches.length).toBeGreaterThan(0);
    });
  });

  describe('Authorization Matrix Cell Permutations & Violation Detection', () => {
    it('flags BOLA / IDOR when Tenant Beta queries Tenant Alpha private invoice', () => {
      const fin = PRESET_MATRICES.financialSaaS;
      const bolaCell = fin.cells.find(
        (c) => c.endpoint === '/api/v1/invoices/:id' && c.personaId === 'user_b',
      );

      expect(bolaCell).toBeDefined();
      expect(bolaCell?.status).toBe('VIOLATION_BOLA');
      expect(bolaCell?.httpStatus).toBe(200);
      expect(bolaCell?.expectedStatus).toContain(403);
      expect(bolaCell?.violationType).toBe('BOLA_HORIZONTAL_IDOR');
      expect(bolaCell?.findingId).toBe('fnd-bola-inv-001');
    });

    it('flags BFLA vertical escalation when finance manager accesses admin audit logs', () => {
      const fin = PRESET_MATRICES.financialSaaS;
      const bflaCell = fin.cells.find(
        (c) => c.endpoint === '/api/v1/admin/audit-logs' && c.personaId === 'user_a',
      );

      expect(bflaCell).toBeDefined();
      expect(bflaCell?.status).toBe('VIOLATION_BFLA');
      expect(bflaCell?.httpStatus).toBe(200);
      expect(bflaCell?.expectedStatus).toContain(403);
      expect(bflaCell?.findingId).toBe('fnd-bfla-audit-003');
    });

    it('flags missing authentication when anonymous guest accesses revenue reporting', () => {
      const fin = PRESET_MATRICES.financialSaaS;
      const noAuthCell = fin.cells.find(
        (c) => c.endpoint === '/api/v1/reports/revenue-metrics' && c.personaId === 'anon',
      );

      expect(noAuthCell).toBeDefined();
      expect(noAuthCell?.status).toBe('VIOLATION_MISSING_AUTH');
      expect(noAuthCell?.httpStatus).toBe(200);
      expect(noAuthCell?.expectedStatus).toContain(401);
    });

    it('correctly marks legitimate access as ALLOWED and legitimate denial as DENIED', () => {
      const fin = PRESET_MATRICES.financialSaaS;
      // Admin on audit logs -> ALLOWED
      const adminCell = fin.cells.find(
        (c) => c.endpoint === '/api/v1/admin/audit-logs' && c.personaId === 'admin',
      );
      expect(adminCell?.status).toBe('ALLOWED');
      expect(adminCell?.httpStatus).toBe(200);

      // User A on delete tenant -> DENIED
      const deniedCell = fin.cells.find(
        (c) => c.endpoint === '/api/v1/admin/tenants/:id' && c.personaId === 'user_a',
      );
      expect(deniedCell?.status).toBe('DENIED');
      expect(deniedCell?.httpStatus).toBe(403);
    });
  });

  describe('Cross-Tenant Perimeter & Isolation Tracking', () => {
    it('identifies cross-tenant data leaks and connects source to victim tenant', () => {
      const fin = PRESET_MATRICES.financialSaaS;
      expect(fin.crossTenantBreaches.length).toBeGreaterThan(0);

      const breach = fin.crossTenantBreaches[0];
      expect(breach.sourceTenant).toBe('tenant-beta');
      expect(breach.targetTenant).toBe('tenant-alpha');
      expect(breach.severity).toBe('CRITICAL');
      expect(breach.leakedDataPreview).toContain('INV-90241');
      expect(fin.evidenceMap[breach.findingId]).toBeDefined();
    });

    it('contains complete request and response evidence in evidenceMap', () => {
      const fin = PRESET_MATRICES.financialSaaS;
      const evidence = fin.evidenceMap['fnd-bola-inv-001'];
      expect(evidence).toBeDefined();
      expect(evidence.actualStatusCode).toBe(200);
      expect(evidence.expectedStatusCode).toBe(403);
      expect(evidence.curlCommand).toContain('curl -X GET');
      expect(evidence.leakedFields).toContain('iban');
      expect(evidence.remediation).toContain('tenant_id');
    });
  });

  describe('Reporting & Ticket Export Generators', () => {
    it('exports full permission matrix as Markdown table with symbols', () => {
      const fin = PRESET_MATRICES.financialSaaS;
      const md = generateMatrixMarkdown(fin);

      expect(md).toContain('# Authorization Permission Matrix:');
      expect(md).toContain('| Route & Method |');
      expect(md).toContain('🚨 **BOLA** (200)');
      expect(md).toContain('🚨 **BFLA** (200)');
      expect(md).toContain('🛡️ Denied (403)');
      expect(md).toContain('✅ Allowed (200)');
      expect(md).toContain('### Detected Cross-Tenant Isolation Breaches');
    });

    it('formats GitHub issue template with reproduction cURL and leaked payload', () => {
      const evidence = PRESET_MATRICES.financialSaaS.evidenceMap['fnd-bola-inv-001'];
      const issueBody = formatGithubIssueBody(evidence);

      expect(issueBody).toContain('### Security Vulnerability Report:');
      expect(issueBody).toContain('**Vulnerability Type**: `BOLA_HORIZONTAL_IDOR`');
      expect(issueBody).toContain('#### 2. Reproduction Steps (cURL)');
      expect(issueBody).toContain('#### 3. Leaked Response Evidence Snippet');
      expect(issueBody).toContain('#### 4. Remediation Guidance');
    });
  });

  describe('PR-05: Dynamic Matrix Aggregation & Truthful Retest Integration', () => {
    it('returns demo preset when no targetId is provided', async () => {
      const dataset = await getAuthzMatrixDataset('financialSaaS');
      expect(dataset).not.toBeNull();
      expect(dataset?.id).toBe('matrix-fin-saas');
      expect(dataset?.cells.length).toBeGreaterThan(0);
    });

    it('returns null (clean empty state) when target has zero BOLA tests or findings', async () => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ success: true, data: null }),
      });

      try {
        const dataset = await getAuthzMatrixDataset(undefined, 'clean-target-123');
        expect(dataset).toBeNull();
        expect(globalThis.fetch).toHaveBeenCalledWith(
          expect.stringContaining('/api/v1/authz/matrix?targetId=clean-target-123'),
          expect.any(Object),
        );
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it('fetches dynamically assembled matrix when target has findings and evidence', async () => {
      const mockDynamicDataset = {
        ...PRESET_MATRICES.financialSaaS,
        id: 'matrix-target-real-456',
        targetId: 'target-real-456',
        targetName: 'Dynamic Live Target',
      };

      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ success: true, data: mockDynamicDataset }),
      });

      try {
        const dataset = await getAuthzMatrixDataset(undefined, 'target-real-456');
        expect(dataset).not.toBeNull();
        expect(dataset?.targetName).toBe('Dynamic Live Target');
        expect(dataset?.id).toBe('matrix-target-real-456');
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it('executes targeted retest for BOLA finding and returns verification timestamp', async () => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          success: true,
          data: {
            stillDetected: false,
            status: 'resolved',
            message: 'Retest verified: Vulnerability resolved. Target endpoint enforced proper authorization checks.',
            retestedAt: new Date().toISOString(),
          },
        }),
      });

      try {
        const result = await retestAuthzFinding('fnd-bola-inv-001');
        expect(result.success).toBe(true);
        expect(result.message).toContain('Vulnerability resolved');
        expect(result.retestedAt).toBeDefined();
        expect(globalThis.fetch).toHaveBeenCalledWith(
          expect.stringContaining('/api/v1/findings/fnd-bola-inv-001/retest'),
          expect.objectContaining({ method: 'POST' }),
        );
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it('strictly throws error and never fabricates fake 403 on server retest failure', async () => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        json: async () => ({
          success: false,
          error: { code: 'RETEST_FAILED', message: 'Target server timed out during retest' },
        }),
      });

      try {
        await expect(retestAuthzFinding('fnd-timeout-001')).rejects.toThrow(
          'Target server timed out during retest',
        );
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });
});
