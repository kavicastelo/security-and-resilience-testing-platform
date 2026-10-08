import http from 'node:http';
import net from 'node:net';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import {
  CURRENT_PROTOCOL_VERSION,
  HEADER_PROTOCOL_VERSION,
} from '@security-lab/contracts';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth, getDatabase } from '../../apps/controller/src/services/db.js';
import {
  agentAuditService,
  scrubSecrets,
  isSensitiveField,
  isSensitiveValue,
  REDACTED_PLACEHOLDER,
} from '../../apps/controller/src/services/agent-audit.service.js';
import {
  computeJobDispatchSecret,
  computeResultSignature,
  computeFindingsHash,
} from '@security-lab/evidence';

describe('Phase 16.9: Security Audit Logging & Distributed Telemetry Observability', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;

  // Mock Target
  let mockTargetServer: http.Server;
  let mockTargetPort: number;
  let mockTargetUrl: string;

  // Tenant Alpha & Beta
  let tenantAId: string;
  let tenantBId: string;
  let tekKeyA: string;
  let _tekKeyB: string;
  let projectAId: string;
  let targetAId: string;

  // Agent Alpha
  let agentAId: string;
  let agentAToken: string;

  beforeAll(async () => {
    app = buildApp({ disableLogging: true });
    await app.listen({ port: 0, host: '127.0.0.1' });

    const health = await checkDatabaseHealth();
    isDbAvailable = health === 'up';

    mockTargetServer = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok' }));
    });

    await new Promise<void>((resolve) => {
      mockTargetServer.listen(0, '127.0.0.1', () => {
        const addr = mockTargetServer.address() as net.AddressInfo;
        mockTargetPort = addr.port;
        mockTargetUrl = `http://127.0.0.1:${mockTargetPort}`;
        resolve();
      });
    });

    const suffix = `${Date.now()}-${Math.floor(Math.random() * 10000)}`;

    // Create Tenant Alpha
    const tenantARes = await app.inject({
      method: 'POST',
      url: '/api/v1/tenants',
      payload: { name: `Audit Corp Alpha ${suffix}`, slug: `audit-alpha-${suffix}`, plan: 'enterprise' },
    });
    expect(tenantARes.statusCode).toBe(201);
    tenantAId = tenantARes.json().data.id;

    // Create Tenant Beta (for cross-tenant checks)
    const tenantBRes = await app.inject({
      method: 'POST',
      url: '/api/v1/tenants',
      payload: { name: `Audit Corp Beta ${suffix}`, slug: `audit-beta-${suffix}`, plan: 'enterprise' },
    });
    expect(tenantBRes.statusCode).toBe(201);
    tenantBId = tenantBRes.json().data.id;

    // Create TEK for Tenant Alpha
    const tekARes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenantAId}/enrollment-keys`,
      payload: { name: 'Audit TEK Alpha' },
    });
    expect(tekARes.statusCode).toBe(201);
    tekKeyA = tekARes.json().data.key;

    // Create TEK for Tenant Beta
    const tekBRes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenantBId}/enrollment-keys`,
      payload: { name: 'Audit TEK Beta' },
    });
    expect(tekBRes.statusCode).toBe(201);
    _tekKeyB = tekBRes.json().data.key;

    // Create Project & Target under Tenant Alpha
    const projRes = await app.inject({
      method: 'POST',
      url: '/api/v1/projects',
      headers: { 'x-tenant-id': tenantAId },
      payload: { name: `Audit Project ${suffix}`, description: 'Audit test project' },
    });
    expect(projRes.statusCode).toBe(201);
    projectAId = projRes.json().data.id;

    const targetRes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectAId}/targets`,
      headers: { 'x-tenant-id': tenantAId },
      payload: {
        name: `Audit Target ${suffix}`,
        baseUrl: mockTargetUrl,
        environment: 'staging',
        criticality: 'medium',
        allowedHosts: ['127.0.0.1'],
        allowedPorts: [mockTargetPort],
        excludedPaths: [],
        testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
        limits: { maxRps: 50, maxConcurrency: 5, maxDuration: '2m' },
      },
    });
    expect(targetRes.statusCode).toBe(201);
    targetAId = targetRes.json().data.id;
  });

  afterAll(async () => {
    if (mockTargetServer) {
      await new Promise<void>((resolve) => mockTargetServer.close(() => resolve()));
    }
    if (app) {
      await app.close();
    }
    await closeDatabase();
  });

  // ============================================================================
  // 1. Secret Scrubbing Engine (Rule 17)
  // ============================================================================
  describe('1. Secret Scrubbing Engine (Rule 17)', () => {
    it('accurately identifies sensitive credential key names', () => {
      expect(isSensitiveField('token')).toBe(true);
      expect(isSensitiveField('agentToken')).toBe(true);
      expect(isSensitiveField('rawToken')).toBe(true);
      expect(isSensitiveField('password')).toBe(true);
      expect(isSensitiveField('db_password')).toBe(true);
      expect(isSensitiveField('secret')).toBe(true);
      expect(isSensitiveField('clientSecret')).toBe(true);
      expect(isSensitiveField('apiKey')).toBe(true);
      expect(isSensitiveField('api_key')).toBe(true);
      expect(isSensitiveField('authorization')).toBe(true);
      expect(isSensitiveField('auth_header')).toBe(true);
      expect(isSensitiveField('key')).toBe(true);
      expect(isSensitiveField('masterKey')).toBe(true);

      // Harmless fields must not be flagged
      expect(isSensitiveField('jobId')).toBe(false);
      expect(isSensitiveField('agentId')).toBe(false);
      expect(isSensitiveField('tenantId')).toBe(false);
      expect(isSensitiveField('status')).toBe(false);
      expect(isSensitiveField('requiredCapabilities')).toBe(false);
      expect(isSensitiveField('attempts')).toBe(false);
    });

    it('accurately identifies raw sensitive tokens in string values', () => {
      expect(isSensitiveValue('Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9')).toBe(true);
      expect(isSensitiveValue('tek_prod_99f3792cb00259b3')).toBe(true);
      expect(isSensitiveValue('agt_sec_87e2b104928e')).toBe(true);

      expect(isSensitiveValue('https://example.com/api')).toBe(false);
      expect(isSensitiveValue('engine-zap')).toBe(false);
      expect(isSensitiveValue('normal text')).toBe(false);
    });

    it('deeply scrubs sensitive nested keys and credential values', () => {
      const sensitivePayload = {
        agentName: 'TestAgent-01',
        token: 'agt_sec_supersecret12345',
        auth: {
          password: 'plain_password',
          apiKey: 'key_1234567890',
          nested: {
            secretToken: 'secret_token_val',
            headers: {
              authorization: 'Bearer token_header_val',
            },
          },
        },
        tags: ['vpc-secure'],
        rawBearerString: 'Bearer some_unkeyed_token_string',
        metrics: {
          count: 42,
          active: true,
        },
      };

      const scrubbed = scrubSecrets(sensitivePayload) as Record<string, unknown>;
      const authObj = scrubbed.auth as Record<string, unknown>;
      const nestedAuth = authObj.nested as Record<string, unknown>;
      const nestedHeaders = nestedAuth.headers as Record<string, unknown>;
      const metricsObj = scrubbed.metrics as Record<string, unknown>;

      expect(scrubbed.token).toBe(REDACTED_PLACEHOLDER);
      expect(authObj.password).toBe(REDACTED_PLACEHOLDER);
      expect(authObj.apiKey).toBe(REDACTED_PLACEHOLDER);
      expect(nestedAuth.secretToken).toBe(REDACTED_PLACEHOLDER);
      expect(nestedHeaders.authorization).toBe(REDACTED_PLACEHOLDER);
      expect(scrubbed.rawBearerString).toBe(REDACTED_PLACEHOLDER);

      // Non-sensitive preserved intact
      expect(scrubbed.agentName).toBe('TestAgent-01');
      expect(scrubbed.tags).toEqual(['vpc-secure']);
      expect(metricsObj.count).toBe(42);
      expect(metricsObj.active).toBe(true);
    });

    it('handles circular references without throwing or stack overflow', () => {
      const circularObj: Record<string, unknown> = {
        name: 'Circular',
        token: 'secret_token',
      };
      circularObj.self = circularObj;

      const result = scrubSecrets(circularObj) as Record<string, unknown>;
      expect(result.name).toBe('Circular');
      expect(result.token).toBe(REDACTED_PLACEHOLDER);
      expect(result.self).toBe('[CIRCULAR]');
    });
  });

  // ============================================================================
  // 2. Database Immutability & Append-Only Enforcement (Rule 20)
  // ============================================================================
  describe('2. Database Immutability & Append-Only Enforcement (Rule 20)', () => {
    it('strictly forbids UPDATE operations on agent_audit_events via trigger', async () => {
      if (!isDbAvailable) return;
      const { sql } = getDatabase();
      if (!sql) return;

      // Insert test audit record
      const [inserted] = await sql<{ id: string }[]>`
        INSERT INTO agent_audit_events (tenant_id, event_type, actor_type, actor_id, metadata)
        VALUES (${tenantAId}, 'agent.enrolled', 'admin', 'test_actor', '{"status":"ok"}'::jsonb)
        RETURNING id;
      `;

      // Attempt to update
      await expect(
        sql`UPDATE agent_audit_events SET event_type = 'agent.tampered' WHERE id = ${inserted.id}`,
      ).rejects.toThrow(/AUDIT_LOG_IMMUTABLE/);
    });

    it('strictly forbids DELETE operations on agent_audit_events via trigger', async () => {
      if (!isDbAvailable) return;
      const { sql } = getDatabase();
      if (!sql) return;

      // Insert test audit record
      const [inserted] = await sql<{ id: string }[]>`
        INSERT INTO agent_audit_events (tenant_id, event_type, actor_type, actor_id, metadata)
        VALUES (${tenantAId}, 'job.leased', 'agent', 'test_actor', '{"status":"leased"}'::jsonb)
        RETURNING id;
      `;

      // Attempt to delete
      await expect(
        sql`DELETE FROM agent_audit_events WHERE id = ${inserted.id}`,
      ).rejects.toThrow(/AUDIT_LOG_IMMUTABLE/);
    });
  });

  // ============================================================================
  // 3. Agent Lifecycle Event Auditing
  // ============================================================================
  describe('3. Agent Lifecycle Event Auditing', () => {
    it('records "agent.enrolled" on successful agent registration with zero plaintext token in audit log', async () => {
      const regRes = await app.inject({
        method: 'POST',
        url: '/api/v1/agents/register',
        headers: {
          authorization: `Bearer ${tekKeyA}`,
          [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        },
        payload: {
          name: 'Audit-Agent-Alpha',
          capabilities: ['engine-zap', 'docker'],
          tags: ['vpc-prod'],
        },
      });

      expect(regRes.statusCode).toBe(201);
      const regData = regRes.json().data;
      agentAId = regData.agentId;
      agentAToken = regData.token;

      // Query audit logs
      const audit = await agentAuditService.getAuditEvents({
        tenantId: tenantAId,
        agentId: agentAId,
        eventType: 'agent.enrolled',
      });

      expect(audit.total).toBeGreaterThanOrEqual(1);
      const enrolledEvent = audit.events.find((e) => e.eventType === 'agent.enrolled');
      expect(enrolledEvent).toBeDefined();
      expect(enrolledEvent!.actorType).toBe('admin');
      expect(enrolledEvent!.metadata.agentName).toBe('Audit-Agent-Alpha');

      // Rule 17 assertion: raw token must NEVER appear anywhere in metadata
      const rawMetadata = JSON.stringify(enrolledEvent!.metadata);
      expect(rawMetadata).not.toContain(agentAToken);
      expect(rawMetadata).not.toContain('agt_sec_');
    });

    it('records "job.leased" audit event when agent claims a job via poll', async () => {
      // 1. Create a Test Run
      const runRes = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        headers: { 'x-tenant-id': tenantAId },
        payload: {
          projectId: projectAId,
          targetId: targetAId,
          profileId: 'native-class-a',
          triggeredBy: 'manual',
        },
      });
      expect(runRes.statusCode).toBe(201);
      const testRunId = runRes.json().data.id;

      // 2. Dispatch a job
      const dispatchRes = await app.inject({
        method: 'POST',
        url: '/api/v1/agents/dispatch',
        headers: { 'x-tenant-id': tenantAId },
        payload: {
          testRunId,
          engineIds: ['engine-zap'],
          requiredCapabilities: ['engine-zap'],
          requiredTags: ['vpc-prod'],
        },
      });
      expect(dispatchRes.statusCode).toBe(202);
      const jobId = dispatchRes.json().data.jobId;

      // 3. Agent polls for the job
      const pollRes = await app.inject({
        method: 'POST',
        url: '/api/v1/agents/poll',
        headers: {
          authorization: `Bearer ${agentAToken}`,
          [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        },
        payload: {
          agentId: agentAId,
          capabilities: ['engine-zap', 'docker'],
          tags: ['vpc-prod'],
          maxJobs: 1,
        },
      });
      expect(pollRes.statusCode).toBe(200);
      expect(pollRes.json().jobs.length).toBe(1);

      // 4. Assert audit event recorded for job.leased
      const audit = await agentAuditService.getAuditEvents({
        tenantId: tenantAId,
        agentId: agentAId,
        eventType: 'job.leased',
      });

      expect(audit.total).toBeGreaterThanOrEqual(1);
      const leaseEvent = audit.events.find((e) => e.metadata.jobId === jobId);
      expect(leaseEvent).toBeDefined();
      expect(leaseEvent!.actorType).toBe('agent');
      expect(leaseEvent!.actorId).toBe(agentAId);
      expect(leaseEvent!.metadata.testRunId).toBe(testRunId);
    });

    it('records "job.completed" audit event upon successful result submission', async () => {
      // 1. Create a Test Run & Dispatch
      const runRes = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        headers: { 'x-tenant-id': tenantAId },
        payload: {
          projectId: projectAId,
          targetId: targetAId,
          profileId: 'native-class-a',
          triggeredBy: 'manual',
        },
      });
      expect(runRes.statusCode).toBe(201);
      const testRunId = runRes.json().data.id;

      const dispatchRes = await app.inject({
        method: 'POST',
        url: '/api/v1/agents/dispatch',
        headers: { 'x-tenant-id': tenantAId },
        payload: {
          testRunId,
          engineIds: ['engine-zap'],
        },
      });
      const jobId = dispatchRes.json().data.jobId;

      // 2. Poll to lease
      const pollRes = await app.inject({
        method: 'POST',
        url: '/api/v1/agents/poll',
        headers: {
          authorization: `Bearer ${agentAToken}`,
          [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        },
        payload: { agentId: agentAId, capabilities: ['engine-zap'], tags: [] },
      });
      const jobDispatch = pollRes.json().jobs[0];

      // 3. Sign and complete
      const findings = [
        {
          sourceEngine: 'engine-zap',
          title: 'Audit Finding',
          description: 'Verified audit event recording',
          rawSeverity: 'medium',
          location: '/status',
        },
      ];
      const executions = [{ engineId: 'engine-zap', status: 'completed', durationMs: 120 }];
      const secret = computeJobDispatchSecret(jobId, jobDispatch.leaseId, agentAId);
      const findingsHash = computeFindingsHash(findings, executions);
      const resultSignature = computeResultSignature(secret, jobId, findingsHash);

      const completeRes = await app.inject({
        method: 'POST',
        url: `/api/v1/agents/jobs/${jobId}/complete`,
        headers: {
          authorization: `Bearer ${agentAToken}`,
          [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        },
        payload: {
          jobId,
          testRunId,
          leaseId: jobDispatch.leaseId,
          status: 'completed',
          findings,
          executions,
          metrics: [],
          resultSignature,
        },
      });
      expect(completeRes.statusCode).toBe(200);

      // 4. Assert audit event recorded for job.completed
      const audit = await agentAuditService.getAuditEvents({
        tenantId: tenantAId,
        agentId: agentAId,
        eventType: 'job.completed',
      });

      const completedEvent = audit.events.find((e) => e.metadata.jobId === jobId);
      expect(completedEvent).toBeDefined();
      expect(completedEvent!.metadata.findingsCount).toBe(1);
      expect(completedEvent!.metadata.executionsCount).toBe(1);
    });

    it('records "agent.token_rotated" audit event upon token rotation', async () => {
      const rotateRes = await app.inject({
        method: 'POST',
        url: '/api/v1/agents/rotate-token',
        headers: {
          authorization: `Bearer ${agentAToken}`,
          [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        },
      });
      expect(rotateRes.statusCode).toBe(200);
      const newRawToken = rotateRes.json().data.token;
      agentAToken = newRawToken;

      const audit = await agentAuditService.getAuditEvents({
        tenantId: tenantAId,
        agentId: agentAId,
        eventType: 'agent.token_rotated',
      });

      expect(audit.total).toBeGreaterThanOrEqual(1);
      const rotateEvent = audit.events[0];
      expect(rotateEvent.eventType).toBe('agent.token_rotated');
      // Rule 17: raw token must not appear in audit metadata
      expect(JSON.stringify(rotateEvent.metadata)).not.toContain(newRawToken);
    });

    it('records "agent.revoked" audit event on administrative revocation', async () => {
      const revokeRes = await app.inject({
        method: 'POST',
        url: `/api/v1/agents/${agentAId}/revoke`,
        headers: {
          'x-tenant-id': tenantAId,
        },
        payload: { reason: 'Decommissioned by compliance officer' },
      });
      expect(revokeRes.statusCode).toBe(200);

      const audit = await agentAuditService.getAuditEvents({
        tenantId: tenantAId,
        agentId: agentAId,
        eventType: 'agent.revoked',
      });

      expect(audit.total).toBeGreaterThanOrEqual(1);
      const revokeEvent = audit.events.find((e) => e.eventType === 'agent.revoked');
      expect(revokeEvent).toBeDefined();
      expect(revokeEvent!.metadata.reason).toBe('Decommissioned by compliance officer');
    });
  });

  // ============================================================================
  // 4. Security Violations & Threat Boundary Auditing (Rule 11 & Rule 20)
  // ============================================================================
  describe('4. Security Violations & Threat Boundary Auditing (Rule 11 & Rule 20)', () => {
    let freshAgentId: string;
    let freshAgentToken: string;

    beforeAll(async () => {
      // Register a fresh agent for violation tests
      const regRes = await app.inject({
        method: 'POST',
        url: '/api/v1/agents/register',
        headers: {
          authorization: `Bearer ${tekKeyA}`,
          [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        },
        payload: {
          name: 'Threat-Audit-Agent',
          capabilities: ['engine-zap'],
          tags: [],
        },
      });
      freshAgentId = regRes.json().data.agentId;
      freshAgentToken = regRes.json().data.token;
    });

    it('records "security.tenant_mismatch" when client attempts tenant header spoofing', async () => {
      // Agent belongs to Tenant Alpha, but sends X-Tenant-Id: Tenant Beta
      const spoofRes = await app.inject({
        method: 'POST',
        url: '/api/v1/agents/heartbeat',
        headers: {
          authorization: `Bearer ${freshAgentToken}`,
          'x-tenant-id': tenantBId,
          [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        },
        payload: {
          agentId: freshAgentId,
          status: 'online',
        },
      });
      expect(spoofRes.statusCode).toBe(403);
      expect(spoofRes.json().error.code).toBe('TENANT_MISMATCH');

      // Assert security audit event was written
      const audit = await agentAuditService.getAuditEvents({
        tenantId: tenantAId,
        agentId: freshAgentId,
        eventType: 'security.tenant_mismatch',
      });

      expect(audit.total).toBeGreaterThanOrEqual(1);
      const mismatchEvent = audit.events.find((e) => e.metadata.action === 'header_spoof_attempt');
      expect(mismatchEvent).toBeDefined();
      expect(mismatchEvent!.metadata.headerTenantId).toBe(tenantBId);
      expect(mismatchEvent!.metadata.agentTenantId).toBe(tenantAId);
    });

    it('records "security.scope_tampering" when agent submits tampered result signature', async () => {
      // 1. Create run and dispatch
      const runRes = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        headers: { 'x-tenant-id': tenantAId },
        payload: {
          projectId: projectAId,
          targetId: targetAId,
          profileId: 'native-class-a',
          triggeredBy: 'manual',
        },
      });
      expect(runRes.statusCode).toBe(201);
      const testRunId = runRes.json().data.id;

      const dispatchRes = await app.inject({
        method: 'POST',
        url: '/api/v1/agents/dispatch',
        headers: { 'x-tenant-id': tenantAId },
        payload: {
          testRunId,
          engineIds: ['engine-zap'],
        },
      });
      const jobId = dispatchRes.json().data.jobId;

      // 2. Poll to lease
      const pollRes = await app.inject({
        method: 'POST',
        url: '/api/v1/agents/poll',
        headers: {
          authorization: `Bearer ${freshAgentToken}`,
          [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        },
        payload: { agentId: freshAgentId, capabilities: ['engine-zap'], tags: [] },
      });
      const jobDispatch = pollRes.json().jobs[0];

      // 3. Submit with forged/tampered signature
      const tamperedRes = await app.inject({
        method: 'POST',
        url: `/api/v1/agents/jobs/${jobId}/complete`,
        headers: {
          authorization: `Bearer ${freshAgentToken}`,
          [HEADER_PROTOCOL_VERSION]: CURRENT_PROTOCOL_VERSION,
        },
        payload: {
          jobId,
          testRunId,
          leaseId: jobDispatch.leaseId,
          status: 'completed',
          findings: [
            {
              sourceEngine: 'engine-zap',
              title: 'Tampered Finding',
              description: 'Attacker injected finding',
              rawSeverity: 'high',
              location: '/admin',
            },
          ],
          executions: [{ engineId: 'engine-zap', status: 'completed', durationMs: 50 }],
          metrics: [],
          resultSignature: 'deadbeef_forged_signature_1234567890',
        },
      });
      expect(tamperedRes.statusCode).toBe(403);
      expect(tamperedRes.json().error.code).toBe('SIGNATURE_INVALID');

      // 4. Assert security audit event recorded
      const audit = await agentAuditService.getAuditEvents({
        tenantId: tenantAId,
        agentId: freshAgentId,
        eventType: 'security.scope_tampering',
      });

      expect(audit.total).toBeGreaterThanOrEqual(1);
      const tamperEvent = audit.events.find((e) => e.metadata.jobId === jobId);
      expect(tamperEvent).toBeDefined();
      expect(tamperEvent!.metadata.reason).toBe('SIGNATURE_MISMATCH');
    });

    it('records "security.protocol_violation" when outdated protocol version is presented', async () => {
      const outdatedRes = await app.inject({
        method: 'POST',
        url: '/api/v1/agents/heartbeat',
        headers: {
          authorization: `Bearer ${freshAgentToken}`,
          'x-tenant-id': tenantAId,
          [HEADER_PROTOCOL_VERSION]: '0.8.0', // Outdated protocol
        },
        payload: {
          agentId: freshAgentId,
          status: 'online',
        },
      });
      expect(outdatedRes.statusCode).toBe(426);

      const audit = await agentAuditService.getAuditEvents({
        tenantId: tenantAId,
        eventType: 'security.protocol_violation',
      });

      expect(audit.total).toBeGreaterThanOrEqual(1);
      const protoEvent = audit.events.find((e) => e.metadata.clientProtocolVersion === '0.8.0');
      expect(protoEvent).toBeDefined();
    });
  });

  // ============================================================================
  // 5. Admin Audit Query API (GET /api/v1/agents/:id/audit-events)
  // ============================================================================
  describe('5. Admin Audit Query API (GET /api/v1/agents/:id/audit-events)', () => {
    it('returns paginated audit trail for an agent belonging to the caller tenant', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/agents/${agentAId}/audit-events?page=1&limit=10`,
        headers: {
          'x-tenant-id': tenantAId,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.success).toBe(true);
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.data.length).toBeGreaterThan(0);
      expect(body.pagination).toBeDefined();
      expect(body.pagination.page).toBe(1);
      expect(body.pagination.limit).toBe(10);
      expect(body.pagination.total).toBeGreaterThanOrEqual(body.data.length);

      // Verify structure of first item
      const item = body.data[0];
      expect(item.id).toMatch(/^[0-9a-f-]{36}$/);
      expect(item.tenantId).toBe(tenantAId);
      expect(item.agentId).toBe(agentAId);
      expect(item.eventType).toBeDefined();
      expect(item.actorType).toBeDefined();
      expect(item.actorId).toBeDefined();
      expect(item.metadata).toBeDefined();
      expect(item.createdAt).toBeDefined();
    });

    it('filters audit trail by eventType query parameter', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/agents/${agentAId}/audit-events?eventType=agent.enrolled`,
        headers: {
          'x-tenant-id': tenantAId,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.length).toBeGreaterThanOrEqual(1);
      for (const event of body.data) {
        expect(event.eventType).toBe('agent.enrolled');
      }
    });

    it('Rule 5 & Rule 11: Rejects cross-tenant access to audit trail with 403 TENANT_MISMATCH', async () => {
      // Caller provides Tenant Beta header attempting to inspect Tenant Alpha's agent
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/agents/${agentAId}/audit-events`,
        headers: {
          'x-tenant-id': tenantBId,
        },
      });

      expect(res.statusCode).toBe(403);
      expect(res.json().error.code).toBe('TENANT_MISMATCH');
    });

    it('returns 404 NOT_FOUND when querying audit events for a non-existent agent', async () => {
      const nonExistentId = '00000000-0000-0000-0000-999999999999';
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/agents/${nonExistentId}/audit-events`,
        headers: {
          'x-tenant-id': tenantAId,
        },
      });

      expect(res.statusCode).toBe(404);
      expect(res.json().error.code).toBe('NOT_FOUND');
    });
  });

  // ============================================================================
  // 6. Telemetry & Observability Metrics
  // ============================================================================
  describe('6. Telemetry & Observability Metrics', () => {
    it('accurately reports written events count, scrubbed fields count, and breakdown by type', () => {
      const metrics = agentAuditService.getMetrics();
      expect(metrics.eventsWrittenTotal).toBeGreaterThan(0);
      expect(metrics.scrubbedFieldsTotal).toBeGreaterThanOrEqual(0);
      expect(Object.keys(metrics.eventsByType).length).toBeGreaterThan(0);

      // Known event types should be tracked in the breakdown
      expect(metrics.eventsByType['agent.enrolled']).toBeGreaterThanOrEqual(1);
    });
  });
});
