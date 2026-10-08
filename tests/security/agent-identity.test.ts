import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth, getDatabase } from '../../apps/controller/src/services/db.js';
import { hashAgentToken } from '../../apps/controller/src/services/agent-dispatcher.service.js';
import { hashEnrollmentKey } from '../../apps/controller/src/services/enrollment-keys.service.js';
import { AgentClient } from '../../apps/agent/src/client.js';

describe('Phase 16.1: Agent Identity, Enrollment Keys & Authentication Hardening', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;
  let controllerUrl: string;

  let tenantA: { id: string; name: string; slug: string };
  let tenantB: { id: string; name: string; slug: string };

  beforeAll(async () => {
    app = buildApp({ disableLogging: true });
    await app.listen({ port: 0, host: '127.0.0.1' });
    const addr = app.server.address();
    if (addr && typeof addr === 'object') {
      controllerUrl = `http://127.0.0.1:${addr.port}`;
    }

    const health = await checkDatabaseHealth();
    isDbAvailable = health === 'up';

    const suffix = Math.floor(Math.random() * 1000000);
    const resA = await app.inject({
      method: 'POST',
      url: '/api/v1/tenants',
      payload: { name: `Identity Tenant Alpha ${suffix}`, slug: `ident-alpha-${suffix}`, plan: 'enterprise' },
    });
    tenantA = resA.json().data;

    const resB = await app.inject({
      method: 'POST',
      url: '/api/v1/tenants',
      payload: { name: `Identity Tenant Beta ${suffix}`, slug: `ident-beta-${suffix}`, plan: 'enterprise' },
    });
    tenantB = resB.json().data;
  });

  afterAll(async () => {
    await app.close();
    if (isDbAvailable) {
      await closeDatabase();
    }
  });

  it('1. Confirms database health and test setup', () => {
    expect(isDbAvailable).toBe(true);
    expect(controllerUrl).toBeDefined();
    expect(tenantA.id).toBeDefined();
    expect(tenantB.id).toBeDefined();
  });

  it('2. Rejects anonymous registration with 401 AGENT_UNAUTHORIZED', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/register',
      headers: { 'x-tenant-id': tenantA.id },
      payload: {
        name: 'unauthorized-anon-agent',
        tags: ['test'],
        capabilities: ['engine-native-headers'],
      },
    });

    expect(res.statusCode).toBe(401);
    const body = res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('AGENT_UNAUTHORIZED');
  });

  it('3. Rejects registration with a completely invalid TEK with 401 INVALID_ENROLLMENT_KEY', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/register',
      headers: {
        authorization: 'Bearer tek_forged_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      },
      payload: {
        name: 'fake-tek-agent',
        tags: ['test'],
        capabilities: ['engine-native-headers'],
      },
    });

    expect(res.statusCode).toBe(401);
    const body = res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('INVALID_ENROLLMENT_KEY');
  });

  it('4. Successfully provisions TEK and registers agent permanently bound to TEK tenant', async () => {
    // 1. Tenant Alpha creates a TEK
    const tekRes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenantA.id}/enrollment-keys`,
      payload: {
        name: 'Alpha CI Agent Enrollment Key',
        maxUses: 5,
        expiresInDays: 30,
      },
    });

    expect(tekRes.statusCode).toBe(201);
    const tekData = tekRes.json().data;
    expect(tekData.id).toBeDefined();
    expect(tekData.tenantId).toBe(tenantA.id);
    expect(tekData.key).toMatch(/^tek_/);
    expect(tekData.keyPrefix).toBeDefined();
    expect(tekData.usesCount).toBe(0);

    // Verify plaintext TEK is NEVER stored in database
    const { sql } = getDatabase();
    const [dbTek] = await sql`
      SELECT id, key_hash, key_prefix, uses_count FROM tenant_enrollment_keys WHERE id = ${tekData.id} LIMIT 1
    `;
    expect(dbTek).toBeDefined();
    expect(dbTek.key_hash).toBe(hashEnrollmentKey(tekData.key));
    expect(dbTek.key_hash).not.toBe(tekData.key);

    // 2. Register agent using TEK and attempt to spoof tenant ID to Tenant B
    const client = new AgentClient(controllerUrl);
    const spoofedTenantId = tenantB.id;

    const registration = await client.register(
      {
        name: 'alpha-worker-01',
        tags: ['production', 'us-east-1'],
        capabilities: ['engine-native-headers', 'engine-zap'],
        systemInfo: { os: 'linux', arch: 'x64', nodeVersion: 'v20.18.0' },
      },
      tekData.key,
      spoofedTenantId, // Attempted spoof!
    );

    expect(registration.agentId).toBeDefined();
    expect(registration.token).toMatch(/^agt_sec_[a-f0-9]{64}$/);
    expect(registration.tokenExpiresAt).toBeDefined();
    // Rule 5: Tenant identity is strictly derived from TEK (Tenant Alpha), spoofed header ignored!
    expect(registration.tenantId).toBe(tenantA.id);
    expect(registration.tenantId).not.toBe(spoofedTenantId);

    // Verify TEK uses_count incremented in DB
    const [updatedDbTek] = await sql`
      SELECT uses_count FROM tenant_enrollment_keys WHERE id = ${tekData.id} LIMIT 1
    `;
    expect(updatedDbTek.uses_count).toBe(1);

    // Verify agent record in DB
    const [dbAgent] = await sql`
      SELECT id, tenant_id, token_hash, expires_at, revoked_at FROM agents WHERE id = ${registration.agentId} LIMIT 1
    `;
    expect(dbAgent).toBeDefined();
    expect(dbAgent.tenant_id).toBe(tenantA.id);
    expect(dbAgent.token_hash).toBe(hashAgentToken(registration.token));
    expect(dbAgent.expires_at).toBeDefined();
    expect(dbAgent.revoked_at).toBeNull();
  });

  it('5. Rejects registration when TEK max_uses is exhausted with 401 ENROLLMENT_KEY_EXHAUSTED', async () => {
    // Create TEK with maxUses: 1
    const tekRes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenantA.id}/enrollment-keys`,
      payload: {
        name: 'Single-Use Ephemeral Key',
        maxUses: 1,
        expiresInDays: 7,
      },
    });
    const tek = tekRes.json().data.key;

    const client = new AgentClient(controllerUrl);

    // 1st enrollment: succeeds
    const reg1 = await client.register(
      { name: 'ephemeral-agent-1', tags: [], capabilities: [] },
      tek,
    );
    expect(reg1.agentId).toBeDefined();

    // 2nd enrollment: fails due to exhausted uses
    const res2 = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/register',
      headers: { authorization: `Bearer ${tek}` },
      payload: { name: 'ephemeral-agent-2', tags: [], capabilities: [] },
    });

    expect(res2.statusCode).toBe(401);
    const body2 = res2.json();
    expect(body2.success).toBe(false);
    expect(body2.error.code).toBe('ENROLLMENT_KEY_EXHAUSTED');
  });

  it('6. Rejects registration when TEK has expired with 401 ENROLLMENT_KEY_EXPIRED', async () => {
    // Create TEK with 0 days (expired)
    const tekRes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenantA.id}/enrollment-keys`,
      payload: {
        name: 'Immediately Expired Key',
        expiresInDays: 1,
      },
    });
    expect(tekRes.statusCode).toBe(201);
    const tekData = tekRes.json().data;

    // Manually set expires_at in DB to 1 hour in the past
    const { sql } = getDatabase();
    await sql`
      UPDATE tenant_enrollment_keys
      SET expires_at = NOW() - INTERVAL '1 hour'
      WHERE id = ${tekData.id}
    `;

    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/register',
      headers: { authorization: `Bearer ${tekData.key}` },
      payload: { name: 'expired-key-agent', tags: [], capabilities: [] },
    });

    expect(res.statusCode).toBe(401);
    const body = res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('ENROLLMENT_KEY_EXPIRED');
  });

  it('7. Rejects registration when TEK has been revoked with 401 ENROLLMENT_KEY_REVOKED', async () => {
    // 1. Create TEK
    const tekRes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenantA.id}/enrollment-keys`,
      payload: { name: 'To-Be-Revoked Key' },
    });
    const tekData = tekRes.json().data;

    // 2. Revoke the TEK
    const revokeRes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenantA.id}/enrollment-keys/${tekData.id}/revoke`,
    });
    expect(revokeRes.statusCode).toBe(200);

    // 3. Attempt enrollment with revoked TEK
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/register',
      headers: { authorization: `Bearer ${tekData.key}` },
      payload: { name: 'revoked-key-agent', tags: [], capabilities: [] },
    });

    expect(res.statusCode).toBe(401);
    const body = res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('ENROLLMENT_KEY_REVOKED');
  });

  it('8. Supports agent token rotation via POST /api/v1/agents/rotate-token', async () => {
    // Enroll agent
    const tekRes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenantA.id}/enrollment-keys`,
      payload: { name: 'Rotation Key' },
    });
    const tek = tekRes.json().data.key;

    const client = new AgentClient(controllerUrl);
    const reg = await client.register(
      { name: 'rotatable-agent', tags: [], capabilities: [] },
      tek,
    );
    const initialToken = reg.token;

    // Verify heartbeat works with initial token
    const hb1 = await client.heartbeat(reg.agentId, 'online');
    expect(hb1.acknowledged).toBe(true);

    // Rotate token
    const rotated = await client.rotateToken();
    expect(rotated.agentId).toBe(reg.agentId);
    expect(rotated.token).toBeDefined();
    expect(rotated.token).not.toBe(initialToken);
    expect(rotated.tokenExpiresAt).toBeDefined();

    // Verify heartbeat succeeds with new rotated token
    const hb2 = await client.heartbeat(reg.agentId, 'online');
    expect(hb2.acknowledged).toBe(true);

    // Verify heartbeat fails with old token
    const oldClient = new AgentClient(controllerUrl, initialToken);
    const hbOldClient = await oldClient.heartbeat(reg.agentId, 'online');
    expect(hbOldClient.acknowledged).toBe(false);

    const hbOld = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/heartbeat',
      headers: { authorization: `Bearer ${initialToken}` },
      payload: { agentId: reg.agentId, status: 'online' },
    });
    expect(hbOld.statusCode).toBe(401);
  });

  it('9. Rejects requests from administratively revoked agents with 401 AGENT_REVOKED', async () => {
    // Enroll agent
    const tekRes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenantA.id}/enrollment-keys`,
      payload: { name: 'Revocation Test Key' },
    });
    const tek = tekRes.json().data.key;

    const client = new AgentClient(controllerUrl);
    const reg = await client.register(
      { name: 'rogue-target-agent', tags: [], capabilities: [] },
      tek,
    );

    // Verify heartbeat works
    const hb1 = await client.heartbeat(reg.agentId, 'online');
    expect(hb1.acknowledged).toBe(true);

    // Admin revokes agent
    const revokeRes = await app.inject({
      method: 'POST',
      url: `/api/v1/agents/${reg.agentId}/revoke`,
      payload: { reason: 'Compromised node in DMZ' },
    });
    expect(revokeRes.statusCode).toBe(200);
    expect(revokeRes.json().data.reason).toBe('Compromised node in DMZ');

    // Subsequent heartbeat must be instantly rejected
    const hb2Res = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/heartbeat',
      headers: { authorization: `Bearer ${reg.token}` },
      payload: { agentId: reg.agentId, status: 'online' },
    });

    expect(hb2Res.statusCode).toBe(401);
    const body = hb2Res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('AGENT_REVOKED');
    expect(body.error.message).toContain('Compromised node in DMZ');
  });

  it('10. Rejects requests from agents with expired tokens with 401 AGENT_TOKEN_EXPIRED', async () => {
    // Enroll agent
    const tekRes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenantA.id}/enrollment-keys`,
      payload: { name: 'Expiration Test Key' },
    });
    const tek = tekRes.json().data.key;

    const client = new AgentClient(controllerUrl);
    const reg = await client.register(
      { name: 'soon-to-expire-agent', tags: [], capabilities: [] },
      tek,
    );

    // Artificially expire the agent's token in DB
    const { sql } = getDatabase();
    await sql`
      UPDATE agents
      SET expires_at = NOW() - INTERVAL '1 day'
      WHERE id = ${reg.agentId}
    `;

    // Heartbeat attempt with expired token
    const hbRes = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/heartbeat',
      headers: { authorization: `Bearer ${reg.token}` },
      payload: { agentId: reg.agentId, status: 'online' },
    });

    expect(hbRes.statusCode).toBe(401);
    const body = hbRes.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('AGENT_TOKEN_EXPIRED');
  });
});
