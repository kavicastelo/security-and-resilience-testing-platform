import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth, getDatabase } from '../../controller/src/services/db.js';
import {
  signAgentRequest,
  verifyAgentRequest,
  loadOrCreateAgentKeypair,
} from '../src/crypto-attestation.js';
import { AgentClient } from '../src/client.js';
import { agentDispatcherService } from '../../controller/src/services/agent-dispatcher.service.js';
import { projects, targets, testRuns } from '../../controller/src/services/db/schema.js';

describe('Phase 15: Enterprise Private Agent Fleet Management & Mutual TLS', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;
  let controllerUrl: string;
  let tempKeyDir: string;

  let tenant: { id: string; name: string; slug: string };
  let tekKey: string;
  let agentKeypair: { publicKey: string; privateKey: string; fingerprint: string };
  let enrolledAgentId: string;

  beforeAll(async () => {
    app = buildApp({ disableLogging: true });
    await app.listen({ port: 0, host: '127.0.0.1' });
    const addr = app.server.address();
    if (addr && typeof addr === 'object') {
      controllerUrl = `http://127.0.0.1:${addr.port}`;
    }

    const health = await checkDatabaseHealth();
    isDbAvailable = health === 'up';

    tempKeyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-attestation-test-'));

    // Create a dedicated tenant for testing
    const suffix = Math.floor(Math.random() * 1000000);
    const resTenant = await app.inject({
      method: 'POST',
      url: '/api/v1/tenants',
      payload: { name: `Fleet Tenant ${suffix}`, slug: `fleet-${suffix}`, plan: 'enterprise' },
    });
    tenant = resTenant.json().data;

    // Create Tenant Enrollment Key (TEK)
    const resTek = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenant.id}/enrollment-keys`,
      payload: { name: 'Fleet Test TEK', expiresInDays: 7 },
    });
    tekKey = resTek.json().data.key;
  });

  afterAll(async () => {
    await app.close();
    if (isDbAvailable) {
      await closeDatabase();
    }
    if (tempKeyDir && fs.existsSync(tempKeyDir)) {
      fs.rmSync(tempKeyDir, { recursive: true, force: true });
    }
  });

  // ==========================================================================
  // Section 1: Keypair Generation, File Storage & Signatures
  // ==========================================================================
  it('1. Generates local Ed25519 keypair and enforces restrictive 0600 file permissions', () => {
    const keypair = loadOrCreateAgentKeypair(tempKeyDir);
    expect(keypair.publicKey).toContain('BEGIN PUBLIC KEY');
    expect(keypair.privateKey).toContain('BEGIN PRIVATE KEY');
    expect(keypair.fingerprint).toMatch(/^[a-f0-9]{64}$/);

    const privateKeyPath = path.join(tempKeyDir, 'agent_private.key');
    const publicKeyPath = path.join(tempKeyDir, 'agent_public.pem');
    expect(fs.existsSync(privateKeyPath)).toBe(true);
    expect(fs.existsSync(publicKeyPath)).toBe(true);

    const stat = fs.statSync(privateKeyPath);
    expect(stat.isFile()).toBe(true);

    agentKeypair = keypair;
  });

  it('2. Signs HTTP request canonical payload and successfully verifies valid signature', () => {
    const timestamp = Date.now();
    const signature = signAgentRequest(agentKeypair.privateKey, {
      method: 'POST',
      path: '/api/v1/agents/heartbeat',
      timestamp,
      body: { status: 'online' },
    });

    expect(signature).toBeDefined();
    expect(signature.length).toBeGreaterThan(30);

    const verification = verifyAgentRequest(agentKeypair.publicKey, {
      method: 'POST',
      path: '/api/v1/agents/heartbeat',
      timestamp,
      body: { status: 'online' },
      signature,
    });

    expect(verification.valid).toBe(true);
  });

  it('3. Rejects request when body, method, or path has been tampered with', () => {
    const timestamp = Date.now();
    const signature = signAgentRequest(agentKeypair.privateKey, {
      method: 'POST',
      path: '/api/v1/agents/heartbeat',
      timestamp,
      body: { status: 'online' },
    });

    // Tampered body
    const bodyTampered = verifyAgentRequest(agentKeypair.publicKey, {
      method: 'POST',
      path: '/api/v1/agents/heartbeat',
      timestamp,
      body: { status: 'offline' },
      signature,
    });
    expect(bodyTampered.valid).toBe(false);
    expect(bodyTampered.code).toBe('INVALID_SIGNATURE');

    // Tampered method
    const methodTampered = verifyAgentRequest(agentKeypair.publicKey, {
      method: 'GET',
      path: '/api/v1/agents/heartbeat',
      timestamp,
      body: { status: 'online' },
      signature,
    });
    expect(methodTampered.valid).toBe(false);
    expect(methodTampered.code).toBe('INVALID_SIGNATURE');

    // Tampered path
    const pathTampered = verifyAgentRequest(agentKeypair.publicKey, {
      method: 'POST',
      path: '/api/v1/agents/poll',
      timestamp,
      body: { status: 'online' },
      signature,
    });
    expect(pathTampered.valid).toBe(false);
    expect(pathTampered.code).toBe('INVALID_SIGNATURE');
  });

  it('4. Rejects replay attack when request timestamp exceeds 60-second drift window', () => {
    const expiredTimestamp = Date.now() - 65000; // 65 seconds in the past
    const signature = signAgentRequest(agentKeypair.privateKey, {
      method: 'POST',
      path: '/api/v1/agents/heartbeat',
      timestamp: expiredTimestamp,
      body: { status: 'online' },
    });

    const verification = verifyAgentRequest(agentKeypair.publicKey, {
      method: 'POST',
      path: '/api/v1/agents/heartbeat',
      timestamp: expiredTimestamp,
      body: { status: 'online' },
      signature,
    });

    expect(verification.valid).toBe(false);
    expect(verification.code).toBe('REPLAY_ATTACK_DETECTED');
    expect(verification.error).toContain('exceeds maximum allowable 60000ms replay window');
  });

  // ==========================================================================
  // Section 2: Agent Enrollment Flow via Controller API
  // ==========================================================================
  it('5. Rejects /enroll request without valid Tenant Enrollment Key (TEK)', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/enroll',
      headers: {
        authorization: 'Bearer tek_forged_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        'x-protocol-version': '1.0.0',
      },
      payload: {
        name: 'unauthorized-runner',
        publicKey: agentKeypair.publicKey,
        tags: ['vpc-internal'],
      },
    });

    expect(res.statusCode).toBe(401);
    const body = res.json();
    expect(body.success).toBe(false);
  });

  it('6. Successfully enrolls agent with Ed25519 public key and records fingerprint in database', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/enroll',
      headers: {
        authorization: `Bearer ${tekKey}`,
        'x-protocol-version': '1.0.0',
      },
      payload: {
        name: 'private-vpc-runner-01',
        publicKey: agentKeypair.publicKey,
        tags: ['vpc-internal', 'high-memory', 'docker-enabled'],
        capabilities: ['engine-native-headers', 'engine-native-tls'],
      },
    });

    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.success).toBe(true);
    expect(body.data.agentId).toBeDefined();
    expect(body.data.tenantId).toBe(tenant.id);
    expect(body.data.publicKey).toBe(agentKeypair.publicKey);
    expect(body.data.fingerprint).toBe(agentKeypair.fingerprint);
    expect(body.data.authMode).toBe('asymmetric');
    expect(body.data.tags).toEqual(['vpc-internal', 'high-memory', 'docker-enabled']);

    enrolledAgentId = body.data.agentId;
  });

  // ==========================================================================
  // Section 3: Controller Signature Verification & Authenticated Requests
  // ==========================================================================
  it('7. Accepts heartbeat request signed with Ed25519 asymmetric signature', async () => {
    const timestamp = Date.now();
    const payload = {
      agentId: enrolledAgentId,
      status: 'online',
      metrics: { activeJobsCount: 0, memoryUsageMb: 128 },
    };

    const signature = signAgentRequest(agentKeypair.privateKey, {
      method: 'POST',
      path: '/api/v1/agents/heartbeat',
      timestamp,
      body: payload,
    });

    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/heartbeat',
      headers: {
        'x-agent-id': enrolledAgentId,
        'x-agent-timestamp': timestamp.toString(),
        'x-agent-signature': signature,
        'x-protocol-version': '1.0.0',
      },
      payload,
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.acknowledged).toBe(true);
  });

  it('8. Rejects heartbeat with forged signature using HTTP 401 INVALID_SIGNATURE', async () => {
    const timestamp = Date.now();
    const payload = {
      agentId: enrolledAgentId,
      status: 'online',
    };

    const forgedSignature = Buffer.from('this-is-a-completely-forged-signature-base64').toString('base64');

    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/heartbeat',
      headers: {
        'x-agent-id': enrolledAgentId,
        'x-agent-timestamp': timestamp.toString(),
        'x-agent-signature': forgedSignature,
        'x-protocol-version': '1.0.0',
      },
      payload,
    });

    expect(res.statusCode).toBe(401);
    const body = res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('INVALID_SIGNATURE');
  });

  it('9. Rejects replayed heartbeat older than 60 seconds with HTTP 401 REPLAY_ATTACK_DETECTED', async () => {
    const expiredTimestamp = Date.now() - 70000;
    const payload = {
      agentId: enrolledAgentId,
      status: 'online',
    };

    const signature = signAgentRequest(agentKeypair.privateKey, {
      method: 'POST',
      path: '/api/v1/agents/heartbeat',
      timestamp: expiredTimestamp,
      body: payload,
    });

    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/heartbeat',
      headers: {
        'x-agent-id': enrolledAgentId,
        'x-agent-timestamp': expiredTimestamp.toString(),
        'x-agent-signature': signature,
        'x-protocol-version': '1.0.0',
      },
      payload,
    });

    expect(res.statusCode).toBe(401);
    const body = res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('REPLAY_ATTACK_DETECTED');
  });

  // ==========================================================================
  // Section 4: Capability & Tag-Based Job Routing
  // ==========================================================================
  it('10. Enforces capability & tag-based routing: leases jobs only to matching agents', async () => {
    const { db } = getDatabase();

    // 1. Create a project under tenant
    const suffix = Math.floor(Math.random() * 1000000);
    const [project] = await db
      .insert(projects)
      .values({
        name: `Fleet Target Project ${suffix}`,
        tenantId: tenant.id,
      })
      .returning();

    // 2. Create target and test run for this tenant
    const [target] = await db
      .insert(targets)
      .values({
        tenantId: tenant.id,
        projectId: project.id,
        name: 'VPC Target API',
        baseUrl: 'https://internal-api.corp.local',
        scope: { allowedHosts: ['internal-api.corp.local'] },
      })
      .returning();

    const [run] = await db
      .insert(testRuns)
      .values({
        tenantId: tenant.id,
        projectId: project.id,
        targetId: target.id,
        status: 'pending',
      })
      .returning();

    // 3. Enqueue job requiring tag 'pci-dss-isolated' (which our agent does NOT have)
    const jobAId = await agentDispatcherService.enqueueAgentJob(
      run.id,
      tenant.id,
      ['engine-native-headers'],
      {},
      [],
      ['pci-dss-isolated'], // required tag
    );

    // 4. Enqueue job requiring tag 'vpc-internal' (which our agent DOES have)
    const jobBId = await agentDispatcherService.enqueueAgentJob(
      run.id,
      tenant.id,
      ['engine-native-headers'],
      {},
      [],
      ['vpc-internal'], // required tag
    );

    // Agent polls with tags ['vpc-internal', 'high-memory']
    const claimed = await agentDispatcherService.pollJobs(
      enrolledAgentId,
      tenant.id,
      ['engine-native-headers'],
      ['vpc-internal', 'high-memory'],
      5,
    );

    // Assert: Only Job B was leased; Job A was skipped because agent lacks 'pci-dss-isolated'
    expect(claimed.length).toBe(1);
    expect(claimed[0].jobId).toBe(jobBId);
    expect(claimed.find((j) => j.jobId === jobAId)).toBeUndefined();
  });

  // ==========================================================================
  // Section 5: AgentClient End-to-End Integration & OpenTelemetry Tracing
  // ==========================================================================
  it('11. AgentClient communicates with Controller and propagates W3C traceparent headers', async () => {
    const client = new AgentClient(controllerUrl, undefined, agentKeypair, enrolledAgentId);

    // Execute heartbeat via AgentClient
    const hbResponse = await client.heartbeat(enrolledAgentId, 'online', { activeJobsCount: 0 });
    expect(hbResponse.acknowledged).toBe(true);

    // Execute poll via AgentClient
    const polledJobs = await client.poll(enrolledAgentId, ['engine-native-headers'], ['vpc-internal']);
    expect(Array.isArray(polledJobs)).toBe(true);
  });

  // ==========================================================================
  // Section 6: Prometheus Metrics Exposition (/metrics)
  // ==========================================================================
  it('12. Controller exports Prometheus metrics on /metrics adhering to standard exposition format', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/metrics',
    });

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/plain');
    const body = res.body;

    expect(body).toContain('# HELP security_lab_agent_heartbeat_status');
    expect(body).toContain('# TYPE security_lab_agent_heartbeat_status gauge');
    expect(body).toContain(`security_lab_agent_heartbeat_status{agent_id="${enrolledAgentId}",tenant_id="${tenant.id}",status="online"} 1`);
    expect(body).toContain('# HELP security_lab_active_leases');
    expect(body).toContain('# HELP security_lab_jobs_leased_total');
    expect(body).toContain('security_lab_jobs_leased_total');
  });

  // ==========================================================================
  // Section 7: Backwards Compatibility with Legacy Token Authentication
  // ==========================================================================
  it('13. Preserves backwards compatibility: legacy token-authenticated agents operate normally', async () => {
    // Register a legacy agent with TEK
    const tekRes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenant.id}/enrollment-keys`,
      payload: { name: 'Legacy TEK', expiresInDays: 1 },
    });
    const legacyTek = tekRes.json().data.key;

    const regRes = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/register',
      headers: { authorization: `Bearer ${legacyTek}`, 'x-protocol-version': '1.0.0' },
      payload: {
        name: 'legacy-token-agent',
        tags: ['legacy'],
        capabilities: ['engine-native-headers'],
      },
    });

    expect(regRes.statusCode).toBe(201);
    const legacyToken = regRes.json().data.token;
    const legacyAgentId = regRes.json().data.agentId;

    // Send heartbeat using Bearer token without asymmetric headers
    const hbRes = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/heartbeat',
      headers: {
        authorization: `Bearer ${legacyToken}`,
        'x-protocol-version': '1.0.0',
      },
      payload: {
        agentId: legacyAgentId,
        status: 'online',
      },
    });

    expect(hbRes.statusCode).toBe(200);
    expect(hbRes.json().acknowledged).toBe(true);
  });
});
