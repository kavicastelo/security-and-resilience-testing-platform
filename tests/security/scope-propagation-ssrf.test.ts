import http from 'node:http';
import net from 'node:net';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase, checkDatabaseHealth } from '../../apps/controller/src/services/db.js';
import {
  AgentClient,
  AgentWorker,
  ScopeTamperingError,
  SecurityBoundaryError,
} from '../../apps/agent/src/index.js';
import { computeScopeSignature } from '@security-lab/evidence';

describe('Phase 16.5: Scope Cryptographic Binding & Distributed SSRF Defense', () => {
  let app: FastifyInstance;
  let isDbAvailable = false;
  let controllerUrl: string;

  let mockTargetServer: http.Server;
  let mockTargetPort: number;
  let mockTargetUrl: string;

  let tenant: { id: string; name: string; slug: string };
  let projectId: string;
  let targetId: string;
  let tekToken: string;

  let agentId: string;
  let _agentToken: string;
  let agentClient: AgentClient;

  async function createTestRun(customTargetId?: string): Promise<string> {
    const runRes = await app.inject({
      method: 'POST',
      url: '/api/v1/test-runs',
      headers: { 'x-tenant-id': tenant.id },
      payload: {
        projectId,
        targetId: customTargetId || targetId,
        profileId: 'native-class-a',
        triggeredBy: 'manual',
      },
    });
    expect(runRes.statusCode).toBe(201);
    return runRes.json().data.id;
  }

  async function dispatchJob(testRunId: string, engineIds: string[] = ['engine-native-headers']): Promise<string> {
    const dispatchRes = await app.inject({
      method: 'POST',
      url: '/api/v1/agents/dispatch',
      headers: { 'x-tenant-id': tenant.id },
      payload: { testRunId, engineIds },
    });
    expect(dispatchRes.statusCode).toBe(202);
    return dispatchRes.json().data.jobId;
  }

  beforeAll(async () => {
    app = buildApp({ disableLogging: true });
    await app.listen({ port: 0, host: '127.0.0.1' });
    const addr = app.server.address() as net.AddressInfo;
    controllerUrl = `http://127.0.0.1:${addr.port}`;

    const health = await checkDatabaseHealth();
    isDbAvailable = health === 'up';

    if (!isDbAvailable) {
      throw new Error('Database is not available for Phase 16.5 testing');
    }

    // Mock Target Server (authorized destination)
    mockTargetServer = http.createServer((req, res) => {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        Server: 'VPC-Target/1.0',
      });
      res.end(JSON.stringify({ status: 'ok', destination: 'authorized-target' }));
    });

    await new Promise<void>((resolve) => {
      mockTargetServer.listen(0, '127.0.0.1', () => {
        const targetAddr = mockTargetServer.address() as net.AddressInfo;
        mockTargetPort = targetAddr.port;
        mockTargetUrl = `http://127.0.0.1:${mockTargetPort}`;
        resolve();
      });
    });

    const suffix = `${Date.now()}-${Math.floor(Math.random() * 10000)}`;

    // 1. Create dedicated testing tenant
    const tenantRes = await app.inject({
      method: 'POST',
      url: '/api/v1/tenants',
      payload: {
        name: `Scope Attestation Corp ${suffix}`,
        slug: `scope-corp-${suffix}`,
        plan: 'enterprise',
      },
    });
    expect(tenantRes.statusCode).toBe(201);
    tenant = tenantRes.json().data;

    // 2. Create Project and Target
    const projectRes = await app.inject({
      method: 'POST',
      url: '/api/v1/projects',
      headers: { 'x-tenant-id': tenant.id },
      payload: { name: `Scope Project ${suffix}`, description: 'Phase 16.5' },
    });
    expect(projectRes.statusCode).toBe(201);
    projectId = projectRes.json().data.id;

    const targetRes = await app.inject({
      method: 'POST',
      url: `/api/v1/projects/${projectId}/targets`,
      headers: { 'x-tenant-id': tenant.id },
      payload: {
        name: `Authorized Target ${suffix}`,
        baseUrl: mockTargetUrl,
        environment: 'staging',
        criticality: 'high',
        allowedHosts: ['127.0.0.1'],
        allowedPorts: [mockTargetPort],
        excludedPaths: [],
        testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
        limits: { maxRps: 50, maxConcurrency: 5, maxDuration: '2m' },
      },
    });
    expect(targetRes.statusCode).toBe(201);
    targetId = targetRes.json().data.id;

    // 3. Create TEK
    const tekRes = await app.inject({
      method: 'POST',
      url: `/api/v1/tenants/${tenant.id}/enrollment-keys`,
      payload: { name: `Scope TEK ${suffix}`, expiresInDays: 30 },
    });
    expect(tekRes.statusCode).toBe(201);
    tekToken = tekRes.json().data.key;

    // 4. Enroll Agent
    agentClient = new AgentClient(controllerUrl);
    const regData = await agentClient.register(
      {
        name: `scope-agent-${suffix}`,
        capabilities: ['engine-native-headers', 'engine-port-scanner'],
        tags: ['vpc-secure'],
        systemInfo: { os: 'linux', arch: 'x64', nodeVersion: 'v20.0.0', cpuCount: 8, totalMemoryMb: 16384 },
      },
      tekToken,
    );
    agentId = regData.agentId;
    _agentToken = regData.token;
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
    if (mockTargetServer) {
      await new Promise<void>((resolve, reject) => {
        mockTargetServer.close((err) => (err ? reject(err) : resolve()));
      });
    }
    await closeDatabase();
  });

  it('1. Controller signs target scope upon dispatch and worker verifies signature successfully', async () => {
    const testRunId = await createTestRun();
    const jobId = await dispatchJob(testRunId);

    const [job] = await agentClient.poll(agentId, ['engine-native-headers'], [], 1);
    expect(job).toBeDefined();
    expect(job.jobId).toBe(jobId);
    expect(job.target.scopeSignature).toBeDefined();
    expect(typeof job.target.scopeSignature).toBe('string');
    expect(job.target.scopeSignature!.length).toBe(64); // SHA-256 hex string

    // Worker executes legitimate job cleanly without error
    const worker = new AgentWorker(agentClient, { allowLocalTesting: true });
    await expect(worker.executeJob(job)).resolves.not.toThrow();

    // Verify test run in controller is now completed
    const runRes = await app.inject({
      method: 'GET',
      url: `/api/v1/test-runs/${testRunId}`,
    });
    expect(runRes.statusCode).toBe(200);
    expect(runRes.json().data.status).toBe('completed');
  });

  it('2. Rule 10: Modifying allowedHosts in job scope triggers ScopeTamperingError before network socket open', async () => {
    const testRunId = await createTestRun();
    await dispatchJob(testRunId);

    const [job] = await agentClient.poll(agentId, ['engine-native-headers'], [], 1);
    expect(job).toBeDefined();

    // Adversary attempts scope expansion by injecting unauthorized subnet into allowedHosts
    const tamperedScope = {
      ...job.target.scope,
      allowedHosts: ['127.0.0.1', '10.0.0.0/8', 'attacker-controlled.net'],
    };

    const tamperedJob = {
      ...job,
      target: {
        ...job.target,
        scope: tamperedScope,
      },
    };

    const worker = new AgentWorker(agentClient, { allowLocalTesting: true });
    await expect(worker.executeJob(tamperedJob)).rejects.toThrow(ScopeTamperingError);
  });

  it('3. Rule 9: Modifying target baseUrl in job triggers ScopeTamperingError', async () => {
    const testRunId = await createTestRun();
    await dispatchJob(testRunId);

    const [job] = await agentClient.poll(agentId, ['engine-native-headers'], [], 1);
    expect(job).toBeDefined();

    // Adversary points probe to another URL while leaving scopeSignature untouched
    const tamperedJob = {
      ...job,
      target: {
        ...job.target,
        baseUrl: 'http://victim.internal.private:8080',
      },
    };

    const worker = new AgentWorker(agentClient, { allowLocalTesting: true });
    await expect(worker.executeJob(tamperedJob)).rejects.toThrow(ScopeTamperingError);
  });

  it('4. Rule 4: Forged or invalid scope signature triggers ScopeTamperingError', async () => {
    const testRunId = await createTestRun();
    await dispatchJob(testRunId);

    const [job] = await agentClient.poll(agentId, ['engine-native-headers'], [], 1);
    expect(job).toBeDefined();

    const tamperedJob = {
      ...job,
      target: {
        ...job.target,
        scopeSignature: 'badc0ffee0000000000000000000000000000000000000000000000000000000',
      },
    };

    const worker = new AgentWorker(agentClient, { allowLocalTesting: true });
    await expect(worker.executeJob(tamperedJob)).rejects.toThrow(ScopeTamperingError);
  });

  it('5. Missing scope signature triggers ScopeTamperingError', async () => {
    const testRunId = await createTestRun();
    await dispatchJob(testRunId);

    const [job] = await agentClient.poll(agentId, ['engine-native-headers'], [], 1);
    expect(job).toBeDefined();

    const unsignedJob = {
      ...job,
      target: {
        ...job.target,
        scopeSignature: undefined,
      },
    };

    const worker = new AgentWorker(agentClient, { allowLocalTesting: true });
    await expect(worker.executeJob(unsignedJob)).rejects.toThrow(ScopeTamperingError);
  });

  it('6. Rule 16: In-agent SSRF defense blocks AWS/Azure IMDS metadata (169.254.169.254) even with signed scope', async () => {
    const testRunId = await createTestRun();
    await dispatchJob(testRunId);

    const [job] = await agentClient.poll(agentId, ['engine-native-headers'], [], 1);
    expect(job).toBeDefined();

    // Even if an attacker had a controller-signed scope for cloud metadata
    const metadataBaseUrl = 'http://169.254.169.254/latest/meta-data/';
    const metadataScope = {
      allowedHosts: ['169.254.169.254'],
      allowedPorts: [80],
      excludedPaths: [],
      testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
      limits: { maxRps: 10, maxConcurrency: 1, maxDuration: '1m' },
    };

    const scopeSignature = computeScopeSignature(job.target.id, metadataBaseUrl, metadataScope);

    const maliciousJob = {
      ...job,
      target: {
        ...job.target,
        baseUrl: metadataBaseUrl,
        scope: metadataScope,
        scopeSignature,
      },
    };

    const worker = new AgentWorker(agentClient, { allowLocalTesting: true });
    await expect(worker.executeJob(maliciousJob)).rejects.toThrow(SecurityBoundaryError);
  });

  it('7. Rule 16: In-agent SSRF defense blocks Google Cloud metadata (metadata.google.internal)', async () => {
    const testRunId = await createTestRun();
    await dispatchJob(testRunId);

    const [job] = await agentClient.poll(agentId, ['engine-native-headers'], [], 1);
    expect(job).toBeDefined();

    const gcpMetadataUrl = 'http://metadata.google.internal/computeMetadata/v1/';
    const gcpScope = {
      allowedHosts: ['metadata.google.internal'],
      allowedPorts: [80],
      excludedPaths: [],
      testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
      limits: { maxRps: 10, maxConcurrency: 1, maxDuration: '1m' },
    };

    const scopeSignature = computeScopeSignature(job.target.id, gcpMetadataUrl, gcpScope);

    const maliciousJob = {
      ...job,
      target: {
        ...job.target,
        baseUrl: gcpMetadataUrl,
        scope: gcpScope,
        scopeSignature,
      },
    };

    const worker = new AgentWorker(agentClient, { allowLocalTesting: true });
    await expect(worker.executeJob(maliciousJob)).rejects.toThrow(SecurityBoundaryError);
  });

  it('8. Rule 16: In-agent SSRF defense blocks alternative decimal IP encoding of metadata (2852039166)', async () => {
    const testRunId = await createTestRun();
    await dispatchJob(testRunId);

    const [job] = await agentClient.poll(agentId, ['engine-native-headers'], [], 1);
    expect(job).toBeDefined();

    // 2852039166 is decimal notation for 169.254.169.254
    const decimalMetadataUrl = 'http://2852039166/latest/meta-data/';
    const decimalScope = {
      allowedHosts: ['2852039166'],
      allowedPorts: [80],
      excludedPaths: [],
      testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
      limits: { maxRps: 10, maxConcurrency: 1, maxDuration: '1m' },
    };

    const scopeSignature = computeScopeSignature(job.target.id, decimalMetadataUrl, decimalScope);

    const maliciousJob = {
      ...job,
      target: {
        ...job.target,
        baseUrl: decimalMetadataUrl,
        scope: decimalScope,
        scopeSignature,
      },
    };

    const worker = new AgentWorker(agentClient, { allowLocalTesting: true });
    await expect(worker.executeJob(maliciousJob)).rejects.toThrow(SecurityBoundaryError);
  });

  it('9. Rule 16: In-agent SSRF defense blocks IPv6 AWS IMDS metadata (fd00:ec2::254)', async () => {
    const testRunId = await createTestRun();
    await dispatchJob(testRunId);

    const [job] = await agentClient.poll(agentId, ['engine-native-headers'], [], 1);
    expect(job).toBeDefined();

    const ipv6MetadataUrl = 'http://[fd00:ec2::254]/latest/meta-data/';
    const ipv6Scope = {
      allowedHosts: ['fd00:ec2::254'],
      allowedPorts: [80],
      excludedPaths: [],
      testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
      limits: { maxRps: 10, maxConcurrency: 1, maxDuration: '1m' },
    };

    const scopeSignature = computeScopeSignature(job.target.id, ipv6MetadataUrl, ipv6Scope);

    const maliciousJob = {
      ...job,
      target: {
        ...job.target,
        baseUrl: ipv6MetadataUrl,
        scope: ipv6Scope,
        scopeSignature,
      },
    };

    const worker = new AgentWorker(agentClient, { allowLocalTesting: true });
    await expect(worker.executeJob(maliciousJob)).rejects.toThrow(SecurityBoundaryError);
  });

  it('10. Rule 16: In-agent SSRF defense blocks Alibaba Cloud metadata (100.100.100.200)', async () => {
    const testRunId = await createTestRun();
    await dispatchJob(testRunId);

    const [job] = await agentClient.poll(agentId, ['engine-native-headers'], [], 1);
    expect(job).toBeDefined();

    const alibabaMetadataUrl = 'http://100.100.100.200/latest/meta-data/';
    const alibabaScope = {
      allowedHosts: ['100.100.100.200'],
      allowedPorts: [80],
      excludedPaths: [],
      testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
      limits: { maxRps: 10, maxConcurrency: 1, maxDuration: '1m' },
    };

    const scopeSignature = computeScopeSignature(job.target.id, alibabaMetadataUrl, alibabaScope);

    const maliciousJob = {
      ...job,
      target: {
        ...job.target,
        baseUrl: alibabaMetadataUrl,
        scope: alibabaScope,
        scopeSignature,
      },
    };

    const worker = new AgentWorker(agentClient, { allowLocalTesting: true });
    await expect(worker.executeJob(maliciousJob)).rejects.toThrow(SecurityBoundaryError);
  });

  it('11. Host local loopback is prohibited when allowLocalTesting is false', async () => {
    const testRunId = await createTestRun();
    await dispatchJob(testRunId);

    const [job] = await agentClient.poll(agentId, ['engine-native-headers'], [], 1);
    expect(job).toBeDefined();

    // Default or strict production agent without --allow-local-testing flag
    const strictWorker = new AgentWorker(agentClient, { allowLocalTesting: false });

    // Job targets localhost / 127.0.0.1
    await expect(strictWorker.executeJob(job)).rejects.toThrow(SecurityBoundaryError);
  });

  it('12. In-agent defense blocks scope if allowedHosts specifies cloud metadata endpoints', async () => {
    const testRunId = await createTestRun();
    await dispatchJob(testRunId);

    const [job] = await agentClient.poll(agentId, ['engine-native-headers'], [], 1);
    expect(job).toBeDefined();

    const scopeWithMetadata = {
      ...job.target.scope,
      allowedHosts: ['127.0.0.1', '169.254.169.254'],
    };

    const scopeSignature = computeScopeSignature(job.target.id, job.target.baseUrl, scopeWithMetadata);

    const tamperedJob = {
      ...job,
      target: {
        ...job.target,
        scope: scopeWithMetadata,
        scopeSignature,
      },
    };

    const worker = new AgentWorker(agentClient, { allowLocalTesting: true });
    await expect(worker.executeJob(tamperedJob)).rejects.toThrow(SecurityBoundaryError);
  });
});
