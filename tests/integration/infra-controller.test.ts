import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { webhookQueueService } from '../../apps/controller/src/services/webhook-queue.js';
import { signJwt, DEFAULT_WORKSPACE_ID } from '../../apps/controller/src/services/auth-token.service.js';

describe('PR-03 Integration: Infrastructure & Supply Chain Engine Controller APIs', () => {
  let app: FastifyInstance;
  let authToken: string;

  beforeAll(async () => {
    app = buildApp({
      disableLogging: true,
      enableReaper: false,
      bypassAuth: false,
    });
    await app.ready();

    authToken = signJwt({
      userId: 'test-engineer-pr03',
      workspaceId: DEFAULT_WORKSPACE_ID,
      role: 'engineer',
    });
  });

  afterAll(async () => {
    webhookQueueService.stopWorker();
    await app.close();
  });

  const SAMPLE_K8S_MANIFEST = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-service
  namespace: production-core
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: processor
          image: payments:2.0.0
          securityContext:
            privileged: true
            runAsRoot: true
`;

  const SAMPLE_CYCLONEDX_SBOM = JSON.stringify({
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: {
      component: {
        name: 'core-api',
        version: '1.0.0',
      },
    },
    components: [
      {
        name: 'jsonwebtoken',
        version: '8.5.1',
        purl: 'pkg:npm/jsonwebtoken@8.5.1',
        licenses: [{ license: { id: 'MIT' } }],
      },
      {
        name: 'gpl-util-package',
        version: '1.0.0',
        purl: 'pkg:npm/gpl-util-package@1.0.0',
        licenses: [{ license: { id: 'AGPL-3.0-only' } }],
      },
    ],
  });

  it('GET /api/v1/infra/overview returns clean baseline posture before audits', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/infra/overview',
      headers: {
        authorization: `Bearer ${authToken}`,
      },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(body.data.k8s).toBeDefined();
    expect(body.data.sbom).toBeDefined();
    expect(body.data.smuggling).toBeDefined();
    expect(body.data.database).toBeDefined();
  });

  it('POST /api/v1/infra/k8s/audit invokes K8sInfraAuditEngine and flags privileged workloads', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/infra/k8s/audit',
      headers: {
        authorization: `Bearer ${authToken}`,
        'content-type': 'application/json',
      },
      payload: {
        manifestYaml: SAMPLE_K8S_MANIFEST,
      },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(body.data.totalWorkloads).toBe(1);
    expect(body.data.workloads[0].name).toBe('payment-service');
    expect(body.data.workloads[0].hasPrivilegedContainer).toBe(true);
    expect(body.data.workloads[0].runsAsRoot).toBe(true);
    expect(body.data.workloads[0].findings.length).toBeGreaterThan(0);
    expect(body.data.pssDistribution.privileged).toBe(1);
  });

  it('POST /api/v1/infra/sbom/audit invokes SbomSupplyChainEngine and evaluates components and licenses', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/infra/sbom/audit',
      headers: {
        authorization: `Bearer ${authToken}`,
        'content-type': 'application/json',
      },
      payload: {
        sbomJson: SAMPLE_CYCLONEDX_SBOM,
        format: 'cyclonedx',
      },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(body.data.totalComponents).toBe(2);
    expect(body.data.components.some((c: any) => c.name === 'jsonwebtoken')).toBe(true);
  });

  it('POST /api/v1/infra/smuggling/probe validates targetUrl and evaluates wire variants', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/infra/smuggling/probe',
      headers: {
        authorization: `Bearer ${authToken}`,
        'content-type': 'application/json',
      },
      payload: {
        targetUrl: 'http://localhost:8080',
        variants: ['CL_TE', 'TE_CL'],
      },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(body.data.targetHost).toBe('localhost');
    expect(body.data.testedVariantsCount).toBe(2);
    expect(body.data.variants.length).toBe(2);
  });

  it('POST /api/v1/infra/smuggling/probe rejects invalid URLs with 400', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/infra/smuggling/probe',
      headers: {
        authorization: `Bearer ${authToken}`,
        'content-type': 'application/json',
      },
      payload: {
        targetUrl: 'invalid-not-a-url',
      },
    });

    expect(res.statusCode).toBe(400);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(false);
  });

  it('POST /api/v1/infra/database/audit audits database security posture', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/infra/database/audit',
      headers: {
        authorization: `Bearer ${authToken}`,
        'content-type': 'application/json',
      },
      payload: {
        engine: 'postgres',
        connectionString: 'postgres://postgres:postgres@127.0.0.1:5432/testdb',
      },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(body.data.totalDatabasesChecked).toBe(1);
    expect(body.data.probes[0].databaseType).toBe('POSTGRES');
  });

  it('GET /api/v1/infra/overview returns live cached records following engine execution', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/infra/overview',
      headers: {
        authorization: `Bearer ${authToken}`,
      },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.success).toBe(true);
    expect(body.data.k8s.totalWorkloads).toBe(1);
    expect(body.data.sbom.totalComponents).toBe(2);
    expect(body.data.smuggling.testedVariantsCount).toBe(2);
    expect(body.data.database.totalDatabasesChecked).toBe(1);
  });
});
