import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { FastifyInstance } from 'fastify';

const mockLeaseRow = {
  job: {
    id: 'job-lease-123',
    agentId: 'agt-test-worker-1',
    tenantId: 'tenant-1',
    testRunId: 'run-999',
    status: 'leased',
    leaseId: 'lease-uuid-456',
    leaseExpiresAt: new Date(Date.now() + 180000),
    dispatchedAt: new Date(Date.now() - 30000),
    createdAt: new Date(Date.now() - 30000),
    payload: {
      target: {
        name: 'Production Ingress Gateway',
        baseUrl: 'https://gateway.internal',
      },
      engineIds: ['engine-native-load'],
    },
    error: null,
  },
  agent: {
    id: 'agt-test-worker-1',
    name: 'worker-us-east-1',
  },
};

vi.mock('../../apps/controller/src/services/db.js', () => {
  const db = {
    insert: vi.fn(() => ({
      values: vi.fn(() => ({
        returning: vi.fn().mockResolvedValue([{ id: 'tenant-1' }]),
      })),
    })),
    select: vi.fn(() => ({
      from: vi.fn(() => ({
        leftJoin: vi.fn(() => ({
          where: vi.fn(() => ({
            orderBy: vi.fn().mockImplementation(() => {
              return Promise.resolve([mockLeaseRow]);
            }),
          })),
        })),
        where: vi.fn(() => ({
          limit: vi.fn().mockResolvedValue([]),
          then: (resolve: any, reject: any) => Promise.resolve([]).then(resolve, reject),
        })),
        limit: vi.fn().mockResolvedValue([]),
        then: (resolve: any, reject: any) => Promise.resolve([]).then(resolve, reject),
      })),
    })),
  };
  return {
    getDatabase: () => ({ db }),
    closeDatabase: vi.fn(),
  };
});

import { buildApp } from '../../apps/controller/src/app/index.js';
import { webhookQueueService } from '../../apps/controller/src/services/webhook-queue.js';
import { signJwt, DEFAULT_WORKSPACE_ID } from '../../apps/controller/src/services/auth-token.service.js';

describe('PR-07 Integration: Agent Fleet Leases Query Controller API', () => {
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
      userId: 'test-fleet-operator',
      workspaceId: DEFAULT_WORKSPACE_ID,
      role: 'engineer',
    });
  });

  afterAll(async () => {
    webhookQueueService.stopWorker();
    await app.close();
  });

  it('queries active agent job leases via GET /api/v1/agents/leases', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/agents/leases',
      headers: {
        authorization: `Bearer ${authToken}`,
      },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.success).toBe(true);
    expect(Array.isArray(body.data)).toBe(true);
    expect(body.data.length).toBe(1);

    const lease = body.data[0];
    expect(lease.jobId).toBe('job-lease-123');
    expect(lease.leaseId).toBe('lease-uuid-456');
    expect(lease.assignedAgentId).toBe('agt-test-worker-1');
    expect(lease.assignedAgentName).toBe('worker-us-east-1');
    expect(lease.targetName).toBe('Production Ingress Gateway');
    expect(lease.targetUrl).toBe('https://gateway.internal');
    expect(lease.engines).toEqual(['engine-native-load']);
    expect(lease.status).toBe('leased');
  });

  it('supports filtering leases by agentId parameter', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/agents/leases?agentId=agt-test-worker-1',
      headers: {
        authorization: `Bearer ${authToken}`,
      },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.success).toBe(true);
    expect(Array.isArray(body.data)).toBe(true);
  });
});
