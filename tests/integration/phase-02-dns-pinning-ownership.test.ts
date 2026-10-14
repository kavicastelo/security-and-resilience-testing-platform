import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import dns from 'node:dns/promises';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../apps/controller/src/app/index.js';
import {
  createDnsPinningLookup,
  DnsPinningCache,
} from '@security-lab/scope-engine';
import {
  TargetCircuitBreaker,
  TargetCircuitBreakerOpenError,
} from '@security-lab/test-runner';

describe('Phase 02: Advanced Target Scope, DNS Pinning & Ownership Verification', () => {
  let app: FastifyInstance;
  let testProjectId: string;
  const adminApiKey = 'sec-key-admin-test-token-0000000000000000';

  beforeAll(async () => {
    app = await buildApp({ logger: false });
    await app.ready();

    // Create a parent test project
    const projRes = await app.inject({
      method: 'POST',
      url: '/api/v1/projects',
      headers: {
        'x-api-key': adminApiKey,
      },
      payload: {
        name: `Phase 02 Verification Project ${Date.now()}`,
      },
    });

    expect(projRes.statusCode).toBe(201);
    const projBody = JSON.parse(projRes.payload);
    testProjectId = projBody.data.id;
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  describe('Objective 1 & 2: Pre-Socket DNS Pinning & SSRF/Rebinding Defense', () => {
    it('rejects cloud metadata IP (169.254.169.254) before socket connection', async () => {
      const mockResolver = async () => ['169.254.169.254'];
      const lookup = createDnsPinningLookup({
        dnsResolver: mockResolver,
        allowPrivateIps: false,
        allowLoopback: false,
      });

      await expect(
        new Promise((resolve, reject) => {
          lookup('meta-data.attacker.com', { family: 4 }, (err, address, family) => {
            if (err) return reject(err);
            resolve({ address, family });
          });
        }),
      ).rejects.toThrow(/cloud metadata/i);
    });

    it('rejects loopback addresses (127.0.0.1) when allowLoopback is false', async () => {
      const mockResolver = async () => ['127.0.0.1'];
      const lookup = createDnsPinningLookup({
        dnsResolver: mockResolver,
        allowLoopback: false,
        allowPrivateIps: false,
      });

      await expect(
        new Promise((resolve, reject) => {
          lookup('rebound-to-localhost.example.com', { family: 4 }, (err, address, family) => {
            if (err) return reject(err);
            resolve({ address, family });
          });
        }),
      ).rejects.toThrow(/loopback/i);
    });

    it('rejects private RFC-1918 addresses (10.0.0.1, 192.168.1.50) when allowPrivateIps is false', async () => {
      const mockResolver = async () => ['10.0.1.5'];
      const lookup = createDnsPinningLookup({
        dnsResolver: mockResolver,
        allowPrivateIps: false,
      });

      await expect(
        new Promise((resolve, reject) => {
          lookup('internal-service.example.com', { family: 4 }, (err, address, family) => {
            if (err) return reject(err);
            resolve({ address, family });
          });
        }),
      ).rejects.toThrow(/private/i);
    });

    it('allows valid public IP and pins the resolved address for the request lifecycle', async () => {
      const mockResolver = vi.fn(async () => ['93.184.216.34']);
      const cache = new DnsPinningCache();
      const lookup = createDnsPinningLookup({
        dnsResolver: mockResolver,
        cache,
        allowPrivateIps: false,
      });

      // First lookup resolves via resolver and caches
      const firstResult = await new Promise<{ address: string; family: number }>((resolve, reject) => {
        lookup('example.com', { family: 4 }, (err, address, family) => {
          if (err) return reject(err);
          resolve({ address: String(address), family: Number(family) });
        });
      });

      expect(firstResult.address).toBe('93.184.216.34');
      expect(mockResolver).toHaveBeenCalledTimes(1);

      // Second lookup uses pinned cache
      const secondResult = await new Promise<{ address: string; family: number }>((resolve, reject) => {
        lookup('example.com', { family: 4 }, (err, address, family) => {
          if (err) return reject(err);
          resolve({ address: String(address), family: Number(family) });
        });
      });

      expect(secondResult.address).toBe('93.184.216.34');
      expect(mockResolver).toHaveBeenCalledTimes(1); // Not called again
    });
  });

  describe('Objective 4: Target Rate-Limiting Adaptive Circuit Breaker', () => {
    it('stays CLOSED when 5xx error rate is below threshold', () => {
      const breaker = new TargetCircuitBreaker({
        slidingWindowSize: 10,
        errorThresholdPercent: 25,
        targetKey: 'test-target-1',
      });

      // 8 successes (200), 2 errors (500) = 20% error rate (< 25%)
      for (let i = 0; i < 8; i++) breaker.recordResponse(200);
      for (let i = 0; i < 2; i++) breaker.recordResponse(500);

      expect(breaker.getState()).toBe('CLOSED');
      expect(breaker.canRequest()).toBe(true);
      expect(breaker.getStats().errorRatePercent).toBe(20);
    });

    it('trips to OPEN when 5xx error rate reaches or exceeds 25% over sliding window', () => {
      const breaker = new TargetCircuitBreaker({
        slidingWindowSize: 10,
        errorThresholdPercent: 25,
        targetKey: 'test-target-2',
      });

      // 7 successes (200), 3 errors (502) = 30% error rate (>= 25%)
      for (let i = 0; i < 7; i++) breaker.recordResponse(200);
      for (let i = 0; i < 3; i++) breaker.recordResponse(502);

      expect(breaker.getState()).toBe('OPEN');
      expect(breaker.canRequest()).toBe(false);
      expect(breaker.getStats().errorRatePercent).toBe(30);

      // Subsequent request attempt throws TargetCircuitBreakerOpenError
      expect(() => breaker.checkExecution()).toThrow(TargetCircuitBreakerOpenError);
    });

    it('transitions to HALF_OPEN after cooldown window expires and recovers on success', async () => {
      const breaker = new TargetCircuitBreaker({
        slidingWindowSize: 10,
        errorThresholdPercent: 25,
        cooldownSeconds: 0.05, // 50ms cooldown for test speed
        halfOpenSuccessThreshold: 1,
        targetKey: 'test-target-3',
      });

      // Trip breaker
      for (let i = 0; i < 6; i++) breaker.recordResponse(200);
      for (let i = 0; i < 4; i++) breaker.recordResponse(503);
      expect(breaker.getState()).toBe('OPEN');

      // Wait 70ms for cooldown
      await new Promise((resolve) => setTimeout(resolve, 70));

      expect(breaker.getState()).toBe('HALF_OPEN');
      expect(breaker.canRequest()).toBe(true);

      // Probing request succeeds (200 OK)
      breaker.recordResponse(200);
      expect(breaker.getState()).toBe('CLOSED');
    });
  });

  describe('Objective 3: Target Ownership Challenges & Scheduler Enforcement', () => {
    let localTargetId: string;
    let externalTargetId: string;

    it('automatically marks localhost / loopback targets as VERIFIED with LOCAL_OVERRIDE', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/projects/${testProjectId}/targets`,
        headers: { 'x-api-key': adminApiKey },
        payload: {
          name: 'Local Dev Target',
          baseUrl: 'http://localhost:8080',
          allowedHosts: ['localhost'],
          allowedPorts: [8080],
          testing: { activeScanning: true, loadTesting: true, chaosTesting: false },
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.verificationStatus).toBe('VERIFIED');
      expect(body.data.verificationMethod).toBe('LOCAL_OVERRIDE');
      expect(body.data.verifiedAt).toBeDefined();
      localTargetId = body.data.id;
    });

    it('registers external target in PENDING verification status with generated challenge token', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/projects/${testProjectId}/targets`,
        headers: { 'x-api-key': adminApiKey },
        payload: {
          name: 'Production Cloud Target',
          baseUrl: 'https://security-audit.example.com',
          allowedHosts: ['security-audit.example.com'],
          allowedPorts: [443],
          testing: { activeScanning: true, loadTesting: true, chaosTesting: false },
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.verificationStatus).toBe('PENDING');
      expect(body.data.verificationToken).toMatch(/^sec-[a-f0-9]{56}$/);
      expect(body.data.verifiedAt).toBeNull();
      externalTargetId = body.data.id;
    });

    it('GET /api/v1/targets/:id/challenge returns DNS TXT and HTTP well-known instructions', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/targets/${externalTargetId}/challenge`,
        headers: { 'x-api-key': adminApiKey },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.token).toBeDefined();
      expect(body.data.status).toBe('PENDING');
      expect(body.data.dns.recordType).toBe('TXT');
      expect(body.data.dns.recordName).toBe('_security-lab-challenge.security-audit.example.com');
      expect(body.data.dns.recordValue).toBe(body.data.token);
      expect(body.data.http.url).toBe(
        'https://security-audit.example.com/.well-known/security-lab-challenge.txt',
      );
      expect(body.data.http.expectedContent).toBe(body.data.token);
    });

    it('blocks active scanning test run against unverified external target with TARGET_UNVERIFIED', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        headers: { 'x-api-key': adminApiKey },
        payload: {
          projectId: testProjectId,
          targetId: externalTargetId,
          profileId: 'active-scan',
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('TARGET_UNVERIFIED');
      expect(body.error.message).toMatch(/verified ownership/i);
    });

    it('permits active scanning test run against verified localhost target', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        headers: { 'x-api-key': adminApiKey },
        payload: {
          projectId: testProjectId,
          targetId: localTargetId,
          profileId: 'active-scan',
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.payload);
      expect(body.success).toBe(true);
      expect(body.data.id).toBeDefined();
      expect(body.data.status).toBe('queued');
    });

    it('POST /api/v1/targets/:id/verify verifies target ownership when DNS TXT matches token', async () => {
      // Get challenge instructions to obtain expected token
      const chalRes = await app.inject({
        method: 'GET',
        url: `/api/v1/targets/${externalTargetId}/challenge`,
        headers: { 'x-api-key': adminApiKey },
      });
      const chalBody = JSON.parse(chalRes.payload);
      const expectedToken = chalBody.data.token;

      // Mock DNS TXT resolution to simulate valid DNS challenge response
      const resolveTxtSpy = vi.spyOn(dns, 'resolveTxt').mockResolvedValue([[expectedToken]]);

      try {
        const verifyRes = await app.inject({
          method: 'POST',
          url: `/api/v1/targets/${externalTargetId}/verify`,
          headers: { 'x-api-key': adminApiKey },
          payload: { method: 'DNS_TXT' },
        });

        expect(verifyRes.statusCode).toBe(200);
        const verifyBody = JSON.parse(verifyRes.payload);
        expect(verifyBody.success).toBe(true);
        expect(verifyBody.data.verified).toBe(true);
        expect(verifyBody.data.status).toBe('VERIFIED');
        expect(verifyBody.data.method).toBe('DNS_TXT');

        // Confirm target now has VERIFIED status
        const targetRes = await app.inject({
          method: 'GET',
          url: `/api/v1/targets/${externalTargetId}`,
          headers: { 'x-api-key': adminApiKey },
        });
        const targetBody = JSON.parse(targetRes.payload);
        expect(targetBody.data.verificationStatus).toBe('VERIFIED');
        expect(targetBody.data.verificationMethod).toBe('DNS_TXT');

        // Now active scanning test run is permitted for this target!
        const runRes = await app.inject({
          method: 'POST',
          url: '/api/v1/test-runs',
          headers: { 'x-api-key': adminApiKey },
          payload: {
            projectId: testProjectId,
            targetId: externalTargetId,
            profileId: 'active-scan',
          },
        });

        expect(runRes.statusCode).toBe(201);
        const runBody = JSON.parse(runRes.payload);
        expect(runBody.success).toBe(true);
        expect(runBody.data.status).toBe('queued');
      } finally {
        resolveTxtSpy.mockRestore();
      }
    });

    it('POST /api/v1/targets/:id/verify fails with 422 when challenge verification fails', async () => {
      // Create another external target that won't have matching DNS/HTTP
      const createRes = await app.inject({
        method: 'POST',
        url: `/api/v1/projects/${testProjectId}/targets`,
        headers: { 'x-api-key': adminApiKey },
        payload: {
          name: 'Failing Target',
          baseUrl: 'https://unreachable-challenge.example.com',
          allowedHosts: ['unreachable-challenge.example.com'],
          allowedPorts: [443],
          testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
        },
      });
      const failingTargetId = JSON.parse(createRes.payload).data.id;

      const verifyRes = await app.inject({
        method: 'POST',
        url: `/api/v1/targets/${failingTargetId}/verify`,
        headers: { 'x-api-key': adminApiKey },
        payload: { method: 'AUTO' },
      });

      expect(verifyRes.statusCode).toBe(422);
      const verifyBody = JSON.parse(verifyRes.payload);
      expect(verifyBody.success).toBe(false);
      expect(verifyBody.error.code).toBe('OWNERSHIP_VERIFICATION_FAILED');
    });
  });
});
