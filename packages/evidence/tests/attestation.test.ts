import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  computeJobDispatchSecret,
  deriveJobLeaseSecret,
  signJobLeaseToken,
  verifyJobLeaseToken,
  computeFindingsHash,
  computeResultSignature,
  verifyResultSignature,
  computeScopeSignature,
  createAgentAttestation,
  verifyScopeSignature,
  verifyAgentAttestation,
  verifyWithRotationSupport,
  getMasterKey,
  getPreviousMasterKey,
  AttestationConfigurationError,
} from '../src/attestation.js';

describe('Local Cryptographic Attestation Secret Hardening (REM-03)', () => {
  const primarySecret = 'primary-super-secret-key-32chars-long-abc';
  const previousSecret = 'previous-old-secret-key-32chars-long-xyz';
  const rogueSecret = 'unauthorized-secret-key-32chars-long-evil';

  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env.AGENT_MASTER_SECRET = primarySecret;
    delete process.env.AGENT_MASTER_SECRET_PREVIOUS;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  describe('1. Secret Resolution & Fail-Closed Enforcement', () => {
    it('resolves valid configured AGENT_MASTER_SECRET in environment', () => {
      process.env.AGENT_MASTER_SECRET = primarySecret;
      expect(getMasterKey()).toBe(primarySecret);
    });

    it('honors explicitly supplied programmatic secret parameter', () => {
      const explicit = 'custom-explicit-key-at-least-32-chars-long';
      expect(getMasterKey(explicit)).toBe(explicit);
    });

    it('throws AttestationConfigurationError in production mode if AGENT_MASTER_SECRET is missing', () => {
      process.env.NODE_ENV = 'production';
      delete process.env.AGENT_MASTER_SECRET;

      expect(() => getMasterKey()).toThrow(AttestationConfigurationError);
      expect(() => getMasterKey()).toThrow(/Missing or invalid AGENT_MASTER_SECRET/);
    });

    it('throws AttestationConfigurationError in production mode if AGENT_MASTER_SECRET is shorter than 32 chars', () => {
      process.env.NODE_ENV = 'production';
      process.env.AGENT_MASTER_SECRET = 'short-secret';

      expect(() => getMasterKey()).toThrow(AttestationConfigurationError);
    });

    it('throws AttestationConfigurationError in production mode if explicit key is shorter than 32 chars', () => {
      process.env.NODE_ENV = 'production';
      expect(() => getMasterKey('too-short')).toThrow(AttestationConfigurationError);
    });

    it('resolves previous key when AGENT_MASTER_SECRET_PREVIOUS is configured', () => {
      process.env.AGENT_MASTER_SECRET_PREVIOUS = previousSecret;
      expect(getPreviousMasterKey()).toBe(previousSecret);
    });

    it('returns undefined when AGENT_MASTER_SECRET_PREVIOUS is unset', () => {
      delete process.env.AGENT_MASTER_SECRET_PREVIOUS;
      expect(getPreviousMasterKey()).toBeUndefined();
    });
  });

  describe('2. Target Scope Attestation & Tamper Detection', () => {
    const target = {
      id: 'target-123',
      baseUrl: 'http://internal.service.local:8080',
      scope: {
        allowedHosts: ['internal.service.local'],
        allowedPorts: [8080],
        testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
      },
    };

    it('generates valid RFC 8785 canonical scope signature and verifies successfully', () => {
      const signature = computeScopeSignature(target.id, target.baseUrl, target.scope);
      expect(signature).toBeDefined();
      expect(typeof signature).toBe('string');
      expect(signature.length).toBe(64); // SHA-256 hex string

      const isValid = verifyScopeSignature({
        targetId: target.id,
        baseUrl: target.baseUrl,
        scope: target.scope,
        signature,
      });

      expect(isValid).toBe(true);
    });

    it('createAgentAttestation and verifyAgentAttestation operate as valid aliases', () => {
      const signature = createAgentAttestation({
        targetId: target.id,
        baseUrl: target.baseUrl,
        scope: target.scope,
        masterKey: primarySecret,
      });

      const isValid = verifyAgentAttestation({
        targetId: target.id,
        baseUrl: target.baseUrl,
        scope: target.scope,
        signature,
        masterKey: primarySecret,
      });

      expect(isValid).toBe(true);
    });

    it('rejects attestation when 1 byte is tampered in target baseUrl', () => {
      const signature = computeScopeSignature(target.id, target.baseUrl, target.scope);

      const isValid = verifyScopeSignature({
        targetId: target.id,
        baseUrl: 'http://internal.service.local:8081', // Tampered port
        scope: target.scope,
        signature,
      });

      expect(isValid).toBe(false);
    });

    it('rejects attestation when scope boundaries are expanded or modified', () => {
      const signature = computeScopeSignature(target.id, target.baseUrl, target.scope);

      const tamperedScope = {
        ...target.scope,
        allowedHosts: ['internal.service.local', '169.254.169.254'], // SSRF injection
      };

      const isValid = verifyScopeSignature({
        targetId: target.id,
        baseUrl: target.baseUrl,
        scope: tamperedScope,
        signature,
      });

      expect(isValid).toBe(false);
    });

    it('rejects attestation when signed with an unauthorized/different key', () => {
      const rogueSignature = computeScopeSignature(
        target.id,
        target.baseUrl,
        target.scope,
        rogueSecret,
      );

      const isValid = verifyScopeSignature({
        targetId: target.id,
        baseUrl: target.baseUrl,
        scope: target.scope,
        signature: rogueSignature,
        masterKey: primarySecret,
      });

      expect(isValid).toBe(false);
    });
  });

  describe('3. Job Dispatch Secret & Token Attestation', () => {
    const jobId = 'job-uuid-1111';
    const leaseId = 'lease-uuid-2222';
    const agentId = 'agent-uuid-3333';

    it('computes deterministic job dispatch secret bound to job, lease, and agent', () => {
      const secret1 = computeJobDispatchSecret(jobId, leaseId, agentId, primarySecret);
      const secret2 = deriveJobLeaseSecret(jobId, leaseId, agentId, primarySecret);

      expect(secret1).toBe(secret2);
      expect(secret1.length).toBe(64);
    });

    it('produces different dispatch secrets for different leases of the same job', () => {
      const secretLease1 = computeJobDispatchSecret(jobId, 'lease-alpha', agentId, primarySecret);
      const secretLease2 = computeJobDispatchSecret(jobId, 'lease-beta', agentId, primarySecret);

      expect(secretLease1).not.toBe(secretLease2);
    });

    it('signs and verifies job lease tokens', () => {
      const token = signJobLeaseToken(jobId, leaseId, agentId, primarySecret);
      expect(verifyJobLeaseToken({ jobId, leaseId, agentId, token, masterKey: primarySecret })).toBe(true);
      expect(verifyJobLeaseToken({ jobId, leaseId, agentId, token: 'invalid-token', masterKey: primarySecret })).toBe(false);
    });
  });

  describe('4. Finding Result Integrity & Idempotency Attestation', () => {
    const jobId = 'job-456';
    const jobDispatchSecret = 'dispatch-secret-for-job-456-hex-digest-abc123';

    const findings = [
      { id: 'f-1', title: 'XSS in search endpoint', severity: 'high' },
      { id: 'f-2', title: 'Missing CSP header', severity: 'low' },
    ];
    const executions = [
      { engineId: 'engine-native-headers', exitCode: 0, status: 'completed' },
    ];

    it('computes deterministic canonical findings hash and signs result', () => {
      const hash1 = computeFindingsHash(findings, executions);
      // Invert key order in finding object to test RFC 8785 canonicalization
      const reorderedFindings = [
        { severity: 'high', title: 'XSS in search endpoint', id: 'f-1' },
        { title: 'Missing CSP header', id: 'f-2', severity: 'low' },
      ];
      const hash2 = computeFindingsHash(reorderedFindings, executions);

      expect(hash1).toBe(hash2);

      const signature = computeResultSignature(jobDispatchSecret, jobId, hash1);
      const isValid = verifyResultSignature({
        jobDispatchSecret,
        jobId,
        findings,
        executions,
        signature,
      });

      expect(isValid).toBe(true);
    });

    it('rejects result verification if findings or executions are altered', () => {
      const signature = computeResultSignature(
        jobDispatchSecret,
        jobId,
        computeFindingsHash(findings, executions),
      );

      const tamperedFindings = [
        { id: 'f-1', title: 'XSS in search endpoint', severity: 'critical' }, // Altered severity
      ];

      const isValid = verifyResultSignature({
        jobDispatchSecret,
        jobId,
        findings: tamperedFindings,
        executions,
        signature,
      });

      expect(isValid).toBe(false);
    });
  });

  describe('5. Zero-Downtime Secret Rotation Architecture', () => {
    const targetId = 'target-rotation-test';
    const baseUrl = 'http://api.service.local';
    const scope = { allowedHosts: ['api.service.local'] };

    it('verifies signature created with previous key when previous key is supplied', () => {
      // Signature was created under previous secret
      const oldSignature = computeScopeSignature(targetId, baseUrl, scope, previousSecret);

      // Verify with primary key and previous key configured
      const isValid = verifyScopeSignature({
        targetId,
        baseUrl,
        scope,
        signature: oldSignature,
        masterKey: primarySecret,
        previousMasterKey: previousSecret,
      });

      expect(isValid).toBe(true);
    });

    it('verifies signature created with previous key via process.env.AGENT_MASTER_SECRET_PREVIOUS', () => {
      process.env.AGENT_MASTER_SECRET = primarySecret;
      process.env.AGENT_MASTER_SECRET_PREVIOUS = previousSecret;

      const oldSignature = computeScopeSignature(targetId, baseUrl, scope, previousSecret);

      const isValid = verifyScopeSignature({
        targetId,
        baseUrl,
        scope,
        signature: oldSignature,
      });

      expect(isValid).toBe(true);
    });

    it('rejects signature when neither primary nor previous key matches', () => {
      const rogueSignature = computeScopeSignature(targetId, baseUrl, scope, rogueSecret);

      const isValid = verifyScopeSignature({
        targetId,
        baseUrl,
        scope,
        signature: rogueSignature,
        masterKey: primarySecret,
        previousMasterKey: previousSecret,
      });

      expect(isValid).toBe(false);
    });

    it('supports result signature rotation via previousJobDispatchSecret', () => {
      const jobId = 'job-rot-1';
      const oldDispatchSecret = 'old-dispatch-secret-32-chars-long-xyz';
      const newDispatchSecret = 'new-dispatch-secret-32-chars-long-abc';

      const findings = [{ id: 'f-1', title: 'Vulnerability' }];
      const executions = [{ engineId: 'native', exitCode: 0 }];

      // Agent signed result using oldDispatchSecret
      const oldSig = computeResultSignature(
        oldDispatchSecret,
        jobId,
        computeFindingsHash(findings, executions),
      );

      // Controller verifying with new dispatch secret and old fallback
      const isValid = verifyResultSignature({
        jobDispatchSecret: newDispatchSecret,
        previousJobDispatchSecret: oldDispatchSecret,
        jobId,
        findings,
        executions,
        signature: oldSig,
      });

      expect(isValid).toBe(true);
    });

    it('generic verifyWithRotationSupport helper invokes previous key only if primary fails', () => {
      const calls: string[] = [];

      const result = verifyWithRotationSupport(
        (key) => {
          calls.push(key);
          return key === previousSecret;
        },
        primarySecret,
        previousSecret,
      );

      expect(result).toBe(true);
      expect(calls).toEqual([primarySecret, previousSecret]);
    });
  });
});
