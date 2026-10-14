import { describe, it, expect, vi } from 'vitest';
import {
  decodeBase32,
  generateTotpCode,
  generateRandomTotpSecret,
  getTotpRemainingSeconds,
  AUTH_FLOW_TEMPLATES,
  executeAuthFlowTest,
} from '../src/api/authVault.js';

describe('Phase UI-07: Stateful Auth Flow Builder, TOTP Simulator & Encrypted Secrets Vault', () => {
  describe('RFC-4648 Base32 Decoding & Validation', () => {
    it('decodes standard Base32 seeds into binary buffers', () => {
      // Standard RFC test vector: "JBSWY3DPEHPK3PXP" corresponds to "Hello!\xde\xad\xbe\xef"
      const decoded = decodeBase32('JBSWY3DPEHPK3PXP');
      expect(decoded).toBeInstanceOf(Uint8Array);
      expect(decoded.length).toBe(10);
    });

    it('handles lowercase, spaces, and hyphens gracefully', () => {
      const decoded = decodeBase32('jbsw-y3dp ehpk-3pxp');
      expect(decoded.length).toBe(10);
    });

    it('throws descriptive error on invalid Base32 characters (e.g. 1, 8, 9, 0)', () => {
      expect(() => decodeBase32('INVALID1890')).toThrowError(/Invalid Base32 character/);
    });

    it('generates valid random Base32 secret seeds', () => {
      const secret = generateRandomTotpSecret(16);
      expect(secret).toHaveLength(16);
      expect(() => decodeBase32(secret)).not.toThrow();
    });
  });

  describe('RFC-6238 TOTP Passcode Generator', () => {
    it('generates a 6-digit zero-padded numeric string', async () => {
      const secret = 'JBSWY3DPEHPK3PXP';
      const code = await generateTotpCode(secret, 1234567890000);
      expect(code).toMatch(/^\d{6}$/);
      expect(code.length).toBe(6);
    });

    it('calculates remaining seconds in 30-second epoch loop', () => {
      const remaining = getTotpRemainingSeconds(30);
      expect(remaining).toBeGreaterThanOrEqual(1);
      expect(remaining).toBeLessThanOrEqual(30);
    });

    it('generates identical code within the same 30-second time step', async () => {
      const secret = 'JBSWY3DPEHPK3PXP';
      // Step-aligned epoch: 1700000010 % 30 == 0
      const baseTime = 1700000010 * 1000;
      const code1 = await generateTotpCode(secret, baseTime);
      const code2 = await generateTotpCode(secret, baseTime + 15000); // 15s later, same step
      expect(code1).toBe(code2);

      const codeNextStep = await generateTotpCode(secret, baseTime + 35000); // 35s later, next step
      expect(codeNextStep).toMatch(/^\d{6}$/);
      expect(codeNextStep).not.toBe(code1);
    });
  });

  describe('Auth Flow Preset Templates', () => {
    it('provides all 4 core authentication templates with complete step sequences', () => {
      const templateKeys = Object.keys(AUTH_FLOW_TEMPLATES);
      expect(templateKeys).toContain('formCsrf');
      expect(templateKeys).toContain('oauth2ClientCredentials');
      expect(templateKeys).toContain('formTotpMfa');
      expect(templateKeys).toContain('bearerToken');

      // Check formCsrf
      const formCsrf = AUTH_FLOW_TEMPLATES.formCsrf.flow;
      expect(formCsrf.type).toBe('FORM');
      expect(formCsrf.steps).toHaveLength(2);
      expect(formCsrf.steps![0].name).toBe('Fetch CSRF Token');
      expect(formCsrf.steps![1].name).toBe('Submit Login Credentials');
      expect(formCsrf.steps![1].extract?.some((e) => e.saveAs === 'token')).toBe(true);

      // Check formTotpMfa
      const totpFlow = AUTH_FLOW_TEMPLATES.formTotpMfa.flow;
      expect(totpFlow.type).toBe('FORM');
      expect(totpFlow.totpSecret).toBeDefined();
      expect(JSON.stringify(totpFlow.steps)).toContain('{{totp}}');

      // Check oauth2ClientCredentials
      const oauth = AUTH_FLOW_TEMPLATES.oauth2ClientCredentials.flow;
      expect(oauth.type).toBe('OAUTH2');
      expect(oauth.oauth2Config?.grantType).toBe('client_credentials');
    });
  });

  describe('Auth Flow Live Test Handshake Simulation', () => {
    it('executes simulated auth handshake and extracts session tokens', async () => {
      const flow = AUTH_FLOW_TEMPLATES.formTotpMfa.flow;
      const targetUrl = 'http://127.0.0.1:8080';

      const result = await executeAuthFlowTest(targetUrl, flow);
      expect(result.success).toBe(true);
      expect(result.stepsExecuted.length).toBeGreaterThan(0);
      expect(result.finalToken).toBeDefined();
      expect(typeof result.finalToken).toBe('string');
      expect(result.totalDurationMs).toBeGreaterThan(0);
    });

    it('verifies OAuth2 client credentials flow extraction', async () => {
      const oauthFlow = AUTH_FLOW_TEMPLATES.oauth2ClientCredentials.flow;
      const targetUrl = 'http://127.0.0.1:8080';

      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            access_token: 'mock-oauth2-jwt-token-999',
            token_type: 'Bearer',
            expires_in: 3600,
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        ),
      );

      const result = await executeAuthFlowTest(targetUrl, oauthFlow);
      expect(result.success).toBe(true);
      expect(result.stepsExecuted[0].method).toBe('POST');
      expect(result.finalToken).toBe('mock-oauth2-jwt-token-999');

      fetchSpy.mockRestore();
    });
  });
});
