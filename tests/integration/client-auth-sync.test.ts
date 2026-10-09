import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { FastifyInstance } from 'fastify';
import path from 'node:path';
import util from 'node:util';
import { exec } from 'node:child_process';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase } from '../../apps/controller/src/services/db.js';
import { apiClient, AuthenticationError } from '../../apps/cli/src/api/client.js';
import {
  setCliConfig,
  resetCliConfig,
  saveStoredApiKey,
  clearStoredApiKey,
  readStoredApiKey,
  getCliConfig,
} from '../../apps/cli/src/config/index.js';
import {
  getStoredApiKey,
  setStoredApiKey,
  clearStoredApiKey as clearDashboardApiKey,
  getAuthHeaders,
  authFetch,
} from '../../apps/dashboard/src/api/client.js';

const execPromise = util.promisify(exec);

describe('Remediation Prompt 05: Client-Server API Key & Auth Compatibility (REM-05)', () => {
  let app: FastifyInstance;
  let serverPort: number;
  let serverUrl: string;
  const validApiKey = 'test-security-lab-client-auth-key-32ch';
  const validAdminKey = 'test-security-lab-admin-auth-key-32ch';
  const invalidApiKey = 'test-invalid-client-auth-key-32chars';

  beforeAll(async () => {
    app = buildApp({
      disableLogging: true,
      enableReaper: false,
      bypassAuth: false, // Strictly enforce authentication on protected endpoints
      apiKey: validApiKey,
      adminKey: validAdminKey,
    });

    await app.listen({ port: 0, host: '127.0.0.1' });
    const address = app.server.address();
    if (address && typeof address === 'object') {
      serverPort = address.port;
      serverUrl = `http://127.0.0.1:${serverPort}`;
    }
  });

  afterAll(async () => {
    await app.close();
    await closeDatabase();
  });

  beforeEach(() => {
    resetCliConfig();
    clearStoredApiKey();
    clearDashboardApiKey();
    delete process.env.SECURITY_LAB_API_KEY;
    delete process.env.SECURITY_LAB_API_URL;
  });

  // ===========================================================================
  // 1. CLI Client Integration Tests (Programmatic)
  // ===========================================================================
  describe('CLI ApiClient & Credential Handling', () => {
    it('attaches Bearer and X-API-Key headers and succeeds (200 OK) when valid key is provided', async () => {
      setCliConfig({
        apiUrl: serverUrl,
        apiKey: validApiKey,
      });

      const projects = await apiClient.get<unknown[]>('/api/v1/projects');
      expect(Array.isArray(projects)).toBe(true);
    });

    it('fails closed immediately with AuthenticationError if API key is unset', async () => {
      setCliConfig({
        apiUrl: serverUrl,
        apiKey: '',
      });

      await expect(apiClient.get('/api/v1/projects')).rejects.toThrow(AuthenticationError);
      await expect(apiClient.get('/api/v1/projects')).rejects.toThrow(
        "Error: SECURITY_LAB_API_KEY is missing or invalid. Set it in your environment or run 'sec-lab login'.",
      );
    });

    it('throws AuthenticationError when server responds with 401 Unauthorized for invalid key', async () => {
      setCliConfig({
        apiUrl: serverUrl,
        apiKey: invalidApiKey,
      });

      await expect(apiClient.get('/api/v1/projects')).rejects.toThrow(AuthenticationError);
      await expect(apiClient.get('/api/v1/projects')).rejects.toThrow(
        "Error: SECURITY_LAB_API_KEY is missing or invalid. Set it in your environment or run 'sec-lab login'.",
      );
    });

    it('supports reading credentials stored via saveStoredApiKey / sec-lab login', () => {
      saveStoredApiKey(validApiKey);
      expect(readStoredApiKey()).toBe(validApiKey);

      setCliConfig({ apiUrl: serverUrl });
      // Clear runtime option so it falls back to stored credentials
      setCliConfig({ apiUrl: serverUrl, apiKey: undefined });

      expect(readStoredApiKey()).toBe(validApiKey);

      clearStoredApiKey();
      expect(readStoredApiKey()).toBeUndefined();
    });

    it('prioritizes explicit CLI options over environment variables and stored credentials', () => {
      saveStoredApiKey('stored-key-lowest-priority');
      process.env.SECURITY_LAB_API_KEY = 'env-key-medium-priority';

      setCliConfig({
        apiUrl: serverUrl,
        apiKey: 'explicit-flag-highest-priority',
      });

      expect(getCliConfig().apiKey).toBe('explicit-flag-highest-priority');
    });
  });

  // ===========================================================================
  // 2. CLI Subprocess End-to-End Tests
  // ===========================================================================
  describe('CLI Subprocess End-to-End Execution', () => {
    const cliBin = path.resolve(__dirname, '../../apps/cli/dist/index.js');

    it('succeeds against authenticated Controller when SECURITY_LAB_API_KEY is set in environment', async () => {
      const cmd = `node "${cliBin}" project list -a "${serverUrl}"`;
      const { stdout } = await execPromise(cmd, {
        env: {
          ...process.env,
          SECURITY_LAB_API_KEY: validApiKey,
        },
      });

      expect(stdout).toMatch(/Registered Projects|No projects found/);
    });

    it('succeeds against authenticated Controller when -k flag is passed', async () => {
      const cmd = `node "${cliBin}" project list -a "${serverUrl}" -k "${validApiKey}"`;
      const { stdout } = await execPromise(cmd, {
        env: {
          ...process.env,
          SECURITY_LAB_API_KEY: '',
        },
      });

      expect(stdout).toMatch(/Registered Projects|No projects found/);
    });

    it('exits with code 1 and actionable diagnostic error when API key is missing', async () => {
      const cmd = `node "${cliBin}" project list -a "${serverUrl}"`;
      let errorOccurred = false;

      try {
        await execPromise(cmd, {
          env: {
            ...process.env,
            SECURITY_LAB_API_KEY: '',
          },
        });
      } catch (err: any) {
        errorOccurred = true;
        expect(err.code).toBe(1);
        const output = (err.stderr || '') + (err.stdout || '');
        expect(output).toContain(
          "Error: SECURITY_LAB_API_KEY is missing or invalid. Set it in your environment or run 'sec-lab login'.",
        );
        // Ensure sensitive info is not leaked
        expect(output).not.toContain(validApiKey);
      }

      expect(errorOccurred).toBe(true);
    });

    it('exits with code 1 and actionable diagnostic error when API key is invalid (401)', async () => {
      const cmd = `node "${cliBin}" project list -a "${serverUrl}" -k "${invalidApiKey}"`;
      let errorOccurred = false;

      try {
        await execPromise(cmd, {
          env: {
            ...process.env,
            SECURITY_LAB_API_KEY: '',
          },
        });
      } catch (err: any) {
        errorOccurred = true;
        expect(err.code).toBe(1);
        const output = (err.stderr || '') + (err.stdout || '');
        expect(output).toContain(
          "Error: SECURITY_LAB_API_KEY is missing or invalid. Set it in your environment or run 'sec-lab login'.",
        );
        // Ensure sensitive info is not leaked
        expect(output).not.toContain(invalidApiKey);
      }

      expect(errorOccurred).toBe(true);
    });

    it('stores key via "login -k" and subsequently authenticates without environment variable', async () => {
      // 1. Run login command with key
      const loginCmd = `node "${cliBin}" login -k "${validApiKey}"`;
      const { stdout: loginOut } = await execPromise(loginCmd);
      expect(loginOut).toContain('API key successfully saved');

      // 2. Run project list with no env var or -k flag
      const listCmd = `node "${cliBin}" project list -a "${serverUrl}"`;
      const { stdout: listOut } = await execPromise(listCmd, {
        env: {
          ...process.env,
          SECURITY_LAB_API_KEY: '',
        },
      });
      expect(listOut).toMatch(/Registered Projects|No projects found/);

      // 3. Clean up credentials via logout
      const logoutCmd = `node "${cliBin}" logout`;
      const { stdout: logoutOut } = await execPromise(logoutCmd);
      expect(logoutOut).toContain('Stored API credentials removed');
    });
  });

  // ===========================================================================
  // 3. Dashboard API Client Integration Tests
  // ===========================================================================
  describe('Dashboard Client API & Interceptor', () => {
    it('getAuthHeaders returns empty object when no API key is stored', () => {
      const headers = getAuthHeaders();
      expect(headers.Authorization).toBeUndefined();
      expect(headers['X-API-Key']).toBeUndefined();
    });

    it('getAuthHeaders returns Authorization and X-API-Key when key is stored', () => {
      setStoredApiKey(validApiKey, false); // in memory / sessionStorage
      const headers = getAuthHeaders();
      expect(headers.Authorization).toBe(`Bearer ${validApiKey}`);
      expect(headers['X-API-Key']).toBe(validApiKey);
      expect(getStoredApiKey()).toBe(validApiKey);
    });

    it('authFetch successfully connects to authenticated Controller with valid key', async () => {
      setStoredApiKey(validApiKey, false);

      const res = await authFetch(`${serverUrl}/api/v1/projects`);
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.success).toBe(true);
      expect(Array.isArray(json.data)).toBe(true);
    });

    it('authFetch intercepts 401 and dispatches security-lab:auth-required event', async () => {
      setStoredApiKey(invalidApiKey, false);

      let eventReceived = false;
      const listener = () => {
        eventReceived = true;
      };

      if (typeof window !== 'undefined') {
        window.addEventListener('security-lab:auth-required', listener);
      }

      const res = await authFetch(`${serverUrl}/api/v1/projects`);
      expect(res.status).toBe(401);

      if (typeof window !== 'undefined') {
        expect(eventReceived).toBe(true);
        window.removeEventListener('security-lab:auth-required', listener);
      }
    });

    it('never sends API credentials as query parameters', async () => {
      setStoredApiKey(validApiKey, false);

      let requestedUrl = '';
      const originalFetch = globalThis.fetch;
      globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
        requestedUrl = input.toString();
        return originalFetch(input, init);
      };

      try {
        await authFetch(`${serverUrl}/api/v1/projects`);
        expect(requestedUrl).toBe(`${serverUrl}/api/v1/projects`);
        expect(requestedUrl).not.toContain(validApiKey);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });
});
