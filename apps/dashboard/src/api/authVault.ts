import { Target, targetsApi } from './targets.js';
import { authFetch } from './client.js';

export type AuthType = 'FORM' | 'OAUTH2' | 'API_KEY' | 'BEARER';

export interface AuthStepExtract {
  from: 'BODY_JSON' | 'BODY_REGEX' | 'HEADER' | 'COOKIE';
  key: string;
  saveAs: string;
}

export interface AuthStep {
  name?: string;
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  headers?: Record<string, string>;
  body?: Record<string, unknown>;
  extract?: AuthStepExtract[];
}

export interface OAuth2Config {
  grantType: 'client_credentials' | 'password' | 'authorization_code' | 'refresh_token';
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  username?: string;
  password?: string;
  scope?: string;
  audience?: string;
}

export interface CsrfConfig {
  tokenUrl?: string;
  paramName?: string;
  headerName?: string;
  regexPattern?: string;
  jsonPath?: string;
}

export interface AuthFlow {
  type: AuthType;
  loginUrl?: string;
  steps?: AuthStep[];
  totpSecret?: string;
  tokenExtractionPath?: string;
  credentials?: Record<string, string>;
  oauth2Config?: OAuth2Config;
  csrfConfig?: CsrfConfig;
  headers?: Record<string, string>;
}

export interface AuthTestStepLog {
  stepIndex: number;
  name: string;
  url: string;
  method: string;
  statusCode: number;
  durationMs: number;
  extractedVariables?: Record<string, string>;
  error?: string;
}

export interface AuthTestResult {
  success: boolean;
  totalDurationMs: number;
  stepsExecuted: AuthTestStepLog[];
  finalToken?: string;
  finalCookies?: Record<string, string>;
  error?: string;
}

export interface TargetCredentialItem {
  targetId: string;
  targetName: string;
  baseUrl: string;
  authConfigured: boolean;
  authType?: AuthType | string;
  lastUpdated?: string;
  maskedPreview?: string;
}

// Pre-built flow templates for quick initialization
export const AUTH_FLOW_TEMPLATES: Record<string, { label: string; desc: string; flow: AuthFlow }> = {
  formCsrf: {
    label: 'Standard Form + CSRF',
    desc: 'Fetch CSRF token from HTML form, submit credentials, and extract session cookie',
    flow: {
      type: 'FORM',
      loginUrl: '/auth/login',
      csrfConfig: {
        tokenUrl: '/auth/login',
        paramName: '_csrf',
        headerName: 'X-CSRF-Token',
      },
      credentials: {
        username: 'security-tester',
        password: 'ChangeMe123!@#',
      },
      steps: [
        {
          name: 'Fetch CSRF Token',
          url: '/auth/login',
          method: 'GET',
          extract: [
            { from: 'COOKIE', key: 'csrf_token', saveAs: 'csrfToken' },
          ],
        },
        {
          name: 'Submit Login Credentials',
          url: '/auth/login',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': '{{csrfToken}}',
          },
          body: {
            username: '{{username}}',
            password: '{{password}}',
          },
          extract: [
            { from: 'BODY_JSON', key: 'access_token', saveAs: 'token' },
            { from: 'COOKIE', key: 'session_id', saveAs: 'sessionId' },
          ],
        },
      ],
      headers: {
        Authorization: 'Bearer {{token}}',
      },
    },
  },
  oauth2ClientCredentials: {
    label: 'OAuth2 Client Credentials',
    desc: 'Exchange Client ID and Client Secret for scoped Bearer access token',
    flow: {
      type: 'OAUTH2',
      oauth2Config: {
        grantType: 'client_credentials',
        tokenUrl: '/oauth/v2/token',
        clientId: 'secops-client-id-001',
        clientSecret: 'secops-client-secret-alpha',
        scope: 'read:all write:all admin',
      },
      headers: {
        Authorization: 'Bearer {{token}}',
      },
    },
  },
  formTotpMfa: {
    label: 'Form Login + RFC 6238 TOTP',
    desc: 'Multi-factor authentication injecting live 6-digit TOTP code into request payload',
    flow: {
      type: 'FORM',
      loginUrl: '/auth/mfa-login',
      totpSecret: 'JBSWY3DPEHPK3PXP', // Base32 RFC-6238 seed
      credentials: {
        username: 'admin@securitylab.local',
        password: 'AdminPassword!2026',
      },
      steps: [
        {
          name: 'Submit Login with TOTP MFA Code',
          url: '/auth/mfa-login',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            username: '{{username}}',
            password: '{{password}}',
            totpCode: '{{totp}}',
          },
          extract: [
            { from: 'BODY_JSON', key: 'token', saveAs: 'token' },
          ],
        },
      ],
      headers: {
        Authorization: 'Bearer {{token}}',
      },
    },
  },
  bearerToken: {
    label: 'Static Bearer Token',
    desc: 'Direct Bearer JWT or Service Token injected into Authorization header',
    flow: {
      type: 'BEARER',
      credentials: {
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      },
      headers: {
        Authorization: 'Bearer {{token}}',
      },
    },
  },
};

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Decodes a Base32 string into Uint8Array (pure browser implementation)
 */
export function decodeBase32(input: string): Uint8Array {
  const cleanInput = input.toUpperCase().replace(/[=\s-]/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (let i = 0; i < cleanInput.length; i++) {
    const char = cleanInput.charAt(i);
    const index = BASE32_CHARS.indexOf(char);
    if (index === -1) {
      throw new Error(`Invalid Base32 character: "${char}"`);
    }

    value = (value << 5) | index;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return new Uint8Array(bytes);
}

/**
 * Generates RFC 6238 TOTP 6-digit passcode using Web Crypto API
 */
export async function generateTotpCode(
  secretBase32: string,
  timestampMs: number = Date.now(),
  stepSeconds: number = 30,
): Promise<string> {
  const keyBytes = decodeBase32(secretBase32);
  const epochSeconds = Math.floor(timestampMs / 1000);
  const counter = Math.floor(epochSeconds / stepSeconds);

  // 8-byte big-endian counter buffer
  const counterBuffer = new ArrayBuffer(8);
  const counterView = new DataView(counterBuffer);
  // Big-endian 64-bit integer
  counterView.setUint32(0, Math.floor(counter / 0x100000000));
  counterView.setUint32(4, counter >>> 0);

  // Import key into Web Crypto Subtle
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    'raw',
    keyBytes.buffer as ArrayBuffer,
    { name: 'HMAC', hash: { name: 'SHA-1' } },
    false,
    ['sign'],
  );

  const signature = await globalThis.crypto.subtle.sign('HMAC', cryptoKey, counterBuffer);
  const signatureBytes = new Uint8Array(signature);

  // Dynamic truncation (RFC 4226)
  const offset = signatureBytes[signatureBytes.length - 1] & 0x0f;
  const binary =
    ((signatureBytes[offset] & 0x7f) << 24) |
    ((signatureBytes[offset + 1] & 0xff) << 16) |
    ((signatureBytes[offset + 2] & 0xff) << 8) |
    (signatureBytes[offset + 3] & 0xff);

  const otp = binary % 1000000;
  return otp.toString().padStart(6, '0');
}

/**
 * Generates a random Base32 TOTP secret seed
 */
export function generateRandomTotpSecret(length: number = 16): string {
  let secret = '';
  const randomBytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(randomBytes);
  for (let i = 0; i < length; i++) {
    secret += BASE32_CHARS[randomBytes[i] % BASE32_CHARS.length];
  }
  return secret;
}

/**
 * Calculates remaining seconds in current 30-second TOTP cycle
 */
export function getTotpRemainingSeconds(stepSeconds: number = 30): number {
  const epoch = Math.floor(Date.now() / 1000);
  return stepSeconds - (epoch % stepSeconds);
}

/**
 * Save / Update AuthFlow for a Target
 */
export async function updateTargetAuthFlow(targetId: string, authFlow: AuthFlow | null): Promise<Target> {
  return targetsApi.updateTarget(targetId, {
    authFlow,
  } as any);
}

/**
 * Executes server-side stateful auth verification flow via Controller backend.
 * Eliminates browser CORS bypass attempts and captures truthful execution diagnostics.
 */
export async function executeAuthFlowTest(
  targetUrlOrId: string,
  flow: AuthFlow,
  targetId?: string,
): Promise<AuthTestResult> {
  const resolvedTargetId = targetId || targetUrlOrId;
  const isUrl = targetUrlOrId.startsWith('http://') || targetUrlOrId.startsWith('https://');

  try {
    const res = await authFetch('/api/v1/auth-vault/verify-flow', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        targetId: resolvedTargetId,
        targetUrl: isUrl ? targetUrlOrId : undefined,
        flow,
      }),
    });

    const body = await res.json().catch(() => null);

    if (!res.ok) {
      const errorMessage =
        body?.error?.message || `Authentication flow verification rejected with HTTP ${res.status}`;
      return {
        success: false,
        totalDurationMs: body?.totalDurationMs ?? 0,
        stepsExecuted: Array.isArray(body?.stepsExecuted) ? body.stepsExecuted : [],
        error: errorMessage,
      };
    }

    const payload = body?.data ?? body;
    return {
      success: Boolean(payload.success),
      totalDurationMs: payload.totalDurationMs ?? 0,
      stepsExecuted: Array.isArray(payload.stepsExecuted) ? payload.stepsExecuted : [],
      finalToken: payload.finalToken,
      finalCookies: payload.finalCookies,
      error: payload.error,
    };
  } catch (err: any) {
    return {
      success: false,
      totalDurationMs: 0,
      stepsExecuted: [],
      error: err.message || 'Failed to dispatch authentication verification to controller backend',
    };
  }
}

