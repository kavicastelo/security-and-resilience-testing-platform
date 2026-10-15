import {
  AuthFlow,
  AuthStep,
  AuthSessionState,
} from '@security-lab/contracts';
import { generateTotp, redactHeaders } from '@security-lab/crypto';
import { createLogger } from '@security-lab/logger';

const logger = createLogger({ name: 'stateful-auth' });

export interface AuthenticatorOptions {
  flow: AuthFlow;
  initialState?: Partial<AuthSessionState>;
  /** Optional custom fetch implementation (useful for tests or mocking) */
  customFetch?: typeof fetch;
}

export class StatefulAuthenticator {
  private flow: AuthFlow;
  private state: AuthSessionState;
  private refreshPromise: Promise<AuthSessionState> | null = null;
  private fetchImpl: typeof fetch;

  constructor(options: AuthenticatorOptions) {
    this.flow = options.flow;
    this.fetchImpl = options.customFetch ?? globalThis.fetch.bind(globalThis);
    this.state = {
      token: options.initialState?.token,
      tokenType: options.initialState?.tokenType ?? 'Bearer',
      cookies: { ...(options.initialState?.cookies ?? {}) },
      headers: { ...(options.initialState?.headers ?? {}) },
      expiresAt: options.initialState?.expiresAt,
      lastRefreshedAt: options.initialState?.lastRefreshedAt ?? Date.now(),
      variables: { ...(options.initialState?.variables ?? {}) },
    };
  }

  /**
   * Returns current active headers, including Authorization and Cookie headers.
   */
  getHeaders(): Record<string, string> {
    const headers: Record<string, string> = { ...this.state.headers };

    if (this.state.token) {
      if (this.flow.headers) {
        for (const [key, value] of Object.entries(this.flow.headers)) {
          headers[key] = this.interpolate(value);
        }
      } else {
        headers['Authorization'] = `${this.state.tokenType} ${this.state.token}`.trim();
      }
    }

    const cookiePairs = Object.entries(this.state.cookies).map(
      ([k, v]) => `${k}=${v}`,
    );
    if (cookiePairs.length > 0) {
      headers['Cookie'] = cookiePairs.join('; ');
    }

    return headers;
  }

  /**
   * Checks if session token is expired or about to expire within 10 seconds.
   */
  isExpired(): boolean {
    if (!this.state.token && Object.keys(this.state.cookies).length === 0) {
      return true;
    }
    if (this.state.expiresAt) {
      // 10 second buffer
      return Date.now() >= this.state.expiresAt - 10000;
    }
    return false;
  }

  /**
   * Returns active session state snapshot.
   */
  getState(): Readonly<AuthSessionState> {
    return { ...this.state };
  }

  /**
   * Refreshes or establishes the session.
   * If a refresh is already in-flight, returns the existing promise to prevent duplicate authentication storms.
   */
  async refreshSession(): Promise<AuthSessionState> {
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    this.refreshPromise = this.executeAuthenticationFlow()
      .then((state) => {
        this.state = state;
        return state;
      })
      .finally(() => {
        this.refreshPromise = null;
      });

    return this.refreshPromise;
  }

  /**
   * Executes the full authentication flow according to its type.
   */
  private async executeAuthenticationFlow(): Promise<AuthSessionState> {
    logger.info({ authType: this.flow.type }, 'Initiating stateful authentication flow');

    switch (this.flow.type) {
      case 'FORM':
        return this.executeFormLoginFlow();
      case 'OAUTH2':
        return this.executeOAuth2Flow();
      case 'API_KEY':
      case 'BEARER':
        return this.executeStaticAuthFlow();
      default:
        throw new Error(`Unsupported authentication type: ${(this.flow as any).type}`);
    }
  }

  /**
   * Executes multi-step form-based authentication, optionally extracting CSRF tokens and computing TOTP codes.
   */
  private async executeFormLoginFlow(): Promise<AuthSessionState> {
    const newState: AuthSessionState = {
      token: undefined,
      tokenType: 'Bearer',
      cookies: { ...this.state.cookies },
      headers: { ...this.state.headers },
      lastRefreshedAt: Date.now(),
      variables: {
        ...this.flow.credentials,
        ...this.state.variables,
      },
    };

    // If TOTP secret is configured, generate and inject the current code
    if (this.flow.totpSecret) {
      const totp = generateTotp(this.flow.totpSecret);
      newState.variables['totp'] = totp;
      newState.variables['otp'] = totp;
      newState.variables['code'] = totp;
      logger.info('Generated RFC-6238 TOTP code for MFA authentication');
    }

    // Determine steps to execute
    const steps: AuthStep[] = this.flow.steps && this.flow.steps.length > 0
      ? this.flow.steps
      : (this.flow.loginUrl
          ? [{
              url: this.flow.loginUrl,
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: this.flow.credentials ?? {},
            }]
          : []);

    if (steps.length === 0) {
      throw new Error('Form authentication requires either "steps" or "loginUrl" in configuration.');
    }

    for (const step of steps) {
      const stepUrl = this.interpolate(step.url, newState.variables);
      const stepMethod = step.method || 'POST';
      const stepHeaders: Record<string, string> = {};

      // Add cookies
      const cookieStr = Object.entries(newState.cookies)
        .map(([k, v]) => `${k}=${v}`)
        .join('; ');
      if (cookieStr) {
        stepHeaders['Cookie'] = cookieStr;
      }

      // Add step headers
      if (step.headers) {
        for (const [k, v] of Object.entries(step.headers)) {
          stepHeaders[k] = this.interpolate(v, newState.variables);
        }
      }

      let stepBody: string | undefined = undefined;
      if (step.body && stepMethod !== 'GET') {
        const interpolatedBody = this.interpolateObject(step.body, newState.variables);
        const contentType = stepHeaders['Content-Type'] || stepHeaders['content-type'] || 'application/json';
        if (contentType.includes('application/x-www-form-urlencoded')) {
          const params = new URLSearchParams();
          for (const [k, v] of Object.entries(interpolatedBody)) {
            params.append(k, String(v));
          }
          stepBody = params.toString();
        } else {
          stepBody = JSON.stringify(interpolatedBody);
          if (!stepHeaders['Content-Type']) {
            stepHeaders['Content-Type'] = 'application/json';
          }
        }
      }

      logger.info(
        {
          stepName: step.name || stepUrl,
          method: stepMethod,
          headers: redactHeaders(stepHeaders),
        },
        'Executing authentication step',
      );

      const response = await this.fetchImpl(stepUrl, {
        method: stepMethod,
        headers: stepHeaders,
        body: stepBody,
        redirect: 'follow',
      });

      // Extract set-cookie headers
      this.extractCookies(response, newState.cookies);

      const responseText = await response.text();
      let responseJson: Record<string, unknown> | null = null;
      try {
        responseJson = JSON.parse(responseText);
      } catch {
        // Body is not JSON (might be HTML or text)
      }

      // Process step extract rules
      if (step.extract && step.extract.length > 0) {
        for (const rule of step.extract) {
          let extractedValue: string | undefined = undefined;

          if (rule.from === 'HEADER') {
            extractedValue = response.headers.get(rule.key) || undefined;
          } else if (rule.from === 'COOKIE') {
            extractedValue = newState.cookies[rule.key];
          } else if (rule.from === 'BODY_JSON' && responseJson) {
            extractedValue = this.extractJsonPath(responseJson, rule.key);
          } else if (rule.from === 'BODY_REGEX') {
            const match = new RegExp(rule.key).exec(responseText);
            if (match && match[1]) {
              extractedValue = match[1];
            }
          }

          if (extractedValue) {
            newState.variables[rule.saveAs] = extractedValue;
            if (rule.saveAs === 'token' || rule.saveAs === 'access_token') {
              newState.token = extractedValue;
            }
          }
        }
      }

      // If tokenExtractionPath is provided and token not yet found, try extracting from response JSON
      if (!newState.token && responseJson) {
        const path = this.flow.tokenExtractionPath || 'access_token';
        const extracted = this.extractJsonPath(responseJson, path);
        if (extracted) {
          newState.token = extracted;
        } else if (responseJson['token']) {
          newState.token = String(responseJson['token']);
        }
      }

      // Also check response authorization header if returned
      const authHeader = response.headers.get('authorization');
      if (authHeader && !newState.token) {
        const parts = authHeader.split(' ');
        if (parts.length === 2 && parts[1]) {
          newState.tokenType = parts[0] ?? 'Bearer';
          newState.token = parts[1];
        }
      }
    }

    logger.info('Form-based authentication flow completed successfully');
    return newState;
  }

  /**
   * Executes OAuth2 token exchange (client_credentials or password grant).
   */
  private async executeOAuth2Flow(): Promise<AuthSessionState> {
    const config = this.flow.oauth2Config;
    if (!config) {
      throw new Error('OAuth2 flow requires oauth2Config');
    }

    const params = new URLSearchParams();
    params.set('grant_type', config.grantType);
    params.set('client_id', config.clientId);
    params.set('client_secret', config.clientSecret);

    if (config.grantType === 'password') {
      const username = config.username || this.flow.credentials?.['username'];
      const password = config.password || this.flow.credentials?.['password'];
      if (!username || !password) {
        throw new Error('OAuth2 password grant requires username and password');
      }
      params.set('username', username);
      params.set('password', password);
    }

    if (config.scope) {
      params.set('scope', config.scope);
    }
    if (config.audience) {
      params.set('audience', config.audience);
    }

    logger.info({ tokenUrl: config.tokenUrl, grantType: config.grantType }, 'Requesting OAuth2 access token');

    const response = await this.fetchImpl(config.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: params.toString(),
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => '');
      throw new Error(`OAuth2 token request failed with HTTP ${response.status}: ${errText}`);
    }

    const data = (await response.json()) as Record<string, unknown>;
    const token = (data['access_token'] || data['token']) as string;
    if (!token) {
      throw new Error('OAuth2 token response did not contain access_token');
    }

    const tokenType = (data['token_type'] as string) || 'Bearer';
    const expiresIn = typeof data['expires_in'] === 'number' ? data['expires_in'] : undefined;
    const expiresAt = expiresIn ? Date.now() + expiresIn * 1000 : undefined;

    const newState: AuthSessionState = {
      token,
      tokenType,
      cookies: { ...this.state.cookies },
      headers: { ...this.state.headers },
      expiresAt,
      lastRefreshedAt: Date.now(),
      variables: { ...this.state.variables, access_token: token },
    };

    this.extractCookies(response, newState.cookies);
    logger.info('OAuth2 access token acquired successfully');
    return newState;
  }

  /**
   * Executes static API Key or Bearer Token authentication.
   */
  private executeStaticAuthFlow(): Promise<AuthSessionState> {
    const token =
      this.flow.credentials?.['token'] ||
      this.flow.credentials?.['apiKey'] ||
      this.flow.credentials?.['key'] ||
      this.state.token;

    const newState: AuthSessionState = {
      token,
      tokenType: this.flow.type === 'API_KEY' ? 'ApiKey' : 'Bearer',
      cookies: { ...this.state.cookies },
      headers: { ...this.state.headers, ...(this.flow.headers ?? {}) },
      lastRefreshedAt: Date.now(),
      variables: { ...this.flow.credentials },
    };

    return Promise.resolve(newState);
  }

  /**
   * Extracts Set-Cookie headers into target cookie map.
   */
  private extractCookies(response: Response, cookieMap: Record<string, string>): void {
    const rawSetCookie = (response.headers as any).getSetCookie
      ? (response.headers as any).getSetCookie()
      : response.headers.get('set-cookie');

    if (!rawSetCookie) return;

    const cookieStrings: string[] = Array.isArray(rawSetCookie)
      ? rawSetCookie
      : [rawSetCookie];

    for (const cookieStr of cookieStrings) {
      const parts = cookieStr.split(';');
      const firstPart = parts[0]?.trim();
      if (!firstPart) continue;
      const eqIdx = firstPart.indexOf('=');
      if (eqIdx > 0) {
        const name = firstPart.substring(0, eqIdx).trim();
        const value = firstPart.substring(eqIdx + 1).trim();
        cookieMap[name] = value;
      }
    }
  }

  /**
   * Resolves nested property path in a JSON object (e.g. "auth.session.token" or "data.0.id").
   */
  private extractJsonPath(obj: Record<string, unknown>, path: string): string | undefined {
    const parts = path.split('.');
    let current: any = obj;

    for (const part of parts) {
      if (current === null || current === undefined) return undefined;
      current = current[part];
    }

    return current !== undefined && current !== null ? String(current) : undefined;
  }

  /**
   * Interpolates template string with variables e.g. "Bearer {{token}}".
   */
  private interpolate(template: string, vars: Record<string, unknown> = this.state.variables): string {
    return template.replace(/\{\{\s*([a-zA-Z0-9_-]+)\s*\}\}/g, (_, key) => {
      const val = vars[key] ?? this.flow.credentials?.[key] ?? (this.state as any)[key];
      return val !== undefined && val !== null ? String(val) : '';
    });
  }

  /**
   * Recursively interpolates object values.
   */
  private interpolateObject(obj: Record<string, unknown>, vars: Record<string, unknown>): Record<string, unknown> {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
      if (typeof v === 'string') {
        result[k] = this.interpolate(v, vars);
      } else if (v && typeof v === 'object' && !Array.isArray(v)) {
        result[k] = this.interpolateObject(v as Record<string, unknown>, vars);
      } else {
        result[k] = v;
      }
    }
    return result;
  }
}

export { StatefulAuthenticator as StatefulAuthService };
