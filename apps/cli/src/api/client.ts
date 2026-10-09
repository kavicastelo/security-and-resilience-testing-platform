import { getCliConfig } from '../config/index.js';

export class AuthenticationError extends Error {
  constructor(
    message = "Error: SECURITY_LAB_API_KEY is missing or invalid. Set it in your environment or run 'sec-lab login'.",
  ) {
    super(message);
    this.name = 'AuthenticationError';
  }
}

export class ApiClient {
  private get baseUrl(): string {
    return getCliConfig().apiUrl.replace(/\/$/, '');
  }

  private getHeaders(customHeaders?: Record<string, string>): Record<string, string> {
    const config = getCliConfig();
    const apiKey = config.apiKey?.trim();

    if (!apiKey) {
      throw new AuthenticationError();
    }

    return {
      Accept: 'application/json',
      Authorization: `Bearer ${apiKey}`,
      'X-API-Key': apiKey,
      ...customHeaders,
    };
  }

  private handleResponse<T>(res: Response, json: { success?: boolean; data?: T; error?: { message?: string } }): T {
    if (res.status === 401) {
      throw new AuthenticationError();
    }
    if (!res.ok) {
      throw new Error(json.error?.message || `HTTP ${res.status}: ${res.statusText}`);
    }
    return json.data as T;
  }

  async get<T>(path: string, headers?: Record<string, string>): Promise<T> {
    const reqHeaders = this.getHeaders(headers);
    const res = await fetch(`${this.baseUrl}${path}`, {
      headers: reqHeaders,
    });

    if (res.status === 401) {
      throw new AuthenticationError();
    }

    const json = (await res.json()) as { success?: boolean; data?: T; error?: { message?: string } };
    return this.handleResponse(res, json);
  }

  async post<T>(path: string, body: unknown, headers?: Record<string, string>): Promise<T> {
    const reqHeaders = this.getHeaders({
      'Content-Type': 'application/json',
      ...headers,
    });

    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: reqHeaders,
      body: JSON.stringify(body),
    });

    if (res.status === 401) {
      throw new AuthenticationError();
    }

    const json = (await res.json()) as { success?: boolean; data?: T; error?: { message?: string } };
    return this.handleResponse(res, json);
  }

  async put<T>(path: string, body: unknown, headers?: Record<string, string>): Promise<T> {
    const reqHeaders = this.getHeaders({
      'Content-Type': 'application/json',
      ...headers,
    });

    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'PUT',
      headers: reqHeaders,
      body: JSON.stringify(body),
    });

    if (res.status === 401) {
      throw new AuthenticationError();
    }

    const json = (await res.json()) as { success?: boolean; data?: T; error?: { message?: string } };
    return this.handleResponse(res, json);
  }

  async patch<T>(path: string, body: unknown, headers?: Record<string, string>): Promise<T> {
    const reqHeaders = this.getHeaders({
      'Content-Type': 'application/json',
      ...headers,
    });

    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'PATCH',
      headers: reqHeaders,
      body: JSON.stringify(body),
    });

    if (res.status === 401) {
      throw new AuthenticationError();
    }

    const json = (await res.json()) as { success?: boolean; data?: T; error?: { message?: string } };
    return this.handleResponse(res, json);
  }

  async delete<T = unknown>(path: string, headers?: Record<string, string>): Promise<T> {
    const reqHeaders = this.getHeaders(headers);
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'DELETE',
      headers: reqHeaders,
    });

    if (res.status === 401) {
      throw new AuthenticationError();
    }

    const json = (await res.json()) as { success?: boolean; data?: T; error?: { message?: string } };
    return this.handleResponse(res, json);
  }

  async getText(path: string, headers?: Record<string, string>): Promise<string> {
    const reqHeaders = this.getHeaders({
      Accept: '*/*',
      ...headers,
    });

    const res = await fetch(`${this.baseUrl}${path}`, {
      headers: reqHeaders,
    });

    if (res.status === 401) {
      throw new AuthenticationError();
    }

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }
    return res.text();
  }
}

export const apiClient = new ApiClient();
