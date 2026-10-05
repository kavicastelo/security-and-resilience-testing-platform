import { getCliConfig } from '../config/index.js';

export class ApiClient {
  private get baseUrl(): string {
    return getCliConfig().apiUrl.replace(/\/$/, '');
  }

  async get<T>(path: string): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      headers: {
        Accept: 'application/json',
      },
    });

    const json = (await res.json()) as { success?: boolean; data?: T; error?: { message?: string } };
    if (!res.ok) {
      throw new Error(json.error?.message || `HTTP ${res.status}: ${res.statusText}`);
    }
    return json.data as T;
  }

  async post<T>(path: string, body: unknown): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(body),
    });

    const json = (await res.json()) as { success?: boolean; data?: T; error?: { message?: string } };
    if (!res.ok) {
      throw new Error(json.error?.message || `HTTP ${res.status}: ${res.statusText}`);
    }
    return json.data as T;
  }

  async getText(path: string): Promise<string> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      headers: {
        Accept: '*/*',
      },
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }
    return res.text();
  }
}

export const apiClient = new ApiClient();
