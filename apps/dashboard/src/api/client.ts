export const STORAGE_KEY = 'security_lab_api_key';
export const ADMIN_STORAGE_KEY = 'security_lab_admin_key';

let inMemoryApiKey: string | null = null;
let inMemoryAdminKey: string | null = null;

/**
 * Resolves API key from in-memory fallback, localStorage, sessionStorage, or environment variable.
 */
export function getStoredApiKey(): string {
  if (inMemoryApiKey !== null) return inMemoryApiKey;

  if (typeof window !== 'undefined') {
    try {
      const local = window.localStorage?.getItem(STORAGE_KEY);
      if (local && local.trim().length > 0) return local.trim();

      const session = window.sessionStorage?.getItem(STORAGE_KEY);
      if (session && session.trim().length > 0) return session.trim();
    } catch {
      // Ignore localStorage security/quota errors
    }
  }

  try {
    const envKey = import.meta.env?.VITE_SECURITY_LAB_API_KEY;
    if (typeof envKey === 'string' && envKey.trim().length > 0) {
      return envKey.trim();
    }
  } catch {
    // Ignore meta env errors in non-vite runtimes
  }

  if (typeof process !== 'undefined' && process.env?.VITE_SECURITY_LAB_API_KEY) {
    return process.env.VITE_SECURITY_LAB_API_KEY.trim();
  }

  return '';
}

/**
 * Resolves optional admin key from in-memory, localStorage, environment variable,
 * or falls back to the operator API key.
 */
export function getStoredAdminKey(): string {
  if (inMemoryAdminKey !== null) return inMemoryAdminKey;

  if (typeof window !== 'undefined') {
    try {
      const local = window.localStorage?.getItem(ADMIN_STORAGE_KEY);
      if (local && local.trim().length > 0) return local.trim();

      const session = window.sessionStorage?.getItem(ADMIN_STORAGE_KEY);
      if (session && session.trim().length > 0) return session.trim();
    } catch {
      // Ignore localStorage security/quota errors
    }
  }

  try {
    const envKey = import.meta.env?.VITE_SECURITY_LAB_ADMIN_KEY;
    if (typeof envKey === 'string' && envKey.trim().length > 0) {
      return envKey.trim();
    }
  } catch {
    // Ignore meta env errors in non-vite runtimes
  }

  if (typeof process !== 'undefined' && process.env?.VITE_SECURITY_LAB_ADMIN_KEY) {
    return process.env.VITE_SECURITY_LAB_ADMIN_KEY.trim();
  }

  // Fallback to primary API key so single-credential setups authenticate for admin features
  return getStoredApiKey();
}

/**
 * Persists API key in browser storage and in-memory cache.
 */
export function setStoredApiKey(key: string, persistent = true): void {
  const trimmed = key.trim();
  inMemoryApiKey = trimmed;

  if (typeof window === 'undefined') return;

  try {
    if (persistent) {
      window.localStorage?.setItem(STORAGE_KEY, trimmed);
      window.sessionStorage?.removeItem(STORAGE_KEY);
    } else {
      window.sessionStorage?.setItem(STORAGE_KEY, trimmed);
      window.localStorage?.removeItem(STORAGE_KEY);
    }
  } catch {
    // Ignore storage quota or access errors
  }
}

/**
 * Removes API key from browser storage and in-memory cache.
 */
export function clearStoredApiKey(): void {
  inMemoryApiKey = '';
  inMemoryAdminKey = '';
  if (typeof process !== 'undefined') {
    if (process.env?.VITE_SECURITY_LAB_API_KEY) delete process.env.VITE_SECURITY_LAB_API_KEY;
    if (process.env?.VITE_SECURITY_LAB_ADMIN_KEY) delete process.env.VITE_SECURITY_LAB_ADMIN_KEY;
  }
  if (typeof window === 'undefined') return;

  try {
    window.localStorage?.removeItem(STORAGE_KEY);
    window.sessionStorage?.removeItem(STORAGE_KEY);
    window.localStorage?.removeItem(ADMIN_STORAGE_KEY);
    window.sessionStorage?.removeItem(ADMIN_STORAGE_KEY);
  } catch {
    // Ignore storage errors
  }
}

/**
 * Persists Admin key in browser storage and in-memory cache.
 */
export function setStoredAdminKey(key: string, persistent = true): void {
  const trimmed = key.trim();
  inMemoryAdminKey = trimmed;

  if (typeof window === 'undefined') return;

  try {
    if (persistent) {
      window.localStorage?.setItem(ADMIN_STORAGE_KEY, trimmed);
      window.sessionStorage?.removeItem(ADMIN_STORAGE_KEY);
    } else {
      window.sessionStorage?.setItem(ADMIN_STORAGE_KEY, trimmed);
      window.localStorage?.removeItem(ADMIN_STORAGE_KEY);
    }
  } catch {
    // Ignore storage quota or access errors
  }
}

/**
 * Removes Admin key from browser storage and in-memory cache.
 */
export function clearStoredAdminKey(): void {
  inMemoryAdminKey = '';
  if (typeof process !== 'undefined' && process.env?.VITE_SECURITY_LAB_ADMIN_KEY) {
    delete process.env.VITE_SECURITY_LAB_ADMIN_KEY;
  }
  if (typeof window === 'undefined') return;

  try {
    window.localStorage?.removeItem(ADMIN_STORAGE_KEY);
    window.sessionStorage?.removeItem(ADMIN_STORAGE_KEY);
  } catch {
    // Ignore storage errors
  }
}

/**
 * Assembles request headers including Authorization and X-API-Key if a key is configured.
 */
export function getAuthHeaders(headers?: HeadersInit): Record<string, string> {
  const result: Record<string, string> = {};

  if (headers) {
    if (typeof Headers !== 'undefined' && headers instanceof Headers) {
      headers.forEach((val, key) => {
        result[key] = val;
      });
    } else if (Array.isArray(headers)) {
      for (const [key, val] of headers) {
        result[key] = val;
      }
    } else if (typeof headers === 'object') {
      Object.assign(result, headers);
    }
  }

  const apiKey = getStoredApiKey();
  if (apiKey) {
    result['Authorization'] = `Bearer ${apiKey}`;
    result['X-API-Key'] = apiKey;
  }

  const adminKey = getStoredAdminKey();
  if (adminKey && !result['X-Admin-Key'] && !result['x-admin-key']) {
    result['X-Admin-Key'] = adminKey;
  }

  return result;
}

/**
 * Authenticated fetch wrapper that attaches API key credentials and dispatches
 * an event when a 401 Unauthorized status is returned.
 */
export async function authFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const headers = getAuthHeaders(init?.headers);
  const response = await fetch(input, {
    ...init,
    headers,
  });

  if (response.status === 401) {
    if (typeof window !== 'undefined') {
      window.dispatchEvent(
        new CustomEvent('security-lab:auth-required', {
          detail: { status: 401, url: typeof input === 'string' ? input : input.toString() },
        }),
      );
    }
  }

  return response;
}

let interceptorInstalled = false;

/**
 * Installs global fetch interceptor to automatically attach API key headers
 * and handle 401 unauthorized challenges across all dashboard components.
 */
export function installAuthInterceptor(): void {
  if (typeof window === 'undefined' || interceptorInstalled) return;
  interceptorInstalled = true;

  const originalFetch = window.fetch;
  window.fetch = async function (input: RequestInfo | URL, init?: RequestInit) {
    const headers = getAuthHeaders(init?.headers);
    const response = await originalFetch(input, {
      ...init,
      headers,
    });

    if (response.status === 401) {
      window.dispatchEvent(
        new CustomEvent('security-lab:auth-required', {
          detail: { status: 401, url: typeof input === 'string' ? input : input.toString() },
        }),
      );
    }

    return response;
  };
}

export const apiClient = {
  getStoredApiKey,
  setStoredApiKey,
  clearStoredApiKey,
  getStoredAdminKey,
  setStoredAdminKey,
  clearStoredAdminKey,
  getAuthHeaders,
  authFetch,
  installAuthInterceptor,

  async get<T>(url: string, init?: RequestInit): Promise<T> {
    const res = await authFetch(url, { ...init, method: 'GET' });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error?.message || `HTTP ${res.status}`);
    return json.data as T;
  },

  async post<T>(url: string, body?: unknown, init?: RequestInit): Promise<T> {
    const headers = new Headers(init?.headers);
    if (!headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
    const res = await authFetch(url, {
      ...init,
      method: 'POST',
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error?.message || `HTTP ${res.status}`);
    return json.data as T;
  },
};
