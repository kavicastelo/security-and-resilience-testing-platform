/**
 * Redaction utility for masking sensitive headers and credentials.
 */

export const SENSITIVE_HEADER_NAMES = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
  'api-key',
  'apikey',
  'token',
  'private-token',
]);

export const REDACTED_VALUE = '***REDACTED***';

/**
 * Checks whether a header key is sensitive.
 */
export function isSensitiveHeader(key: string): boolean {
  return SENSITIVE_HEADER_NAMES.has(key.toLowerCase().trim());
}

/**
 * Redacts sensitive header values in a Record or Headers object.
 */
export function redactHeaders(headers: Record<string, string | undefined> | Headers | undefined): Record<string, string> {
  if (!headers) return {};

  const result: Record<string, string> = {};

  if (typeof (headers as Headers).forEach === 'function') {
    (headers as Headers).forEach((value, key) => {
      result[key] = isSensitiveHeader(key) ? REDACTED_VALUE : value;
    });
    return result;
  }

  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    result[key] = isSensitiveHeader(key) ? REDACTED_VALUE : String(value);
  }

  return result;
}

/**
 * Deeply scans and redacts sensitive keys from an object or payload before logging or storing evidence.
 */
export function redactObject<T>(input: T): T {
  if (!input || typeof input !== 'object') {
    return input;
  }

  if (Array.isArray(input)) {
    return input.map((item) => redactObject(item)) as unknown as T;
  }

  const output: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
    if (value && typeof value === 'object') {
      output[key] = redactObject(value);
    } else if (isSensitiveHeader(key) || /password|secret|token|apikey|dek/i.test(key)) {
      output[key] = REDACTED_VALUE;
    } else {
      output[key] = value;
    }
  }

  return output as T;
}
