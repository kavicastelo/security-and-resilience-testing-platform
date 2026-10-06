/**
 * RFC 8785 Canonical JSON (JSON Canonicalization Scheme - JCS) Implementation
 *
 * Guarantees that any two logically equivalent JavaScript objects or data structures
 * serialize to the EXACT same byte sequence, regardless of key insertion order.
 */

export function canonicalizeJson(value: unknown): string {
  if (value === null) {
    return 'null';
  }

  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      return 'null';
    }
    return JSON.stringify(value);
  }

  if (typeof value === 'string') {
    return JSON.stringify(value);
  }

  if (value instanceof Date) {
    return JSON.stringify(value.toISOString());
  }

  if (Array.isArray(value)) {
    const items = value.map((item) => {
      const canonicalItem = canonicalizeJson(item);
      return canonicalItem === undefined ? 'null' : canonicalItem;
    });
    return `[${items.join(',')}]`;
  }

  if (typeof value === 'object') {
    // If object defines a custom toJSON method, use its result
    const maybeToJSON = (value as { toJSON?: () => unknown }).toJSON;
    if (typeof maybeToJSON === 'function') {
      return canonicalizeJson(maybeToJSON.call(value));
    }

    const obj = value as Record<string, unknown>;
    // Sort keys lexicographically according to UTF-16 code units (RFC 8785)
    const sortedKeys = Object.keys(obj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const entries: string[] = [];

    for (const key of sortedKeys) {
      const val = obj[key];
      // Skip undefined, functions, and symbols in objects
      if (val !== undefined && typeof val !== 'function' && typeof val !== 'symbol') {
        const canonicalVal = canonicalizeJson(val);
        if (canonicalVal !== undefined) {
          entries.push(`${JSON.stringify(key)}:${canonicalVal}`);
        }
      }
    }

    return `{${entries.join(',')}}`;
  }

  // Unsupported types (functions, symbols, undefined) return empty string or undefined
  return '';
}
