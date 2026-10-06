import { ExtractionRule } from './index.js';

// Sensitive prototype pollution keys that must never be set or evaluated
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Retrieves a variable value from a Map or plain object context.
 * Supports "varName", "variables.varName", or "context.varName".
 */
export function getContextVariable(
  context: Record<string, unknown> | Map<string, unknown>,
  key: string,
): unknown {
  const cleanKey = key
    .replace(/^variables\./, '')
    .replace(/^context\./, '');

  if (FORBIDDEN_KEYS.has(cleanKey)) {
    return undefined;
  }

  if (context instanceof Map) {
    if (context.has(cleanKey)) return context.get(cleanKey);
    if (context.has(key)) return context.get(key);
  } else if (context && typeof context === 'object') {
    if (cleanKey in context) return context[cleanKey];
    if (key in context) return context[key];
    // Check nested key e.g. "auth.token"
    return extractFieldValue(context, cleanKey);
  }

  return undefined;
}

/**
 * Interpolates variables formatted as ${varName} in a template string.
 */
export function interpolateString(
  template: string,
  context: Record<string, unknown> | Map<string, unknown>,
): string {
  if (!template || typeof template !== 'string') {
    return template;
  }

  return template.replace(/\$\{\s*([a-zA-Z0-9_.-]+)\s*\}/g, (match, varName) => {
    const val = getContextVariable(context, varName);
    if (val === undefined || val === null) {
      // Leave intact or return empty if missing
      return match;
    }
    if (typeof val === 'object') {
      return JSON.stringify(val);
    }
    return String(val);
  });
}

/**
 * Interpolates a value that may be a string, object, array, or primitive.
 * If the string is solely a single variable placeholder "${varName}",
 * the raw typed value (e.g. number, boolean, object) is preserved.
 */
export function interpolateValue(
  val: unknown,
  context: Record<string, unknown> | Map<string, unknown>,
): unknown {
  if (typeof val === 'string') {
    const singleVarMatch = val.trim().match(/^\$\{\s*([a-zA-Z0-9_.-]+)\s*\}$/);
    if (singleVarMatch && singleVarMatch[1]) {
      const resolved = getContextVariable(context, singleVarMatch[1]);
      if (resolved !== undefined) {
        return resolved;
      }
    }
    return interpolateString(val, context);
  }

  if (Array.isArray(val)) {
    return val.map((item) => interpolateValue(item, context));
  }

  if (val !== null && typeof val === 'object') {
    return interpolateObject(val as Record<string, unknown>, context);
  }

  return val;
}

/**
 * Recursively interpolates string values in an object while protecting against prototype pollution.
 */
export function interpolateObject<T>(
  data: T,
  context: Record<string, unknown> | Map<string, unknown>,
): T {
  if (data === null || data === undefined || typeof data !== 'object') {
    return data;
  }

  if (Array.isArray(data)) {
    return data.map((item) => interpolateValue(item, context)) as unknown as T;
  }

  const result: Record<string, unknown> = Object.create(null);

  for (const [key, val] of Object.entries(data as Record<string, unknown>)) {
    if (FORBIDDEN_KEYS.has(key)) {
      continue;
    }
    const interpolatedKey = interpolateString(key, context);
    result[interpolatedKey] = interpolateValue(val, context);
  }

  return result as T;
}

/**
 * Replaces path parameters formatted as {param} or :param and variables ${param}.
 */
export function substitutePathParams(
  urlPath: string,
  pathParams: Record<string, unknown> | undefined,
  context: Record<string, unknown> | Map<string, unknown>,
): string {
  let result = urlPath;

  // 1. Substitute path parameters {param} and :param
  if (pathParams && typeof pathParams === 'object') {
    for (const [key, rawVal] of Object.entries(pathParams)) {
      if (FORBIDDEN_KEYS.has(key)) continue;
      const val = String(interpolateValue(rawVal, context) ?? '');
      // Match {key}
      result = result.replace(new RegExp(`\\{${key}\\}`, 'g'), encodeURIComponent(val));
      // Match :key
      result = result.replace(new RegExp(`:${key}(?=[/?#]|$)`, 'g'), encodeURIComponent(val));
    }
  }

  // 2. Substitute any remaining ${param} in path
  result = interpolateString(result, context);

  return result;
}

/**
 * Extracts a nested field value from an object using dot notation and array indexing.
 * Examples: "body.token", "body.users[0].id", "headers.authorization", "status"
 */
export function extractFieldValue(data: unknown, path: string): unknown {
  if (data === null || data === undefined || !path) {
    return undefined;
  }

  // Normalize array index brackets to dot notation: "users[0].id" -> "users.0.id"
  const normalizedPath = path.replace(/\[(\d+)\]/g, '.$1');
  const parts = normalizedPath.split('.');
  let current: unknown = data;

  for (const part of parts) {
    if (current === null || current === undefined || typeof current !== 'object') {
      return undefined;
    }

    if (FORBIDDEN_KEYS.has(part)) {
      return undefined;
    }

    const obj = current as Record<string, unknown>;

    // Direct key match
    if (part in obj) {
      current = obj[part];
      continue;
    }

    // Array index
    if (Array.isArray(obj)) {
      const idx = parseInt(part, 10);
      current = !isNaN(idx) ? obj[idx] : undefined;
      continue;
    }

    // Case-insensitive match (crucial for HTTP headers)
    const matchingKey = Object.keys(obj).find((k) => k.toLowerCase() === part.toLowerCase());
    current = matchingKey ? obj[matchingKey] : undefined;
  }

  return current;
}

/**
 * Extracts a variable from response data according to an ExtractionRule.
 */
export function extractFromResponse(
  responseData: Record<string, unknown>,
  rule: ExtractionRule,
): unknown {
  const rawValue = extractFieldValue(responseData, rule.field);

  if (rawValue === undefined || rawValue === null) {
    return rule.defaultValue;
  }

  if (rule.regex) {
    try {
      const strVal = String(rawValue);
      const re = new RegExp(rule.regex);
      const match = strVal.match(re);
      if (match) {
        // If capture group 1 exists, use it; otherwise use full match
        return match[1] !== undefined ? match[1] : match[0];
      }
      return rule.defaultValue;
    } catch {
      return rule.defaultValue;
    }
  }

  return rawValue;
}
