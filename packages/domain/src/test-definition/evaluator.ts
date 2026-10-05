import { SingleTestSpec } from './index.js';

export type AssertionSpec = SingleTestSpec['assertions'][number];

export interface AssertionEvaluationResult {
  passed: boolean;
  operator: string;
  field: string;
  expected?: unknown;
  actual?: unknown;
  message?: string;
}

/**
 * Extracts a nested field value from a target object using dot notation (e.g. "headers.content-type" or "status").
 */
export function extractFieldValue(data: Record<string, unknown>, path: string): unknown {
  const parts = path.split('.');
  let current: unknown = data;

  for (const part of parts) {
    if (current === null || current === undefined || typeof current !== 'object') {
      return undefined;
    }

    // Case-insensitive match for headers
    const obj = current as Record<string, unknown>;
    const matchingKey = Object.keys(obj).find((k) => k.toLowerCase() === part.toLowerCase());
    current = matchingKey ? obj[matchingKey] : obj[part];
  }

  return current;
}

/**
 * Evaluates an individual assertion rule against an actual response value.
 */
export function evaluateAssertion(assertion: AssertionSpec, actualValue: unknown): AssertionEvaluationResult {
  const { operator, value: expectedValue, field, message } = assertion;

  let passed = false;

  switch (operator) {
    case 'exists':
      passed = actualValue !== undefined && actualValue !== null && actualValue !== '';
      break;

    case 'does_not_exist':
      passed = actualValue === undefined || actualValue === null || actualValue === '';
      break;

    case 'equals':
      passed = String(actualValue).trim().toLowerCase() === String(expectedValue).trim().toLowerCase();
      break;

    case 'not_equals':
      passed = String(actualValue).trim().toLowerCase() !== String(expectedValue).trim().toLowerCase();
      break;

    case 'contains':
      if (typeof actualValue === 'string') {
        passed = actualValue.toLowerCase().includes(String(expectedValue).toLowerCase());
      } else if (Array.isArray(actualValue)) {
        passed = actualValue.includes(expectedValue);
      }
      break;

    case 'not_contains':
      if (typeof actualValue === 'string') {
        passed = !actualValue.toLowerCase().includes(String(expectedValue).toLowerCase());
      } else if (Array.isArray(actualValue)) {
        passed = !actualValue.includes(expectedValue);
      } else {
        passed = true;
      }
      break;

    case 'matches_regex':
      try {
        const regex = new RegExp(String(expectedValue), 'i');
        passed = regex.test(String(actualValue ?? ''));
      } catch {
        passed = false;
      }
      break;

    default:
      passed = false;
  }

  return {
    passed,
    operator,
    field,
    expected: expectedValue,
    actual: actualValue,
    message: passed ? undefined : message || `Assertion failed: [${field}] ${operator} "${expectedValue}" (actual: "${actualValue}")`,
  };
}
