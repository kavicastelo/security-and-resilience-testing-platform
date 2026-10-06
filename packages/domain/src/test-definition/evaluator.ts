import { SingleTestSpec } from './index.js';
import { extractFieldValue } from './interpolator.js';

export type AssertionSpec = SingleTestSpec['assertions'][number];

export interface AssertionEvaluationResult {
  passed: boolean;
  operator: string;
  field: string;
  expected?: unknown;
  actual?: unknown;
  message?: string;
}

export { extractFieldValue };

/**
 * Validates whether a value matches a simple schema or type name.
 */
function matchesTypeOrSchema(val: unknown, schema: unknown): boolean {
  if (typeof schema === 'string') {
    const type = schema.trim().toLowerCase();
    switch (type) {
      case 'string':
        return typeof val === 'string';
      case 'number':
        return typeof val === 'number' && !isNaN(val);
      case 'integer':
      case 'int':
        return typeof val === 'number' && Number.isInteger(val);
      case 'boolean':
      case 'bool':
        return typeof val === 'boolean';
      case 'array':
        return Array.isArray(val);
      case 'object':
        return typeof val === 'object' && val !== null && !Array.isArray(val);
      case 'null':
        return val === null;
      case 'date':
        return typeof val === 'string' && !isNaN(Date.parse(val));
      default:
        return false;
    }
  }

  if (schema && typeof schema === 'object' && !Array.isArray(schema)) {
    if (val === null || val === undefined || typeof val !== 'object') {
      return false;
    }
    const valObj = val as Record<string, unknown>;
    for (const [prop, expectedType] of Object.entries(schema as Record<string, unknown>)) {
      if (!matchesTypeOrSchema(valObj[prop], expectedType)) {
        return false;
      }
    }
    return true;
  }

  return false;
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

    case 'contains_json_path': {
      if (expectedValue !== undefined && expectedValue !== null) {
        const nestedVal = extractFieldValue(actualValue, String(expectedValue));
        passed = nestedVal !== undefined && nestedVal !== null;
      } else {
        passed = actualValue !== undefined && actualValue !== null;
      }
      break;
    }

    case 'not_contains_json_path': {
      if (expectedValue !== undefined && expectedValue !== null) {
        const nestedVal = extractFieldValue(actualValue, String(expectedValue));
        passed = nestedVal === undefined || nestedVal === null;
      } else {
        passed = actualValue === undefined || actualValue === null;
      }
      break;
    }

    case 'schema_matches':
      passed = matchesTypeOrSchema(actualValue, expectedValue);
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
    message: passed
      ? undefined
      : message || `Assertion failed: [${field}] ${operator} "${expectedValue}" (actual: "${actualValue}")`,
  };
}
