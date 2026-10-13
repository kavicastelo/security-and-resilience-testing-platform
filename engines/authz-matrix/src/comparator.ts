import { AuthzMatrixTestCase } from '@security-lab/contracts';
import { ComparisonResult } from './types.js';

const SENSITIVE_KEYWORDS = [
  'payroll',
  'salary',
  'ssn',
  'creditcard',
  'financial',
  'medical',
  'confidential',
  'secret',
  'password',
  'private_key',
  'patient',
  'billing',
];

/**
 * Normalizes response content by replacing dynamic timestamps and ephemeral tokens.
 */
export function normalizeResponseBody(body: string): string {
  return body
    // ISO-8601 Timestamps
    .replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})/gi, '<TIMESTAMP>')
    // Epoch milliseconds / seconds
    .replace(/\b1\d{9,12}\b/g, '<EPOCH>')
    // UUIDs / Request Traces
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '<UUID>')
    // ETag headers / hashes
    .replace(/W\/"[a-f0-9]+"/gi, '<ETAG>');
}

/**
 * Checks whether a 200 OK body is actually an API-level error in disguise.
 */
export function isSoftErrorResponse(body: string): boolean {
  try {
    const json = JSON.parse(body);
    if (json && typeof json === 'object') {
      if (
        json.error === 'unauthorized' ||
        json.error === 'forbidden' ||
        json.error === 'access_denied' ||
        json.code === 401 ||
        json.code === 403 ||
        json.status === 401 ||
        json.status === 403 ||
        json.success === false
      ) {
        return true;
      }
    }
  } catch {
    // Non-JSON body
  }
  return false;
}

/**
 * Evaluates whether an HTTP response indicates a broken authorization vulnerability.
 */
export function evaluateAuthzResponse(
  testCase: AuthzMatrixTestCase,
  statusCode: number,
  responseBody: string,
): ComparisonResult {
  // If the target responded with one of the expected denial codes (e.g. 401, 403, 404)
  if (testCase.expectedStatuses.includes(statusCode)) {
    return {
      isViolation: false,
      severity: 'LOW',
      reason: `Route properly rejected request with HTTP ${statusCode}`,
      dataLeakageDetected: false,
    };
  }

  // If status is 2xx (Success), verify whether it's an authorization bypass
  if (statusCode >= 200 && statusCode < 300) {
    if (isSoftErrorResponse(responseBody)) {
      return {
        isViolation: false,
        severity: 'LOW',
        reason: 'Received HTTP 200 but body contains application-level denial envelope',
        dataLeakageDetected: false,
      };
    }

    const normalized = normalizeResponseBody(responseBody.toLowerCase());
    let dataLeakage = false;

    // Check if victim's specific resource ID or owner identity leaked in response
    if (testCase.targetResourceId && normalized.includes(testCase.targetResourceId.toLowerCase())) {
      dataLeakage = true;
    }
    if (testCase.ownerPersona && normalized.includes(testCase.ownerPersona.id.toLowerCase())) {
      dataLeakage = true;
    }

    // Check for high-sensitivity data fields
    const sensitiveMatch = SENSITIVE_KEYWORDS.find((kw) => normalized.includes(kw));

    switch (testCase.type) {
      case 'BOLA_HORIZONTAL_IDOR': {
        const severity = dataLeakage || sensitiveMatch || testCase.method !== 'GET' ? 'CRITICAL' : 'HIGH';
        const reason = dataLeakage
          ? `BOLA/IDOR Violation: Persona "${testCase.actorPersona.id}" successfully accessed victim "${testCase.ownerPersona?.id || 'owner'}" resource "${testCase.targetResourceId}" with HTTP ${statusCode} and confirmed data leakage`
          : `BOLA/IDOR Violation: Persona "${testCase.actorPersona.id}" received HTTP ${statusCode} on unauthorized resource "${testCase.targetResourceId}" (expected ${testCase.expectedStatuses.join('/')})`;
        return {
          isViolation: true,
          violationType: 'BOLA_HORIZONTAL_IDOR',
          severity,
          reason,
          dataLeakageDetected: dataLeakage,
        };
      }

      case 'BFLA_VERTICAL_ESCALATION': {
        const severity = testCase.actorPersona.role === 'anonymous' ? 'CRITICAL' : 'CRITICAL';
        return {
          isViolation: true,
          violationType: 'BFLA_VERTICAL_ESCALATION',
          severity,
          reason: `BFLA Violation: Unprivileged persona "${testCase.actorPersona.id}" (role: ${testCase.actorPersona.role}) successfully executed administrative route "${testCase.method} ${testCase.endpointPath}" with HTTP ${statusCode}`,
          dataLeakageDetected: Boolean(sensitiveMatch),
        };
      }

      case 'MISSING_AUTHENTICATION': {
        return {
          isViolation: true,
          violationType: 'MISSING_AUTHENTICATION',
          severity: 'HIGH',
          reason: `Missing Authentication: Protected route "${testCase.method} ${testCase.endpointPath}" responded with HTTP ${statusCode} to unauthenticated anonymous request`,
          dataLeakageDetected: false,
        };
      }
    }
  }

  // Any other unexpected status code (e.g. 500 error or redirect)
  return {
    isViolation: false,
    severity: 'LOW',
    reason: `Target returned HTTP ${statusCode}`,
    dataLeakageDetected: false,
  };
}
