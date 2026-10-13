import { FaultRule, FaultAction } from './types.js';

export interface EvaluatedFault {
  rule: FaultRule;
  action: FaultAction;
  delayMs?: number;
  statusCode?: number;
  statusBody?: string;
  truncateBytes?: number;
  details: string;
}

export function matchesPath(pattern: string, actualPath: string): boolean {
  if (pattern === '*' || pattern === actualPath) return true;

  // Simple wildcard matching (e.g. /api/*)
  if (pattern.endsWith('*')) {
    const prefix = pattern.slice(0, -1);
    return actualPath.startsWith(prefix);
  }

  // Regex pattern (e.g. /api\/v[12]\/.*/)
  if (pattern.startsWith('/') && pattern.endsWith('/')) {
    try {
      const regex = new RegExp(pattern.slice(1, -1));
      return regex.test(actualPath);
    } catch {
      return false;
    }
  }

  return false;
}

export function matchesMethod(ruleMethod: string, actualMethod: string): boolean {
  if (ruleMethod === '*' || !ruleMethod) return true;
  return ruleMethod.toUpperCase() === actualMethod.toUpperCase();
}

/**
 * Finds the first matching active fault rule for an incoming request.
 */
export function matchFaultRule(
  rules: FaultRule[],
  path: string,
  method: string,
): EvaluatedFault | null {
  for (const rule of rules) {
    if (!matchesMethod(rule.match.method, method)) {
      continue;
    }

    if (!matchesPath(rule.match.path, path)) {
      continue;
    }

    // Check probability percentage
    const pct = rule.percentage ?? 100;
    if (pct < 100) {
      const rand = Math.random() * 100;
      if (rand >= pct) {
        // Probability threshold not met, pass through
        continue;
      }
    }

    // Match found! Formulate evaluated fault
    switch (rule.action) {
      case 'LATENCY': {
        const baseDelay = rule.latencyMs ?? 500;
        const jitterRange = rule.jitterMs ?? 0;
        const jitter = jitterRange > 0 ? (Math.random() * 2 - 1) * jitterRange : 0;
        const totalDelay = Math.max(0, Math.round(baseDelay + jitter));
        return {
          rule,
          action: 'LATENCY',
          delayMs: totalDelay,
          details: `Injected artificial latency of ${totalDelay}ms (base: ${baseDelay}ms, jitter: +/-${jitterRange}ms)`,
        };
      }

      case 'STATUS_CODE': {
        const code = rule.statusCode ?? 503;
        const body =
          rule.statusBody ||
          JSON.stringify({
            error: 'Chaos Fault Injected: Service Unavailable',
            statusCode: code,
            ruleId: rule.id,
          });
        return {
          rule,
          action: 'STATUS_CODE',
          statusCode: code,
          statusBody: body,
          details: `Injected synthetic HTTP ${code} error`,
        };
      }

      case 'DROP': {
        return {
          rule,
          action: 'DROP',
          details: 'Injected connection drop: Socket forcibly terminated/reset',
        };
      }

      case 'TRUNCATE': {
        const truncateBytes = rule.truncateBytes ?? 64;
        return {
          rule,
          action: 'TRUNCATE',
          truncateBytes,
          details: `Injected payload truncation after ${truncateBytes} bytes`,
        };
      }
    }
  }

  return null;
}
