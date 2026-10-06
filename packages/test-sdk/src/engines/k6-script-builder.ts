export interface K6Stage {
  duration: string;
  target: number;
}

export interface K6ScriptOptions {
  targetUrl: string;
  vus?: number;
  duration?: string;
  durationSec?: number;
  stages?: K6Stage[];
  thresholds?: Record<string, string[]>;
  maxP95Ms?: number;
  maxFailedRatio?: number;
  method?: string;
  headers?: Record<string, string>;
  body?: string | Record<string, unknown>;
  scenarioType?: 'load_sla' | 'concurrency_soak' | 'burst_resilience';
}

/**
 * Generates an executable Grafana k6 JavaScript ES-module test script
 * defining VUs, duration, stages, thresholds, and request logic.
 */
export function buildK6Script(options: K6ScriptOptions): string {
  const method = (options.method || 'GET').toUpperCase();
  const maxP95Ms = options.maxP95Ms ?? 500;
  const maxFailedRatio = options.maxFailedRatio ?? 0.05;

  const k6Options: Record<string, unknown> = {};

  if (options.stages && options.stages.length > 0) {
    k6Options.stages = options.stages;
  } else {
    k6Options.vus = options.vus || 1;
    k6Options.duration = options.duration || `${options.durationSec || 3}s`;
  }

  k6Options.thresholds = {
    http_req_duration: [`p(95)<${maxP95Ms}`],
    http_req_failed: [`rate<${maxFailedRatio}`],
    ...(options.thresholds || {}),
  };

  const headers: Record<string, string> = {
    'User-Agent': 'SecurityLab-K6Worker/1.0',
    Accept: '*/*',
    ...(options.headers || {}),
  };

  // Generate request invocation based on HTTP method
  let requestStatement: string;
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    requestStatement = `const res = http.${method.toLowerCase()}(url, params);`;
  } else if (method === 'DELETE') {
    requestStatement = 'const res = http.del(url, null, params);';
  } else {
    const payloadStr =
      typeof options.body === 'object' && options.body !== null
        ? JSON.stringify(options.body)
        : options.body || '';
    requestStatement = `const payload = ${JSON.stringify(payloadStr)};\n  const res = http.${method.toLowerCase()}(url, payload, params);`;
  }

  return `// Auto-generated Grafana k6 execution script by Security Lab
import http from 'k6/http';
import { check } from 'k6';

export const options = ${JSON.stringify(k6Options, null, 2)};

export function handleSummary(data) {
  return {
    '/scripts/summary.json': JSON.stringify(data),
  };
}

export default function () {
  const url = ${JSON.stringify(options.targetUrl)};
  const params = {
    headers: ${JSON.stringify(headers, null, 2)},
  };
  ${requestStatement}
  check(res, {
    'status is valid': (r) => r.status >= 200 && r.status < 400,
  });
}
`;
}
