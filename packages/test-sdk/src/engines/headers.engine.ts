import { TestEngine } from '../engine.js';
import { TestCapability } from '../capability.js';
import { ExecutionContext } from '../context.js';
import { TestInput, TestResult, ValidationResult, RawEngineFinding } from '../result.js';

export class HeadersSecurityEngine implements TestEngine {
  readonly id = 'engine-native-headers';
  readonly version = '1.0.0';

  capabilities(): TestCapability[] {
    return [
      {
        id: 'headers_audit',
        name: 'OWASP Secure Headers Audit',
        category: 'passive_analysis',
        description: 'Audits defensive HTTP response headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options)',
        isDisruptive: false,
      },
    ];
  }

  validate(input: TestInput): ValidationResult {
    try {
      new URL(input.targetUrl);
      return { valid: true };
    } catch {
      return {
        valid: false,
        errors: [{ path: 'targetUrl', message: `Invalid target URL: "${input.targetUrl}"` }],
      };
    }
  }

  async execute(input: TestInput, context: ExecutionContext): Promise<TestResult> {
    const startTime = Date.now();
    context.reportProgress(10, 'Initiating HTTP request for header inspection...');

    let res: Response;
    try {
      res = await fetch(input.targetUrl, {
        method: 'GET',
        headers: {
          'User-Agent': 'SecurityLab-QA/1.0',
          Accept: '*/*',
          ...input.customHeaders,
        },
        signal: context.abortSignal,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        engineId: this.id,
        durationMs: Date.now() - startTime,
        success: false,
        findings: [],
        metrics: [],
        error: `Failed to connect to target: ${msg}`,
      };
    }

    context.reportProgress(50, 'Analyzing response headers against defensive baseline...');

    const headers: Record<string, string> = {};
    res.headers.forEach((val, key) => {
      headers[key.toLowerCase()] = val;
    });

    const findings: RawEngineFinding[] = [];

    // 1. Strict-Transport-Security (HSTS)
    const hsts = headers['strict-transport-security'];
    if (!hsts) {
      findings.push({
        title: 'Missing HTTP Strict Transport Security (HSTS) Header',
        category: 'headers',
        severity: 'medium',
        description: 'The target response did not include a Strict-Transport-Security header, leaving transport vulnerable to SSL stripping.',
        recommendation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" to all HTTPS responses.',
        evidence: {
          request: { method: 'GET', url: input.targetUrl, headers: input.customHeaders || {} },
          response: { statusCode: res.status, headers, responseTimeMs: Date.now() - startTime },
          expected: 'Strict-Transport-Security header present',
          actual: 'Header missing',
        },
      });
    }

    // 2. Content-Security-Policy (CSP)
    const csp = headers['content-security-policy'];
    if (!csp) {
      findings.push({
        title: 'Missing Content Security Policy (CSP)',
        category: 'headers',
        severity: 'medium',
        description: 'No Content-Security-Policy header was detected, reducing defense-in-depth against Cross-Site Scripting (XSS).',
        recommendation: 'Define a restrictive CSP specifying permitted script and style sources.',
        evidence: {
          request: { method: 'GET', url: input.targetUrl, headers: input.customHeaders || {} },
          response: { statusCode: res.status, headers, responseTimeMs: Date.now() - startTime },
          expected: 'Content-Security-Policy header present',
          actual: 'Header missing',
        },
      });
    }

    // 3. X-Content-Type-Options
    const nosniff = headers['x-content-type-options'];
    if (!nosniff || nosniff.toLowerCase() !== 'nosniff') {
      findings.push({
        title: 'Missing or Ineffective X-Content-Type-Options Header',
        category: 'headers',
        severity: 'low',
        description: 'The X-Content-Type-Options header is absent or not set to "nosniff", allowing browsers to MIME-sniff response bodies.',
        recommendation: 'Set "X-Content-Type-Options: nosniff" on all responses.',
        evidence: {
          request: { method: 'GET', url: input.targetUrl, headers: input.customHeaders || {} },
          response: { statusCode: res.status, headers, responseTimeMs: Date.now() - startTime },
          expected: 'X-Content-Type-Options: nosniff',
          actual: nosniff || 'Missing',
        },
      });
    }

    // 4. Clickjacking Protection (X-Frame-Options or CSP frame-ancestors)
    const xfo = headers['x-frame-options'];
    const hasFrameAncestors = csp && csp.toLowerCase().includes('frame-ancestors');
    if (!xfo && !hasFrameAncestors) {
      findings.push({
        title: 'Missing Anti-Clickjacking Header (X-Frame-Options / CSP frame-ancestors)',
        category: 'headers',
        severity: 'medium',
        description: 'Neither X-Frame-Options nor CSP frame-ancestors directive was detected. The page may be framed by third-party origins.',
        recommendation: 'Configure "X-Frame-Options: DENY" or "frame-ancestors \'none\'" in your CSP.',
        evidence: {
          request: { method: 'GET', url: input.targetUrl, headers: input.customHeaders || {} },
          response: { statusCode: res.status, headers, responseTimeMs: Date.now() - startTime },
          expected: 'X-Frame-Options or frame-ancestors directive',
          actual: 'Missing',
        },
      });
    }

    // 5. Information Disclosure (Server Banner / X-Powered-By)
    const serverBanner = headers['server'];
    const poweredBy = headers['x-powered-by'];
    if (poweredBy || (serverBanner && /\d+\.\d+/.test(serverBanner))) {
      findings.push({
        title: 'Server Technology Fingerprint Disclosure',
        category: 'headers',
        severity: 'low',
        description: `Response discloses underlying runtime versions: ${[serverBanner, poweredBy].filter(Boolean).join(', ')}`,
        recommendation: 'Suppress "Server" version tokens and remove "X-Powered-By" headers in production configuration.',
        evidence: {
          request: { method: 'GET', url: input.targetUrl, headers: input.customHeaders || {} },
          response: { statusCode: res.status, headers, responseTimeMs: Date.now() - startTime },
          expected: 'No version banner disclosure',
          actual: `Server: ${serverBanner}, X-Powered-By: ${poweredBy}`,
        },
      });
    }

    context.reportProgress(100, `Completed header audit: ${findings.length} findings identified.`);

    return {
      engineId: this.id,
      durationMs: Date.now() - startTime,
      success: true,
      findings,
      metrics: [
        {
          name: 'headers_audited_count',
          value: Object.keys(headers).length,
          unit: 'headers',
        },
        {
          name: 'response_time_ms',
          value: Date.now() - startTime,
          unit: 'ms',
        },
      ],
      rawOutput: headers,
    };
  }
}
