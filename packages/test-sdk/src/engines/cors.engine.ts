import { TestEngine } from '../engine.js';
import { TestCapability } from '../capability.js';
import { ExecutionContext } from '../context.js';
import { TestInput, TestResult, ValidationResult, RawEngineFinding } from '../result.js';

export class CorsSecurityEngine implements TestEngine {
  readonly id = 'engine-native-cors';
  readonly version = '1.0.0';

  capabilities(): TestCapability[] {
    return [
      {
        id: 'cors_audit',
        name: 'Cross-Origin Resource Sharing (CORS) Audit',
        category: 'passive_analysis',
        description: 'Audits CORS origin reflection, credential leaks, and permissive headers',
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
    const untrustedOrigin = 'https://untrusted-security-test.example.com';
    const findings: RawEngineFinding[] = [];

    context.reportProgress(20, 'Dispatching CORS pre-flight check with arbitrary Origin...');

    let res: Response;
    try {
      res = await fetch(input.targetUrl, {
        method: 'OPTIONS',
        headers: {
          Origin: untrustedOrigin,
          'Access-Control-Request-Method': 'GET',
          'Access-Control-Request-Headers': 'Authorization,Content-Type',
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
        error: `CORS preflight request failed: ${msg}`,
      };
    }

    const allowOrigin = res.headers.get('access-control-allow-origin');
    const allowCredentials = res.headers.get('access-control-allow-credentials');

    context.reportProgress(60, 'Evaluating CORS response headers...');

    // 1. Wildcard Origin with Credentials
    if (allowOrigin === '*' && allowCredentials === 'true') {
      findings.push({
        title: 'CORS Wildcard Allowed Origin with Credentials Enabled',
        category: 'cors',
        severity: 'high',
        description: 'Target specifies Access-Control-Allow-Origin: * alongside Access-Control-Allow-Credentials: true. While modern browsers reject this, it indicates flawed access control assumptions.',
        recommendation: 'Explicitly specify trusted origins rather than using a wildcard when credentials are required.',
        evidence: {
          request: { method: 'OPTIONS', url: input.targetUrl, headers: { Origin: untrustedOrigin } },
          response: { statusCode: res.status, headers: { 'access-control-allow-origin': allowOrigin, 'access-control-allow-credentials': allowCredentials } },
          expected: 'No wildcard origin with credentials',
          actual: `Allow-Origin: ${allowOrigin}, Allow-Credentials: ${allowCredentials}`,
        },
      });
    }

    // 2. Arbitrary Origin Reflection
    if (allowOrigin === untrustedOrigin) {
      findings.push({
        title: 'Arbitrary Origin Reflection in CORS Response',
        category: 'cors',
        severity: allowCredentials === 'true' ? 'high' : 'medium',
        description: `Target dynamically echoed back untrusted Origin "${untrustedOrigin}" in Access-Control-Allow-Origin without allowlist verification.`,
        recommendation: 'Validate the Origin request header against a strict domain whitelist before reflecting it in Access-Control-Allow-Origin.',
        evidence: {
          request: { method: 'OPTIONS', url: input.targetUrl, headers: { Origin: untrustedOrigin } },
          response: { statusCode: res.status, headers: { 'access-control-allow-origin': allowOrigin } },
          expected: 'Origin validated against allowlist',
          actual: `Reflected untrusted origin: ${allowOrigin}`,
        },
      });
    }

    context.reportProgress(100, `Completed CORS audit: ${findings.length} findings identified.`);

    return {
      engineId: this.id,
      durationMs: Date.now() - startTime,
      success: true,
      findings,
      metrics: [
        {
          name: 'cors_preflight_status',
          value: res.status,
          unit: 'status',
        },
      ],
      rawOutput: {
        allowOrigin,
        allowCredentials,
        allowMethods: res.headers.get('access-control-allow-methods'),
        allowHeaders: res.headers.get('access-control-allow-headers'),
      },
    };
  }
}
