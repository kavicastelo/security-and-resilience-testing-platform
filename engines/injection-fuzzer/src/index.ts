import crypto from 'node:crypto';
import {
  TestEngine,
  TestCapability,
  ExecutionContext,
  TestInput,
  TestResult,
  ValidationResult,
  RawEngineFinding,
  RawEngineMetric,
  safeFetch,
} from '@security-lab/engine-sdk';
import { validateUrlAgainstScope } from '@security-lab/domain';
import {
  CrawledTargetInventory,
  DiscoveredRoute,
  FormDefinition,
} from '@security-lab/contracts';
import { OastListener, OastInteraction } from '@security-lab/test-runner';
import { createLogger } from '@security-lab/logger';

const logger = createLogger({ name: 'engine-injection-fuzzer' });

export interface InjectionFuzzerOptions {
  inventory?: CrawledTargetInventory;
  routes?: DiscoveredRoute[];
  oastListener?: OastListener;
  fuzzXss?: boolean;
  fuzzSqli?: boolean;
  fuzzSsrf?: boolean;
  fuzzCmd?: boolean;
  timeoutMs?: number;
}

interface InjectionPoint {
  url: string;
  method: 'GET' | 'POST';
  parameter: string;
  location: 'query' | 'body';
  enctype?: string;
  formAction?: string;
  extraParams?: Record<string, string>;
}

export class InjectionFuzzerEngine implements TestEngine {
  readonly id = 'engine-injection-fuzzer';
  readonly version = '1.0.0';
  readonly executionClass = 'class_a_native' as const;

  capabilities(): TestCapability[] {
    return [
      {
        id: 'injection_fuzzing',
        name: 'Context-Aware Injection Fuzzer (XSS, SQLi, SSRF, Command Injection)',
        category: 'active_fuzzing',
        description:
          'Automated active injection fuzzing with safe non-destructive canaries for Reflected XSS, SQL Injection error patterns, Command Injection, and blind Out-of-Band (OAST) SSRF callbacks.',
        isDisruptive: true,
        requiredScopeFlags: ['allow_active_scanning'],
      },
    ];
  }

  validate(input: TestInput): ValidationResult {
    try {
      const url = new URL(input.targetUrl);
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        return {
          valid: false,
          errors: [{ path: 'targetUrl', message: 'Target URL must use http or https protocol' }],
        };
      }
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
    const options = (input.options || {}) as InjectionFuzzerOptions;
    const scope = context.target?.scope;

    // Check scope boundary
    if (scope) {
      const scopeCheck = validateUrlAgainstScope(input.targetUrl, scope);
      if (!scopeCheck.valid) {
        return {
          engineId: this.id,
          durationMs: Date.now() - startTime,
          success: false,
          findings: [],
          metrics: [],
          error: `Target URL "${input.targetUrl}" is out of authorized scope: ${scopeCheck.violations.join('; ')}`,
        };
      }
    }

    context.reportProgress(5, `Initializing injection fuzzer for ${input.targetUrl}...`);

    const fuzzXss = options.fuzzXss ?? true;
    const fuzzSqli = options.fuzzSqli ?? true;
    const fuzzSsrf = options.fuzzSsrf ?? true;
    const fuzzCmd = options.fuzzCmd ?? true;

    // Setup or reuse OAST listener
    let oastListener = options.oastListener;
    let localOastStarted = false;

    if (fuzzSsrf && !oastListener) {
      try {
        oastListener = new OastListener();
        await oastListener.start();
        localOastStarted = true;
      } catch (err: unknown) {
        logger.warn(
          { event: 'fuzzer.oast.start_failed', error: err instanceof Error ? err.message : String(err) },
          'Failed to initialize ephemeral OAST listener; continuing without out-of-band SSRF testing.',
        );
      }
    }

    const findings: RawEngineFinding[] = [];
    let requestsCount = 0;

    try {
      // 1. Collect target injection points
      const injectionPoints = this.collectInjectionPoints(input.targetUrl, options);
      logger.info(
        { event: 'fuzzer.points_discovered', count: injectionPoints.length },
        `Identified ${injectionPoints.length} injection candidate points.`,
      );

      const totalSteps = injectionPoints.length;
      let currentStep = 0;

      for (const point of injectionPoints) {
        if (context.abortSignal?.aborted) break;
        currentStep++;
        const pct = Math.min(95, Math.round((currentStep / Math.max(1, totalSteps)) * 85) + 10);
        context.reportProgress(pct, `Fuzzing point [${currentStep}/${totalSteps}]: ${point.parameter} on ${point.url}`);

        // A. Reflected XSS Fuzzing
        if (fuzzXss) {
          const xssFinding = await this.testReflectedXss(point, input, context);
          requestsCount += 2;
          if (xssFinding) findings.push(xssFinding);
        }

        // B. SQL Injection Fuzzing
        if (fuzzSqli) {
          const sqliFinding = await this.testSqlInjection(point, input, context);
          requestsCount += 2;
          if (sqliFinding) findings.push(sqliFinding);
        }

        // C. Blind SSRF / OAST Callback Fuzzing
        if (fuzzSsrf && oastListener) {
          const ssrfFinding = await this.testBlindSsrf(point, input, context, oastListener);
          requestsCount += 1;
          if (ssrfFinding) findings.push(ssrfFinding);
        }

        // D. Command Injection Fuzzing
        if (fuzzCmd) {
          const cmdFinding = await this.testCommandInjection(point, input, context);
          requestsCount += 2;
          if (cmdFinding) findings.push(cmdFinding);
        }
      }

      context.reportProgress(100, `Injection fuzzing complete. Identified ${findings.length} findings across ${requestsCount} requests.`);

      const durationMs = Date.now() - startTime;
      const metrics: RawEngineMetric[] = [
        { name: 'injection_points_tested', value: injectionPoints.length, unit: 'count' },
        { name: 'fuzzing_requests_sent', value: requestsCount, unit: 'count' },
        { name: 'vulnerabilities_detected', value: findings.length, unit: 'count' },
      ];

      return {
        engineId: this.id,
        durationMs,
        success: true,
        findings,
        metrics,
      };
    } catch (err: unknown) {
      const durationMs = Date.now() - startTime;
      const errorMsg = err instanceof Error ? err.message : String(err);
      return {
        engineId: this.id,
        durationMs,
        success: false,
        findings,
        metrics: [],
        error: `Injection fuzzer execution error: ${errorMsg}`,
      };
    } finally {
      if (localOastStarted && oastListener) {
        await oastListener.stop();
      }
    }
  }

  private collectInjectionPoints(targetUrl: string, options: InjectionFuzzerOptions): InjectionPoint[] {
    const points: InjectionPoint[] = [];
    const seen = new Set<string>();

    const addPoint = (p: InjectionPoint) => {
      const key = `${p.method}:${p.url}:${p.parameter}:${p.location}`;
      if (!seen.has(key)) {
        seen.add(key);
        points.push(p);
      }
    };

    // 1. From provided inventory routes & forms
    if (options.inventory) {
      for (const route of options.inventory.routes) {
        for (const qp of route.queryParams) {
          addPoint({ url: route.url, method: 'GET', parameter: qp, location: 'query' });
        }
        for (const form of route.forms) {
          this.addFormPoints(form, addPoint);
        }
      }
      for (const form of options.inventory.forms) {
        this.addFormPoints(form, addPoint);
      }
    }

    // 2. From explicit routes array
    if (options.routes) {
      for (const route of options.routes) {
        for (const qp of route.queryParams) {
          addPoint({ url: route.url, method: 'GET', parameter: qp, location: 'query' });
        }
        for (const form of route.forms) {
          this.addFormPoints(form, addPoint);
        }
      }
    }

    // 3. From base targetUrl query params
    try {
      const parsed = new URL(targetUrl);
      for (const key of parsed.searchParams.keys()) {
        addPoint({ url: targetUrl, method: 'GET', parameter: key, location: 'query' });
      }
    } catch {
      // Ignore
    }

    // 4. Default common parameter probes if no parameters discovered
    if (points.length === 0) {
      const commonParams = ['q', 'search', 'id', 'url', 'dest', 'redirect', 'cmd'];
      for (const param of commonParams) {
        addPoint({ url: targetUrl, method: 'GET', parameter: param, location: 'query' });
      }
    }

    return points;
  }

  private addFormPoints(form: FormDefinition, addPoint: (p: InjectionPoint) => void): void {
    const extraParams: Record<string, string> = {};
    for (const f of form.fields) {
      extraParams[f.name] = f.value || 'test';
    }

    for (const field of form.fields) {
      if (['submit', 'button', 'reset'].includes(field.type.toLowerCase())) continue;
      addPoint({
        url: form.action,
        method: form.method === 'GET' ? 'GET' : 'POST',
        parameter: field.name,
        location: form.method === 'GET' ? 'query' : 'body',
        enctype: form.enctype,
        formAction: form.action,
        extraParams,
      });
    }
  }

  private async testReflectedXss(
    point: InjectionPoint,
    input: TestInput,
    context: ExecutionContext,
  ): Promise<RawEngineFinding | null> {
    const token = crypto.randomBytes(4).toString('hex');
    const canary = `<secxss_${token}>`;

    const requestInfo = this.buildRequest(point, canary, input);

    try {
      const startTime = Date.now();
      const res = await safeFetch(requestInfo.url, {
        method: requestInfo.method,
        headers: {
          ...requestInfo.headers,
          Accept: 'text/html,application/xhtml+xml,*/*',
        },
        body: requestInfo.body,
        signal: context.abortSignal,
        scope: context.target?.scope,
      });

      const responseTimeMs = Date.now() - startTime;
      const body = await res.text();

      // Check if unescaped canary is reflected in response
      if (body.includes(canary)) {
        const evidencePayload = {
          request: {
            method: requestInfo.method,
            url: requestInfo.url,
            headers: requestInfo.headers,
            body: requestInfo.body,
          },
          response: {
            statusCode: res.status,
            headers: this.extractResponseHeaders(res),
            body: this.truncate(body, 2048),
            responseTimeMs,
          },
          expected: 'Parameter sanitized and HTML-entity encoded without rendering executable tag',
          actual: `Unescaped payload reflected: "${canary}" in HTTP response body`,
        };

        const sha256 = crypto
          .createHash('sha256')
          .update(JSON.stringify(evidencePayload))
          .digest('hex');

        return {
          title: `Reflected Cross-Site Scripting (XSS) in Parameter "${point.parameter}"`,
          category: 'injection',
          severity: 'high',
          description: `The application returned unsanitized input in response to an injection probe in parameter "${point.parameter}". An attacker could execute arbitrary scripts in victim browser sessions.`,
          recommendation:
            'Contextually encode all user-supplied output using HTML entity encoding or adopt a modern component framework that safely escapes template bindings.',
          evidence: {
            ...evidencePayload,
            immutableHash: sha256,
          },
        };
      }
    } catch {
      // Ignore network errors during individual probe
    }

    return null;
  }

  private async testSqlInjection(
    point: InjectionPoint,
    input: TestInput,
    context: ExecutionContext,
  ): Promise<RawEngineFinding | null> {
    // Safe syntax error probe: single quote and boolean operator
    const probe = `1' OR 'secsqli'='secsqli`;
    const requestInfo = this.buildRequest(point, probe, input);

    try {
      const startTime = Date.now();
      const res = await safeFetch(requestInfo.url, {
        method: requestInfo.method,
        headers: requestInfo.headers,
        body: requestInfo.body,
        signal: context.abortSignal,
        scope: context.target?.scope,
      });

      const responseTimeMs = Date.now() - startTime;
      const body = await res.text();

      // Check for SQL database error signatures
      const sqlErrorPatterns = [
        /syntax error at or near/i,
        /you have an error in your sql syntax/i,
        /unclosed quotation mark after the character string/i,
        /quoted string not properly terminated/i,
        /sqlite3::SQLException/i,
        /near ".*": syntax error/i,
        /pg_query\(\)/i,
        /ORA-01756/i,
        /Microsoft OLE DB Provider for SQL Server/i,
        /SQLSTATE\[[0-9A-Z]{5}\]/i,
      ];

      for (const pattern of sqlErrorPatterns) {
        if (pattern.test(body)) {
          const evidencePayload = {
            request: {
              method: requestInfo.method,
              url: requestInfo.url,
              headers: requestInfo.headers,
              body: requestInfo.body,
            },
            response: {
              statusCode: res.status,
              headers: this.extractResponseHeaders(res),
              body: this.truncate(body, 2048),
              responseTimeMs,
            },
            expected: 'Parameterized query execution without syntax errors or database engine disclosure',
            actual: `Database error signature detected matching pattern ${pattern.toString()}`,
          };

          const sha256 = crypto
            .createHash('sha256')
            .update(JSON.stringify(evidencePayload))
            .digest('hex');

          return {
            title: `SQL Injection (Error-Based) in Parameter "${point.parameter}"`,
            category: 'injection',
            severity: 'critical',
            description: `The application disclosed an internal database syntax error when injected with an escape sequence on parameter "${point.parameter}", indicating unsafe SQL string concatenation.`,
            recommendation:
              'Replace raw dynamic SQL query construction with parameterized queries or an Object-Relational Mapper (ORM).',
            evidence: {
              ...evidencePayload,
              immutableHash: sha256,
            },
          };
        }
      }
    } catch {
      // Ignore network errors
    }

    return null;
  }

  private async testBlindSsrf(
    point: InjectionPoint,
    input: TestInput,
    context: ExecutionContext,
    oast: OastListener,
  ): Promise<RawEngineFinding | null> {
    const oastToken = oast.createToken({
      vulnerabilityType: 'ssrf',
      targetUrl: point.url,
      parameter: point.parameter,
    });

    const requestInfo = this.buildRequest(point, oastToken.callbackUrl, input);

    try {
      const startTime = Date.now();
      const res = await safeFetch(requestInfo.url, {
        method: requestInfo.method,
        headers: {
          ...requestInfo.headers,
          'X-Forwarded-For': oastToken.callbackUrl,
        },
        body: requestInfo.body,
        signal: context.abortSignal,
        scope: context.target?.scope,
      });

      const responseTimeMs = Date.now() - startTime;
      const resBody = await res.text();

      // Poll ephemeral OAST listener for incoming callback
      const interaction: OastInteraction | null = await oast.waitForInteraction(oastToken.token, 1500);

      if (interaction) {
        const evidencePayload = {
          request: {
            method: requestInfo.method,
            url: requestInfo.url,
            headers: requestInfo.headers,
            body: requestInfo.body,
          },
          response: {
            statusCode: res.status,
            headers: this.extractResponseHeaders(res),
            body: this.truncate(resBody, 1024),
            responseTimeMs,
          },
          expected: 'No outbound network callback dispatched to injected URL',
          actual: `Out-of-band HTTP callback received from ${interaction.remoteAddress} on ${interaction.url}`,
        };

        const sha256 = crypto
          .createHash('sha256')
          .update(JSON.stringify(evidencePayload))
          .digest('hex');

        return {
          title: `Server-Side Request Forgery (SSRF) in Parameter "${point.parameter}"`,
          category: 'injection',
          severity: 'high',
          description: `The application initiated an out-of-band network interaction to the ephemeral callback URL upon receiving an untrusted target destination in parameter "${point.parameter}".`,
          recommendation:
            'Enforce strict allowlists of permissible outbound hosts, disable redirects, and block requests to internal or non-routable IP ranges.',
          evidence: {
            ...evidencePayload,
            immutableHash: sha256,
          },
        };
      }
    } catch {
      // Ignore network errors
    }

    return null;
  }

  private async testCommandInjection(
    point: InjectionPoint,
    input: TestInput,
    context: ExecutionContext,
  ): Promise<RawEngineFinding | null> {
    const token = crypto.randomBytes(4).toString('hex');
    const canary = `seccmd_${token}`;
    const probe = `; echo ${canary};`;

    const requestInfo = this.buildRequest(point, probe, input);

    try {
      const startTime = Date.now();
      const res = await safeFetch(requestInfo.url, {
        method: requestInfo.method,
        headers: requestInfo.headers,
        body: requestInfo.body,
        signal: context.abortSignal,
        scope: context.target?.scope,
      });

      const responseTimeMs = Date.now() - startTime;
      const body = await res.text();

      // Check if echo output appears cleanly in response body without the semicolon prefix
      if (body.includes(canary) && !body.includes(probe)) {
        const evidencePayload = {
          request: {
            method: requestInfo.method,
            url: requestInfo.url,
            headers: requestInfo.headers,
            body: requestInfo.body,
          },
          response: {
            statusCode: res.status,
            headers: this.extractResponseHeaders(res),
            body: this.truncate(body, 2048),
            responseTimeMs,
          },
          expected: 'No command execution on underlying host operating system',
          actual: `Command execution output observed in response body: "${canary}"`,
        };

        const sha256 = crypto
          .createHash('sha256')
          .update(JSON.stringify(evidencePayload))
          .digest('hex');

        return {
          title: `OS Command Injection in Parameter "${point.parameter}"`,
          category: 'injection',
          severity: 'critical',
          description: `The server executed operating system commands supplied via parameter "${point.parameter}". An attacker could achieve remote code execution (RCE) on the host environment.`,
          recommendation:
            'Avoid invoking shell commands with user-controlled input; use dedicated programmatic system APIs with strict argument arrays.',
          evidence: {
            ...evidencePayload,
            immutableHash: sha256,
          },
        };
      }
    } catch {
      // Ignore network errors
    }

    return null;
  }

  private buildRequest(
    point: InjectionPoint,
    payload: string,
    input: TestInput,
  ): { url: string; method: string; headers: Record<string, string>; body?: string } {
    const headers: Record<string, string> = {
      'User-Agent': 'SecurityLab-InjectionFuzzer/1.0',
      ...(input.customHeaders || {}),
    };

    if (point.location === 'query' || point.method === 'GET') {
      const parsed = new URL(point.url);
      parsed.searchParams.set(point.parameter, payload);
      return { url: parsed.toString(), method: 'GET', headers };
    } else {
      // POST body injection
      const params = new URLSearchParams(point.extraParams || {});
      params.set(point.parameter, payload);
      headers['Content-Type'] = point.enctype || 'application/x-www-form-urlencoded';
      return {
        url: point.url,
        method: 'POST',
        headers,
        body: params.toString(),
      };
    }
  }

  private extractResponseHeaders(res: Response): Record<string, string> {
    const headers: Record<string, string> = {};
    res.headers.forEach((val, key) => {
      headers[key.toLowerCase()] = val;
    });
    return headers;
  }

  private truncate(str: string, maxLength: number): string {
    if (str.length <= maxLength) return str;
    return str.slice(0, maxLength) + '... [truncated]';
  }
}

export const injectionFuzzerEngine = new InjectionFuzzerEngine();

try {
  // Self-register into engine-sdk dynamic worker registry
  const { dynamicWorkerEngineRegistry } = await import('@security-lab/engine-sdk');
  dynamicWorkerEngineRegistry.register(injectionFuzzerEngine);
} catch {
  // Ignore registration errors during isolated contexts
}
