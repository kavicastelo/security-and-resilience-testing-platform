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
import { validateUrlAgainstScope, TargetScope } from '@security-lab/domain';
import {
  CrawledTargetInventory,
  DiscoveredRoute,
  FormDefinition,
  FormField,
  CrawlerConfig,
  CrawlerConfigSchema,
} from '@security-lab/contracts';
import { createLogger } from '@security-lab/logger';

const logger = createLogger({ name: 'engine-web-crawler' });

export interface WebCrawlerExecutionOptions extends Partial<CrawlerConfig> {
  disableBrowser?: boolean;
}

export class WebCrawlerEngine implements TestEngine {
  readonly id = 'engine-web-crawler';
  readonly version = '1.0.0';
  readonly executionClass = 'class_a_native' as const;

  capabilities(): TestCapability[] {
    return [
      {
        id: 'web_crawler',
        name: 'Modern SPA & REST Route Discovery Crawler',
        category: 'passive_analysis',
        description:
          'Headless browser and DOM/SPA crawler discovering dynamic routes, forms, input fields, interactive buttons, and API endpoints while respecting scope constraints.',
        isDisruptive: false,
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
    const config = CrawlerConfigSchema.parse(input.options || {});
    const scope = context.target?.scope;

    // Validate root targetUrl against scope
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

    context.reportProgress(5, `Starting web crawler for ${input.targetUrl}...`);

    try {
      const inventory = await this.crawl(input.targetUrl, config, context, scope);
      const durationMs = Date.now() - startTime;

      const metrics: RawEngineMetric[] = [
        {
          name: 'pages_crawled',
          value: inventory.pagesCrawled,
          unit: 'count',
        },
        {
          name: 'routes_discovered',
          value: inventory.routes.length,
          unit: 'count',
        },
        {
          name: 'api_endpoints_discovered',
          value: inventory.apiEndpoints.length,
          unit: 'count',
        },
        {
          name: 'forms_discovered',
          value: inventory.forms.length,
          unit: 'count',
        },
      ];

      const findings: RawEngineFinding[] = [];

      // If sensitive or unauthenticated API endpoints or forms with password inputs are detected, emit findings
      const passwordForms = inventory.forms.filter((f) =>
        f.fields.some((field) => field.type.toLowerCase() === 'password'),
      );
      if (passwordForms.length > 0 && input.targetUrl.startsWith('http://')) {
        const evidencePayload = {
          request: { method: 'GET', url: input.targetUrl, headers: input.customHeaders || {} },
          response: {
            statusCode: 200,
            headers: {},
            body: `Discovered ${passwordForms.length} password form(s) submitting over unencrypted HTTP: ${passwordForms[0]?.action}`,
          },
          expected: 'Encrypted HTTPS form submission',
          actual: 'Cleartext HTTP form transmission',
        };

        const sha256 = crypto
          .createHash('sha256')
          .update(JSON.stringify(evidencePayload))
          .digest('hex');

        findings.push({
          title: 'Unencrypted Form Transmitting Sensitive Credentials',
          category: 'transport_security',
          severity: 'high',
          description: `Discovered login or password form submitted over cleartext HTTP (${passwordForms[0]?.action}).`,
          recommendation: 'Enforce HTTPS on all pages serving or processing authentication credentials.',
          evidence: {
            ...evidencePayload,
            immutableHash: sha256,
          },
        });
      }

      context.reportProgress(100, `Crawling complete: ${inventory.routes.length} routes, ${inventory.forms.length} forms discovered.`);

      return {
        engineId: this.id,
        durationMs,
        success: true,
        findings,
        metrics,
        // Attach inventory inside custom result or details
        inventory,
      } as TestResult & { inventory: CrawledTargetInventory };
    } catch (err: unknown) {
      const durationMs = Date.now() - startTime;
      const errorMsg = err instanceof Error ? err.message : String(err);
      logger.error({ event: 'crawler.failed', error: errorMsg }, 'Web crawler execution encountered error');

      return {
        engineId: this.id,
        durationMs,
        success: false,
        findings: [],
        metrics: [],
        error: `Web crawler failed: ${errorMsg}`,
      };
    }
  }

  private async crawl(
    targetUrl: string,
    config: CrawlerConfig,
    context: ExecutionContext,
    scope?: TargetScope,
  ): Promise<CrawledTargetInventory> {
    const startTime = Date.now();
    const visited = new Set<string>();
    const routesMap = new Map<string, DiscoveredRoute>();
    const apiEndpointsMap = new Map<string, DiscoveredRoute>();
    const forms: FormDefinition[] = [];
    const errors: string[] = [];

    const queue: Array<{ url: string; depth: number }> = [{ url: targetUrl, depth: 0 }];

    // Attempt Playwright headless browser crawling if available and permitted
    const useBrowser = !(config as WebCrawlerExecutionOptions).disableBrowser;
    let browserCrawlSucceeded = false;

    if (useBrowser) {
      try {
        const playwrightModule = await this.tryImportPlaywright();
        if (playwrightModule) {
          logger.info({ event: 'crawler.browser_starting', url: targetUrl }, 'Launching Playwright headless browser for SPA crawling');
          await this.crawlWithPlaywright(
            playwrightModule,
            targetUrl,
            config,
            context,
            scope,
            visited,
            routesMap,
            apiEndpointsMap,
            forms,
            errors,
          );
          browserCrawlSucceeded = true;
        }
      } catch (err: unknown) {
        logger.warn(
          { event: 'crawler.browser_fallback', error: err instanceof Error ? err.message : String(err) },
          'Playwright browser launch failed or unavailable; falling back cleanly to native SPA/DOM crawler.',
        );
      }
    }

    // If browser crawl did not run or finished, ensure native DOM/SPA traversal covers any remaining queue
    if (!browserCrawlSucceeded) {
      await this.crawlWithNativeEngine(
        queue,
        config,
        context,
        scope,
        visited,
        routesMap,
        apiEndpointsMap,
        forms,
        errors,
      );
    }

    return {
      targetUrl,
      crawledAt: new Date().toISOString(),
      durationMs: Date.now() - startTime,
      pagesCrawled: visited.size,
      routes: Array.from(routesMap.values()),
      apiEndpoints: Array.from(apiEndpointsMap.values()),
      forms,
      errors,
    };
  }

  private async tryImportPlaywright(): Promise<any | null> {
    try {
      // Dynamic import to avoid static bundling requirement if not installed
      // eslint-disable-next-line @typescript-eslint/no-implied-eval
      const dynamicImport = new Function('specifier', 'return import(specifier)');
      const pw = await dynamicImport('playwright');
      return pw?.chromium ? pw : null;
    } catch {
      return null;
    }
  }

  private async crawlWithPlaywright(
    playwright: any,
    targetUrl: string,
    config: CrawlerConfig,
    context: ExecutionContext,
    scope: TargetScope | undefined,
    visited: Set<string>,
    routesMap: Map<string, DiscoveredRoute>,
    apiEndpointsMap: Map<string, DiscoveredRoute>,
    forms: FormDefinition[],
    errors: string[],
  ): Promise<void> {
    const browser = await playwright.chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    });

    try {
      const page = await browser.newPage({
        viewport: config.viewport,
        userAgent: config.userAgent || 'SecurityLab-DAST-Crawler/1.0',
      });

      // Intercept XHR and Fetch network calls to extract API endpoints
      if (config.interceptNetwork) {
        page.on('request', (request: any) => {
          const reqUrl = request.url();
          const method = request.method() as DiscoveredRoute['method'];
          const resourceType = request.resourceType();

          if (resourceType === 'xhr' || resourceType === 'fetch') {
            if (this.isUrlInScope(reqUrl, scope)) {
              try {
                const parsed = new URL(reqUrl);
                const queryParams = Array.from(parsed.searchParams.keys());
                apiEndpointsMap.set(`${method}:${reqUrl}`, {
                  url: reqUrl,
                  path: parsed.pathname,
                  method,
                  source: resourceType === 'xhr' ? 'xhr' : 'fetch',
                  queryParams,
                  headers: request.headers(),
                  forms: [],
                  dynamicElements: [],
                });
              } catch {
                // Ignore URL parsing errors
              }
            }
          }
        });
      }

      const queue: Array<{ url: string; depth: number }> = [{ url: targetUrl, depth: 0 }];

      while (queue.length > 0 && visited.size < config.maxPages) {
        if (context.abortSignal?.aborted) break;

        const current = queue.shift();
        if (!current) break;
        if (visited.has(current.url)) continue;
        visited.add(current.url);

        try {
          await page.goto(current.url, {
            waitUntil: 'domcontentloaded',
            timeout: config.timeoutMs,
          });

          // Extract DOM elements: links, forms, buttons
          const domData = await page.evaluate(() => {
            const links: string[] = [];
            document.querySelectorAll('a[href]').forEach((el) => {
              const href = (el as HTMLAnchorElement).href;
              if (href) links.push(href);
            });

            const buttons: string[] = [];
            document.querySelectorAll('button, [role="button"], input[type="submit"], input[type="button"]').forEach((el) => {
              const text = el.textContent?.trim() || (el as HTMLInputElement).value || '';
              const id = el.id || el.getAttribute('name') || '';
              buttons.push(`button:${id || text}`);
            });

            const parsedForms: Array<{
              action: string;
              method: string;
              enctype: string;
              fields: Array<{ name: string; type: string; value?: string; required: boolean }>;
            }> = [];

            document.querySelectorAll('form').forEach((form) => {
              const action = (form as HTMLFormElement).action || window.location.href;
              const method = ((form as HTMLFormElement).method || 'POST').toUpperCase();
              const enctype = (form as HTMLFormElement).enctype || 'application/x-www-form-urlencoded';

              const fields: Array<{ name: string; type: string; value?: string; required: boolean }> = [];
              form.querySelectorAll('input, textarea, select').forEach((field) => {
                const name = field.getAttribute('name') || field.id || '';
                const type = field.getAttribute('type') || 'text';
                const required = (field as HTMLInputElement).required || false;
                const value = (field as HTMLInputElement).value || '';
                if (name) {
                  fields.push({ name, type, value, required });
                }
              });

              parsedForms.push({ action, method, enctype, fields });
            });

            // Extract client-side routing definitions if present
            const clientRoutes: string[] = [];
            document.querySelectorAll('script').forEach((script) => {
              const content = script.textContent || '';
              const routeMatches = content.matchAll(/path:\s*['"]([/a-zA-Z0-9_\-:]+)['"]/g);
              for (const m of routeMatches) {
                if (m[1]) clientRoutes.push(m[1]);
              }
            });

            return { links, buttons, parsedForms, clientRoutes };
          });

          // Record route
          const parsed = new URL(current.url);
          const formDefs: FormDefinition[] = domData.parsedForms.map((f: any) => ({
            action: f.action,
            method: f.method,
            enctype: f.enctype,
            fields: f.fields,
          }));

          for (const f of formDefs) {
            forms.push(f);
          }

          routesMap.set(`GET:${current.url}`, {
            url: current.url,
            path: parsed.pathname,
            method: 'GET',
            source: current.depth === 0 ? 'link' : 'spa_router',
            queryParams: Array.from(parsed.searchParams.keys()),
            forms: formDefs,
            dynamicElements: domData.buttons,
          });

          // Queue in-scope links for next depth level
          if (current.depth < config.maxDepth) {
            for (const link of domData.links) {
              if (this.isUrlInScope(link, scope) && !visited.has(link)) {
                queue.push({ url: link, depth: current.depth + 1 });
              }
            }
          }
        } catch (err: unknown) {
          errors.push(`Failed to crawl ${current.url}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
    } finally {
      await browser.close();
    }
  }

  private async crawlWithNativeEngine(
    queue: Array<{ url: string; depth: number }>,
    config: CrawlerConfig,
    context: ExecutionContext,
    scope: TargetScope | undefined,
    visited: Set<string>,
    routesMap: Map<string, DiscoveredRoute>,
    apiEndpointsMap: Map<string, DiscoveredRoute>,
    forms: FormDefinition[],
    errors: string[],
  ): Promise<void> {
    while (queue.length > 0 && visited.size < config.maxPages) {
      if (context.abortSignal?.aborted) break;

      const current = queue.shift();
      if (!current) break;
      if (visited.has(current.url)) continue;
      visited.add(current.url);

      const progressPct = Math.min(90, Math.round((visited.size / config.maxPages) * 80) + 10);
      context.reportProgress(progressPct, `Crawling [${visited.size}/${config.maxPages}]: ${current.url}`);

      try {
        const res = await safeFetch(current.url, {
          method: 'GET',
          headers: {
            'User-Agent': config.userAgent || 'SecurityLab-Native-Crawler/1.0',
            Accept: 'text/html,application/xhtml+xml,application/json,*/*',
          },
          signal: context.abortSignal,
          scope,
        });

        const contentType = res.headers.get('content-type') || '';
        const bodyText = await res.text();
        const currentUrlObj = new URL(current.url);

        // Record the current route
        const routeForms: FormDefinition[] = [];
        const dynamicElements: string[] = [];

        if (contentType.includes('text/html') || contentType.includes('application/xhtml')) {
          // 1. Extract forms and inputs
          const parsedForms = this.parseHtmlForms(bodyText, current.url);
          for (const form of parsedForms) {
            forms.push(form);
            routeForms.push(form);

            // Also record form action as a candidate route if in scope
            if (this.isUrlInScope(form.action, scope)) {
              routesMap.set(`${form.method}:${form.action}`, {
                url: form.action,
                path: new URL(form.action).pathname,
                method: form.method as DiscoveredRoute['method'],
                source: 'form',
                queryParams: [],
                forms: [form],
                dynamicElements: [],
              });
            }
          }

          // 2. Extract buttons and interactive elements
          const buttonRegex = /<(?:button|input\s+type=["'](?:submit|button)["'])[^>]*>(?:([\s\S]*?)<\/button>)?/gi;
          let buttonMatch: RegExpExecArray | null;
          while ((buttonMatch = buttonRegex.exec(bodyText)) !== null) {
            const raw = buttonMatch[0];
            const nameMatch = /name=["']([^"']+)["']/i.exec(raw);
            const idMatch = /id=["']([^"']+)["']/i.exec(raw);
            dynamicElements.push(`button:${idMatch?.[1] || nameMatch?.[1] || 'submit'}`);
          }

          // 3. Extract hyperlinks
          const linkRegex = /<a\s+[^>]*href=["']([^"'#\s]+)["'][^>]*>/gi;
          let linkMatch: RegExpExecArray | null;
          while ((linkMatch = linkRegex.exec(bodyText)) !== null) {
            const href = linkMatch[1];
            if (!href || href.startsWith('javascript:') || href.startsWith('mailto:')) continue;

            try {
              const resolvedUrl = new URL(href, current.url).toString();
              if (this.isUrlInScope(resolvedUrl, scope)) {
                if (!visited.has(resolvedUrl) && current.depth < config.maxDepth) {
                  queue.push({ url: resolvedUrl, depth: current.depth + 1 });
                }
              }
            } catch {
              // Ignore invalid relative URL resolutions
            }
          }

          // 4. Extract script endpoints & SPA client routes
          if (config.extractSpaRoutes) {
            this.extractSpaAndApiEndpoints(bodyText, current.url, scope, apiEndpointsMap);
          }
        } else if (contentType.includes('application/json')) {
          // If response is JSON, record as API endpoint
          apiEndpointsMap.set(`GET:${current.url}`, {
            url: current.url,
            path: currentUrlObj.pathname,
            method: 'GET',
            source: 'fetch',
            queryParams: Array.from(currentUrlObj.searchParams.keys()),
            contentType,
            statusCode: res.status,
            forms: [],
            dynamicElements: [],
          });
        }

        routesMap.set(`GET:${current.url}`, {
          url: current.url,
          path: currentUrlObj.pathname,
          method: 'GET',
          source: current.depth === 0 ? 'link' : 'spa_router',
          queryParams: Array.from(currentUrlObj.searchParams.keys()),
          contentType,
          statusCode: res.status,
          forms: routeForms,
          dynamicElements,
        });
      } catch (err: unknown) {
        errors.push(`Failed to crawl ${current.url}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  }

  private parseHtmlForms(html: string, baseUrl: string): FormDefinition[] {
    const results: FormDefinition[] = [];
    const formRegex = /<form([^>]*)>([\s\S]*?)<\/form>/gi;
    let formMatch: RegExpExecArray | null;

    while ((formMatch = formRegex.exec(html)) !== null) {
      const formAttributes = formMatch[1] ?? '';
      const formInnerHtml = formMatch[2] ?? '';

      const actionMatch = /action=["']([^"']*)["']/i.exec(formAttributes);
      const methodMatch = /method=["']([^"']*)["']/i.exec(formAttributes);
      const enctypeMatch = /enctype=["']([^"']*)["']/i.exec(formAttributes);

      const actionRaw = actionMatch?.[1]?.trim() || baseUrl;
      let resolvedAction = baseUrl;
      try {
        resolvedAction = new URL(actionRaw, baseUrl).toString();
      } catch {
        resolvedAction = baseUrl;
      }

      const rawMethod = (methodMatch?.[1]?.toUpperCase() || 'POST') as FormDefinition['method'];
      const method: FormDefinition['method'] = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].includes(rawMethod)
        ? rawMethod
        : 'POST';
      const enctype = enctypeMatch?.[1] || 'application/x-www-form-urlencoded';

      // Parse fields inside form
      const fields: FormField[] = [];
      const inputRegex = /<(?:input|textarea|select)([^>]*)(?:>|[\s\S]*?<\/(?:textarea|select)>)/gi;
      let inputMatch: RegExpExecArray | null;

      while ((inputMatch = inputRegex.exec(formInnerHtml)) !== null) {
        const inputAttrs = inputMatch[1] ?? '';
        const nameMatch = /name=["']([^"']+)["']/i.exec(inputAttrs);
        const typeMatch = /type=["']([^"']+)["']/i.exec(inputAttrs);
        const valueMatch = /value=["']([^"']*)["']/i.exec(inputAttrs);
        const required = /required/i.test(inputAttrs);

        if (nameMatch?.[1]) {
          fields.push({
            name: nameMatch[1],
            type: typeMatch?.[1]?.toLowerCase() || 'text',
            value: valueMatch?.[1],
            required,
          });
        }
      }

      results.push({
        action: resolvedAction,
        method,
        enctype,
        fields,
      });
    }

    return results;
  }

  private extractSpaAndApiEndpoints(
    html: string,
    baseUrl: string,
    scope: TargetScope | undefined,
    apiEndpointsMap: Map<string, DiscoveredRoute>,
  ): void {
    // Search for fetch('/api/...') or axios.get('/api/...') or REST path strings
    const patterns = [
      /(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"]([/a-zA-Z0-9_\-?&=.]+)['"]/gi,
      /['"](\/api\/v\d+\/[a-zA-Z0-9_\-/]+)['"]/gi,
      /path:\s*['"]([/a-zA-Z0-9_\-:]+)['"]/gi,
    ];

    for (const regex of patterns) {
      let match: RegExpExecArray | null;
      while ((match = regex.exec(html)) !== null) {
        const endpoint = match[1];
        if (!endpoint || endpoint === '/' || endpoint.includes('..')) continue;

        try {
          const resolvedUrl = new URL(endpoint, baseUrl).toString();
          if (this.isUrlInScope(resolvedUrl, scope)) {
            const parsed = new URL(resolvedUrl);
            apiEndpointsMap.set(`GET:${resolvedUrl}`, {
              url: resolvedUrl,
              path: parsed.pathname,
              method: 'GET',
              source: 'spa_router',
              queryParams: Array.from(parsed.searchParams.keys()),
              forms: [],
              dynamicElements: [],
            });
          }
        } catch {
          // Ignore invalid resolutions
        }
      }
    }
  }

  private isUrlInScope(url: string, scope?: TargetScope): boolean {
    if (!scope) return true;
    try {
      const check = validateUrlAgainstScope(url, scope);
      return check.valid;
    } catch {
      return false;
    }
  }
}

export const webCrawlerEngine = new WebCrawlerEngine();

try {
  // Self-register into engine-sdk dynamic worker registry
  const { dynamicWorkerEngineRegistry } = await import('@security-lab/engine-sdk');
  dynamicWorkerEngineRegistry.register(webCrawlerEngine);
} catch {
  // Ignore registration errors during isolated contexts
}
