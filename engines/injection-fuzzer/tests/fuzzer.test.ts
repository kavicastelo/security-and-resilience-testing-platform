import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import { webCrawlerEngine } from '@security-lab/web-crawler';
import { injectionFuzzerEngine } from '@security-lab/injection-fuzzer';
import { OastListener, executeSandboxedEngine } from '@security-lab/test-runner';
import { ExecutionContext, TargetExecutionContext } from '@security-lab/engine-sdk';
import { TargetScope } from '@security-lab/domain';

describe('Phase 04: Web DAST Crawler & Dynamic Injection Fuzzing', () => {
  let server: http.Server;
  let serverUrl: string;
  let serverPort: number;

  beforeAll(async () => {
    // Start mock vulnerable web server with SPA routes, forms, XSS, SQLi, and SSRF
    await new Promise<void>((resolve) => {
      server = http.createServer(async (req, res) => {
        const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
        const pathname = url.pathname;

        // 1. Root SPA Page with routes, forms, dynamic buttons, and script endpoints
        if (pathname === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end(`
            <!DOCTYPE html>
            <html>
            <head><title>Mock Vulnerable SPA</title></head>
            <body>
              <nav>
                <a href="/search?q=default">Search Items</a>
                <a href="/profile">User Profile</a>
                <a href="https://disallowed-external-target.com/trap">Disallowed External Link</a>
              </nav>

              <form action="/login" method="POST" enctype="application/x-www-form-urlencoded">
                <input name="username" type="text" placeholder="Username" required />
                <input name="password" type="password" placeholder="Password" required />
                <button type="submit" id="btn-login">Log In</button>
              </form>

              <button id="btn-dashboard" data-role="button">Dashboard View</button>

              <script>
                // Dynamic SPA API calls
                fetch('/api/v1/user/settings');
                const routerConfig = { path: '/admin/audit' };
              </script>
            </body>
            </html>
          `);
          return;
        }

        // 2. Reflected XSS Endpoint
        if (pathname === '/search') {
          const q = url.searchParams.get('q') || '';
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          // Reflect unsanitized input
          res.end(`<html><body><h1>Search Results</h1><div>Results for: ${q}</div></body></html>`);
          return;
        }

        // 3. SQL Injection Endpoint (discloses database syntax error)
        if (pathname === '/api/user') {
          const id = url.searchParams.get('id') || '';
          if (id.includes("'") || id.includes('secsqli')) {
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end("Database error: pg_query(): syntax error at or near 'secsqli' in SQL query");
            return;
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ id, name: 'Alice Developer' }));
          return;
        }

        // 4. Server-Side Request Forgery (SSRF) Endpoint
        if (pathname === '/fetch-preview') {
          const target = url.searchParams.get('url') || '';
          if (target && target.startsWith('http')) {
            try {
              // Initiate outbound HTTP request to target
              const targetRes = await fetch(target, { method: 'GET' });
              res.writeHead(200, { 'Content-Type': 'text/plain' });
              res.end(`Fetched: ${targetRes.status}`);
              return;
            } catch (err: unknown) {
              res.writeHead(502, { 'Content-Type': 'text/plain' });
              res.end(`SSRF fetch failed: ${String(err)}`);
              return;
            }
          }
          res.writeHead(400, { 'Content-Type': 'text/plain' });
          res.end('Missing or invalid url parameter');
          return;
        }

        // 5. Command Injection Endpoint
        if (pathname === '/exec') {
          const cmd = url.searchParams.get('cmd') || '';
          if (cmd.includes('echo seccmd_')) {
            // Emulate execution of echo canary
            const match = /echo\s+(seccmd_[a-f0-9]+)/.exec(cmd);
            const canary = match ? match[1] : 'seccmd_output';
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end(`Command executed successfully.\n${canary}\n`);
            return;
          }
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end(`Command queued: ${cmd}`);
          return;
        }

        // 6. User Profile Page
        if (pathname === '/profile') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body><h2>User Profile</h2><p>Welcome back!</p></body></html>');
          return;
        }

        // 7. Login Form Handler
        if (pathname === '/login') {
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end('Login processed');
          return;
        }

        // Default 404
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
      });

      server.listen(0, '127.0.0.1', () => {
        const address = server.address();
        if (address && typeof address === 'object') {
          serverPort = address.port;
          serverUrl = `http://127.0.0.1:${serverPort}`;
        }
        resolve();
      });
    });
  });

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  const createMockContext = (scopeAllowedHosts: string[] = ['127.0.0.1', 'localhost']): ExecutionContext => {
    const scope: TargetScope = {
      allowedHosts: scopeAllowedHosts,
      allowedPorts: [serverPort, 80, 443],
      excludedPaths: ['/admin/forbidden'],
      testing: {
        activeScanning: true,
        loadTesting: true,
        chaosTesting: true,
      },
      limits: {
        maxRps: 100,
        maxConcurrency: 10,
        maxDuration: '10m',
      },
      allowPrivateIps: true,
    };

    const target: TargetExecutionContext = {
      id: 'target-00000000-0000-0000-0000-000000000001',
      name: 'Local Test Target',
      baseUrl: serverUrl,
      scope,
    };

    return {
      correlationId: 'test-correlation-phase-04',
      testRunId: '00000000-0000-0000-0000-000000000001',
      target,
      reportProgress: () => {},
      logger: {
        info: () => {},
        warn: () => {},
        error: () => {},
        debug: () => {},
      } as any,
    };
  };

  describe('1. Web Application DAST Crawler Engine', () => {
    it('discovers dynamically rendered routes, forms, input fields, and buttons', async () => {
      const context = createMockContext();
      const result = await webCrawlerEngine.execute(
        {
          targetUrl: serverUrl,
          options: {
            maxDepth: 2,
            maxPages: 10,
            extractSpaRoutes: true,
          },
        },
        context,
      );

      expect(result.success).toBe(true);
      expect(result.engineId).toBe('engine-web-crawler');

      const inventory = (result as any).inventory;
      expect(inventory).toBeDefined();
      expect(inventory.pagesCrawled).toBeGreaterThanOrEqual(1);

      // Verify discovered routes
      const discoveredPaths = inventory.routes.map((r: any) => r.path);
      expect(discoveredPaths).toContain('/');
      expect(discoveredPaths).toContain('/search');
      expect(discoveredPaths).toContain('/profile');

      // Verify discovered forms & fields
      expect(inventory.forms.length).toBeGreaterThanOrEqual(1);
      const loginForm = inventory.forms.find((f: any) => f.action.includes('/login'));
      expect(loginForm).toBeDefined();
      expect(loginForm.method).toBe('POST');
      expect(loginForm.fields.some((field: any) => field.name === 'username')).toBe(true);
      expect(loginForm.fields.some((field: any) => field.name === 'password')).toBe(true);

      // Verify dynamic elements captured
      const rootRoute = inventory.routes.find((r: any) => r.path === '/');
      expect(rootRoute.dynamicElements.some((e: string) => e.includes('btn-dashboard') || e.includes('btn-login'))).toBe(true);

      // Verify SPA script endpoints extracted
      const apiEndpoints = inventory.apiEndpoints.map((e: any) => e.path);
      expect(apiEndpoints.some((p: string) => p.includes('/api/v1/user/settings'))).toBe(true);
      expect(apiEndpoints.some((p: string) => p.includes('/admin/audit'))).toBe(true);

      // Negative assertion: out-of-scope link must NOT be visited
      expect(inventory.routes.some((r: any) => r.url.includes('disallowed-external-target.com'))).toBe(false);
    });

    it('rejects targets outside of authorized target scope', async () => {
      const context = createMockContext(['different-host.com']);
      const result = await webCrawlerEngine.execute(
        {
          targetUrl: serverUrl, // 127.0.0.1 not in different-host.com
        },
        context,
      );

      expect(result.success).toBe(false);
      expect(result.error).toMatch(/out of authorized scope/i);
    });
  });

  describe('2. Ephemeral OAST Service (Out-of-Band Listener)', () => {
    it('starts on ephemeral port, records HTTP callbacks with tokens, and stops cleanly', async () => {
      const oast = new OastListener();
      const { httpPort, baseUrl } = await oast.start();
      expect(httpPort).toBeGreaterThan(0);
      expect(baseUrl).toContain(`:${httpPort}`);

      const tokenInfo = oast.createToken({
        vulnerabilityType: 'ssrf',
        targetUrl: serverUrl,
        parameter: 'url',
      });

      expect(tokenInfo.token).toBeDefined();
      expect(tokenInfo.callbackUrl).toContain(tokenInfo.token);

      // Send callback request to OAST listener
      const callbackRes = await fetch(tokenInfo.callbackUrl, {
        method: 'POST',
        headers: { 'X-Test-Sender': 'SecurityLab-Unit' },
        body: 'callback-payload-evidence',
      });

      expect(callbackRes.status).toBe(200);

      // Verify callback was recorded and correlated
      expect(oast.hasInteractions(tokenInfo.token)).toBe(true);
      const interactions = oast.getInteractions(tokenInfo.token);
      expect(interactions.length).toBe(1);
      expect(interactions[0]?.remoteAddress).toBeDefined();
      expect(interactions[0]?.headers?.['x-test-sender']).toBe('SecurityLab-Unit');
      expect(interactions[0]?.body).toBe('callback-payload-evidence');

      await oast.stop();
    });
  });

  describe('3. Context-Aware Injection Fuzzer Engine', () => {
    it('detects Reflected Cross-Site Scripting (XSS) with non-destructive canary', async () => {
      const context = createMockContext();
      const result = await injectionFuzzerEngine.execute(
        {
          targetUrl: `${serverUrl}/search?q=initial`,
          options: {
            fuzzXss: true,
            fuzzSqli: false,
            fuzzSsrf: false,
            fuzzCmd: false,
          },
        },
        context,
      );

      expect(result.success).toBe(true);
      expect(result.findings.length).toBeGreaterThanOrEqual(1);

      const xssFinding = result.findings.find((f) => f.title.includes('Cross-Site Scripting'));
      expect(xssFinding).toBeDefined();
      expect(xssFinding?.category).toBe('injection');
      expect(xssFinding?.severity).toBe('high');
      expect(xssFinding?.evidence?.actual).toMatch(/Unescaped payload reflected/i);
      expect(xssFinding?.evidence?.immutableHash).toBeDefined();
    });

    it('detects SQL Injection error signatures with safe escape sequence', async () => {
      const context = createMockContext();
      const result = await injectionFuzzerEngine.execute(
        {
          targetUrl: `${serverUrl}/api/user?id=1`,
          options: {
            fuzzXss: false,
            fuzzSqli: true,
            fuzzSsrf: false,
            fuzzCmd: false,
          },
        },
        context,
      );

      expect(result.success).toBe(true);
      const sqliFinding = result.findings.find((f) => f.title.includes('SQL Injection'));
      expect(sqliFinding).toBeDefined();
      expect(sqliFinding?.severity).toBe('critical');
      expect(sqliFinding?.evidence?.actual).toMatch(/syntax error at or near/i);
      expect(sqliFinding?.evidence?.immutableHash).toBeDefined();
    });

    it('detects Blind SSRF via Ephemeral OAST callback', async () => {
      const context = createMockContext();
      const oast = new OastListener();
      await oast.start();

      try {
        const result = await injectionFuzzerEngine.execute(
          {
            targetUrl: `${serverUrl}/fetch-preview?url=placeholder`,
            options: {
              oastListener: oast,
              fuzzXss: false,
              fuzzSqli: false,
              fuzzSsrf: true,
              fuzzCmd: false,
            },
          },
          context,
        );

        expect(result.success).toBe(true);
        const ssrfFinding = result.findings.find((f) => f.title.includes('Server-Side Request Forgery'));
        expect(ssrfFinding).toBeDefined();
        expect(ssrfFinding?.severity).toBe('high');
        expect(ssrfFinding?.evidence?.actual).toMatch(/Out-of-band HTTP callback received/i);
      } finally {
        await oast.stop();
      }
    });

    it('detects OS Command Injection via benign echo canary', async () => {
      const context = createMockContext();
      const result = await injectionFuzzerEngine.execute(
        {
          targetUrl: `${serverUrl}/exec?cmd=test`,
          options: {
            fuzzXss: false,
            fuzzSqli: false,
            fuzzSsrf: false,
            fuzzCmd: true,
          },
        },
        context,
      );

      expect(result.success).toBe(true);
      const cmdFinding = result.findings.find((f) => f.title.includes('OS Command Injection'));
      expect(cmdFinding).toBeDefined();
      expect(cmdFinding?.severity).toBe('critical');
      expect(cmdFinding?.evidence?.actual).toMatch(/Command execution output observed/i);
    });

    it('integrates Crawler inventory directly into Fuzzer pipeline', async () => {
      const context = createMockContext();

      // Step 1: Run Crawler
      const crawlResult = await webCrawlerEngine.execute(
        {
          targetUrl: serverUrl,
          options: {
            maxDepth: 1,
            maxPages: 5,
            extractSpaRoutes: true,
          },
        },
        context,
      );

      expect(crawlResult.success).toBe(true);
      const inventory = (crawlResult as any).inventory;

      // Step 2: Feed Crawled Inventory to Injection Fuzzer
      const fuzzResult = await injectionFuzzerEngine.execute(
        {
          targetUrl: serverUrl,
          options: {
            inventory,
            fuzzXss: true,
            fuzzSqli: false,
            fuzzSsrf: false,
            fuzzCmd: false,
          },
        },
        context,
      );

      expect(fuzzResult.success).toBe(true);
      // Crawled route /search?q=default should have been tested and identified as XSS
      const xssFinding = fuzzResult.findings.find((f) => f.title.includes('Cross-Site Scripting'));
      expect(xssFinding).toBeDefined();
    });

    it('executes injection fuzzer inside isolated worker thread harness (Phase 03 integration)', async () => {
      const context = createMockContext();
      const result = await executeSandboxedEngine(
        injectionFuzzerEngine.id,
        {
          targetUrl: `${serverUrl}/search?q=test`,
          options: {
            fuzzXss: true,
            fuzzSqli: false,
            fuzzSsrf: false,
            fuzzCmd: false,
          },
        },
        context,
        { sandbox: true, timeoutMs: 10000 },
      );

      expect(result.success).toBe(true);
      expect(result.findings.length).toBeGreaterThanOrEqual(1);
      expect(result.findings.some((f) => f.title.includes('Cross-Site Scripting'))).toBe(true);
    });
  });
});
