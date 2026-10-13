import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import net from 'node:net';
import { AddressInfo } from 'node:net';
import {
  HttpSmugglingEngine,
  rawSocketSender,
  formatHexDump,
  parseRawHttpResponse,
} from '../src/index.js';
import { executeSandboxedEngine } from '@security-lab/test-runner';

describe('Phase 11: Traffic Routing & HTTP Request Smuggling Verifier', () => {
  let mockServer: net.Server;
  let serverPort: number;
  let serverUrl: string;

  beforeAll(async () => {
    // Create an in-memory dual-layer proxy/backend TCP simulator
    mockServer = net.createServer((socket) => {
      let buffer = Buffer.alloc(0);

      socket.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        const text = buffer.toString('utf-8');

        // 1. Host Header Poisoning simulator
        if (
          text.includes('X-Forwarded-Host: evil-canary.internal.testing') ||
          text.includes('X-Forwarded-Host: canary.internal.testing')
        ) {
          const hostMatch = /X-Forwarded-Host:\s*([^\r\n]+)/i.exec(text);
          const reflectedHost = hostMatch ? hostMatch[1]?.trim() : 'canary.internal.testing';
          const redirectResponse =
            `HTTP/1.1 302 Found\r\n` +
            `Location: http://${reflectedHost}/oauth/callback\r\n` +
            `Content-Length: 0\r\n` +
            `Connection: close\r\n\r\n`;
          socket.write(redirectResponse);
          socket.end();
          return;
        }

        // 2. Hop-by-hop Header Stripping simulator
        if (
          text.includes('Connection: close, X-Internal-Token') ||
          text.includes('Connection: close, X-Forwarded-For')
        ) {
          const hopResponse =
            `HTTP/1.1 200 OK\r\n` +
            `Content-Type: text/plain\r\n` +
            `X-Hop-Bypass-Detected: true\r\n` +
            `Content-Length: 26\r\n` +
            `Connection: close\r\n\r\n` +
            `hop-by-hop-stripped: true\n`;
          socket.write(hopResponse);
          socket.end();
          return;
        }

        // 3. CL.TE Smuggling simulator
        const hasCl = /content-length:\s*(\d+)/i.exec(text);
        const hasTe = /transfer-encoding:\s*chunked/i.test(text);

        if (hasCl && hasTe && text.includes('0\r\n\r\nGET ')) {
          const firstResp =
            `HTTP/1.1 200 OK\r\n` +
            `Content-Type: text/plain\r\n` +
            `Content-Length: 17\r\n` +
            `Connection: keep-alive\r\n\r\n` +
            `Primary processed`;
          socket.write(firstResp);

          const canaryCheckMatch = /X-Canary-Check:\s*([^\r\n]+)/i.exec(text);
          const canaryMarker = canaryCheckMatch ? canaryCheckMatch[1]?.trim() : 'canary-detected';

          setTimeout(() => {
            const smuggledResp =
              `HTTP/1.1 404 Not Found\r\n` +
              `Content-Type: text/plain\r\n` +
              `X-Canary-Check: ${canaryMarker}\r\n` +
              `Content-Length: 28\r\n` +
              `Connection: close\r\n\r\n` +
              `Canary route ${canaryMarker} 404`;
            socket.write(smuggledResp);
            socket.end();
          }, 20);
          return;
        }

        // 4. TE.CL Smuggling simulator
        if (hasCl && hasTe && text.includes('Content-Length: 4') && text.includes('X-Canary-Check:')) {
          const firstResp =
            `HTTP/1.1 200 OK\r\n` +
            `Content-Type: text/plain\r\n` +
            `Content-Length: 17\r\n` +
            `Connection: keep-alive\r\n\r\n` +
            `TE.CL first ok`;
          socket.write(firstResp);

          const canaryCheckMatch = /X-Canary-Check:\s*([^\r\n]+)/i.exec(text);
          const canaryMarker = canaryCheckMatch ? canaryCheckMatch[1]?.trim() : 'te-cl-canary';

          setTimeout(() => {
            const smuggledResp =
              `HTTP/1.1 404 Not Found\r\n` +
              `Content-Type: text/plain\r\n` +
              `X-Canary-Check: ${canaryMarker}\r\n` +
              `Content-Length: 29\r\n` +
              `Connection: close\r\n\r\n` +
              `TE.CL smuggled ${canaryMarker}`;
            socket.write(smuggledResp);
            socket.end();
          }, 20);
          return;
        }

        // 5. Default POST responder (prevents socket timeout on timing/mutation probes)
        if (text.includes('POST ') && (text.includes('\r\n\r\n') || text.includes('\n\n'))) {
          const postResp =
            `HTTP/1.1 200 OK\r\n` +
            `Content-Type: text/plain\r\n` +
            `Content-Length: 13\r\n` +
            `Connection: close\r\n\r\n` +
            `POST received`;
          socket.write(postResp);
          socket.end();
          return;
        }

        // 6. Baseline GET request handler
        if (text.includes('GET ') && (text.includes('\r\n\r\n') || text.includes('\n\n'))) {
          const okResp =
            `HTTP/1.1 200 OK\r\n` +
            `Content-Type: text/plain\r\n` +
            `Content-Length: 15\r\n` +
            `Connection: close\r\n\r\n` +
            `Baseline target`;
          socket.write(okResp);
          socket.end();
          return;
        }
      });
    });

    await new Promise<void>((resolve) => {
      mockServer.listen(0, '127.0.0.1', () => {
        serverPort = (mockServer.address() as AddressInfo).port;
        serverUrl = `http://127.0.0.1:${serverPort}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      mockServer.close(() => resolve());
    });
  });

  it('1. Raw Socket Transmitter & Hex Dump Utilities > transmits un-normalized payload and formats hex dumps', async () => {
    const rawPayload = `GET / HTTP/1.1\r\nHost: 127.0.0.1:${serverPort}\r\nConnection: close\r\n\r\n`;
    const resp = await rawSocketSender.sendRawPayload({
      host: '127.0.0.1',
      port: serverPort,
      useTls: false,
      payload: rawPayload,
      timeoutMs: 2000,
    });

    expect(resp.statusCode).toBe(200);
    expect(resp.body).toContain('Baseline target');
    expect(resp.requestHexDump).toContain('0000');
    expect(resp.responseHexDump).toContain('0000');

    const sampleBuf = Buffer.from('TEST RAW BYTES FOR HEX DUMP');
    const dump = formatHexDump(sampleBuf);
    expect(dump).toContain('|TEST RAW BYTES F|');
  });

  it('2. Raw Response Parser > parses status line, headers, and body correctly', () => {
    const rawBuffer = Buffer.from(
      'HTTP/1.1 302 Found\r\nLocation: https://example.com/login\r\nServer: Custom-LB\r\n\r\nRedirecting to login...',
    );
    const parsed = parseRawHttpResponse(rawBuffer);

    expect(parsed.statusCode).toBe(302);
    expect(parsed.statusLine).toBe('HTTP/1.1 302 Found');
    expect(parsed.headers['location']).toBe('https://example.com/login');
    expect(parsed.headers['server']).toBe('Custom-LB');
    expect(parsed.body).toBe('Redirecting to login...');
  });

  it('3. CL.TE Smuggling Verification > detects request desynchronization and canary reflection', async () => {
    const engine = new HttpSmugglingEngine();
    const result = await engine.execute(
      {
        targetUrl: serverUrl,
        options: {
          techniques: ['CL_TE'],
          canaryPath: '/robots.txt',
          normalPath: '/',
          timeoutMs: 2000,
          timingDelayThresholdMs: 1000,
        },
      },
      {
        executionId: 'exec-cl-te-test',
        testRunId: 'run-cl-te-test',
        target: {
          id: 'target-mock',
          baseUrl: serverUrl,
          scope: {
            allowedHosts: ['127.0.0.1', 'localhost'],
            allowedPorts: [80, 443, serverPort],
            allowPrivateRanges: true,
            excludedPaths: [],
          },
        },
      },
    );

    expect(result.success).toBe(true);
    const clTeFinding = result.findings.find((f) => f.title.includes('CL.TE'));
    expect(clTeFinding).toBeDefined();
    expect(clTeFinding?.severity).toBe('critical');
    expect(clTeFinding?.evidence?.metadata?.technique).toBe('CL_TE');
    expect(clTeFinding?.evidence?.response?.body).toContain('Canary route');
  });

  it('4. TE.CL Smuggling Verification > detects request desynchronization and canary reflection', async () => {
    const engine = new HttpSmugglingEngine();
    const result = await engine.execute(
      {
        targetUrl: serverUrl,
        options: {
          techniques: ['TE_CL'],
          canaryPath: '/robots.txt',
          normalPath: '/',
          timeoutMs: 2000,
          timingDelayThresholdMs: 1000,
        },
      },
      {
        executionId: 'exec-te-cl-test',
        testRunId: 'run-te-cl-test',
        target: {
          id: 'target-mock',
          baseUrl: serverUrl,
          scope: {
            allowedHosts: ['127.0.0.1', 'localhost'],
            allowedPorts: [80, 443, serverPort],
            allowPrivateRanges: true,
            excludedPaths: [],
          },
        },
      },
    );

    expect(result.success).toBe(true);
    const teClFinding = result.findings.find((f) => f.title.includes('TE.CL'));
    expect(teClFinding).toBeDefined();
    expect(teClFinding?.severity).toBe('critical');
    expect(teClFinding?.evidence?.metadata?.technique).toBe('TE_CL');
    expect(teClFinding?.evidence?.response?.body).toContain('TE.CL smuggled');
  });

  it('5. Reverse Proxy Host Header Poisoning > detects reflection of poisoned host in 302 redirect', async () => {
    const engine = new HttpSmugglingEngine();
    const result = await engine.execute(
      {
        targetUrl: serverUrl,
        options: {
          techniques: ['HOST_POISONING'],
          canaryPath: '/robots.txt',
          normalPath: '/',
          poisonCanaryHost: 'canary.internal.testing',
          timeoutMs: 2000,
        },
      },
      {
        executionId: 'exec-host-poison-test',
        testRunId: 'run-host-poison-test',
        target: {
          id: 'target-mock',
          baseUrl: serverUrl,
          scope: {
            allowedHosts: ['127.0.0.1', 'localhost'],
            allowedPorts: [80, 443, serverPort],
            allowPrivateRanges: true,
            excludedPaths: [],
          },
        },
      },
    );

    expect(result.success).toBe(true);
    const hostPoisonFinding = result.findings.find((f) => f.title.includes('Host Header Poisoning'));
    expect(hostPoisonFinding).toBeDefined();
    expect(hostPoisonFinding?.severity).toBe('high');
    expect(hostPoisonFinding?.evidence?.metadata?.reflectedLocation).toContain('canary.internal.testing');
  });

  it('6. Hop-by-Hop Header Stripping > detects intermediate header removal via Connection header', async () => {
    const engine = new HttpSmugglingEngine();
    const result = await engine.execute(
      {
        targetUrl: serverUrl,
        options: {
          techniques: ['HOP_BY_HOP'],
          canaryPath: '/robots.txt',
          normalPath: '/',
          timeoutMs: 2000,
        },
      },
      {
        executionId: 'exec-hop-test',
        testRunId: 'run-hop-test',
        target: {
          id: 'target-mock',
          baseUrl: serverUrl,
          scope: {
            allowedHosts: ['127.0.0.1', 'localhost'],
            allowedPorts: [80, 443, serverPort],
            allowPrivateRanges: true,
            excludedPaths: [],
          },
        },
      },
    );

    expect(result.success).toBe(true);
    const hopFinding = result.findings.find((f) => f.title.includes('Hop-by-Hop'));
    expect(hopFinding).toBeDefined();
    expect(hopFinding?.severity).toBe('medium');
  });

  it('7. Target Scope Enforcement Invariants > strictly blocks out-of-scope targets (Rule 2 Compliance)', async () => {
    const engine = new HttpSmugglingEngine();
    const result = await engine.execute(
      {
        targetUrl: 'http://unauthorized.external.attacker.com',
      },
      {
        executionId: 'exec-scope-block-test',
        testRunId: 'run-scope-block-test',
        target: {
          id: 'target-mock',
          baseUrl: 'http://unauthorized.external.attacker.com',
          scope: {
            allowedHosts: ['127.0.0.1'],
            allowedPorts: [80, 443],
            allowPrivateRanges: true,
            excludedPaths: [],
          },
        },
      },
    );

    expect(result.success).toBe(false);
    expect(result.error).toContain('is not within authorized scope');
    expect(result.findings).toHaveLength(0);
  });

  it('8. Input Validation & Capabilities > validates input URL schemas correctly', () => {
    const engine = new HttpSmugglingEngine();
    expect(engine.validate({ targetUrl: 'http://example.com' }).valid).toBe(true);
    expect(engine.validate({ targetUrl: 'https://example.com' }).valid).toBe(true);
    expect(engine.validate({ targetUrl: 'ftp://example.com' }).valid).toBe(false);
    expect(engine.validate({ targetUrl: 'not-a-valid-url' }).valid).toBe(false);

    const capabilities = engine.capabilities();
    expect(capabilities.length).toBe(5);
    expect(capabilities.map((c) => c.id)).toContain('http_smuggling_cl_te');
    expect(capabilities.map((c) => c.id)).toContain('http_smuggling_te_cl');
    expect(capabilities.map((c) => c.id)).toContain('reverse_proxy_host_poisoning');
  });

  it('9. Worker Thread Sandboxed Execution > executes http-smuggling engine in isolated V8 worker thread', async () => {
    const result = await executeSandboxedEngine(
      'engine-http-smuggling',
      {
        targetUrl: serverUrl,
        options: {
          techniques: ['CL_TE'],
          canaryPath: '/robots.txt',
          normalPath: '/',
          timeoutMs: 2000,
          timingDelayThresholdMs: 1000,
        },
      },
      {
        runId: 'run-sandboxed-smuggle-test',
        engineId: 'engine-http-smuggling',
        target: {
          id: 'target-mock',
          url: serverUrl,
          scope: {
            allowedHosts: ['127.0.0.1', 'localhost'],
            allowedPorts: [80, 443, serverPort],
            allowPrivateRanges: true,
            excludedPaths: [],
          },
        },
      },
      {
        timeoutMs: 15000,
      },
    );

    expect(result.engineId).toBe('engine-http-smuggling');
    expect(result.success).toBe(true);
    expect(result.findings.length).toBeGreaterThan(0);
    const clTe = result.findings.find((f) => f.title.includes('CL.TE'));
    expect(clTe).toBeDefined();
  });
});
