import http from 'http';
import https from 'https';
import { URL } from 'url';
import { TargetScope, validateUrlAgainstScope } from '@security-lab/domain';
import { createLogger } from '@security-lab/logger';
import { FaultRule, InjectedFaultRecord } from './types.js';
import { matchFaultRule, EvaluatedFault } from './fault-rules.js';

const logger = createLogger({ name: 'engine-chaos-mitm-proxy' });

export interface ChaosProxyOptions {
  upstreamBaseUrl: string;
  faultRules: FaultRule[];
  scope?: TargetScope;
  timeoutMs?: number;
}

export class ChaosMitmProxy {
  private server: http.Server | null = null;
  private port: number = 0;
  private activeSockets = new Set<any>();
  private faultLog: InjectedFaultRecord[] = [];
  private totalRequests = 0;
  private faultsInjected = 0;
  private faultsByType: Record<string, number> = {};

  constructor(private readonly options: ChaosProxyOptions) {}

  get listeningPort(): number {
    return this.port;
  }

  get proxyUrl(): string {
    return `http://127.0.0.1:${this.port}`;
  }

  get stats() {
    return {
      totalRequests: this.totalRequests,
      faultsInjected: this.faultsInjected,
      faultsByType: { ...this.faultsByType },
      faultLog: [...this.faultLog],
    };
  }

  async start(): Promise<number> {
    const upstreamUrl = new URL(this.options.upstreamBaseUrl);

    // 1. Verify upstream URL against scope before starting (Rule 2 / Safety Req 13)
    if (this.options.scope) {
      const scopeCheck = validateUrlAgainstScope(this.options.upstreamBaseUrl, this.options.scope);
      if (!scopeCheck.valid) {
        throw new Error(
          `Target upstream URL "${this.options.upstreamBaseUrl}" violates security scope: ${scopeCheck.violations.join('; ')}`,
        );
      }
    }

    this.server = http.createServer(async (req, res) => {
      this.totalRequests++;
      const method = req.method || 'GET';
      const reqUrl = new URL(req.url || '/', 'http://127.0.0.1');
      const pathAndQuery = reqUrl.pathname + reqUrl.search;

      // Construct target upstream URL for this request
      const forwardTargetUrl = new URL(pathAndQuery, upstreamUrl).toString();

      // Enforce Scope check for every forward target
      if (this.options.scope) {
        const check = validateUrlAgainstScope(forwardTargetUrl, this.options.scope);
        if (!check.valid) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              error: 'Forbidden: Target outside authorized security scope',
              violations: check.violations,
            }),
          );
          return;
        }
      }

      // Check Fault Rules
      const matchedFault: EvaluatedFault | null = matchFaultRule(
        this.options.faultRules,
        reqUrl.pathname,
        method,
      );

      if (matchedFault) {
        this.recordFault(matchedFault, reqUrl.pathname, method);
      }

      // Handle Immediate Faults (DROP or STATUS_CODE)
      if (matchedFault?.action === 'DROP') {
        req.socket.destroy();
        return;
      }

      if (matchedFault?.action === 'STATUS_CODE') {
        const code = matchedFault.statusCode || 503;
        res.writeHead(code, {
          'Content-Type': 'application/json',
          'X-Chaos-Fault': 'STATUS_CODE',
          'X-Chaos-Rule': matchedFault.rule.id,
        });
        res.end(matchedFault.statusBody);
        return;
      }

      // Handle Latency Fault
      if (matchedFault?.action === 'LATENCY' && matchedFault.delayMs) {
        await new Promise((resolve) => setTimeout(resolve, matchedFault.delayMs));
      }

      // Forward to Upstream
      this.forwardToUpstream(req, res, forwardTargetUrl, matchedFault);
    });

    // Track active sockets for clean shutdown
    this.server.on('connection', (sock) => {
      this.activeSockets.add(sock);
      sock.once('close', () => this.activeSockets.delete(sock));
    });

    await new Promise<void>((resolve, reject) => {
      this.server!.listen(0, '127.0.0.1', () => {
        const addr = this.server!.address();
        if (addr && typeof addr === 'object') {
          this.port = addr.port;
          logger.info(
            { port: this.port, upstream: this.options.upstreamBaseUrl },
            'Chaos MITM fault-injection proxy listening',
          );
          resolve();
        } else {
          reject(new Error('Failed to obtain listening address for Chaos proxy'));
        }
      });
      this.server!.once('error', reject);
    });

    return this.port;
  }

  private recordFault(fault: EvaluatedFault, path: string, method: string) {
    this.faultsInjected++;
    this.faultsByType[fault.action] = (this.faultsByType[fault.action] || 0) + 1;

    const record: InjectedFaultRecord = {
      ruleId: fault.rule.id,
      ruleName: fault.rule.name,
      action: fault.action,
      path,
      method,
      details: fault.details,
      timestamp: Date.now(),
    };

    this.faultLog.push(record);
    logger.info(
      `[FAULT INJECTED] Route: ${path} (${method}) Action: ${fault.action} -> ${fault.details}`,
    );
  }

  private forwardToUpstream(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    targetUrl: string,
    fault: EvaluatedFault | null,
  ) {
    const upstreamUrl = new URL(targetUrl);
    const isHttps = upstreamUrl.protocol === 'https:';
    const client = isHttps ? https : http;

    const headers: Record<string, any> = { ...req.headers };
    headers['host'] = upstreamUrl.host;
    delete headers['connection'];

    const proxyReq = client.request(
      {
        protocol: upstreamUrl.protocol,
        hostname: upstreamUrl.hostname,
        port: upstreamUrl.port || (isHttps ? 443 : 80),
        path: upstreamUrl.pathname + upstreamUrl.search,
        method: req.method,
        headers,
        timeout: this.options.timeoutMs || 15000,
        rejectUnauthorized: false,
      },
      (upstreamRes) => {
        if (fault?.action === 'TRUNCATE') {
          const maxBytes = fault.truncateBytes || 64;
          let bytesSent = 0;

          res.writeHead(upstreamRes.statusCode || 200, {
            ...upstreamRes.headers,
            'X-Chaos-Fault': 'TRUNCATE',
          });

          upstreamRes.on('data', (chunk: Buffer) => {
            const remaining = maxBytes - bytesSent;
            if (remaining > 0) {
              const toSend = chunk.subarray(0, remaining);
              res.write(toSend);
              bytesSent += toSend.length;
            }
            if (bytesSent >= maxBytes) {
              // Destroy client connection to simulate truncation failure
              upstreamRes.destroy();
              res.socket?.destroy();
            }
          });

          upstreamRes.on('end', () => {
            if (bytesSent < maxBytes) {
              res.end();
            }
          });
          return;
        }

        // Normal forwarding
        res.writeHead(upstreamRes.statusCode || 200, upstreamRes.headers);
        upstreamRes.pipe(res);
      },
    );

    proxyReq.on('error', (err) => {
      logger.warn({ error: err.message, target: targetUrl }, 'Upstream forwarding error in Chaos proxy');
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Chaos Proxy: Bad Gateway', upstreamError: err.message }));
      }
    });

    req.pipe(proxyReq);
  }

  async stop(): Promise<void> {
    for (const sock of this.activeSockets) {
      try {
        sock.destroy();
      } catch {
        // Ignore socket destroy errors
      }
    }
    this.activeSockets.clear();

    if (this.server) {
      await new Promise<void>((resolve) => {
        this.server!.close(() => resolve());
      });
      this.server = null;
      logger.info({ port: this.port }, 'Chaos MITM proxy stopped and port released');
    }
  }
}
