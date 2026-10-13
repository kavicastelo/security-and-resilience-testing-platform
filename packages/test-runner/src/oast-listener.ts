import http from 'node:http';
import dgram from 'node:dgram';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import { createLogger } from '@security-lab/logger';

const logger = createLogger({ name: 'oast-listener' });

export interface OastTokenMetadata {
  testRunId?: string;
  engineId?: string;
  targetUrl?: string;
  parameter?: string;
  vulnerabilityType?: 'ssrf' | 'sqli' | 'xxe' | 'rce' | 'deserialization' | 'other';
  [key: string]: unknown;
}

export interface OastTokenInfo {
  token: string;
  callbackUrl: string;
  dnsHost: string;
  createdAt: Date;
  metadata?: OastTokenMetadata;
}

export interface OastInteraction {
  id: string;
  token: string;
  protocol: 'http' | 'dns';
  timestamp: Date;
  remoteAddress: string;
  remotePort?: number;
  method?: string;
  url?: string;
  headers?: Record<string, string>;
  body?: string;
  queryName?: string;
  queryType?: string;
  metadata?: OastTokenMetadata;
}

export interface OastListenerOptions {
  host?: string;
  httpPort?: number;
  dnsPort?: number;
  enableDns?: boolean;
}

export class OastListener extends EventEmitter {
  private httpServer: http.Server | null = null;
  private dnsSocket: dgram.Socket | null = null;
  private host: string;
  private requestedHttpPort: number;
  private requestedDnsPort: number;
  private enableDns: boolean;
  private actualHttpPort = 0;
  private actualDnsPort = 0;
  private isRunning = false;

  private tokens = new Map<string, OastTokenInfo>();
  private interactions: OastInteraction[] = [];

  constructor(options: OastListenerOptions = {}) {
    super();
    this.host = options.host ?? '127.0.0.1';
    this.requestedHttpPort = options.httpPort ?? 0;
    this.requestedDnsPort = options.dnsPort ?? 0;
    this.enableDns = options.enableDns ?? false;
  }

  public get port(): number {
    return this.actualHttpPort;
  }

  public get dnsListenerPort(): number {
    return this.actualDnsPort;
  }

  public get baseUrl(): string {
    return `http://${this.host}:${this.actualHttpPort}`;
  }

  public async start(): Promise<{ httpPort: number; dnsPort?: number; baseUrl: string }> {
    if (this.isRunning) {
      return {
        httpPort: this.actualHttpPort,
        dnsPort: this.enableDns ? this.actualDnsPort : undefined,
        baseUrl: this.baseUrl,
      };
    }

    // Start HTTP listener
    await new Promise<void>((resolve, reject) => {
      this.httpServer = http.createServer((req, res) => {
        this.handleHttpRequest(req, res);
      });

      this.httpServer.on('error', (err) => {
        logger.error({ event: 'oast.http.error', error: err.message }, 'OAST HTTP server error');
        if (!this.isRunning) reject(err);
      });

      this.httpServer.listen(this.requestedHttpPort, this.host, () => {
        const address = this.httpServer?.address();
        if (address && typeof address === 'object') {
          this.actualHttpPort = address.port;
        }
        resolve();
      });
    });

    // Optionally start UDP DNS responder
    if (this.enableDns) {
      await new Promise<void>((resolve, reject) => {
        this.dnsSocket = dgram.createSocket('udp4');

        this.dnsSocket.on('error', (err) => {
          logger.error({ event: 'oast.dns.error', error: err.message }, 'OAST DNS socket error');
          if (!this.isRunning) reject(err);
        });

        this.dnsSocket.on('message', (msg, rinfo) => {
          this.handleDnsPacket(msg, rinfo);
        });

        this.dnsSocket.bind(this.requestedDnsPort, this.host, () => {
          const address = this.dnsSocket?.address();
          if (address && typeof address === 'object') {
            this.actualDnsPort = address.port;
          }
          resolve();
        });
      });
    }

    this.isRunning = true;
    logger.info(
      {
        event: 'oast.started',
        httpPort: this.actualHttpPort,
        dnsPort: this.enableDns ? this.actualDnsPort : undefined,
        host: this.host,
      },
      `Ephemeral OAST service listening on ${this.baseUrl}`,
    );

    return {
      httpPort: this.actualHttpPort,
      dnsPort: this.enableDns ? this.actualDnsPort : undefined,
      baseUrl: this.baseUrl,
    };
  }

  public async stop(): Promise<void> {
    if (!this.isRunning) return;

    if (this.httpServer) {
      await new Promise<void>((resolve) => {
        this.httpServer?.close(() => resolve());
      });
      this.httpServer = null;
    }

    if (this.dnsSocket) {
      await new Promise<void>((resolve) => {
        this.dnsSocket?.close(() => resolve());
      });
      this.dnsSocket = null;
    }

    this.isRunning = false;
    logger.info({ event: 'oast.stopped' }, 'Ephemeral OAST service stopped');
  }

  public createToken(metadata?: OastTokenMetadata): OastTokenInfo {
    const token = crypto.randomBytes(12).toString('hex');
    const callbackUrl = `${this.baseUrl}/cb/${token}`;
    const dnsHost = `${token}.oast.local`;

    const info: OastTokenInfo = {
      token,
      callbackUrl,
      dnsHost,
      createdAt: new Date(),
      metadata,
    };

    this.tokens.set(token, info);
    return info;
  }

  public getInteractions(token?: string): OastInteraction[] {
    if (!token) return [...this.interactions];
    return this.interactions.filter((i) => i.token === token);
  }

  public hasInteractions(token: string): boolean {
    return this.interactions.some((i) => i.token === token);
  }

  public async waitForInteraction(token: string, timeoutMs = 5000): Promise<OastInteraction | null> {
    const existing = this.interactions.find((i) => i.token === token);
    if (existing) return existing;

    return new Promise((resolve) => {
      let timer: NodeJS.Timeout | null = null;

      const onInteraction = (interaction: OastInteraction) => {
        if (interaction.token === token) {
          if (timer) clearTimeout(timer);
          this.removeListener('interaction', onInteraction);
          resolve(interaction);
        }
      };

      timer = setTimeout(() => {
        this.removeListener('interaction', onInteraction);
        resolve(null);
      }, timeoutMs);

      this.on('interaction', onInteraction);
    });
  }

  public reset(): void {
    this.tokens.clear();
    this.interactions = [];
  }

  private handleHttpRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    const url = req.url || '/';
    let body = '';

    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 65536) {
        req.destroy();
      }
    });

    req.on('end', () => {
      // Find matching token in path, query, or headers
      const matchedToken = this.findMatchingToken(url, req.headers);

      if (matchedToken) {
        const tokenInfo = this.tokens.get(matchedToken);
        const headersRecord: Record<string, string> = {};
        for (const [key, value] of Object.entries(req.headers)) {
          if (value) {
            headersRecord[key] = Array.isArray(value) ? value.join(', ') : value;
          }
        }

        const interaction: OastInteraction = {
          id: crypto.randomUUID(),
          token: matchedToken,
          protocol: 'http',
          timestamp: new Date(),
          remoteAddress: req.socket.remoteAddress || '127.0.0.1',
          remotePort: req.socket.remotePort,
          method: req.method,
          url,
          headers: headersRecord,
          body: body || undefined,
          metadata: tokenInfo?.metadata,
        };

        this.interactions.push(interaction);
        logger.info(
          {
            event: 'oast.interaction.received',
            protocol: 'http',
            token: matchedToken,
            remoteAddress: interaction.remoteAddress,
            url,
          },
          `OAST interaction received for token ${matchedToken} from ${interaction.remoteAddress}`,
        );

        this.emit('interaction', interaction);
      }

      res.writeHead(200, {
        'Content-Type': 'application/json',
        'X-Oast-Service': 'Security-Lab-OAST',
      });
      res.end(JSON.stringify({ status: 'ok', recorded: Boolean(matchedToken) }));
    });
  }

  private findMatchingToken(url: string, headers: http.IncomingHttpHeaders): string | null {
    // 1. Check path e.g. /cb/:token
    const pathOnly = url.split('?')[0] ?? '';
    const pathParts = pathOnly.split('/');
    for (const part of pathParts) {
      if (this.tokens.has(part)) return part;
    }

    // 2. Check query string e.g. ?token=...
    for (const token of this.tokens.keys()) {
      if (url.includes(token)) return token;
    }

    // 3. Check headers (e.g. X-Oast-Token or User-Agent containing token)
    for (const val of Object.values(headers)) {
      if (!val) continue;
      const strVal = Array.isArray(val) ? val.join(' ') : val;
      for (const token of this.tokens.keys()) {
        if (strVal.includes(token)) return token;
      }
    }

    return null;
  }

  private handleDnsPacket(msg: Buffer, rinfo: dgram.RemoteInfo): void {
    if (msg.length < 12) return;

    try {
      // Basic DNS query parsing to extract QNAME
      let offset = 12;
      const labels: string[] = [];
      while (offset < msg.length) {
        const len = msg[offset];
        if (len === undefined || len === 0) break;
        offset++;
        if (offset + len > msg.length) return;
        labels.push(msg.subarray(offset, offset + len).toString('ascii'));
        offset += len;
      }
      const qname = labels.join('.');

      // Check if any registered token is part of qname
      for (const token of this.tokens.keys()) {
        if (qname.toLowerCase().includes(token.toLowerCase())) {
          const tokenInfo = this.tokens.get(token);
          const interaction: OastInteraction = {
            id: crypto.randomUUID(),
            token,
            protocol: 'dns',
            timestamp: new Date(),
            remoteAddress: rinfo.address,
            remotePort: rinfo.port,
            queryName: qname,
            metadata: tokenInfo?.metadata,
          };
          this.interactions.push(interaction);
          this.emit('interaction', interaction);
          break;
        }
      }

      // Build minimal standard DNS response (A record pointing to 127.0.0.1)
      const response = Buffer.from(msg);
      if (response.length < 12) return;
      // Set QR = 1 (Response), AA = 1
      const byte2 = response[2] ?? 0;
      response[2] = byte2 | 0x84;
      // Set ANCOUNT = 1
      response[6] = 0x00;
      response[7] = 0x01;

      // Append Answer Section: Name pointer (0xc00c), Type A (0x0001), Class IN (0x0001), TTL (60s), DataLen (4), IP (127.0.0.1)
      const answer = Buffer.from([
        0xc0, 0x0c,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x3c,
        0x00, 0x04,
        127, 0, 0, 1,
      ]);

      const fullPacket = Buffer.concat([response, answer]);
      this.dnsSocket?.send(fullPacket, rinfo.port, rinfo.address);
    } catch {
      // Ignore malformed UDP packets
    }
  }
}

export const defaultOastListener = new OastListener();
