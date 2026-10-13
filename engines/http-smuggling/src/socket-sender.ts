import net from 'node:net';
import tls from 'node:tls';
import {
  RawSocketSendOptions,
  RawSocketResponse,
  DualSocketSendOptions,
  DualSocketResponse,
} from './types.js';

/**
 * Produces a classic hex dump representation of a byte buffer for diagnostic observability.
 */
export function formatHexDump(buffer: Buffer, maxBytes: number = 512): string {
  const slice = buffer.subarray(0, maxBytes);
  const lines: string[] = [];
  for (let i = 0; i < slice.length; i += 16) {
    const chunk = slice.subarray(i, i + 16);
    const hex = Array.from(chunk)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(' ')
      .padEnd(48, ' ');
    const ascii = Array.from(chunk)
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
      .join('');
    lines.push(`${i.toString(16).padStart(4, '0')}  ${hex}  |${ascii}|`);
  }
  if (buffer.length > maxBytes) {
    lines.push(`... (${buffer.length - maxBytes} additional bytes omitted)`);
  }
  return lines.join('\n');
}

/**
 * Parses raw HTTP response bytes into status line, status code, headers, and body.
 */
export function parseRawHttpResponse(rawBuffer: Buffer): {
  statusLine?: string;
  statusCode?: number;
  headers: Record<string, string>;
  rawHeaders: string;
  body: string;
} {
  const rawStr = rawBuffer.toString('utf-8');
  const headerEndIndex = rawStr.indexOf('\r\n\r\n');
  const lfHeaderEndIndex = headerEndIndex === -1 ? rawStr.indexOf('\n\n') : headerEndIndex;

  if (lfHeaderEndIndex === -1) {
    return {
      rawHeaders: '',
      headers: {},
      body: rawStr,
    };
  }

  const separatorLength = rawStr.includes('\r\n\r\n') ? 4 : 2;
  const rawHeaders = rawStr.substring(0, lfHeaderEndIndex);
  const body = rawStr.substring(lfHeaderEndIndex + separatorLength);

  const lines = rawHeaders.split(/\r?\n/);
  const statusLine = lines[0];
  let statusCode: number | undefined;

  if (statusLine) {
    const parts = statusLine.split(' ');
    const codePart = parts[1];
    if (codePart) {
      const code = parseInt(codePart, 10);
      if (!Number.isNaN(code)) {
        statusCode = code;
      }
    }
  }

  const headers: Record<string, string> = {};
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    const colonIndex = line.indexOf(':');
    if (colonIndex > 0) {
      const key = line.substring(0, colonIndex).trim().toLowerCase();
      const val = line.substring(colonIndex + 1).trim();
      headers[key] = val;
    }
  }

  return {
    statusLine,
    statusCode,
    headers,
    rawHeaders,
    body,
  };
}

/**
 * Low-level TCP/TLS socket transmitter. Transmits exact un-normalized byte buffers
 * preserving all malformed headers and custom linebreaks.
 */
export class RawSocketSender {
  /**
   * Transmits a single raw un-normalized HTTP payload over a raw TCP/TLS socket.
   */
  async sendRawPayload(options: RawSocketSendOptions): Promise<RawSocketResponse> {
    const {
      host,
      port,
      useTls,
      payload,
      timeoutMs = 5000,
      allowSelfSignedTls = true,
    } = options;

    const payloadBuffer = typeof payload === 'string' ? Buffer.from(payload, 'utf-8') : payload;
    const requestSent = payloadBuffer.toString('utf-8');
    const requestHexDump = formatHexDump(payloadBuffer);
    const startTime = Date.now();

    return new Promise<RawSocketResponse>((resolve) => {
      const chunks: Buffer[] = [];
      let isSettled = false;
      let timer: NodeJS.Timeout | null = null;
      let socket: net.Socket | tls.TLSSocket;

      const finish = (result: Partial<RawSocketResponse>) => {
        if (isSettled) return;
        isSettled = true;
        if (timer) clearTimeout(timer);
        try {
          socket.destroy();
        } catch {
          // ignore
        }

        const totalBuffer = Buffer.concat(chunks);
        const parsed = parseRawHttpResponse(totalBuffer);
        const latencyMs = Date.now() - startTime;

        resolve({
          statusCode: result.statusCode ?? parsed.statusCode,
          statusLine: result.statusLine ?? parsed.statusLine,
          headers: parsed.headers,
          rawHeaders: parsed.rawHeaders,
          body: parsed.body,
          rawBuffer: totalBuffer,
          latencyMs,
          timedOut: result.timedOut ?? false,
          error: result.error,
          requestSent,
          requestHexDump,
          responseHexDump: formatHexDump(totalBuffer),
        });
      };

      timer = setTimeout(() => {
        finish({ timedOut: true, error: `Socket timed out after ${timeoutMs}ms` });
      }, timeoutMs);

      const onConnect = () => {
        socket.write(payloadBuffer);
      };

      if (useTls) {
        socket = tls.connect(
          {
            host,
            port,
            rejectUnauthorized: !allowSelfSignedTls,
            servername: host,
          },
          onConnect,
        );
      } else {
        socket = net.connect({ host, port }, onConnect);
      }

      socket.on('data', (data: Buffer) => {
        chunks.push(data);
        const currentBuffer = Buffer.concat(chunks);
        const rawStr = currentBuffer.toString('utf-8');

        // Check if response has completed (Content-Length satisfied or chunked end or connection closed)
        const headerEnd = rawStr.indexOf('\r\n\r\n');
        if (headerEnd !== -1) {
          const rawHeaders = rawStr.substring(0, headerEnd);
          const clMatch = /content-length:\s*(\d+)/i.exec(rawHeaders);
          if (clMatch && clMatch[1]) {
            const contentLength = parseInt(clMatch[1], 10);
            const bodyBytes = Buffer.byteLength(rawStr.substring(headerEnd + 4), 'utf-8');
            if (bodyBytes >= contentLength) {
              finish({});
              return;
            }
          }
          if (rawHeaders.toLowerCase().includes('transfer-encoding: chunked')) {
            if (rawStr.substring(headerEnd + 4).includes('0\r\n\r\n')) {
              finish({});
              return;
            }
          }
        }
      });

      socket.on('end', () => {
        finish({});
      });

      socket.on('close', () => {
        finish({});
      });

      socket.on('error', (err: Error) => {
        finish({ error: err.message });
      });
    });
  }

  /**
   * Transmits two HTTP requests sequentially over the exact same keep-alive TCP socket
   * to verify whether the first request desynchronized backend parsing for the second request.
   */
  async sendDualPayloads(options: DualSocketSendOptions): Promise<DualSocketResponse> {
    const {
      host,
      port,
      useTls,
      firstPayload,
      secondPayload,
      delayBetweenMs = 50,
      timeoutMs = 6000,
      allowSelfSignedTls = true,
    } = options;

    const firstBuf = typeof firstPayload === 'string' ? Buffer.from(firstPayload, 'utf-8') : firstPayload;
    const secondBuf = typeof secondPayload === 'string' ? Buffer.from(secondPayload, 'utf-8') : secondPayload;
    const startTime = Date.now();

    return new Promise<DualSocketResponse>((resolve) => {
      let isSettled = false;
      let timer: NodeJS.Timeout | null = null;
      let socket: net.Socket | tls.TLSSocket;
      const chunks: Buffer[] = [];

      const finish = (result: Partial<DualSocketResponse>) => {
        if (isSettled) return;
        isSettled = true;
        if (timer) clearTimeout(timer);
        try {
          socket.destroy();
        } catch {
          // ignore
        }

        const totalBuffer = Buffer.concat(chunks);
        const parsed = parseRawHttpResponse(totalBuffer);
        const latencyMs = Date.now() - startTime;

        const firstResp: RawSocketResponse = {
          statusCode: parsed.statusCode,
          statusLine: parsed.statusLine,
          headers: parsed.headers,
          rawHeaders: parsed.rawHeaders,
          body: parsed.body,
          rawBuffer: totalBuffer,
          latencyMs,
          timedOut: result.timedOut ?? false,
          error: result.secondResponse?.error,
          requestSent: firstBuf.toString('utf-8'),
          requestHexDump: formatHexDump(firstBuf),
          responseHexDump: formatHexDump(totalBuffer),
        };

        resolve({
          firstResponse: firstResp,
          secondResponse: result.secondResponse,
          timedOut: result.timedOut ?? false,
          latencyMs,
          desynchronized: result.desynchronized ?? false,
          details: result.details,
        });
      };

      timer = setTimeout(() => {
        finish({ timedOut: true });
      }, timeoutMs);

      const onConnect = () => {
        // Send first payload
        socket.write(firstBuf);

        // Wait brief delay before sending second payload over the exact same socket
        setTimeout(() => {
          if (!socket.destroyed) {
            socket.write(secondBuf);
          }
        }, delayBetweenMs);
      };

      if (useTls) {
        socket = tls.connect(
          {
            host,
            port,
            rejectUnauthorized: !allowSelfSignedTls,
            servername: host,
          },
          onConnect,
        );
      } else {
        socket = net.connect({ host, port }, onConnect);
      }

      socket.on('data', (data: Buffer) => {
        chunks.push(data);
      });

      socket.on('end', () => {
        finish({});
      });

      socket.on('close', () => {
        finish({});
      });

      socket.on('error', (err: Error) => {
        finish({
          secondResponse: {
            headers: {},
            rawHeaders: '',
            body: '',
            rawBuffer: Buffer.alloc(0),
            latencyMs: Date.now() - startTime,
            timedOut: false,
            error: err.message,
            requestSent: secondBuf.toString('utf-8'),
            requestHexDump: formatHexDump(secondBuf),
            responseHexDump: '',
          },
        });
      });
    });
  }
}

export const rawSocketSender = new RawSocketSender();
