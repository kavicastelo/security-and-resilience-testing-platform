import net from 'net';
import tls from 'tls';
import { URL } from 'url';
import { createLogger } from '@security-lab/logger';
import { RaceConditionTest, BurstSocketResult, BurstTestSummary } from './types.js';

const logger = createLogger({ name: 'engine-burst-synchro' });

const MAX_BURST_CONCURRENCY = 30; // Rule 13: Cap race condition burst requests to max 30

export interface BurstSynchroOptions {
  timeoutMs?: number;
  concurrency?: number;
}

export function parseRawHttpResponse(raw: string): {
  statusCode: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
} {
  const crlfSplit = raw.indexOf('\r\n\r\n');
  const lfSplit = raw.indexOf('\n\n');
  const splitIdx = crlfSplit !== -1 ? crlfSplit : lfSplit;
  const delimLen = crlfSplit !== -1 ? 4 : 2;

  if (splitIdx === -1) {
    const lines = raw.split(/\r?\n/);
    const statusLine = lines[0] || '';
    const match = statusLine.match(/^HTTP\/1\.[01]\s+(\d{3})(?:\s+(.*))?$/i);
    const codeStr = match?.[1];
    const statusCode = codeStr ? parseInt(codeStr, 10) : 0;
    const statusText = match?.[2] ? match[2].trim() : '';
    return {
      statusCode,
      statusText,
      headers: {},
      body: raw,
    };
  }

  const headerBlock = raw.slice(0, splitIdx);
  let body = raw.slice(splitIdx + delimLen);

  const lines = headerBlock.split(/\r?\n/);
  const statusLine = lines[0] || '';
  const match = statusLine.match(/^HTTP\/1\.[01]\s+(\d{3})(?:\s+(.*))?$/i);
  const codeStr = match?.[1];
  const statusCode = codeStr ? parseInt(codeStr, 10) : 0;
  const statusText = match?.[2] ? match[2].trim() : '';

  const headers: Record<string, string> = {};
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    const colonIdx = line.indexOf(':');
    if (colonIdx !== -1) {
      const k = line.slice(0, colonIdx).trim().toLowerCase();
      const v = line.slice(colonIdx + 1).trim();
      headers[k] = v;
    }
  }

  // Handle simple chunked transfer decoding if necessary
  if (headers['transfer-encoding']?.toLowerCase().includes('chunked')) {
    try {
      let decoded = '';
      let remaining = body;
      while (remaining.length > 0) {
        const nextCrlf = remaining.indexOf('\r\n');
        if (nextCrlf === -1) break;
        const chunkSizeHex = remaining.slice(0, nextCrlf).trim();
        const chunkSize = parseInt(chunkSizeHex, 16);
        if (isNaN(chunkSize) || chunkSize === 0) break;
        const chunkData = remaining.slice(nextCrlf + 2, nextCrlf + 2 + chunkSize);
        decoded += chunkData;
        remaining = remaining.slice(nextCrlf + 2 + chunkSize + 2);
      }
      if (decoded.length > 0) body = decoded;
    } catch {
      // Keep raw body on chunk parse error
    }
  }

  return { statusCode, statusText, headers, body };
}

/**
 * Executes a synchronized HTTP single-packet / burst race-condition test across pre-warmed sockets.
 */
export async function executeSynchronizedBurst(
  targetBaseUrl: string,
  test: RaceConditionTest,
  options: BurstSynchroOptions = {},
): Promise<BurstTestSummary> {
  const timeoutMs = options.timeoutMs ?? 15000;
  const concurrency = Math.min(
    MAX_BURST_CONCURRENCY,
    Math.max(2, test.concurrency ?? options.concurrency ?? 20),
  );

  const fullUrl = new URL(test.endpointPath, targetBaseUrl);
  const isHttps = fullUrl.protocol === 'https:';
  const port = fullUrl.port ? parseInt(fullUrl.port, 10) : isHttps ? 443 : 80;
  const host = fullUrl.hostname;

  const method = (test.method || 'POST').toUpperCase();
  const path = fullUrl.pathname + fullUrl.search;

  const bodyContent =
    test.body !== undefined
      ? typeof test.body === 'string'
        ? test.body
        : JSON.stringify(test.body)
      : '';

  const bodyBuffer = Buffer.from(bodyContent, 'utf-8');

  // Build HTTP headers
  const headerLines: string[] = [
    `${method} ${path} HTTP/1.1`,
    `Host: ${host}${fullUrl.port ? `:${fullUrl.port}` : ''}`,
    'User-Agent: SecurityLab-BurstSynchro/1.0',
    'Connection: keep-alive',
    'Accept: application/json, text/plain, */*',
  ];

  if (bodyBuffer.length > 0) {
    if (!test.headers || (!test.headers['content-type'] && !test.headers['Content-Type'])) {
      headerLines.push('Content-Type: application/json');
    }
    headerLines.push(`Content-Length: ${bodyBuffer.length}`);
  } else {
    headerLines.push('Content-Length: 0');
  }

  if (test.headers) {
    for (const [k, v] of Object.entries(test.headers)) {
      if (k.toLowerCase() !== 'host' && k.toLowerCase() !== 'content-length') {
        headerLines.push(`${k}: ${v}`);
      }
    }
  }

  const rawHeaders = headerLines.join('\r\n') + '\r\n\r\n';
  const headersBuffer = Buffer.from(rawHeaders, 'utf-8');

  // Prepare synchronized hold-back buffers:
  // We hold back the final byte of the request (either of body or headers)
  let headBuffer: Buffer;
  let finalByte: Buffer;

  if (bodyBuffer.length > 0) {
    const totalBuffer = Buffer.concat([headersBuffer, bodyBuffer]);
    headBuffer = totalBuffer.subarray(0, totalBuffer.length - 1);
    finalByte = totalBuffer.subarray(totalBuffer.length - 1);
  } else {
    headBuffer = headersBuffer.subarray(0, headersBuffer.length - 1);
    finalByte = headersBuffer.subarray(headersBuffer.length - 1);
  }

  logger.info(
    { host, port, path, concurrency, method },
    'Pre-warming sockets for single-packet synchronized burst',
  );

  const sockets: (net.Socket | tls.TLSSocket)[] = [];
  const results: BurstSocketResult[] = [];

  try {
    // 1. Pre-warm and connect all sockets
    const connectPromises = Array.from({ length: concurrency }, () => {
      return new Promise<net.Socket | tls.TLSSocket>((resolve, reject) => {
        let sock: net.Socket | tls.TLSSocket;
        let connected = false;

        const onConnect = () => {
          connected = true;
          sock.setNoDelay(true); // Disable Nagle's algorithm for instant transmission
          resolve(sock);
        };

        if (isHttps) {
          sock = tls.connect(
            {
              host,
              port,
              rejectUnauthorized: false,
              servername: host,
            },
            onConnect,
          );
        } else {
          sock = net.connect({ host, port }, onConnect);
        }

        sock.setTimeout(timeoutMs);

        sock.once('error', (err) => {
          if (!connected) reject(err);
        });

        sock.once('timeout', () => {
          if (!connected) {
            sock.destroy();
            reject(new Error(`Socket connection timed out after ${timeoutMs}ms`));
          }
        });
      });
    });

    // Wait for all sockets to connect
    const openedSockets = await Promise.all(connectPromises);
    sockets.push(...openedSockets);

    // 2. Send headBuffer across all sockets (holding back finalByte)
    await Promise.all(
      sockets.map((sock) => {
        return new Promise<void>((resolve, reject) => {
          sock.write(headBuffer, (err) => {
            if (err) reject(err);
            else resolve();
          });
        });
      }),
    );

    // Micro-delay (5ms) to allow headBuffers to arrive in the remote kernel TCP receive queue
    await new Promise((resolve) => setTimeout(resolve, 5));

    // 3. Set up response listeners on each socket
    let releaseTimestamp = 0;
    const responsePromises = sockets.map((sock, index) => {
      return new Promise<BurstSocketResult>((resolve) => {
        let rawResponse = '';
        let arrivalTimestamp = 0;

        const onData = (chunk: Buffer) => {
          if (!arrivalTimestamp) {
            arrivalTimestamp = performance.now();
          }
          rawResponse += chunk.toString('utf-8');

          // Check if response is complete
          const crlf = rawResponse.indexOf('\r\n\r\n');
          if (crlf !== -1) {
            const parsed = parseRawHttpResponse(rawResponse);
            const cl = parsed.headers['content-length'];
            if (cl) {
              const expectedLen = parseInt(cl, 10);
              if (parsed.body.length >= expectedLen) {
                cleanupAndResolve();
                return;
              }
            } else if (parsed.headers['transfer-encoding']?.includes('chunked')) {
              if (rawResponse.includes('\r\n0\r\n\r\n')) {
                cleanupAndResolve();
                return;
              }
            } else if (rawResponse.length > 0 && !parsed.headers['connection']?.includes('keep-alive')) {
              // Non-keep-alive closing
            }
          }
        };

        const cleanupAndResolve = (errorMsg?: string) => {
          sock.removeListener('data', onData);
          sock.removeListener('close', onClose);
          sock.removeListener('error', onError);

          const parsed = parseRawHttpResponse(rawResponse);
          const endTimestamp = arrivalTimestamp || performance.now();
          const latency = releaseTimestamp > 0 ? endTimestamp - releaseTimestamp : 0;

          resolve({
            index,
            statusCode: parsed.statusCode,
            statusText: parsed.statusText,
            headers: parsed.headers,
            body: parsed.body,
            latencyMs: Math.max(0, Math.round(latency)),
            arrivalTimestamp: endTimestamp,
            error: errorMsg,
          });
        };

        const onClose = () => cleanupAndResolve();
        const onError = (err: Error) => cleanupAndResolve(err.message);

        sock.on('data', onData);
        sock.once('close', onClose);
        sock.once('error', onError);

        // Fallback safety timer for response completion
        setTimeout(() => {
          cleanupAndResolve('Response wait timeout');
        }, timeoutMs);
      });
    });

    // 4. Synchronized Millisecond Barrier: Release finalByte synchronously across all sockets
    releaseTimestamp = performance.now();
    for (const sock of sockets) {
      sock.write(finalByte);
    }

    // 5. Await all socket responses
    const socketResults = await Promise.all(responsePromises);
    results.push(...socketResults);
  } catch (err: any) {
    logger.warn({ error: err.message }, 'Raw socket burst failed, falling back to parallel fetch burst');
    return executeFetchBurstFallback(fullUrl.toString(), test, concurrency, timeoutMs);
  } finally {
    // Ensure all sockets are cleanly destroyed
    for (const s of sockets) {
      try {
        s.destroy();
      } catch {
        // Ignore cleanup error
      }
    }
  }

  return evaluateBurstResults(test, results, concurrency);
}

/**
 * Fallback burst implementation using Promise.all with immediate fetch dispatch
 */
async function executeFetchBurstFallback(
  targetUrl: string,
  test: RaceConditionTest,
  concurrency: number,
  timeoutMs: number,
): Promise<BurstTestSummary> {
  const method = (test.method || 'POST').toUpperCase();
  const headers = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    ...(test.headers || {}),
  };

  const body =
    test.body !== undefined
      ? typeof test.body === 'string'
        ? test.body
        : JSON.stringify(test.body)
      : undefined;

  const startTimestamp = performance.now();
  const results: BurstSocketResult[] = [];

  const promises = Array.from({ length: concurrency }, async (_, index) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetch(targetUrl, {
        method,
        headers,
        body,
        signal: controller.signal,
      });
      clearTimeout(timer);

      const arrivalTimestamp = performance.now();
      const bodyText = await res.text().catch(() => '');
      const respHeaders: Record<string, string> = {};
      res.headers.forEach((v, k) => {
        respHeaders[k] = v;
      });

      return {
        index,
        statusCode: res.status,
        statusText: res.statusText,
        headers: respHeaders,
        body: bodyText,
        latencyMs: Math.round(arrivalTimestamp - startTimestamp),
        arrivalTimestamp,
      };
    } catch (err: any) {
      clearTimeout(timer);
      const arrivalTimestamp = performance.now();
      return {
        index,
        statusCode: 0,
        statusText: 'Fetch Error',
        headers: {},
        body: '',
        latencyMs: Math.round(arrivalTimestamp - startTimestamp),
        arrivalTimestamp,
        error: err.message,
      };
    }
  });

  const resolved = await Promise.all(promises);
  results.push(...resolved);

  return evaluateBurstResults(test, results, concurrency);
}

function evaluateBurstResults(
  test: RaceConditionTest,
  results: BurstSocketResult[],
  concurrency: number,
): BurstTestSummary {
  const successCodes = test.expectedSuccessCodes ?? [200, 201, 204];
  const maxAllowedSuccess = test.expectedMaxSuccessCount ?? 1;

  const successfulResponses = results.filter((r) => successCodes.includes(r.statusCode)).length;
  const failedResponses = results.length - successfulResponses;
  const statusCodes = results.map((r) => r.statusCode);

  const arrivalTimestamps = results.map((r) => r.arrivalTimestamp).filter((t) => t > 0);
  const jitterSpreadMs =
    arrivalTimestamps.length > 1
      ? Math.round((Math.max(...arrivalTimestamps) - Math.min(...arrivalTimestamps)) * 100) / 100
      : 0;

  const isVulnerable = successfulResponses > maxAllowedSuccess;

  const details = isVulnerable
    ? `Race condition detected: ${successfulResponses} concurrent requests succeeded (expected at most ${maxAllowedSuccess}) out of ${concurrency} bursts (Jitter spread: ${jitterSpreadMs}ms).`
    : `No race condition detected: ${successfulResponses} request(s) succeeded within expected threshold (max: ${maxAllowedSuccess}) across ${concurrency} bursts (Jitter spread: ${jitterSpreadMs}ms).`;

  logger.info(
    {
      testId: test.id,
      endpoint: test.endpointPath,
      concurrency,
      successfulResponses,
      maxAllowedSuccess,
      jitterSpreadMs,
      isVulnerable,
    },
    'Synchronized burst race condition evaluation completed',
  );

  return {
    testId: test.id,
    name: test.name,
    endpoint: test.endpointPath,
    method: test.method || 'POST',
    concurrency,
    successfulResponses,
    failedResponses,
    statusCodes,
    jitterSpreadMs,
    isVulnerable,
    details,
    results,
  };
}
