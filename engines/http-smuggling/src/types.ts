export * from '@security-lab/contracts';

export interface RawSocketSendOptions {
  host: string;
  port: number;
  useTls: boolean;
  payload: Buffer | string;
  timeoutMs?: number;
  keepAlive?: boolean;
  allowSelfSignedTls?: boolean;
}

export interface RawSocketResponse {
  statusCode?: number;
  statusLine?: string;
  headers: Record<string, string>;
  rawHeaders: string;
  body: string;
  rawBuffer: Buffer;
  latencyMs: number;
  timedOut: boolean;
  error?: string;
  requestSent: string;
  requestHexDump: string;
  responseHexDump: string;
}

export interface DualSocketSendOptions {
  host: string;
  port: number;
  useTls: boolean;
  firstPayload: Buffer | string;
  secondPayload: Buffer | string;
  delayBetweenMs?: number;
  timeoutMs?: number;
  allowSelfSignedTls?: boolean;
}

export interface DualSocketResponse {
  firstResponse?: RawSocketResponse;
  secondResponse?: RawSocketResponse;
  timedOut: boolean;
  latencyMs: number;
  desynchronized: boolean;
  details?: Record<string, unknown>;
}

export interface SmugglingProbeTarget {
  host: string;
  port: number;
  useTls: boolean;
  canaryPath: string;
  normalPath: string;
}
