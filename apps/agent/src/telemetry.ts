import crypto from 'node:crypto';

// ============================================================================
// W3C Trace Context (Distributed Tracing / OpenTelemetry for Agent)
// ============================================================================

export interface ParsedTraceparent {
  valid: boolean;
  version?: string;
  traceId?: string;
  spanId?: string;
  sampled?: boolean;
}

export function generateTraceId(): string {
  return crypto.randomBytes(16).toString('hex');
}

export function generateSpanId(): string {
  return crypto.randomBytes(8).toString('hex');
}

export function createTraceparent(
  traceId: string = generateTraceId(),
  spanId: string = generateSpanId(),
  sampled: boolean = true,
): string {
  const flags = sampled ? '01' : '00';
  return `00-${traceId}-${spanId}-${flags}`;
}

export function parseTraceparent(header?: string | null): ParsedTraceparent {
  if (!header || typeof header !== 'string') {
    return { valid: false };
  }

  const parts = header.trim().split('-');
  if (parts.length < 4) {
    return { valid: false };
  }

  const [version, traceId, spanId, flags] = parts;
  if (!version || !traceId || !spanId || !flags) {
    return { valid: false };
  }

  if (traceId.length !== 32 || spanId.length !== 16 || flags.length !== 2) {
    return { valid: false };
  }

  if (/^0+$/.test(traceId) || /^0+$/.test(spanId)) {
    return { valid: false };
  }

  return {
    valid: true,
    version,
    traceId,
    spanId,
    sampled: flags === '01',
  };
}
