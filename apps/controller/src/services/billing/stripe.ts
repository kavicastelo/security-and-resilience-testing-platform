import crypto from 'node:crypto';

export interface StripeSignaturePayload {
  timestamp: number;
  signatures: string[];
}

/**
 * Parses the Stripe-Signature header format:
 * t=1492774577,v1=5257a869e7ecebeda32affa62cd4908f483a621d473780484460ba3574f670f9,v0=...
 */
export function parseStripeSignatureHeader(header: string): StripeSignaturePayload {
  const parts = header.split(',');
  let timestamp = 0;
  const signatures: string[] = [];

  for (const part of parts) {
    const [key, value] = part.split('=').map((s) => s.trim());
    if (key === 't' && value) {
      timestamp = parseInt(value, 10);
    } else if (key === 'v1' && value) {
      signatures.push(value);
    }
  }

  return { timestamp, signatures };
}

/**
 * Generates an HMAC-SHA256 signature matching Stripe's webhook format.
 */
export function computeStripeSignature(payload: string, timestamp: number, secret: string): string {
  const signedPayload = `${timestamp}.${payload}`;
  return crypto.createHmac('sha256', secret).update(signedPayload, 'utf-8').digest('hex');
}

/**
 * Verifies that an incoming Stripe webhook request signature is valid and not expired.
 */
export function verifyStripeSignature(
  rawBody: string,
  sigHeader: string,
  secret: string,
  toleranceSeconds: number = 300,
): boolean {
  if (!rawBody || !sigHeader || !secret) {
    return false;
  }

  const { timestamp, signatures } = parseStripeSignatureHeader(sigHeader);
  if (!timestamp || signatures.length === 0) {
    return false;
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSeconds - timestamp) > toleranceSeconds) {
    return false; // Replay attack or excessive clock drift
  }

  const expectedSignature = computeStripeSignature(rawBody, timestamp, secret);

  for (const sig of signatures) {
    try {
      const a = Buffer.from(sig, 'hex');
      const b = Buffer.from(expectedSignature, 'hex');
      if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
        return true;
      }
    } catch {
      // Invalid hex string, try next
    }
  }

  return false;
}
