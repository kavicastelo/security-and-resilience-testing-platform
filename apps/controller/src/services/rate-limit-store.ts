import type { FastifyRateLimitStore } from '@fastify/rate-limit';

interface CacheEntry {
  current: number;
  ttl: number;
  iterationStartMs: number;
}

/**
 * Shared in-memory rate limit store for single-node / local-first controller operations.
 * Enables grouped routes (such as scan execution endpoints and aliases) to share the
 * same rate limiting buckets across child store instances while maintaining distinct
 * namespace isolation (scan:, purge:, auth:, ip:).
 */
export class SharedRateLimitStore implements FastifyRateLimitStore {
  private static sharedStore = new Map<string, CacheEntry>();
  private static readonly maxEntries = 10000;
  private continueExceeding: boolean;
  private exponentialBackoff: boolean;

  constructor(options: { continueExceeding?: boolean; exponentialBackoff?: boolean } = {}) {
    this.continueExceeding = Boolean(options.continueExceeding);
    this.exponentialBackoff = Boolean(options.exponentialBackoff);
  }

  incr(
    key: string,
    cb: (err: Error | null, result?: { current: number; ttl: number }) => void,
    timeWindow: number,
    max: number,
  ): void {
    const nowInMs = Date.now();
    let current = SharedRateLimitStore.sharedStore.get(key);

    if (!current) {
      if (SharedRateLimitStore.sharedStore.size >= SharedRateLimitStore.maxEntries) {
        const oldestKey = SharedRateLimitStore.sharedStore.keys().next().value;
        if (oldestKey) SharedRateLimitStore.sharedStore.delete(oldestKey);
      }
      current = { current: 1, ttl: timeWindow, iterationStartMs: nowInMs };
    } else if (current.iterationStartMs + timeWindow <= nowInMs) {
      current.current = 1;
      current.ttl = timeWindow;
      current.iterationStartMs = nowInMs;
    } else {
      ++current.current;
      if (this.continueExceeding && current.current > max) {
        current.ttl = timeWindow;
        current.iterationStartMs = nowInMs;
      } else if (this.exponentialBackoff && current.current > max) {
        const backoffExponent = current.current - max - 1;
        const ttl = timeWindow * (2 ** backoffExponent);
        current.ttl = Number.isSafeInteger(ttl) ? ttl : Number.MAX_SAFE_INTEGER;
        current.iterationStartMs = nowInMs;
      } else {
        current.ttl = timeWindow - (nowInMs - current.iterationStartMs);
      }
    }

    SharedRateLimitStore.sharedStore.set(key, current);
    cb(null, current);
  }

  read(
    key: string,
    cb: (err: Error | null, result?: { current: number; ttl: number }) => void,
    timeWindow: number,
    _max?: number,
  ): void {
    const nowInMs = Date.now();
    const current = SharedRateLimitStore.sharedStore.get(key);
    if (!current || current.iterationStartMs + timeWindow <= nowInMs) {
      cb(null, { current: 0, ttl: 0 });
      return;
    }
    const ttl = timeWindow - (nowInMs - current.iterationStartMs);
    cb(null, { current: current.current, ttl });
  }

  child(routeOptions: any): FastifyRateLimitStore {
    return new SharedRateLimitStore(routeOptions);
  }

  static reset(): void {
    SharedRateLimitStore.sharedStore.clear();
  }
}
