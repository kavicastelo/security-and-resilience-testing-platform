import { logger } from '@security-lab/logger';

export type CircuitBreakerState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitBreakerOptions {
  failureThreshold?: number; // e.g. 0.25 (25%)
  errorThresholdPercent?: number; // e.g. 25 (%)
  windowSize?: number; // e.g. 10 requests
  slidingWindowSize?: number; // alias for windowSize
  cooldownPeriodMs?: number; // e.g. 30000ms (30s)
  cooldownSeconds?: number; // alias for cooldownPeriodMs in seconds
  minRequests?: number; // minimum requests before evaluating threshold (default: 4)
  halfOpenSuccessThreshold?: number; // consecutive successes in HALF_OPEN to recover (default: 2)
  targetKey?: string;
  onTrip?: (breaker: TargetCircuitBreaker) => void;
  onRecover?: (breaker: TargetCircuitBreaker) => void;
}

export class TargetCircuitBreakerOpenError extends Error {
  readonly targetKey: string;
  readonly errorRate: number;
  readonly cooldownRemainingMs: number;

  constructor(targetKey: string, errorRate: number, cooldownRemainingMs: number) {
    const errorPct = (errorRate * 100).toFixed(1);
    super(
      `Target circuit breaker is OPEN for "${targetKey}": Target failure rate (${errorPct}%) exceeded threshold. Backing off for ${Math.ceil(cooldownRemainingMs / 1000)}s.`,
    );
    this.name = 'TargetCircuitBreakerOpenError';
    this.targetKey = targetKey;
    this.errorRate = errorRate;
    this.cooldownRemainingMs = cooldownRemainingMs;
  }
}

/**
 * Adaptive Target Circuit Breaker.
 * Protects downstream target applications and APIs from denial of service under distress.
 * Tracks rolling window of response status codes (default 10 requests).
 * If >= 25% of responses are 5xx server errors, trips to OPEN state to pause scanning.
 */
export class TargetCircuitBreaker {
  private state: CircuitBreakerState = 'CLOSED';
  private slidingWindow: boolean[] = []; // true = success, false = failure (5xx)
  private trippedAt: number | null = null;
  private consecutiveHalfOpenSuccesses = 0;

  readonly targetKey: string;
  readonly failureThreshold: number;
  readonly windowSize: number;
  readonly cooldownPeriodMs: number;
  readonly minRequests: number;
  readonly halfOpenSuccessThreshold: number;

  private readonly onTrip?: (breaker: TargetCircuitBreaker) => void;
  private readonly onRecover?: (breaker: TargetCircuitBreaker) => void;

  constructor(options: CircuitBreakerOptions = {}) {
    this.targetKey = options.targetKey || 'default-target';
    this.failureThreshold =
      options.failureThreshold ??
      (options.errorThresholdPercent !== undefined ? options.errorThresholdPercent / 100 : 0.25);
    this.windowSize = options.windowSize ?? options.slidingWindowSize ?? 10;
    this.cooldownPeriodMs =
      options.cooldownPeriodMs ??
      (options.cooldownSeconds !== undefined ? Math.round(options.cooldownSeconds * 1000) : 30000);
    this.minRequests = options.minRequests ?? 4;
    this.halfOpenSuccessThreshold = options.halfOpenSuccessThreshold ?? 2;
    this.onTrip = options.onTrip;
    this.onRecover = options.onRecover;
  }

  getState(): CircuitBreakerState {
    this.evaluateStateTransition();
    return this.state;
  }

  isAllowed(): boolean {
    const currentState = this.getState();
    if (currentState === 'CLOSED' || currentState === 'HALF_OPEN') {
      return true;
    }
    return false;
  }

  canRequest(): boolean {
    return this.isAllowed();
  }

  checkExecution(): void {
    if (!this.isAllowed()) {
      throw new TargetCircuitBreakerOpenError(
        this.targetKey,
        this.getErrorRate(),
        this.getCooldownRemainingMs(),
      );
    }
  }

  getStats(): {
    errorRate: number;
    errorRatePercent: number;
    state: CircuitBreakerState;
    totalRequests: number;
  } {
    const errorRate = this.getErrorRate();
    return {
      errorRate,
      errorRatePercent: Math.round(errorRate * 100),
      state: this.getState(),
      totalRequests: this.slidingWindow.length,
    };
  }

  getErrorRate(): number {
    if (this.slidingWindow.length === 0) return 0;
    const failures = this.slidingWindow.filter((success) => !success).length;
    return failures / this.slidingWindow.length;
  }

  getCooldownRemainingMs(): number {
    if (!this.trippedAt) return 0;
    const elapsed = Date.now() - this.trippedAt;
    return Math.max(0, this.cooldownPeriodMs - elapsed);
  }

  recordResponse(statusCode: number): void {
    const isFailure = statusCode >= 500 && statusCode <= 599;
    this.recordOutcome(!isFailure, statusCode);
  }

  recordFailure(error?: unknown): void {
    this.recordOutcome(false, 500, error);
  }

  recordSuccess(): void {
    this.recordOutcome(true, 200);
  }

  private recordOutcome(success: boolean, statusCode?: number, error?: unknown): void {
    const currentState = this.getState();

    if (currentState === 'HALF_OPEN') {
      if (success) {
        this.consecutiveHalfOpenSuccesses++;
        if (this.consecutiveHalfOpenSuccesses >= this.halfOpenSuccessThreshold) {
          this.recover();
        }
      } else {
        this.trip(`Probe request failed in HALF_OPEN state with status ${statusCode}`);
      }
      return;
    }

    // Record in sliding window
    this.slidingWindow.push(success);
    if (this.slidingWindow.length > this.windowSize) {
      this.slidingWindow.shift();
    }

    // Evaluate failure threshold if window has accumulated minimum sample
    if (this.slidingWindow.length >= this.minRequests) {
      const errorRate = this.getErrorRate();
      if (errorRate >= this.failureThreshold) {
        const errorPct = (errorRate * 100).toFixed(1);
        this.trip(
          `Target error rate ${errorPct}% (>= ${(this.failureThreshold * 100).toFixed(0)}%) exceeded threshold over last ${this.slidingWindow.length} requests`,
          statusCode,
          error,
        );
      }
    }
  }

  private evaluateStateTransition(): void {
    if (this.state === 'OPEN' && this.trippedAt) {
      const elapsed = Date.now() - this.trippedAt;
      if (elapsed >= this.cooldownPeriodMs) {
        this.state = 'HALF_OPEN';
        this.consecutiveHalfOpenSuccesses = 0;
        logger.info(
          {
            event: 'circuit_breaker.half_open',
            target: this.targetKey,
            cooldownPeriodMs: this.cooldownPeriodMs,
          },
          `Circuit breaker for "${this.targetKey}" cooled down and entered HALF_OPEN state; probing target health.`,
        );
      }
    }
  }

  trip(reason: string, statusCode?: number, error?: unknown): void {
    const errorRate = this.getErrorRate();
    this.state = 'OPEN';
    this.trippedAt = Date.now();
    this.consecutiveHalfOpenSuccesses = 0;

    logger.warn(
      {
        event: 'circuit_breaker.tripped',
        target: this.targetKey,
        errorRate,
        windowSize: this.slidingWindow.length,
        statusCode,
        cooldownPeriodMs: this.cooldownPeriodMs,
        reason,
        err: error instanceof Error ? error.message : undefined,
      },
      `Target Circuit Breaker TRIPPED to OPEN for "${this.targetKey}": ${reason}`,
    );

    if (this.onTrip) {
      this.onTrip(this);
    }
  }

  recover(): void {
    this.state = 'CLOSED';
    this.trippedAt = null;
    this.consecutiveHalfOpenSuccesses = 0;
    this.slidingWindow = [];

    logger.info(
      {
        event: 'circuit_breaker.recovered',
        target: this.targetKey,
      },
      `Target Circuit Breaker RECOVERED to CLOSED for "${this.targetKey}". Target health restored.`,
    );

    if (this.onRecover) {
      this.onRecover(this);
    }
  }

  reset(): void {
    this.state = 'CLOSED';
    this.slidingWindow = [];
    this.trippedAt = null;
    this.consecutiveHalfOpenSuccesses = 0;
  }

  async execute<T>(action: () => Promise<T>): Promise<T> {
    if (!this.isAllowed()) {
      throw new TargetCircuitBreakerOpenError(
        this.targetKey,
        this.getErrorRate(),
        this.getCooldownRemainingMs(),
      );
    }

    try {
      const result = await action();

      // Inspect result for status code
      if (result && typeof result === 'object') {
        const candidateStatus = (result as { status?: number; statusCode?: number }).status ??
          (result as { status?: number; statusCode?: number }).statusCode;
        if (typeof candidateStatus === 'number') {
          this.recordResponse(candidateStatus);
        } else {
          this.recordSuccess();
        }
      } else {
        this.recordSuccess();
      }

      return result;
    } catch (err: unknown) {
      if (err instanceof TargetCircuitBreakerOpenError) {
        throw err;
      }
      this.recordFailure(err);
      throw err;
    }
  }
}

/**
 * Registry of TargetCircuitBreaker instances keyed by target URL, host, or target ID.
 */
export class CircuitBreakerRegistry {
  private breakers = new Map<string, TargetCircuitBreaker>();

  getBreaker(targetKey: string, options: CircuitBreakerOptions = {}): TargetCircuitBreaker {
    const cleanKey = targetKey.toLowerCase().trim();
    let breaker = this.breakers.get(cleanKey);
    if (!breaker) {
      breaker = new TargetCircuitBreaker({
        ...options,
        targetKey: cleanKey,
      });
      this.breakers.set(cleanKey, breaker);
    }
    return breaker;
  }

  clear(): void {
    this.breakers.clear();
  }
}

export const circuitBreakerRegistry = new CircuitBreakerRegistry();
