import { LatencyPercentiles } from './types.js';

export class LatencyHistogram {
  private samples: number[] = [];
  private minVal = Infinity;
  private maxVal = 0;
  private sumVal = 0;
  private sumSqVal = 0;
  private isSorted = false;

  record(latencyMs: number): void {
    const val = Math.max(0, Math.round(latencyMs * 100) / 100);
    this.samples.push(val);
    if (val < this.minVal) this.minVal = val;
    if (val > this.maxVal) this.maxVal = val;
    this.sumVal += val;
    this.sumSqVal += val * val;
    this.isSorted = false;
  }

  get count(): number {
    return this.samples.length;
  }

  get min(): number {
    return this.samples.length === 0 ? 0 : this.minVal;
  }

  get max(): number {
    return this.samples.length === 0 ? 0 : this.maxVal;
  }

  get avg(): number {
    if (this.samples.length === 0) return 0;
    return Math.round((this.sumVal / this.samples.length) * 100) / 100;
  }

  get stdDev(): number {
    const n = this.samples.length;
    if (n <= 1) return 0;
    const variance = Math.max(0, (this.sumSqVal - (this.sumVal * this.sumVal) / n) / (n - 1));
    return Math.round(Math.sqrt(variance) * 100) / 100;
  }

  getPercentile(percentile: number): number {
    if (this.samples.length === 0) return 0;
    if (percentile <= 0) return this.min;
    if (percentile >= 100) return this.max;

    if (!this.isSorted) {
      this.samples.sort((a, b) => a - b);
      this.isSorted = true;
    }

    const rank = (percentile / 100) * (this.samples.length - 1);
    const lower = Math.floor(rank);
    const upper = Math.ceil(rank);
    const weight = rank - lower;

    const lowerVal = this.samples[lower] ?? 0;
    const upperVal = this.samples[upper] ?? lowerVal;

    const result = lowerVal * (1 - weight) + upperVal * weight;
    return Math.round(result * 100) / 100;
  }

  getSummary(): LatencyPercentiles {
    return {
      p50: this.getPercentile(50),
      p90: this.getPercentile(90),
      p95: this.getPercentile(95),
      p99: this.getPercentile(99),
      p999: this.getPercentile(99.9),
      min: this.min,
      max: this.max,
      avg: this.avg,
      stdDev: this.stdDev,
    };
  }

  reset(): void {
    this.samples = [];
    this.minVal = Infinity;
    this.maxVal = 0;
    this.sumVal = 0;
    this.sumSqVal = 0;
    this.isSorted = false;
  }
}
