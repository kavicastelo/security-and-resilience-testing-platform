import { describe, it, expect } from 'vitest';
import {
  calculateSaturationKnee,
  computeHistogramBins,
  compareWithBaseline,
  fetchPerformanceSnapshot,
  fetchHistoricalBaselines,
  PRESET_BENCHMARKS,
  PerformanceMetricPoint,
  LatencyPercentileSummary,
} from '../src/api/performance.js';

describe('Phase UI-10: Native Performance Engineering, Latency Histograms & Capacity Studio', () => {
  describe('Analytical Saturation Knee Point Detector', () => {
    it('detects saturation inflection when latency escalates faster than throughput gains', () => {
      // Create a curve where throughput flattens at 60 VUs and latency shoots up
      const testPoints: PerformanceMetricPoint[] = [
        {
          timestamp: 1000,
          timeSec: 0,
          rps: 500,
          concurrencyVUs: 10,
          p50: 20,
          p90: 35,
          p95: 45,
          p99: 60,
          errorRate: 0,
          status2xx: 500,
          status4xx: 0,
          status5xx: 0,
          bytesPerSec: 50000,
        },
        {
          timestamp: 2000,
          timeSec: 10,
          rps: 1500,
          concurrencyVUs: 30,
          p50: 24,
          p90: 40,
          p95: 55,
          p99: 75,
          errorRate: 0,
          status2xx: 1500,
          status4xx: 0,
          status5xx: 0,
          bytesPerSec: 150000,
        },
        {
          timestamp: 3000,
          timeSec: 20,
          rps: 2800,
          concurrencyVUs: 60,
          p50: 32,
          p90: 55,
          p95: 75,
          p99: 110,
          errorRate: 0.001,
          status2xx: 2800,
          status4xx: 3,
          status5xx: 0,
          bytesPerSec: 280000,
        },
        {
          timestamp: 4000,
          timeSec: 30,
          rps: 2850,
          concurrencyVUs: 80,
          p50: 75,
          p90: 160,
          p95: 280,
          p99: 450,
          errorRate: 0.02,
          status2xx: 2800,
          status4xx: 30,
          status5xx: 20,
          bytesPerSec: 285000,
        },
        {
          timestamp: 5000,
          timeSec: 40,
          rps: 2400,
          concurrencyVUs: 100,
          p50: 180,
          p90: 420,
          p95: 680,
          p99: 1200,
          errorRate: 0.05,
          status2xx: 2280,
          status4xx: 50,
          status5xx: 70,
          bytesPerSec: 240000,
        },
      ];

      const analysis = calculateSaturationKnee(testPoints);
      expect(analysis.kneeConcurrency).toBeGreaterThanOrEqual(30);
      expect(analysis.kneeConcurrency).toBeLessThanOrEqual(80);
      expect(analysis.maxSustainedRps).toBeGreaterThanOrEqual(1500);
      expect(analysis.status).toBe('severe_overload');
      expect(analysis.postKneeLatencyDegradationPct).toBeGreaterThan(100);
      expect(analysis.bottleneckDiagnosis).toContain('saturation');
      expect(analysis.recommendation).toBeDefined();
    });

    it('returns optimal status when throughput scales linearly without queuing inflection', () => {
      const linearPoints: PerformanceMetricPoint[] = [
        {
          timestamp: 1000,
          timeSec: 0,
          rps: 400,
          concurrencyVUs: 10,
          p50: 15,
          p90: 25,
          p95: 35,
          p99: 50,
          errorRate: 0,
          status2xx: 400,
          status4xx: 0,
          status5xx: 0,
          bytesPerSec: 40000,
        },
        {
          timestamp: 2000,
          timeSec: 10,
          rps: 800,
          concurrencyVUs: 20,
          p50: 16,
          p90: 26,
          p95: 36,
          p99: 52,
          errorRate: 0,
          status2xx: 800,
          status4xx: 0,
          status5xx: 0,
          bytesPerSec: 80000,
        },
        {
          timestamp: 3000,
          timeSec: 20,
          rps: 1200,
          concurrencyVUs: 30,
          p50: 17,
          p90: 27,
          p95: 38,
          p99: 55,
          errorRate: 0,
          status2xx: 1200,
          status4xx: 0,
          status5xx: 0,
          bytesPerSec: 120000,
        },
      ];

      const analysis = calculateSaturationKnee(linearPoints);
      expect(analysis.status).toBe('optimal');
      expect(analysis.postKneeLatencyDegradationPct).toBeLessThan(40);
      expect(analysis.recommendation).toContain('Capacity ceiling not reached');
    });

    it('handles minimal boundary points gracefully', () => {
      const minimalPoints: PerformanceMetricPoint[] = [
        {
          timestamp: 1000,
          timeSec: 0,
          rps: 300,
          concurrencyVUs: 5,
          p50: 10,
          p90: 20,
          p95: 30,
          p99: 40,
          errorRate: 0,
          status2xx: 300,
          status4xx: 0,
          status5xx: 0,
          bytesPerSec: 30000,
        },
      ];

      const analysis = calculateSaturationKnee(minimalPoints);
      expect(analysis.kneeConcurrency).toBe(5);
      expect(analysis.status).toBe('optimal');
      expect(analysis.bottleneckDiagnosis).toContain('Insufficient data points');
    });
  });

  describe('Percentile Latency Histogram Binning', () => {
    it('computes discrete histogram bins with correct SLA color categories', () => {
      const percentiles: LatencyPercentileSummary = {
        p50: 45.0,
        p90: 110.0,
        p95: 185.0,
        p99: 310.0,
        p999: 490.0,
        min: 15.0,
        max: 650.0,
        avg: 68.4,
        stdDev: 32.1,
      };

      const bins = computeHistogramBins(percentiles, 100000);
      expect(bins.length).toBe(8);

      // Verify color categories based on SLA boundaries
      const greenBins = bins.filter((b) => b.colorCategory === 'green');
      const amberBins = bins.filter((b) => b.colorCategory === 'amber');
      const crimsonBins = bins.filter((b) => b.colorCategory === 'crimson');

      expect(greenBins.length).toBe(3); // 0-50, 50-100, 100-200ms
      expect(amberBins.length).toBe(2); // 200-350, 350-500ms
      expect(crimsonBins.length).toBe(3); // 500-750, 750-1000, >1000ms

      // Verify sum of percentages is within expected range
      const totalPct = bins.reduce((acc, b) => acc + b.percentage, 0);
      expect(totalPct).toBeGreaterThan(95);
      expect(totalPct).toBeLessThanOrEqual(105);
    });

    it('dynamically increases tail bin weighting when p95 breaches 500ms SLA', () => {
      const breachedPercentiles: LatencyPercentileSummary = {
        p50: 180.0,
        p90: 450.0,
        p95: 680.0,
        p99: 1200.0,
        p999: 2100.0,
        min: 25.0,
        max: 3400.0,
        avg: 240.0,
        stdDev: 210.0,
      };

      const bins = computeHistogramBins(breachedPercentiles, 100000);
      const severeBin = bins.find((b) => b.label === '>1000ms');
      expect(severeBin).toBeDefined();
      expect(severeBin!.count).toBeGreaterThan(0);
    });
  });

  describe('Automated Performance Regression Baseline Comparison', () => {
    it('detects 10%+ latency regressions and assigns warning or critical severity', () => {
      const current: LatencyPercentileSummary = {
        p50: 38.0,
        p90: 85.0,
        p95: 145.0, // Regressed from 100.0 (+45%)
        p99: 240.0,
        p999: 450.0,
        min: 15.0,
        max: 600.0,
        avg: 55.0,
        stdDev: 25.0,
      };

      const baseline: LatencyPercentileSummary = {
        p50: 32.0,
        p90: 65.0,
        p95: 100.0,
        p99: 180.0,
        p999: 350.0,
        min: 12.0,
        max: 450.0,
        avg: 44.0,
        stdDev: 20.0,
      };

      const comparisons = compareWithBaseline(
        current,
        2500,
        0.002,
        baseline,
        2700,
        0.001
      );

      const p95Comp = comparisons.find((c) => c.metric === 'p95 Latency (SLA)');
      expect(p95Comp).toBeDefined();
      expect(p95Comp!.delta).toBe(45);
      expect(p95Comp!.deltaPct).toBe(45);
      expect(p95Comp!.isRegression).toBe(true);
      expect(p95Comp!.severity).toBe('critical'); // > 25% is critical

      const p50Comp = comparisons.find((c) => c.metric === 'Median Latency (p50)');
      expect(p50Comp).toBeDefined();
      expect(p50Comp!.deltaPct).toBe(18.8);
      expect(p50Comp!.isRegression).toBe(true);
      expect(p50Comp!.severity).toBe('warning'); // > 10% but <= 25%
    });

    it('identifies improvements when latency drops or throughput increases', () => {
      const current: LatencyPercentileSummary = {
        p50: 25.0,
        p90: 50.0,
        p95: 75.0,
        p99: 120.0,
        p999: 200.0,
        min: 10.0,
        max: 300.0,
        avg: 32.0,
        stdDev: 15.0,
      };

      const baseline: LatencyPercentileSummary = {
        p50: 35.0,
        p90: 70.0,
        p95: 105.0,
        p99: 160.0,
        p999: 280.0,
        min: 15.0,
        max: 420.0,
        avg: 48.0,
        stdDev: 22.0,
      };

      const comparisons = compareWithBaseline(
        current,
        3200, // Higher throughput
        0.0005,
        baseline,
        2800,
        0.001
      );

      const rpsComp = comparisons.find((c) => c.metric === 'Throughput (RPS)');
      expect(rpsComp).toBeDefined();
      expect(rpsComp!.isRegression).toBe(false);
      expect(rpsComp!.severity).toBe('improved');

      const p95Comp = comparisons.find((c) => c.metric === 'p95 Latency (SLA)');
      expect(p95Comp).toBeDefined();
      expect(p95Comp!.isRegression).toBe(false);
      expect(p95Comp!.severity).toBe('improved');
    });
  });

  describe('Preset Benchmark Profiles & Historical Baselines', () => {
    it('provides core presets matching platform service profiles', () => {
      const presets = Object.keys(PRESET_BENCHMARKS);
      expect(presets).toContain('api-gateway-standard');
      expect(presets).toContain('payment-ingestion-spike');
      expect(presets).toContain('auth-token-signing');

      const gw = PRESET_BENCHMARKS['api-gateway-standard'].snapshot;
      expect(gw.peakRps).toBe(2850);
      expect(gw.sloPassed).toBe(true);
      expect(gw.timeSeries.length).toBeGreaterThan(5);

      const pay = PRESET_BENCHMARKS['payment-ingestion-spike'].snapshot;
      expect(pay.sloPassed).toBe(false);
      expect(pay.sloViolations.length).toBeGreaterThan(0);
      expect(pay.saturation.status).toBe('severe_overload');
    });

    it('fetches historical baselines including the golden baseline release', () => {
      const baselines = fetchHistoricalBaselines();
      expect(baselines.length).toBeGreaterThanOrEqual(3);

      const golden = baselines.find((b) => b.isGolden);
      expect(golden).toBeDefined();
      expect(golden!.id).toBe('base-golden-v2.4');
      expect(golden!.p95).toBe(98.0);
    });

    it('retrieves performance snapshot asynchronously for preset', async () => {
      const snapshot = await fetchPerformanceSnapshot(undefined, 'api-gateway-standard');
      expect(snapshot.runId).toBe('run-perf-gw-01');
      expect(snapshot.percentiles.p95).toBe(112.4);
      expect(snapshot.histogramBins.length).toBe(8);
      expect(snapshot.statusDistribution.status2xx).toBeGreaterThan(100000);
    });
  });
});
