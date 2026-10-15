import { authFetch } from './client.js';

export interface PerformanceMetricPoint {
  timestamp: number;
  timeSec: number;
  rps: number;
  concurrencyVUs: number;
  p50: number;
  p90: number;
  p95: number;
  p99: number;
  errorRate: number;
  status2xx: number;
  status4xx: number;
  status5xx: number;
  bytesPerSec: number;
}

export interface LatencyHistogramBin {
  minMs: number;
  maxMs: number;
  label: string;
  count: number;
  percentage: number;
  colorCategory: 'green' | 'amber' | 'crimson';
}

export interface LatencyPercentileSummary {
  p50: number;
  p90: number;
  p95: number;
  p99: number;
  p999: number;
  min: number;
  max: number;
  avg: number;
  stdDev: number;
}

export interface SaturationKneeAnalysis {
  kneeConcurrency: number;
  maxSustainedRps: number;
  kneeLatencyMs: number;
  postKneeLatencyDegradationPct: number;
  postKneeThroughputDropPct: number;
  bottleneckDiagnosis: string;
  recommendation: string;
  status: 'optimal' | 'saturated' | 'severe_overload';
}

export interface BaselineComparison {
  metric: string;
  current: number;
  baseline: number;
  delta: number;
  deltaPct: number;
  unit: string;
  isRegression: boolean;
  thresholdPct: number;
  severity: 'normal' | 'improved' | 'warning' | 'critical';
}

export interface PerformanceStudioSnapshot {
  runId: string;
  targetId: string;
  targetUrl: string;
  profileName: string;
  durationSec: number;
  totalRequests: number;
  peakRps: number;
  avgRps: number;
  errorRate: number;
  percentiles: LatencyPercentileSummary;
  timeSeries: PerformanceMetricPoint[];
  histogramBins: LatencyHistogramBin[];
  saturation: SaturationKneeAnalysis;
  baselineComparison: BaselineComparison[];
  statusDistribution: {
    status2xx: number;
    status4xx: number;
    status5xx: number;
    codeCounts: Record<string, number>;
  };
  sloPassed: boolean;
  sloViolations: string[];
}

export interface HistoricalBaseline {
  id: string;
  name: string;
  runDate: string;
  p95: number;
  peakRps: number;
  errorRate: number;
  isGolden: boolean;
}

// ============================================================================
// Math & Analytical Engine for Saturation and Histogram Calculations
// ============================================================================

export function calculateSaturationKnee(points: PerformanceMetricPoint[]): SaturationKneeAnalysis {
  if (points.length < 3) {
    return {
      kneeConcurrency: points[0]?.concurrencyVUs ?? 10,
      maxSustainedRps: points[0]?.rps ?? 500,
      kneeLatencyMs: points[0]?.p95 ?? 50,
      postKneeLatencyDegradationPct: 0,
      postKneeThroughputDropPct: 0,
      bottleneckDiagnosis: 'Insufficient data points to detect inflection knee.',
      recommendation: 'Run an extended ramp test with wider concurrency increments.',
      status: 'optimal',
    };
  }

  // Find the point where Throughput Efficiency (RPS / Concurrency) drops sharply,
  // or where Latency spikes while RPS plateaus.
  let kneeIndex = 0;
  let maxEfficiency = -Infinity;
  let maxRps = 0;

  for (let i = 0; i < points.length; i++) {
    const pt = points[i];
    if (pt.rps > maxRps) {
      maxRps = pt.rps;
    }
    const efficiency = pt.rps / Math.max(1, pt.concurrencyVUs);
    if (efficiency >= maxEfficiency) {
      maxEfficiency = efficiency;
      kneeIndex = i;
    }
  }

  // Refine knee: the point after which latency rises > 40% faster than RPS
  for (let i = kneeIndex; i < points.length - 1; i++) {
    const curr = points[i];
    const next = points[i + 1];
    const rpsGrowth = (next.rps - curr.rps) / Math.max(1, curr.rps);
    const latencyGrowth = (next.p95 - curr.p95) / Math.max(1, curr.p95);

    if (latencyGrowth > 0.4 && rpsGrowth < 0.1) {
      kneeIndex = i;
      break;
    }
  }

  const kneePoint = points[kneeIndex];
  const lastPoint = points[points.length - 1];

  const postKneeLatencyDegradationPct =
    kneePoint.p95 > 0 ? Math.round(((lastPoint.p95 - kneePoint.p95) / kneePoint.p95) * 1000) / 10 : 0;

  const postKneeThroughputDropPct =
    maxRps > 0 ? Math.max(0, Math.round(((maxRps - lastPoint.rps) / maxRps) * 1000) / 10) : 0;

  let status: SaturationKneeAnalysis['status'] = 'optimal';
  let bottleneckDiagnosis = 'Linear scaling maintained across all concurrency stages.';
  let recommendation = 'Capacity ceiling not reached. Concurrency can be safely increased.';

  if (postKneeLatencyDegradationPct > 150 || postKneeThroughputDropPct > 20) {
    status = 'severe_overload';
    bottleneckDiagnosis =
      'Severe saturation knee detected: Downstream thread pool depletion or database connection starvation.';
    recommendation =
      'Immediate action required: Enforce upstream token bucket rate-limiting at ' +
      Math.round(kneePoint.rps * 0.9) +
      ' RPS and scale connection pools.';
  } else if (postKneeLatencyDegradationPct > 35 || (kneeIndex < points.length - 1 && postKneeLatencyDegradationPct > 20)) {
    status = 'saturated';
    bottleneckDiagnosis =
      'System inflection point reached. Marginal concurrency yields diminishing throughput and latency inflation.';
    recommendation =
      'Maintain maximum sustained workload below ' +
      kneePoint.concurrencyVUs +
      ' concurrent VUs (' +
      Math.round(kneePoint.rps) +
      ' RPS).';
  }

  return {
    kneeConcurrency: kneePoint.concurrencyVUs,
    maxSustainedRps: Math.round(kneePoint.rps),
    kneeLatencyMs: Math.round(kneePoint.p95 * 100) / 100,
    postKneeLatencyDegradationPct,
    postKneeThroughputDropPct,
    bottleneckDiagnosis,
    recommendation,
    status,
  };
}

export function computeHistogramBins(
  percentiles: LatencyPercentileSummary,
  totalRequests: number
): LatencyHistogramBin[] {
  const binDefs = [
    { min: 0, max: 50, label: '0-50ms', color: 'green' as const, weight: 0.35 },
    { min: 50, max: 100, label: '50-100ms', color: 'green' as const, weight: 0.28 },
    { min: 100, max: 200, label: '100-200ms', color: 'green' as const, weight: 0.18 },
    { min: 200, max: 350, label: '200-350ms', color: 'amber' as const, weight: 0.09 },
    { min: 350, max: 500, label: '350-500ms', color: 'amber' as const, weight: 0.05 },
    { min: 500, max: 750, label: '500-750ms', color: 'crimson' as const, weight: 0.03 },
    { min: 750, max: 1000, label: '750-1000ms', color: 'crimson' as const, weight: 0.015 },
    { min: 1000, max: 5000, label: '>1000ms', color: 'crimson' as const, weight: 0.005 },
  ];

  // Adjust distribution weights based on actual p50, p95, p99
  let accumulated = 0;
  return binDefs.map((b) => {
    // Dynamic shift based on p95
    let factor = b.weight;
    if (percentiles.p95 > 500 && b.max > 500) {
      factor *= 2.5;
    } else if (percentiles.p95 <= 100 && b.max <= 100) {
      factor *= 1.3;
    }
    const count = Math.round(totalRequests * factor);
    accumulated += count;

    return {
      minMs: b.min,
      maxMs: b.max,
      label: b.label,
      count,
      percentage: Math.min(100, Math.round((count / Math.max(1, totalRequests)) * 1000) / 10),
      colorCategory: b.color,
    };
  });
}

export function compareWithBaseline(
  current: LatencyPercentileSummary,
  currentRps: number,
  currentErrorRate: number,
  baseline: LatencyPercentileSummary,
  baselineRps: number,
  baselineErrorRate: number
): BaselineComparison[] {
  const regressionThresholdPct = 10.0;

  const metrics: Array<{
    name: string;
    curr: number;
    base: number;
    unit: string;
    higherIsBetter?: boolean;
  }> = [
    { name: 'Throughput (RPS)', curr: currentRps, base: baselineRps, unit: 'req/s', higherIsBetter: true },
    { name: 'Median Latency (p50)', curr: current.p50, base: baseline.p50, unit: 'ms' },
    { name: 'p90 Latency', curr: current.p90, base: baseline.p90, unit: 'ms' },
    { name: 'p95 Latency (SLA)', curr: current.p95, base: baseline.p95, unit: 'ms' },
    { name: 'p99 Latency (Tail)', curr: current.p99, base: baseline.p99, unit: 'ms' },
    { name: 'Average Latency', curr: current.avg, base: baseline.avg, unit: 'ms' },
    { name: 'Error Rate', curr: currentErrorRate * 100, base: baselineErrorRate * 100, unit: '%' },
  ];

  return metrics.map((m) => {
    const delta = Math.round((m.curr - m.base) * 100) / 100;
    const deltaPct = m.base > 0 ? Math.round(((m.curr - m.base) / m.base) * 1000) / 10 : 0;

    let isRegression = false;
    let severity: BaselineComparison['severity'] = 'normal';

    if (m.higherIsBetter) {
      if (deltaPct < -regressionThresholdPct) {
        isRegression = true;
        severity = deltaPct < -25 ? 'critical' : 'warning';
      } else if (deltaPct > 5) {
        severity = 'improved';
      }
    } else {
      if (deltaPct > regressionThresholdPct) {
        isRegression = true;
        severity = deltaPct > 25 ? 'critical' : 'warning';
      } else if (deltaPct < -5) {
        severity = 'improved';
      }
    }

    return {
      metric: m.name,
      current: m.curr,
      baseline: m.base,
      delta,
      deltaPct,
      unit: m.unit,
      isRegression,
      thresholdPct: regressionThresholdPct,
      severity,
    };
  });
}

// ============================================================================
// Built-In Preset Benchmarks for Rapid Evaluation & Production Simulation
// ============================================================================

export const PRESET_BENCHMARKS: Record<string, { name: string; target: string; description: string; snapshot: PerformanceStudioSnapshot }> = {
  'api-gateway-standard': {
    name: 'Core REST API Gateway Ramping Load',
    target: 'https://api.internal.security-lab.local/v1/checkout',
    description: '120-second multi-stage concurrency ramp up to 120 VUs evaluating connection pooling and ingress routing.',
    snapshot: generateGatewayPreset(),
  },
  'payment-ingestion-spike': {
    name: 'Payment Ingestion Saturation Spike',
    target: 'https://pay.internal.security-lab.local/transactions',
    description: 'High-concurrency spike triggering database connection pool exhaustion and latency knees at 50 VUs.',
    snapshot: generatePaymentSpikePreset(),
  },
  'auth-token-signing': {
    name: 'OAuth2 / JWT Token Minting Benchmark',
    target: 'https://auth.internal.security-lab.local/oauth/token',
    description: 'CPU-intensive RS256 token generation testing crypto engine throughput limits and tail latency.',
    snapshot: generateAuthTokenPreset(),
  },
};

function generateGatewayPreset(): PerformanceStudioSnapshot {
  const points: PerformanceMetricPoint[] = [];
  const durationSec = 60;
  for (let sec = 0; sec <= durationSec; sec += 5) {
    const progress = sec / durationSec;
    // Concurrency ramps 10 -> 100
    const vus = Math.round(10 + progress * 90);
    // Linear throughput up to 60 VUs, then flattens at 2,850 RPS
    const rps = vus <= 60 ? Math.round(vus * 46) : Math.round(2760 + (vus - 60) * 5);
    const p50 = Math.round((28 + (vus > 60 ? (vus - 60) * 1.8 : progress * 8)) * 100) / 100;
    const p90 = Math.round((p50 * 1.6) * 100) / 100;
    const p95 = Math.round((p50 * 2.1 + (vus > 70 ? (vus - 70) * 3.5 : 0)) * 100) / 100;
    const p99 = Math.round((p95 * 1.5) * 100) / 100;
    const errorRate = vus > 75 ? Math.round(((vus - 75) * 0.08) * 100) / 10000 : 0.0005;

    points.push({
      timestamp: Date.now() - (durationSec - sec) * 1000,
      timeSec: sec,
      rps,
      concurrencyVUs: vus,
      p50,
      p90,
      p95,
      p99,
      errorRate,
      status2xx: Math.round(rps * 5 * (1 - errorRate)),
      status4xx: Math.round(rps * 5 * errorRate * 0.4),
      status5xx: Math.round(rps * 5 * errorRate * 0.6),
      bytesPerSec: rps * 1420,
    });
  }

  const percentiles: LatencyPercentileSummary = {
    p50: 34.5,
    p90: 68.2,
    p95: 112.4,
    p99: 188.0,
    p999: 345.0,
    min: 12.1,
    max: 420.5,
    avg: 48.6,
    stdDev: 24.3,
  };

  const goldenBaselinePercentiles: LatencyPercentileSummary = {
    p50: 31.0,
    p90: 60.5,
    p95: 98.0,
    p99: 165.0,
    p999: 310.0,
    min: 11.5,
    max: 380.0,
    avg: 43.2,
    stdDev: 21.0,
  };

  const totalReqs = 142500;
  const saturation = calculateSaturationKnee(points);
  const baselineComparison = compareWithBaseline(
    percentiles,
    2850,
    0.002,
    goldenBaselinePercentiles,
    2920,
    0.001
  );

  return {
    runId: 'run-perf-gw-01',
    targetId: 'tgt-api-gateway',
    targetUrl: 'https://api.internal.security-lab.local/v1/checkout',
    profileName: 'Core REST API Gateway Ramping Load',
    durationSec,
    totalRequests: totalReqs,
    peakRps: 2850,
    avgRps: 2375,
    errorRate: 0.002,
    percentiles,
    timeSeries: points,
    histogramBins: computeHistogramBins(percentiles, totalReqs),
    saturation,
    baselineComparison,
    statusDistribution: {
      status2xx: 142215,
      status4xx: 185,
      status5xx: 100,
      codeCounts: { '200': 138500, '201': 3715, '429': 185, '503': 100 },
    },
    sloPassed: true,
    sloViolations: [],
  };
}

function generatePaymentSpikePreset(): PerformanceStudioSnapshot {
  const points: PerformanceMetricPoint[] = [];
  const durationSec = 60;
  for (let sec = 0; sec <= durationSec; sec += 5) {
    const progress = sec / durationSec;
    const vus = Math.round(20 + progress * 130);
    // Severe knee at 50 VUs (approx sec 15)
    let rps = 0;
    let p95 = 0;
    let errorRate = 0;

    if (vus <= 50) {
      rps = Math.round(vus * 42);
      p95 = Math.round((45 + progress * 40) * 100) / 100;
      errorRate = 0.001;
    } else {
      // Saturation knee hit: RPS declines, p95 explodes
      rps = Math.round(2100 - (vus - 50) * 8.5);
      p95 = Math.round((85 + Math.pow(vus - 50, 1.45) * 4.2) * 100) / 100;
      errorRate = Math.min(0.085, Math.round((0.001 + (vus - 50) * 0.0009) * 1000) / 1000);
    }

    const p50 = Math.round((p95 * 0.45) * 100) / 100;
    const p90 = Math.round((p95 * 0.85) * 100) / 100;
    const p99 = Math.round((p95 * 1.65) * 100) / 100;

    points.push({
      timestamp: Date.now() - (durationSec - sec) * 1000,
      timeSec: sec,
      rps: Math.max(500, rps),
      concurrencyVUs: vus,
      p50,
      p90,
      p95,
      p99,
      errorRate,
      status2xx: Math.round(rps * 5 * (1 - errorRate)),
      status4xx: Math.round(rps * 5 * errorRate * 0.3),
      status5xx: Math.round(rps * 5 * errorRate * 0.7),
      bytesPerSec: rps * 2150,
    });
  }

  const percentiles: LatencyPercentileSummary = {
    p50: 165.0,
    p90: 420.0,
    p95: 642.5,
    p99: 1080.0,
    p999: 1850.0,
    min: 24.0,
    max: 2450.0,
    avg: 215.4,
    stdDev: 185.0,
  };

  const baselinePercentiles: LatencyPercentileSummary = {
    p50: 95.0,
    p90: 240.0,
    p95: 380.0,
    p99: 620.0,
    p999: 980.0,
    min: 22.0,
    max: 1200.0,
    avg: 124.0,
    stdDev: 92.0,
  };

  const totalReqs = 98400;
  const saturation = calculateSaturationKnee(points);
  const baselineComparison = compareWithBaseline(
    percentiles,
    2100,
    0.042,
    baselinePercentiles,
    2450,
    0.005
  );

  return {
    runId: 'run-perf-pay-02',
    targetId: 'tgt-payment-engine',
    targetUrl: 'https://pay.internal.security-lab.local/transactions',
    profileName: 'Payment Ingestion Saturation Spike',
    durationSec,
    totalRequests: totalReqs,
    peakRps: 2100,
    avgRps: 1640,
    errorRate: 0.042,
    percentiles,
    timeSeries: points,
    histogramBins: computeHistogramBins(percentiles, totalReqs),
    saturation,
    baselineComparison,
    statusDistribution: {
      status2xx: 94267,
      status4xx: 1240,
      status5xx: 2893,
      codeCounts: { '200': 94267, '429': 1240, '500': 1893, '504': 1000 },
    },
    sloPassed: false,
    sloViolations: [
      'p95 Latency (642.50ms) exceeded maximum threshold (500.00ms)',
      'Error rate (4.20%) exceeded policy limit (1.00%)',
    ],
  };
}

function generateAuthTokenPreset(): PerformanceStudioSnapshot {
  const points: PerformanceMetricPoint[] = [];
  const durationSec = 60;
  for (let sec = 0; sec <= durationSec; sec += 5) {
    const progress = sec / durationSec;
    const vus = Math.round(10 + progress * 60);
    // CPU bound at 40 VUs (~1,800 RPS)
    const rps = vus <= 40 ? Math.round(vus * 45) : Math.round(1800 + (vus - 40) * 3);
    const p50 = Math.round((22 + (vus > 40 ? (vus - 40) * 1.5 : progress * 5)) * 100) / 100;
    const p90 = Math.round((p50 * 1.5) * 100) / 100;
    const p95 = Math.round((p50 * 1.95) * 100) / 100;
    const p99 = Math.round((p95 * 1.4) * 100) / 100;
    const errorRate = 0.0002;

    points.push({
      timestamp: Date.now() - (durationSec - sec) * 1000,
      timeSec: sec,
      rps,
      concurrencyVUs: vus,
      p50,
      p90,
      p95,
      p99,
      errorRate,
      status2xx: Math.round(rps * 5),
      status4xx: 0,
      status5xx: 0,
      bytesPerSec: rps * 850,
    });
  }

  const percentiles: LatencyPercentileSummary = {
    p50: 32.1,
    p90: 54.0,
    p95: 78.5,
    p99: 115.0,
    p999: 180.0,
    min: 14.0,
    max: 220.0,
    avg: 38.2,
    stdDev: 14.5,
  };

  const baselinePercentiles: LatencyPercentileSummary = {
    p50: 30.5,
    p90: 52.0,
    p95: 75.0,
    p99: 110.0,
    p999: 175.0,
    min: 13.5,
    max: 210.0,
    avg: 36.8,
    stdDev: 13.8,
  };

  const totalReqs = 82400;
  const saturation = calculateSaturationKnee(points);
  const baselineComparison = compareWithBaseline(
    percentiles,
    1800,
    0.0002,
    baselinePercentiles,
    1820,
    0.0001
  );

  return {
    runId: 'run-perf-auth-03',
    targetId: 'tgt-auth-service',
    targetUrl: 'https://auth.internal.security-lab.local/oauth/token',
    profileName: 'OAuth2 / JWT Token Minting Benchmark',
    durationSec,
    totalRequests: totalReqs,
    peakRps: 1800,
    avgRps: 1373,
    errorRate: 0.0002,
    percentiles,
    timeSeries: points,
    histogramBins: computeHistogramBins(percentiles, totalReqs),
    saturation,
    baselineComparison,
    statusDistribution: {
      status2xx: 82384,
      status4xx: 16,
      status5xx: 0,
      codeCounts: { '200': 82384, '400': 16 },
    },
    sloPassed: true,
    sloViolations: [],
  };
}

// ============================================================================
// API Client Invocation Functions
// ============================================================================

export type MetricsStudioSnapshot = PerformanceStudioSnapshot;

export async function fetchMetricsStudioData(
  runId?: string
): Promise<MetricsStudioSnapshot | null> {
  if (!runId || runId === 'preset') {
    return null;
  }
  const apiUrl = import.meta.env?.VITE_API_URL || 'http://localhost:3000';
  try {
    const res = await authFetch(`${apiUrl}/api/v1/performance/runs/${encodeURIComponent(runId)}/timeseries`);
    if (res.ok) {
      const json = await res.json();
      return json.data ?? null;
    }
  } catch {
    // API unavailable or network failure
  }
  return null;
}

export async function fetchPerformanceSnapshot(
  runId?: string,
  presetId?: string
): Promise<PerformanceStudioSnapshot | null> {
  if (runId && runId !== 'preset') {
    return fetchMetricsStudioData(runId);
  }
  if (presetId && PRESET_BENCHMARKS[presetId]) {
    return PRESET_BENCHMARKS[presetId].snapshot;
  }
  return null;
}

export async function fetchHistoricalBaselines(targetId?: string): Promise<HistoricalBaseline[]> {
  const apiUrl = import.meta.env?.VITE_API_URL || 'http://localhost:3000';
  try {
    const query = targetId ? `?targetId=${encodeURIComponent(targetId)}` : '';
    const res = await authFetch(`${apiUrl}/api/v1/performance/baselines${query}`);
    if (res.ok) {
      const json = await res.json();
      return json.data || [];
    }
  } catch {
    // API unavailable or network failure
  }
  return [];
}

export async function promoteGoldenBaseline(payload: {
  targetId: string;
  testRunId: string;
  name: string;
  isGolden?: boolean;
}): Promise<HistoricalBaseline | null> {
  const apiUrl = import.meta.env?.VITE_API_URL || 'http://localhost:3000';
  try {
    const res = await authFetch(`${apiUrl}/api/v1/performance/baselines`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });
    if (res.ok) {
      const json = await res.json();
      return json.data ?? null;
    }
  } catch {
    // API unavailable
  }
  return null;
}

export async function executeLoadTest(payload: {
  targetId: string;
  scenario?: {
    vus?: number;
    duration?: string;
    rpsTarget?: number;
    endpoints?: Array<{ path: string; method?: string; weight?: number }>;
  };
  concurrency?: number;
  duration?: string;
  rpsTarget?: number;
}): Promise<{ testRunId: string; status: string; totalRequests: number; errorRate: number } | null> {
  const apiUrl = import.meta.env?.VITE_API_URL || 'http://localhost:3000';
  try {
    const res = await authFetch(`${apiUrl}/api/v1/performance/load/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });
    if (res.ok) {
      const json = await res.json();
      return json.data ?? null;
    }
  } catch {
    // API unavailable
  }
  return null;
}

