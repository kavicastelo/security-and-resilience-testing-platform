import React, { useState } from 'react';
import { BarChart3, ShieldCheck, AlertCircle, Info } from 'lucide-react';
import { LatencyHistogramBin, LatencyPercentileSummary } from '../../api/performance.js';

export interface PercentileHistogramChartProps {
  bins: LatencyHistogramBin[];
  percentiles: LatencyPercentileSummary;
  totalRequests: number;
  slaThresholdMs?: number;
  className?: string;
}

export const PercentileHistogramChart: React.FC<PercentileHistogramChartProps> = ({
  bins,
  percentiles,
  totalRequests,
  slaThresholdMs = 500,
  className = '',
}) => {
  const [hoveredBin, setHoveredBin] = useState<LatencyHistogramBin | null>(null);

  const isBreached = percentiles.p95 > slaThresholdMs;
  const maxBinCount = Math.max(...bins.map((b) => b.count), 1);

  // SVG coordinate dimensions
  const width = 800;
  const height = 280;
  const padding = { top: 40, right: 30, bottom: 45, left: 55 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;

  const barWidth = chartWidth / bins.length;

  // Percentile marker positions mapped across the bins
  // We can calculate the exact X coordinate for a given latency value
  const getXForLatency = (latencyMs: number) => {
    // Find which bin this latency falls into
    for (let i = 0; i < bins.length; i++) {
      const bin = bins[i];
      if (latencyMs >= bin.minMs && latencyMs < bin.maxMs) {
        const binSpan = Math.max(1, bin.maxMs - bin.minMs);
        const ratio = (latencyMs - bin.minMs) / binSpan;
        return padding.left + i * barWidth + ratio * barWidth;
      }
    }
    // If beyond last bin
    return padding.left + chartWidth - 10;
  };

  const p50X = getXForLatency(percentiles.p50);
  const p90X = getXForLatency(percentiles.p90);
  const p95X = getXForLatency(percentiles.p95);
  const p99X = getXForLatency(percentiles.p99);
  const slaX = getXForLatency(slaThresholdMs);

  const getColorClass = (category: LatencyHistogramBin['colorCategory']) => {
    switch (category) {
      case 'green':
        return { fill: '#10b981', hover: '#34d399', text: 'text-emerald-400' };
      case 'amber':
        return { fill: '#f59e0b', hover: '#fbbf24', text: 'text-amber-400' };
      case 'crimson':
        return { fill: '#f43f5e', hover: '#fb7185', text: 'text-rose-400' };
    }
  };

  return (
    <div className={`p-5 rounded-2xl bg-card/60 border border-border/60 shadow-xl space-y-4 ${className}`}>
      {/* Header & SLA Status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border/40">
        <div>
          <div className="flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-indigo-400" />
            <h3 className="font-semibold text-foreground text-sm tracking-wide">
              High-Resolution Percentile Latency Distribution
            </h3>
            <span
              className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border ${
                isBreached
                  ? 'bg-rose-500/15 text-rose-400 border-rose-500/30'
                  : 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
              }`}
            >
              {isBreached ? 'SLA Breached (>500ms)' : 'SLA Compliant (≤500ms)'}
            </span>
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">
            Log-linear latency distribution with p50, p90, p95, and p99 percentile indicators.
          </p>
        </div>

        {/* SLA Callout Badge */}
        <div className="flex items-center gap-2 text-xs font-mono">
          <div className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-background/80 border border-border/60">
            {isBreached ? (
              <AlertCircle className="w-4 h-4 text-rose-400" />
            ) : (
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
            )}
            <span className="text-muted-foreground">P95 SLA:</span>
            <span className={`font-bold ${isBreached ? 'text-rose-400' : 'text-emerald-400'}`}>
              {percentiles.p95.toFixed(2)} ms
            </span>
            <span className="text-muted-foreground text-[10px]">/ {slaThresholdMs}ms limit</span>
          </div>
        </div>
      </div>

      {/* SVG Latency Histogram Canvas */}
      <div className="relative w-full aspect-[8/2.8] select-none">
        <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-full overflow-visible">
          <defs>
            <linearGradient id="barGreen" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#10b981" stopOpacity="0.85" />
              <stop offset="100%" stopColor="#059669" stopOpacity="0.4" />
            </linearGradient>
            <linearGradient id="barAmber" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.85" />
              <stop offset="100%" stopColor="#d97706" stopOpacity="0.4" />
            </linearGradient>
            <linearGradient id="barCrimson" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#f43f5e" stopOpacity="0.85" />
              <stop offset="100%" stopColor="#be123c" stopOpacity="0.4" />
            </linearGradient>
          </defs>

          {/* Background Grid Lines */}
          {[0, 0.25, 0.5, 0.75, 1].map((ratio) => {
            const y = padding.top + chartHeight - ratio * chartHeight;
            const countLabel = Math.round(ratio * maxBinCount);
            return (
              <g key={ratio}>
                <line
                  x1={padding.left}
                  y1={y}
                  x2={padding.left + chartWidth}
                  y2={y}
                  stroke="currentColor"
                  strokeWidth="0.5"
                  strokeDasharray="2 3"
                  className="text-border/25"
                />
                <text
                  x={padding.left - 8}
                  y={y + 3}
                  textAnchor="end"
                  fontSize="10"
                  fill="currentColor"
                  className="font-mono text-[9px] text-muted-foreground fill-muted-foreground"
                >
                  {countLabel.toLocaleString()}
                </text>
              </g>
            );
          })}

          {/* SLA Threshold Vertical Reference Line */}
          <line
            x1={slaX}
            y1={padding.top - 15}
            x2={slaX}
            y2={padding.top + chartHeight}
            stroke="#f43f5e"
            strokeWidth="1.5"
            strokeDasharray="4 3"
          />
          <text
            x={slaX}
            y={padding.top - 20}
            textAnchor="middle"
            fontSize="9"
            fill="#f43f5e"
            fontWeight="bold"
            className="font-mono"
          >
            SLA GATE (500ms)
          </text>

          {/* Histogram Bars */}
          {bins.map((bin, i) => {
            const x = padding.left + i * barWidth + 3;
            const w = Math.max(2, barWidth - 6);
            const barH = (bin.count / maxBinCount) * chartHeight;
            const y = padding.top + chartHeight - barH;

            const isHovered = hoveredBin?.label === bin.label;
            const gradientId =
              bin.colorCategory === 'green'
                ? 'url(#barGreen)'
                : bin.colorCategory === 'amber'
                ? 'url(#barAmber)'
                : 'url(#barCrimson)';

            return (
              <g key={bin.label} onMouseEnter={() => setHoveredBin(bin)} onMouseLeave={() => setHoveredBin(null)}>
                <rect
                  x={x}
                  y={y}
                  width={w}
                  height={barH}
                  rx="3"
                  fill={gradientId}
                  stroke={isHovered ? '#ffffff' : 'transparent'}
                  strokeWidth="1.5"
                  className="cursor-pointer transition-all duration-150"
                  style={{ opacity: hoveredBin && !isHovered ? 0.45 : 1 }}
                />

                {/* X-axis bin label */}
                <text
                  x={x + w / 2}
                  y={padding.top + chartHeight + 18}
                  textAnchor="middle"
                  fontSize="9"
                  fill="currentColor"
                  className="font-mono text-[9px] text-muted-foreground fill-muted-foreground"
                >
                  {bin.label}
                </text>

                {/* Percentage on top of significant bars */}
                {bin.percentage >= 4 && (
                  <text
                    x={x + w / 2}
                    y={Math.max(padding.top + 15, y - 6)}
                    textAnchor="middle"
                    fontSize="9"
                    fill="currentColor"
                    className="font-mono text-[9px] fill-foreground font-semibold"
                  >
                    {bin.percentage}%
                  </text>
                )}
              </g>
            );
          })}

          {/* Percentile Markers & Pins */}
          {/* P50 Marker (Cyan) */}
          <g>
            <line
              x1={p50X}
              y1={padding.top + 10}
              x2={p50X}
              y2={padding.top + chartHeight}
              stroke="#38bdf8"
              strokeWidth="2"
            />
            <rect x={p50X - 25} y={padding.top + 10} width="50" height="15" rx="3" fill="#0369a1" />
            <text
              x={p50X}
              y={padding.top + 21}
              textAnchor="middle"
              fontSize="9"
              fontWeight="bold"
              fill="#e0f2fe"
              className="font-mono"
            >
              p50: {percentiles.p50.toFixed(1)}
            </text>
          </g>

          {/* P90 Marker (Indigo) */}
          <g>
            <line
              x1={p90X}
              y1={padding.top + 25}
              x2={p90X}
              y2={padding.top + chartHeight}
              stroke="#818cf8"
              strokeWidth="1.8"
              strokeDasharray="3 2"
            />
            <rect x={p90X - 25} y={padding.top + 25} width="50" height="15" rx="3" fill="#4338ca" />
            <text
              x={p90X}
              y={padding.top + 36}
              textAnchor="middle"
              fontSize="9"
              fontWeight="bold"
              fill="#e0e7ff"
              className="font-mono"
            >
              p90: {percentiles.p90.toFixed(1)}
            </text>
          </g>

          {/* P95 Marker (Purple / Crimson) */}
          <g>
            <line
              x1={p95X}
              y1={padding.top}
              x2={p95X}
              y2={padding.top + chartHeight}
              stroke={percentiles.p95 > slaThresholdMs ? '#f43f5e' : '#c084fc'}
              strokeWidth="2.2"
            />
            <rect
              x={p95X - 26}
              y={padding.top - 2}
              width="52"
              height="16"
              rx="3"
              fill={percentiles.p95 > slaThresholdMs ? '#9f1239' : '#6b21a8'}
            />
            <text
              x={p95X}
              y={padding.top + 10}
              textAnchor="middle"
              fontSize="9"
              fontWeight="bold"
              fill="#ffffff"
              className="font-mono"
            >
              p95: {percentiles.p95.toFixed(1)}
            </text>
          </g>

          {/* P99 Marker (Pink / Crimson) */}
          <g>
            <line
              x1={p99X}
              y1={padding.top + 20}
              x2={p99X}
              y2={padding.top + chartHeight}
              stroke="#f472b6"
              strokeWidth="1.8"
              strokeDasharray="3 2"
            />
            <rect x={p99X - 25} y={padding.top + 20} width="50" height="15" rx="3" fill="#9d174d" />
            <text
              x={p99X}
              y={padding.top + 31}
              textAnchor="middle"
              fontSize="9"
              fontWeight="bold"
              fill="#fce7f3"
              className="font-mono"
            >
              p99: {percentiles.p99.toFixed(1)}
            </text>
          </g>
        </svg>
      </div>

      {/* Selected Bin Details / Tooltip bar */}
      <div className="p-2.5 rounded-xl bg-background/60 border border-border/40 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs">
        {hoveredBin ? (
          <div className="flex items-center gap-3">
            <span className="font-semibold text-foreground font-mono px-2 py-0.5 rounded bg-muted/50 border border-border/40">
              Bin: {hoveredBin.label}
            </span>
            <span className="text-muted-foreground">
              Requests:{' '}
              <strong className="text-foreground font-mono">{hoveredBin.count.toLocaleString()}</strong>
            </span>
            <span className="text-muted-foreground">
              Share:{' '}
              <strong className={`font-mono ${getColorClass(hoveredBin.colorCategory).text}`}>
                {hoveredBin.percentage}%
              </strong>
            </span>
          </div>
        ) : (
          <div className="flex items-center gap-2 text-muted-foreground text-[11px]">
            <Info className="w-3.5 h-3.5 text-blue-400" />
            <span>Hover over any histogram bar to inspect sample volumes and latency boundaries.</span>
          </div>
        )}

        {/* Statistical Summary Tags */}
        <div className="flex items-center gap-3 text-xs font-mono">
          <span className="text-muted-foreground">
            Avg: <strong className="text-foreground">{percentiles.avg.toFixed(2)}ms</strong>
          </span>
          <span className="text-muted-foreground">
            StdDev: <strong className="text-foreground">±{percentiles.stdDev.toFixed(2)}ms</strong>
          </span>
          <span className="text-muted-foreground">
            Max: <strong className="text-rose-400">{percentiles.max.toFixed(1)}ms</strong>
          </span>
          <span className="text-muted-foreground text-[11px]">
            ({totalRequests.toLocaleString()} total reqs)
          </span>
        </div>
      </div>
    </div>
  );
};
