import React from 'react';
import { Gauge, CheckCircle2, AlertTriangle } from 'lucide-react';

export interface LatencyDistributionChartProps {
  p50?: number;
  p90?: number;
  p95?: number;
  p99?: number;
  slaThresholdMs?: number;
  title?: string;
  className?: string;
}

export const LatencyDistributionChart: React.FC<LatencyDistributionChartProps> = ({
  p50 = 45,
  p90,
  p95 = 120,
  p99 = 210,
  slaThresholdMs = 500,
  title = 'Response Latency Percentile Distribution Curve',
  className = '',
}) => {
  // If p90 is not explicitly provided, estimate it accurately between p50 and p95
  const effectiveP90 = p90 ?? Math.round(p50 + (p95 - p50) * 0.8);
  const dataPoints = [
    { label: 'p50 (Median)', percentile: 50, value: p50, color: '#38bdf8' },
    { label: 'p90', percentile: 90, value: effectiveP90, color: '#818cf8' },
    { label: 'p95', percentile: 95, value: p95, color: p95 > slaThresholdMs ? '#f43f5e' : '#a78bfa' },
    { label: 'p99', percentile: 99, value: p99, color: p99 > slaThresholdMs ? '#f43f5e' : '#ec4899' },
  ];

  const isBreached = p95 > slaThresholdMs;
  const maxValue = Math.max(slaThresholdMs * 1.25, p99 * 1.2, 100);

  // SVG dimensions & coordinate calculations
  const width = 560;
  const height = 180;
  const padding = { top: 25, right: 35, bottom: 35, left: 45 };
  const graphWidth = width - padding.left - padding.right;
  const graphHeight = height - padding.top - padding.bottom;

  // Map percentiles to X coordinates: [50, 90, 95, 99]
  const getX = (percentile: number) => {
    // Distribute nicely along width: 50 -> 15%, 90 -> 45%, 95 -> 72%, 99 -> 95%
    const relativeMap: Record<number, number> = {
      50: 0.12,
      90: 0.44,
      95: 0.72,
      99: 0.94,
    };
    const ratio = relativeMap[percentile] ?? (percentile / 100);
    return padding.left + ratio * graphWidth;
  };

  const getY = (val: number) => {
    const clamped = Math.min(val, maxValue);
    return padding.top + graphHeight - (clamped / maxValue) * graphHeight;
  };

  const slaY = getY(slaThresholdMs);

  // Construct SVG Path
  const points = dataPoints.map((d) => ({ x: getX(d.percentile), y: getY(d.value) }));
  
  // Create smooth cubic Bezier path
  let pathD = `M ${points[0]!.x} ${points[0]!.y}`;
  for (let i = 0; i < points.length - 1; i++) {
    const p0 = points[i]!;
    const p1 = points[i + 1]!;
    const cx = (p0.x + p1.x) / 2;
    pathD += ` C ${cx} ${p0.y}, ${cx} ${p1.y}, ${p1.x} ${p1.y}`;
  }

  const fillD = `${pathD} L ${points[points.length - 1]!.x} ${padding.top + graphHeight} L ${points[0]!.x} ${padding.top + graphHeight} Z`;

  return (
    <div className={`p-4 rounded-xl bg-card/80 border border-border shadow-sm space-y-3 ${className}`}>
      {/* Header with Title and SLA Badge */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Gauge className="w-4 h-4 text-blue-400" />
          <span className="text-xs font-semibold text-foreground">{title}</span>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-medium border ${
              isBreached
                ? 'bg-rose-500/15 text-rose-400 border-rose-500/30'
                : 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
            }`}
          >
            {isBreached ? (
              <>
                <AlertTriangle className="w-3 h-3 text-rose-400" />
                <span>P95 SLA Breached ({p95}ms &gt; {slaThresholdMs}ms)</span>
              </>
            ) : (
              <>
                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                <span>P95 SLA Compliant ({p95}ms &le; {slaThresholdMs}ms)</span>
              </>
            )}
          </span>
        </div>
      </div>

      {/* SVG Latency Graph */}
      <div className="relative w-full overflow-hidden bg-background/50 rounded-lg p-2 border border-border/60">
        <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-auto select-none overflow-visible">
          <defs>
            <linearGradient id="latencyAreaGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.35" />
              <stop offset="70%" stopColor="#8b5cf6" stopOpacity="0.12" />
              <stop offset="100%" stopColor="#1e1b4b" stopOpacity="0" />
            </linearGradient>
            <linearGradient id="latencyLineGrad" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="#38bdf8" />
              <stop offset="50%" stopColor="#818cf8" />
              <stop offset="100%" stopColor="#ec4899" />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          <line
            x1={padding.left}
            y1={padding.top + graphHeight}
            x2={width - padding.right}
            y2={padding.top + graphHeight}
            stroke="#27272a"
            strokeWidth="1"
          />
          <line
            x1={padding.left}
            y1={padding.top + graphHeight / 2}
            x2={width - padding.right}
            y2={padding.top + graphHeight / 2}
            stroke="#27272a"
            strokeDasharray="3 3"
            strokeWidth="1"
          />

          {/* SLA Threshold Horizontal Line */}
          <line
            x1={padding.left}
            y1={slaY}
            x2={width - padding.right}
            y2={slaY}
            stroke="#ef4444"
            strokeDasharray="4 4"
            strokeWidth="1.5"
            strokeOpacity="0.85"
          />
          <text
            x={width - padding.right - 4}
            y={slaY - 5}
            fill="#ef4444"
            fontSize="10"
            textAnchor="end"
            fontFamily="monospace"
            fontWeight="bold"
          >
            SLA: {slaThresholdMs}ms
          </text>

          {/* Gradient Area Fill */}
          <path d={fillD} fill="url(#latencyAreaGrad)" />

          {/* Main Curve Line */}
          <path
            d={pathD}
            fill="none"
            stroke="url(#latencyLineGrad)"
            strokeWidth="2.5"
            strokeLinecap="round"
          />

          {/* Data Points and Value Callouts */}
          {dataPoints.map((pt, i) => {
            const x = points[i]!.x;
            const y = points[i]!.y;
            return (
              <g key={pt.percentile} className="group cursor-pointer">
                {/* Vertical Drop Line */}
                <line
                  x1={x}
                  y1={y}
                  x2={x}
                  y2={padding.top + graphHeight}
                  stroke="#3f3f46"
                  strokeDasharray="2 2"
                  strokeWidth="1"
                />

                {/* Point Circle */}
                <circle
                  cx={x}
                  cy={y}
                  r="5"
                  fill="#09090b"
                  stroke={pt.color}
                  strokeWidth="2.5"
                  className="transition-transform duration-200 group-hover:scale-125"
                />

                {/* Latency Value Label (above point) */}
                <text
                  x={x}
                  y={y - 9}
                  fill={pt.color}
                  fontSize="11"
                  fontWeight="bold"
                  textAnchor="middle"
                  fontFamily="monospace"
                >
                  {pt.value}ms
                </text>

                {/* X-Axis Percentile Label (bottom) */}
                <text
                  x={x}
                  y={padding.top + graphHeight + 18}
                  fill="#a1a1aa"
                  fontSize="10"
                  textAnchor="middle"
                  fontFamily="monospace"
                >
                  p{pt.percentile}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Metric Breakdown Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 font-mono text-xs">
        {dataPoints.map((pt) => (
          <div
            key={pt.percentile}
            className="p-2.5 rounded-lg bg-background/60 border border-border/60 flex flex-col gap-1"
          >
            <span className="text-[10px] text-muted-foreground uppercase font-sans tracking-wide">
              {pt.label}
            </span>
            <div className="flex items-baseline justify-between">
              <span className="text-sm font-bold" style={{ color: pt.color }}>
                {pt.value} ms
              </span>
              <span className="text-[10px] text-muted-foreground font-sans">
                {pt.value <= slaThresholdMs ? '≤ SLA' : '> SLA'}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
