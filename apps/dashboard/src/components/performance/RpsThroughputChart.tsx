import React, { useState } from 'react';
import { Activity, Users, Clock, Layers } from 'lucide-react';
import { PerformanceMetricPoint, SaturationKneeAnalysis } from '../../api/performance.js';

export interface RpsThroughputChartProps {
  points: PerformanceMetricPoint[];
  saturation?: SaturationKneeAnalysis;
  className?: string;
}

export const RpsThroughputChart: React.FC<RpsThroughputChartProps> = ({
  points,
  saturation,
  className = '',
}) => {
  const [hoverIndex, setHoverIndex] = useState<number | null>(null);
  const [showLatency, setShowLatency] = useState(true);
  const [showVUs, setShowVUs] = useState(true);

  if (!points || points.length === 0) {
    return (
      <div className="p-8 text-center text-muted-foreground text-sm border border-border/40 rounded-xl bg-card/40">
        No time-series throughput data available.
      </div>
    );
  }

  // Calculate scales
  const maxRps = Math.max(...points.map((p) => p.rps), 100);
  const maxVUs = Math.max(...points.map((p) => p.concurrencyVUs), 10);
  const maxLatency = Math.max(...points.map((p) => p.p95), 50);

  // SVG coordinate bounding
  const width = 800;
  const height = 300;
  const padding = { top: 30, right: 60, bottom: 40, left: 60 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;

  const getX = (index: number) => {
    if (points.length <= 1) return padding.left;
    return padding.left + (index / (points.length - 1)) * chartWidth;
  };

  const getYPrimary = (val: number, max: number) => {
    const ratio = Math.min(1, Math.max(0, val / (max * 1.15)));
    return padding.top + chartHeight - ratio * chartHeight;
  };

  const getYSecondary = (val: number) => {
    const ratio = Math.min(1, Math.max(0, val / (maxLatency * 1.2)));
    return padding.top + chartHeight - ratio * chartHeight;
  };

  // Generate SVG paths
  // RPS Area & Line
  const rpsPoints = points.map((p, i) => `${getX(i)},${getYPrimary(p.rps, maxRps)}`);
  const rpsLinePath = `M ${rpsPoints.join(' L ')}`;
  const rpsAreaPath = `${rpsLinePath} L ${getX(points.length - 1)},${padding.top + chartHeight} L ${getX(0)},${padding.top + chartHeight} Z`;

  // VUs Area & Line
  const vuPoints = points.map((p, i) => `${getX(i)},${getYPrimary(p.concurrencyVUs, maxVUs)}`);
  const vuLinePath = `M ${vuPoints.join(' L ')}`;
  const vuAreaPath = `${vuLinePath} L ${getX(points.length - 1)},${padding.top + chartHeight} L ${getX(0)},${padding.top + chartHeight} Z`;

  // Secondary Axis: P95 Latency Line
  const latPoints = points.map((p, i) => `${getX(i)},${getYSecondary(p.p95)}`);
  const latLinePath = `M ${latPoints.join(' L ')}`;

  // Find saturation point index for vertical marker
  const kneeIndex = saturation
    ? points.findIndex((p) => p.concurrencyVUs >= saturation.kneeConcurrency)
    : -1;

  const activePoint = hoverIndex !== null ? points[hoverIndex] : points[points.length - 1];

  // Aggregated status distribution across points
  const total2xx = points.reduce((acc, p) => acc + p.status2xx, 0);
  const total4xx = points.reduce((acc, p) => acc + p.status4xx, 0);
  const total5xx = points.reduce((acc, p) => acc + p.status5xx, 0);
  const totalReqs = Math.max(1, total2xx + total4xx + total5xx);

  return (
    <div className={`p-5 rounded-2xl bg-card/60 border border-border/60 shadow-xl space-y-4 ${className}`}>
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border/40">
        <div>
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            <h3 className="font-semibold text-foreground text-sm tracking-wide">
              Dual-Axis Throughput & Concurrency Waterfall
            </h3>
            <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              60fps Vector
            </span>
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">
            Primary Axis: Throughput (RPS) vs Virtual Users (VUs) • Secondary Axis: P95 Latency (ms)
          </p>
        </div>

        {/* Legend / Toggles */}
        <div className="flex items-center gap-2 text-xs font-mono">
          <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-background/80 border border-border/40 text-cyan-400">
            <span className="w-2.5 h-2.5 rounded-sm bg-cyan-400"></span>
            <span>RPS ({activePoint.rps.toLocaleString()})</span>
          </div>

          <button
            type="button"
            onClick={() => setShowVUs(!showVUs)}
            className={`flex items-center gap-1.5 px-2 py-1 rounded border transition-colors ${
              showVUs
                ? 'bg-blue-500/15 border-blue-500/40 text-blue-300'
                : 'bg-background/40 border-border/40 text-muted-foreground opacity-60'
            }`}
          >
            <Users className="w-3 h-3" />
            <span>VUs ({activePoint.concurrencyVUs})</span>
          </button>

          <button
            type="button"
            onClick={() => setShowLatency(!showLatency)}
            className={`flex items-center gap-1.5 px-2 py-1 rounded border transition-colors ${
              showLatency
                ? 'bg-rose-500/15 border-rose-500/40 text-rose-300'
                : 'bg-background/40 border-border/40 text-muted-foreground opacity-60'
            }`}
          >
            <Clock className="w-3 h-3" />
            <span>P95 ({activePoint.p95.toFixed(1)}ms)</span>
          </button>
        </div>
      </div>

      {/* SVG Canvas */}
      <div className="relative w-full aspect-[8/3] select-none">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="w-full h-full overflow-visible"
          onMouseLeave={() => setHoverIndex(null)}
        >
          <defs>
            {/* RPS Gradient */}
            <linearGradient id="rpsAreaGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.4" />
              <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.0" />
            </linearGradient>

            {/* VUs Gradient */}
            <linearGradient id="vuAreaGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.25" />
              <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.0" />
            </linearGradient>

            {/* Grid Pattern */}
            <pattern id="chartGrid" width="40" height="30" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 30" fill="none" stroke="currentColor" strokeWidth="0.5" className="text-border/20" />
            </pattern>
          </defs>

          {/* Background grid */}
          <rect
            x={padding.left}
            y={padding.top}
            width={chartWidth}
            height={chartHeight}
            fill="url(#chartGrid)"
          />

          {/* Horizontal Reference Lines */}
          {[0, 0.25, 0.5, 0.75, 1].map((ratio) => {
            const y = padding.top + chartHeight - ratio * chartHeight;
            const rpsVal = Math.round(ratio * maxRps * 1.15);
            const latVal = Math.round(ratio * maxLatency * 1.2);
            return (
              <g key={ratio}>
                <line
                  x1={padding.left}
                  y1={y}
                  x2={padding.left + chartWidth}
                  y2={y}
                  stroke="currentColor"
                  strokeWidth="0.7"
                  strokeDasharray="3 3"
                  className="text-border/30"
                />
                {/* Primary axis label (Left - RPS) */}
                <text
                  x={padding.left - 8}
                  y={y + 3}
                  textAnchor="end"
                  fontSize="10"
                  fill="currentColor"
                  className="font-mono text-[10px] text-muted-foreground fill-muted-foreground"
                >
                  {rpsVal}
                </text>
                {/* Secondary axis label (Right - Latency ms) */}
                {showLatency && (
                  <text
                    x={padding.left + chartWidth + 8}
                    y={y + 3}
                    textAnchor="start"
                    fontSize="10"
                    fill="#f43f5e"
                    className="font-mono text-[10px]"
                  >
                    {latVal}ms
                  </text>
                )}
              </g>
            );
          })}

          {/* VUs Area & Line (Secondary Primary scale) */}
          {showVUs && (
            <g>
              <path d={vuAreaPath} fill="url(#vuAreaGradient)" />
              <path
                d={vuLinePath}
                fill="none"
                stroke="#60a5fa"
                strokeWidth="2"
                strokeDasharray="4 2"
                strokeLinecap="round"
              />
            </g>
          )}

          {/* RPS Area & Line */}
          <g>
            <path d={rpsAreaPath} fill="url(#rpsAreaGradient)" />
            <path
              d={rpsLinePath}
              fill="none"
              stroke="#06b6d4"
              strokeWidth="2.5"
              strokeLinecap="round"
            />
          </g>

          {/* P95 Latency Line (Secondary Axis) */}
          {showLatency && (
            <g>
              <path
                d={latLinePath}
                fill="none"
                stroke="#f43f5e"
                strokeWidth="2.5"
                strokeLinecap="round"
              />
            </g>
          )}

          {/* Saturation Knee Vertical Marker */}
          {kneeIndex >= 0 && (
            <g>
              <line
                x1={getX(kneeIndex)}
                y1={padding.top}
                x2={getX(kneeIndex)}
                y2={padding.top + chartHeight}
                stroke="#eab308"
                strokeWidth="2"
                strokeDasharray="4 4"
              />
              <rect
                x={getX(kneeIndex) - 45}
                y={padding.top - 20}
                width="90"
                height="18"
                rx="4"
                fill="#854d0e"
                className="opacity-90"
              />
              <text
                x={getX(kneeIndex)}
                y={padding.top - 7}
                textAnchor="middle"
                fontSize="10"
                fontWeight="bold"
                fill="#fef08a"
                className="font-mono"
              >
                ⚡ KNEE ({saturation?.kneeConcurrency} VUs)
              </text>
            </g>
          )}

          {/* Scrubbing Hover Line & Circles */}
          {hoverIndex !== null && (
            <g>
              <line
                x1={getX(hoverIndex)}
                y1={padding.top}
                x2={getX(hoverIndex)}
                y2={padding.top + chartHeight}
                stroke="#ffffff"
                strokeWidth="1.5"
                strokeDasharray="2 2"
              />
              {/* RPS marker circle */}
              <circle
                cx={getX(hoverIndex)}
                cy={getYPrimary(points[hoverIndex].rps, maxRps)}
                r="4.5"
                fill="#06b6d4"
                stroke="#ffffff"
                strokeWidth="2"
              />
              {/* VUs marker circle */}
              {showVUs && (
                <circle
                  cx={getX(hoverIndex)}
                  cy={getYPrimary(points[hoverIndex].concurrencyVUs, maxVUs)}
                  r="4"
                  fill="#3b82f6"
                  stroke="#ffffff"
                  strokeWidth="1.5"
                />
              )}
              {/* Latency marker circle */}
              {showLatency && (
                <circle
                  cx={getX(hoverIndex)}
                  cy={getYSecondary(points[hoverIndex].p95)}
                  r="4.5"
                  fill="#f43f5e"
                  stroke="#ffffff"
                  strokeWidth="2"
                />
              )}
            </g>
          )}

          {/* Interactive Transparent Hit-Boxes for Hover Scrubbing */}
          {points.map((_, i) => {
            const x = getX(i) - (chartWidth / points.length) / 2;
            const w = chartWidth / points.length;
            return (
              <rect
                key={i}
                x={x}
                y={padding.top}
                width={w}
                height={chartHeight}
                fill="transparent"
                className="cursor-crosshair"
                onMouseEnter={() => setHoverIndex(i)}
              />
            );
          })}

          {/* Time axis labels */}
          {points.map((p, i) => {
            if (i % 2 !== 0 && i !== points.length - 1) return null;
            return (
              <text
                key={p.timeSec}
                x={getX(i)}
                y={padding.top + chartHeight + 20}
                textAnchor="middle"
                fontSize="10"
                fill="currentColor"
                className="font-mono text-[10px] text-muted-foreground fill-muted-foreground"
              >
                {p.timeSec}s
              </text>
            );
          })}
        </svg>

        {/* Floating Tooltip during Scrubbing */}
        {hoverIndex !== null && (
          <div
            className="absolute pointer-events-none z-20 py-2 px-3 rounded-lg bg-popover/95 border border-border/80 shadow-2xl backdrop-blur-md text-xs font-mono"
            style={{
              left: `${(getX(hoverIndex) / width) * 100}%`,
              top: '20px',
              transform: getX(hoverIndex) > width * 0.7 ? 'translateX(-105%)' : 'translateX(10%)',
            }}
          >
            <div className="text-muted-foreground border-b border-border/40 pb-1 mb-1.5 flex items-center justify-between gap-4 font-sans font-medium text-[11px]">
              <span>T = {activePoint.timeSec}s elapsed</span>
              <span className="text-foreground font-mono">{(activePoint.bytesPerSec / 1024).toFixed(1)} KB/s</span>
            </div>
            <div className="space-y-1">
              <div className="flex items-center justify-between gap-4 text-cyan-400">
                <span>Throughput:</span>
                <span className="font-bold">{activePoint.rps.toLocaleString()} RPS</span>
              </div>
              <div className="flex items-center justify-between gap-4 text-blue-400">
                <span>Concurrency:</span>
                <span className="font-bold">{activePoint.concurrencyVUs} VUs</span>
              </div>
              <div className="flex items-center justify-between gap-4 text-rose-400">
                <span>P95 Latency:</span>
                <span className="font-bold">{activePoint.p95.toFixed(2)} ms</span>
              </div>
              <div className="flex items-center justify-between gap-4 text-emerald-400">
                <span>P50 Latency:</span>
                <span>{activePoint.p50.toFixed(2)} ms</span>
              </div>
              {activePoint.errorRate > 0 && (
                <div className="flex items-center justify-between gap-4 text-amber-400 pt-0.5 border-t border-border/30">
                  <span>Error Rate:</span>
                  <span className="font-bold">{(activePoint.errorRate * 100).toFixed(2)}%</span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Status Code Distribution Bar & Metrics */}
      <div className="pt-2 border-t border-border/40 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2 text-muted-foreground">
          <Layers className="w-3.5 h-3.5 text-blue-400" />
          <span>Status Distribution:</span>
        </div>

        {/* Visual Multi-Segment Bar */}
        <div className="flex-1 max-w-md w-full h-3 rounded-full bg-background/80 overflow-hidden flex border border-border/40">
          <div
            style={{ width: `${(total2xx / totalReqs) * 100}%` }}
            className="bg-emerald-500 h-full transition-all"
            title={`2xx Success: ${total2xx.toLocaleString()} (${((total2xx / totalReqs) * 100).toFixed(1)}%)`}
          />
          <div
            style={{ width: `${(total4xx / totalReqs) * 100}%` }}
            className="bg-amber-500 h-full transition-all"
            title={`4xx Client Errors: ${total4xx.toLocaleString()} (${((total4xx / totalReqs) * 100).toFixed(1)}%)`}
          />
          <div
            style={{ width: `${(total5xx / totalReqs) * 100}%` }}
            className="bg-rose-500 h-full transition-all"
            title={`5xx Server Errors: ${total5xx.toLocaleString()} (${((total5xx / totalReqs) * 100).toFixed(1)}%)`}
          />
        </div>

        {/* Status Counts */}
        <div className="flex items-center gap-3 font-mono text-[11px]">
          <span className="flex items-center gap-1 text-emerald-400">
            <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
            2xx: {((total2xx / totalReqs) * 100).toFixed(1)}%
          </span>
          <span className="flex items-center gap-1 text-amber-400">
            <span className="w-2 h-2 rounded-full bg-amber-500"></span>
            4xx: {((total4xx / totalReqs) * 100).toFixed(1)}%
          </span>
          <span className="flex items-center gap-1 text-rose-400">
            <span className="w-2 h-2 rounded-full bg-rose-500"></span>
            5xx: {((total5xx / totalReqs) * 100).toFixed(1)}%
          </span>
        </div>
      </div>
    </div>
  );
};
