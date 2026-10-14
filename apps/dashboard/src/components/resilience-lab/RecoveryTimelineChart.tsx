import React from 'react';
import { Activity } from 'lucide-react';
import { RecoveryTimelinePoint, ChaosExecutionStats } from '../../api/resilience.js';

interface RecoveryTimelineChartProps {
  timeline: RecoveryTimelinePoint[];
  stats: ChaosExecutionStats;
}

export const RecoveryTimelineChart: React.FC<RecoveryTimelineChartProps> = ({
  timeline,
  stats,
}) => {
  // Chart dimensions
  const width = 800;
  const height = 240;
  const padding = { top: 20, right: 30, bottom: 35, left: 50 };

  const innerWidth = width - padding.left - padding.right;
  const innerHeight = height - padding.top - padding.bottom;

  const maxLatency = Math.max(...timeline.map((p) => p.latencyP95Ms), 500);

  // Scalers
  const getX = (index: number) => padding.left + (index / (timeline.length - 1)) * innerWidth;
  const getYLatency = (latency: number) =>
    padding.top + innerHeight - (latency / maxLatency) * innerHeight;
  const getYError = (errorRate: number) =>
    padding.top + innerHeight - (errorRate / 100) * innerHeight;

  // SVG Paths
  const latencyPoints = timeline.map((p, i) => `${getX(i)},${getYLatency(p.latencyP95Ms)}`).join(' ');
  const errorPoints = timeline.map((p, i) => `${getX(i)},${getYError(p.errorRate)}`).join(' ');

  const latencyArea = `${getX(0)},${padding.top + innerHeight} ${latencyPoints} ${getX(
    timeline.length - 1,
  )},${padding.top + innerHeight}`;
  const errorArea = `${getX(0)},${padding.top + innerHeight} ${errorPoints} ${getX(
    timeline.length - 1,
  )},${padding.top + innerHeight}`;

  return (
    <div className="p-6 rounded-xl bg-card border border-border/80 shadow-lg space-y-6">
      {/* Header and Telemetry KPIs */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-1.5 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
              <Activity className="w-4 h-4" />
            </span>
            <h3 className="text-base font-bold text-foreground">
              Resilience & Recovery Timeline (RTO)
            </h3>
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">
            Real-time degradation profile during fault injection and automatic application recovery curve.
          </p>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
            <span className="text-muted-foreground">P95 Latency (ms)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-red-400" />
            <span className="text-muted-foreground">Error Rate (%)</span>
          </div>
        </div>
      </div>

      {/* SVG Chart */}
      <div className="relative p-4 rounded-xl bg-slate-950/80 border border-border/70 overflow-hidden">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="w-full h-auto overflow-visible font-mono text-[10px]"
        >
          <defs>
            <linearGradient id="latencyGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.3" />
              <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.0" />
            </linearGradient>
            <linearGradient id="errorGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#ef4444" stopOpacity="0.35" />
              <stop offset="100%" stopColor="#ef4444" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          {[0, 0.25, 0.5, 0.75, 1].map((pct, idx) => {
            const y = padding.top + pct * innerHeight;
            return (
              <g key={idx}>
                <line
                  x1={padding.left}
                  y1={y}
                  x2={width - padding.right}
                  y2={y}
                  stroke="#1e293b"
                  strokeDasharray="4 4"
                />
                <text
                  x={padding.left - 8}
                  y={y + 3}
                  textAnchor="end"
                  fill="#64748b"
                >
                  {Math.round(maxLatency * (1 - pct))}ms
                </text>
                <text
                  x={width - padding.right + 8}
                  y={y + 3}
                  textAnchor="start"
                  fill="#64748b"
                >
                  {Math.round(100 * (1 - pct))}%
                </text>
              </g>
            );
          })}

          {/* Phase Boundary Shading for Injection */}
          <rect
            x={getX(3)}
            y={padding.top}
            width={getX(7) - getX(3)}
            height={innerHeight}
            fill="#ef4444"
            fillOpacity="0.06"
          />
          <text
            x={(getX(3) + getX(7)) / 2}
            y={padding.top + 14}
            textAnchor="middle"
            fill="#ef4444"
            fontWeight="bold"
            letterSpacing="1px"
          >
            FAULT INJECTION WINDOW
          </text>

          {/* Areas */}
          <polygon points={latencyArea} fill="url(#latencyGrad)" />
          <polygon points={errorArea} fill="url(#errorGrad)" />

          {/* Curves */}
          <polyline
            fill="none"
            stroke="#06b6d4"
            strokeWidth="2.5"
            points={latencyPoints}
          />
          <polyline
            fill="none"
            stroke="#ef4444"
            strokeWidth="2.5"
            points={errorPoints}
          />

          {/* Points */}
          {timeline.map((p, i) => (
            <g key={i}>
              <circle
                cx={getX(i)}
                cy={getYLatency(p.latencyP95Ms)}
                r="3.5"
                fill="#06b6d4"
                stroke="#020617"
                strokeWidth="1.5"
              />
              <circle
                cx={getX(i)}
                cy={getYError(p.errorRate)}
                r="3.5"
                fill="#ef4444"
                stroke="#020617"
                strokeWidth="1.5"
              />
              {/* X axis labels */}
              <text
                x={getX(i)}
                y={height - 10}
                textAnchor="middle"
                fill="#94a3b8"
              >
                {p.timeLabel}
              </text>
            </g>
          ))}
        </svg>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3.5 rounded-xl bg-card border border-border/70 shadow-sm">
          <div className="text-[10px] font-mono uppercase text-muted-foreground">
            Recovery Time (RTO)
          </div>
          <div className="text-xl font-bold font-mono text-emerald-400 mt-1">
            {stats.rtoSeconds} s
          </div>
          <div className="text-[10px] text-muted-foreground mt-0.5">Time to healthy baseline</div>
        </div>

        <div className="p-3.5 rounded-xl bg-card border border-border/70 shadow-sm">
          <div className="text-[10px] font-mono uppercase text-muted-foreground">
            Circuit Breaker
          </div>
          <div
            className={`text-xl font-bold font-mono mt-1 ${
              stats.circuitBreakerState === 'OPEN'
                ? 'text-red-400'
                : stats.circuitBreakerState === 'HALF_OPEN'
                ? 'text-amber-400'
                : 'text-emerald-400'
            }`}
          >
            {stats.circuitBreakerState}
          </div>
          <div className="text-[10px] text-muted-foreground mt-0.5">Tripping state</div>
        </div>

        <div className="p-3.5 rounded-xl bg-card border border-border/70 shadow-sm">
          <div className="text-[10px] font-mono uppercase text-muted-foreground">
            Faults Injected
          </div>
          <div className="text-xl font-bold font-mono text-amber-400 mt-1">
            {stats.faultsInjected}
          </div>
          <div className="text-[10px] text-muted-foreground mt-0.5">of {stats.totalRequests} requests</div>
        </div>

        <div className="p-3.5 rounded-xl bg-card border border-border/70 shadow-sm">
          <div className="text-[10px] font-mono uppercase text-muted-foreground">
            Resilience Score
          </div>
          <div className="text-xl font-bold font-mono text-cyan-400 mt-1">
            {stats.resilienceScore}%
          </div>
          <div className="text-[10px] text-muted-foreground mt-0.5">Graceful degradation rate</div>
        </div>
      </div>
    </div>
  );
};
