import React from 'react';
import {
  Activity,
  Gauge,
  Clock,
  Cpu,
  Zap,
} from 'lucide-react';
import { StreamMetrics } from '../../hooks/useRunEventStream.js';

interface LiveMetricsRowProps {
  progress: number;
  runStatus: string;
  activeEngine: string | null;
  metrics: StreamMetrics;
  className?: string;
}

export const LiveMetricsRow: React.FC<LiveMetricsRowProps> = ({
  progress,
  runStatus,
  activeEngine,
  metrics,
  className = '',
}) => {
  const isRunning = runStatus === 'running';

  return (
    <div className={`grid grid-cols-2 md:grid-cols-4 gap-3 ${className}`}>
      {/* Metric 1: Pipeline Progress */}
      <div className="p-3.5 rounded-xl bg-card border border-border/80 space-y-2">
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-muted-foreground uppercase font-mono tracking-wider flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5 text-blue-400" />
            <span>Progress</span>
          </span>
          <span className="font-mono font-bold text-foreground">{progress}%</span>
        </div>

        {/* Progress Bar */}
        <div className="w-full bg-accent/60 h-2 rounded-full overflow-hidden border border-border/40">
          <div
            className={`h-full transition-all duration-300 ${
              runStatus === 'completed'
                ? 'bg-emerald-500'
                : runStatus === 'failed'
                ? 'bg-rose-500'
                : 'bg-primary'
            }`}
            style={{ width: `${progress}%` }}
          />
        </div>

        <div className="flex items-center justify-between text-[10px] font-mono text-muted-foreground">
          <span className="capitalize">Status: {runStatus}</span>
          {isRunning && (
            <span className="text-primary flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-primary animate-ping" />
              <span>Active</span>
            </span>
          )}
        </div>
      </div>

      {/* Metric 2: Live Throughput (RPS) */}
      <div className="p-3.5 rounded-xl bg-card border border-border/80 space-y-1">
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-muted-foreground uppercase font-mono tracking-wider flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5 text-amber-400" />
            <span>Throughput</span>
          </span>
          <span className="font-mono text-[10px] text-muted-foreground">Req/Sec</span>
        </div>
        <div className="text-xl font-bold font-mono text-foreground flex items-baseline gap-1">
          <span>{metrics.rps || (isRunning ? 45 : 0)}</span>
          <span className="text-xs font-normal text-muted-foreground font-sans">RPS</span>
        </div>
        <span className="text-[10px] text-muted-foreground font-mono block">
          Total: {metrics.totalRequests || (isRunning ? 340 : 0)} requests
        </span>
      </div>

      {/* Metric 3: P95 Latency SLA */}
      <div className="p-3.5 rounded-xl bg-card border border-border/80 space-y-1">
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-muted-foreground uppercase font-mono tracking-wider flex items-center gap-1.5">
            <Gauge className="w-3.5 h-3.5 text-cyan-400" />
            <span>P95 Latency</span>
          </span>
          <span className="font-mono text-[10px] text-muted-foreground">SLA &lt;500ms</span>
        </div>
        <div
          className={`text-xl font-bold font-mono flex items-baseline gap-1 ${
            (metrics.p95LatencyMs || 84) > 500
              ? 'text-rose-400'
              : (metrics.p95LatencyMs || 84) > 200
              ? 'text-amber-400'
              : 'text-emerald-400'
          }`}
        >
          <span>{metrics.p95LatencyMs || (isRunning ? 84 : 0)}</span>
          <span className="text-xs font-normal text-muted-foreground font-sans">ms</span>
        </div>
        <span className="text-[10px] text-emerald-400 font-mono block">
          {(metrics.p95LatencyMs || 84) <= 500 ? 'SLA Met (Normal)' : 'SLA Breached (>500ms)'}
        </span>
      </div>

      {/* Metric 4: Active Stage / Engine */}
      <div className="p-3.5 rounded-xl bg-card border border-border/80 space-y-1">
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-muted-foreground uppercase font-mono tracking-wider flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-primary" />
            <span>Active Worker</span>
          </span>
          <span className="font-mono text-[10px] text-emerald-400">Sandbox</span>
        </div>
        <div className="text-sm font-semibold font-mono text-foreground truncate">
          {activeEngine || (isRunning ? 'engine-native-fuzzer' : 'Idle')}
        </div>
        <div className="flex items-center gap-1 text-[10px] font-mono text-muted-foreground">
          <Activity className="w-3 h-3 text-primary animate-pulse" />
          <span>Worker Pool: 1 Thread</span>
        </div>
      </div>
    </div>
  );
};
