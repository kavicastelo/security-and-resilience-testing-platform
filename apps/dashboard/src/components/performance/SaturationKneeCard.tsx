import React from 'react';
import { Zap, AlertTriangle, CheckCircle, TrendingUp, Cpu, Server, Database } from 'lucide-react';
import { SaturationKneeAnalysis } from '../../api/performance.js';

export interface SaturationKneeCardProps {
  saturation: SaturationKneeAnalysis;
  peakRps: number;
  className?: string;
}

export const SaturationKneeCard: React.FC<SaturationKneeCardProps> = ({
  saturation,
  peakRps,
  className = '',
}) => {
  const isSevere = saturation.status === 'severe_overload';
  const isSaturated = saturation.status === 'saturated';

  return (
    <div className={`p-5 rounded-2xl bg-card/60 border border-border/60 shadow-xl space-y-4 ${className}`}>
      {/* Header with Saturation Status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border/40">
        <div className="flex items-center gap-2">
          <div
            className={`p-2 rounded-xl border ${
              isSevere
                ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                : isSaturated
                ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
            }`}
          >
            <Zap className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-semibold text-foreground text-sm tracking-wide flex items-center gap-2">
              System Saturation & Capacity Knee Detector
            </h3>
            <p className="text-xs text-muted-foreground">
              Inflection analysis identifying the threshold where concurrency adds queue delay without throughput gains.
            </p>
          </div>
        </div>

        {/* State Badge */}
        <div
          className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-medium border ${
            isSevere
              ? 'bg-rose-500/15 text-rose-400 border-rose-500/30'
              : isSaturated
              ? 'bg-amber-500/15 text-amber-400 border-amber-500/30'
              : 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
          }`}
        >
          {isSevere ? (
            <AlertTriangle className="w-3.5 h-3.5" />
          ) : isSaturated ? (
            <TrendingUp className="w-3.5 h-3.5" />
          ) : (
            <CheckCircle className="w-3.5 h-3.5" />
          )}
          <span className="uppercase">
            {isSevere ? 'Severe Overload Knee' : isSaturated ? 'Inflection Knee Hit' : 'Optimal Capacity'}
          </span>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
        {/* Knee Concurrency */}
        <div className="p-3 rounded-xl bg-background/60 border border-border/40 space-y-1">
          <div className="flex items-center justify-between text-muted-foreground text-[11px]">
            <span>Knee Concurrency</span>
            <Server className="w-3.5 h-3.5 text-blue-400" />
          </div>
          <div className="text-lg font-bold font-mono text-blue-400">
            {saturation.kneeConcurrency} <span className="text-xs font-normal text-muted-foreground">VUs</span>
          </div>
          <p className="text-[10px] text-muted-foreground">Maximum safe concurrency limit</p>
        </div>

        {/* Max Sustained RPS */}
        <div className="p-3 rounded-xl bg-background/60 border border-border/40 space-y-1">
          <div className="flex items-center justify-between text-muted-foreground text-[11px]">
            <span>Peak Sustained RPS</span>
            <TrendingUp className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-lg font-bold font-mono text-cyan-400">
            {saturation.maxSustainedRps.toLocaleString()}{' '}
            <span className="text-xs font-normal text-muted-foreground">req/s</span>
          </div>
          <p className="text-[10px] text-muted-foreground">
            {peakRps > saturation.maxSustainedRps
              ? `Spike peak was ${peakRps.toLocaleString()} RPS`
              : 'Linear throughput plateau'}
          </p>
        </div>

        {/* Knee Latency */}
        <div className="p-3 rounded-xl bg-background/60 border border-border/40 space-y-1">
          <div className="flex items-center justify-between text-muted-foreground text-[11px]">
            <span>Latency at Knee</span>
            <Zap className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-lg font-bold font-mono text-amber-400">
            {saturation.kneeLatencyMs.toFixed(2)}{' '}
            <span className="text-xs font-normal text-muted-foreground">ms</span>
          </div>
          <p className="text-[10px] text-muted-foreground">P95 before queuing inflation</p>
        </div>

        {/* Post-Knee Latency Degradation */}
        <div className="p-3 rounded-xl bg-background/60 border border-border/40 space-y-1">
          <div className="flex items-center justify-between text-muted-foreground text-[11px]">
            <span>Post-Knee Latency Rise</span>
            <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div
            className={`text-lg font-bold font-mono ${
              saturation.postKneeLatencyDegradationPct > 50
                ? 'text-rose-400'
                : saturation.postKneeLatencyDegradationPct > 15
                ? 'text-amber-400'
                : 'text-emerald-400'
            }`}
          >
            +{saturation.postKneeLatencyDegradationPct}%
          </div>
          <p className="text-[10px] text-muted-foreground">Tail latency growth beyond knee</p>
        </div>
      </div>

      {/* Diagnosis & Actionable Recommendation Banner */}
      <div
        className={`p-3.5 rounded-xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs ${
          isSevere
            ? 'bg-rose-500/10 border-rose-500/30'
            : isSaturated
            ? 'bg-amber-500/10 border-amber-500/30'
            : 'bg-blue-500/10 border-blue-500/30'
        }`}
      >
        <div className="space-y-1 flex-1">
          <div className="flex items-center gap-2 font-semibold">
            {isSevere ? (
              <Database className="w-4 h-4 text-rose-400" />
            ) : isSaturated ? (
              <Cpu className="w-4 h-4 text-amber-400" />
            ) : (
              <CheckCircle className="w-4 h-4 text-emerald-400" />
            )}
            <span
              className={
                isSevere ? 'text-rose-300' : isSaturated ? 'text-amber-300' : 'text-blue-300'
              }
            >
              Bottleneck Diagnosis: {saturation.bottleneckDiagnosis}
            </span>
          </div>
          <p className="text-muted-foreground text-[11px] leading-relaxed">
            <strong className="text-foreground">Recommendation:</strong> {saturation.recommendation}
          </p>
        </div>

        <div className="flex items-center gap-2 self-end sm:self-center font-mono text-[11px] bg-background/80 px-3 py-1.5 rounded-lg border border-border/40 shrink-0">
          <span className="text-muted-foreground">Safe Target:</span>
          <span className="text-emerald-400 font-bold">≤ {saturation.kneeConcurrency} VUs</span>
        </div>
      </div>
    </div>
  );
};
