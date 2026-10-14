import React from 'react';
import {
  Activity,
  AlertOctagon,
  ShieldCheck,
  Shield,
  Lock,
} from 'lucide-react';
import { TargetLimits } from '../../api/targets.js';

interface SafetyBudgetGaugesProps {
  limits: TargetLimits;
  allowPrivateIps?: boolean;
  className?: string;
}

export const SafetyBudgetGauges: React.FC<SafetyBudgetGaugesProps> = ({
  limits,
  allowPrivateIps = false,
  className = '',
}) => {
  // SVG Circular Gauge Helper
  const renderRadialGauge = (
    value: number,
    maxValue: number,
    label: string,
    unit: string,
    colorClass: string,
    strokeColor: string,
  ) => {
    const percentage = Math.min(Math.round((value / maxValue) * 100), 100);
    const radius = 38;
    const circumference = 2 * Math.PI * radius;
    const strokeDashoffset = circumference - (percentage / 100) * circumference;

    return (
      <div className="flex flex-col items-center p-4 rounded-xl bg-accent/30 border border-border/60 relative">
        <div className="relative w-28 h-28 flex items-center justify-center">
          <svg className="w-full h-full -rotate-90" viewBox="0 0 96 96">
            <circle
              cx="48"
              cy="48"
              r={radius}
              className="text-muted/20 stroke-current"
              strokeWidth="7"
              fill="transparent"
            />
            <circle
              cx="48"
              cy="48"
              r={radius}
              style={{
                strokeDasharray: circumference,
                strokeDashoffset,
                transition: 'stroke-dashoffset 0.6s ease',
              }}
              stroke={strokeColor}
              strokeWidth="7"
              strokeLinecap="round"
              fill="transparent"
            />
          </svg>
          <div className="absolute flex flex-col items-center justify-center text-center">
            <span className={`text-base font-bold font-mono ${colorClass}`}>
              {value}
            </span>
            <span className="text-[10px] text-muted-foreground uppercase font-mono">
              {unit}
            </span>
          </div>
        </div>
        <span className="text-xs font-medium text-foreground mt-2 text-center">
          {label}
        </span>
        <span className="text-[10px] text-muted-foreground font-mono mt-0.5">
          Limit: {maxValue} {unit}
        </span>
      </div>
    );
  };

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Three Safety Metric Dials */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {/* Gauge 1: Max RPS */}
        {renderRadialGauge(
          limits.maxRps,
          500,
          'Rate Limit Ceiling',
          'RPS',
          limits.maxRps > 300
            ? 'text-amber-400'
            : limits.maxRps > 150
            ? 'text-blue-400'
            : 'text-emerald-400',
          limits.maxRps > 300 ? '#f59e0b' : limits.maxRps > 150 ? '#3b82f6' : '#10b981',
        )}

        {/* Gauge 2: Max Concurrency */}
        {renderRadialGauge(
          limits.maxConcurrency,
          100,
          'Concurrency Pool',
          'VUs',
          limits.maxConcurrency > 50 ? 'text-indigo-400' : 'text-cyan-400',
          limits.maxConcurrency > 50 ? '#818cf8' : '#06b6d4',
        )}

        {/* Gauge 3: Adaptive Circuit Breaker 5xx Threshold */}
        <div className="flex flex-col items-center p-4 rounded-xl bg-accent/30 border border-border/60 relative">
          <div className="relative w-28 h-28 flex items-center justify-center">
            <svg className="w-full h-full -rotate-90" viewBox="0 0 96 96">
              <circle
                cx="48"
                cy="48"
                r="38"
                className="text-muted/20 stroke-current"
                strokeWidth="7"
                fill="transparent"
              />
              <circle
                cx="48"
                cy="48"
                r="38"
                style={{
                  strokeDasharray: 2 * Math.PI * 38,
                  strokeDashoffset: (2 * Math.PI * 38) * (1 - 0.25),
                }}
                stroke="#ef4444"
                strokeWidth="7"
                strokeLinecap="round"
                fill="transparent"
              />
            </svg>
            <div className="absolute flex flex-col items-center justify-center text-center">
              <span className="text-base font-bold font-mono text-rose-400">
                25%
              </span>
              <span className="text-[10px] text-muted-foreground uppercase font-mono">
                Trip Threshold
              </span>
            </div>
          </div>
          <span className="text-xs font-medium text-foreground mt-2 text-center flex items-center gap-1">
            <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />
            <span>5xx Circuit Breaker</span>
          </span>
          <span className="text-[10px] text-emerald-400 font-mono mt-0.5 flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <span>Status: CLOSED (Safe)</span>
          </span>
        </div>
      </div>

      {/* Circuit Breaker & Safety Details Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
        {/* Adaptive Circuit Breaker Spec */}
        <div className="p-4 rounded-xl bg-card border border-border/80 space-y-3">
          <div className="flex items-center justify-between border-b border-border/60 pb-2">
            <h4 className="font-semibold text-foreground flex items-center gap-2">
              <Activity className="w-4 h-4 text-rose-400" />
              <span>Adaptive Circuit Breaker Parameters</span>
            </h4>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950/40 text-rose-400 border border-rose-800/40">
              Phase 02 Engine
            </span>
          </div>

          <div className="space-y-2 text-muted-foreground">
            <div className="flex items-center justify-between">
              <span>Sliding Error Window:</span>
              <span className="font-mono text-foreground font-semibold">10 Requests</span>
            </div>
            <div className="flex items-center justify-between">
              <span>Auto-Trip Condition:</span>
              <span className="font-mono text-rose-400 font-semibold">&gt;= 25% 5xx Server Errors</span>
            </div>
            <div className="flex items-center justify-between">
              <span>Backoff Cooldown:</span>
              <span className="font-mono text-foreground font-semibold">30 Seconds</span>
            </div>
            <div className="flex items-center justify-between">
              <span>Probe Canary State:</span>
              <span className="font-mono text-blue-400 font-semibold">HALF_OPEN (Single Request)</span>
            </div>
            <div className="flex items-center justify-between">
              <span>Max Duration Ceiling:</span>
              <span className="font-mono text-foreground font-semibold">{limits.maxDuration || '10m'}</span>
            </div>
          </div>
        </div>

        {/* DNS Pinning & Network Boundary Badges */}
        <div className="p-4 rounded-xl bg-card border border-border/80 space-y-3">
          <div className="flex items-center justify-between border-b border-border/60 pb-2">
            <h4 className="font-semibold text-foreground flex items-center gap-2">
              <Shield className="w-4 h-4 text-primary" />
              <span>Network Boundary Defenses</span>
            </h4>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/40 text-emerald-400 border border-emerald-800/40">
              Pre-Socket Protected
            </span>
          </div>

          <div className="space-y-2.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-blue-400" />
                <span>Pre-Socket DNS Pinning:</span>
              </span>
              <span className="font-mono text-[11px] text-emerald-400 font-semibold">
                ACTIVE (Anti-TOCTOU)
              </span>
            </div>

            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                <span>Cloud Metadata Protection:</span>
              </span>
              <span className="font-mono text-[11px] text-emerald-400 font-semibold">
                BLOCKED (169.254.169.254)
              </span>
            </div>

            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                <span>Loopback Interfaces:</span>
              </span>
              <span className="font-mono text-[11px] text-emerald-400 font-semibold">
                BLOCKED (127.0.0.0/8)
              </span>
            </div>

            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                <span>RFC-1918 Private Subnets:</span>
              </span>
              <span
                className={`font-mono text-[11px] font-semibold ${
                  allowPrivateIps ? 'text-amber-400' : 'text-emerald-400'
                }`}
              >
                {allowPrivateIps ? 'AUTHORIZED (Override)' : 'BLOCKED (Default)'}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
