import React, { useState } from 'react';
import {
  Server,
  Cpu,
  HardDrive,
  ShieldCheck,
  Wifi,
  Play,
  RotateCw,
  PowerOff,
  Tag,
  Clock,
  CheckCircle,
} from 'lucide-react';
import { AgentFleetNode } from '../../api/agents.js';

export interface AgentNodeCardProps {
  node: AgentFleetNode;
  onViewLeases: (node: AgentFleetNode) => void;
  onDrain: (node: AgentFleetNode) => void;
  onRevoke: (node: AgentFleetNode) => void;
  className?: string;
}

export const AgentNodeCard: React.FC<AgentNodeCardProps> = ({
  node,
  onViewLeases,
  onDrain,
  onRevoke,
  className = '',
}) => {
  const [drainingSuccess, setDrainingSuccess] = useState(false);

  const isOnline = node.status === 'online';
  const isBusy = node.status === 'busy';
  const isDraining = node.status === 'draining';
  const isOffline = node.status === 'offline';

  const handleDrainClick = () => {
    onDrain(node);
    setDrainingSuccess(true);
    setTimeout(() => setDrainingSuccess(false), 3000);
  };

  const getStatusBadge = () => {
    if (isBusy) {
      return (
        <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase bg-blue-500/15 text-blue-400 border border-blue-500/30">
          <span className="w-2 h-2 rounded-full bg-blue-400 animate-ping" />
          Busy (Running Job)
        </span>
      );
    }
    if (isOnline) {
      return (
        <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          Online & Ready
        </span>
      );
    }
    if (isDraining) {
      return (
        <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase bg-amber-500/15 text-amber-400 border border-amber-500/30">
          <RotateCw className="w-3 h-3 text-amber-400 animate-spin" />
          Draining Leases
        </span>
      );
    }
    return (
      <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase bg-muted/60 text-muted-foreground border border-border/40">
        <PowerOff className="w-3 h-3" />
        Offline
      </span>
    );
  };

  const cpuPercent = node.currentCpuUsagePercent || 0;
  const memoryUsedMb = node.currentMemoryUsageMb || 0;
  const memoryTotalMb = node.totalMemoryMb || 8192;
  const memoryPercent = Math.min(100, Math.round((memoryUsedMb / memoryTotalMb) * 100));

  return (
    <div
      className={`rounded-2xl border transition-all p-5 space-y-4 ${
        isBusy
          ? 'bg-card/90 border-blue-500/40 shadow-xl'
          : isOnline
          ? 'bg-card/70 border-border/60 hover:border-border/90 shadow-lg'
          : isDraining
          ? 'bg-card/60 border-amber-500/30 shadow-md'
          : 'bg-card/30 border-border/30 opacity-70'
      } ${className}`}
    >
      {/* Header: Node Name, IP, Region, Status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-border/40">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Server className={`w-4 h-4 ${isBusy ? 'text-blue-400' : isOnline ? 'text-emerald-400' : 'text-muted-foreground'}`} />
            <h3 className="font-mono font-bold text-foreground text-sm tracking-wide">
              {node.name}
            </h3>
            <span className="text-[10px] font-mono text-muted-foreground px-1.5 py-0.2 rounded bg-background/80 border border-border/40">
              {node.ipAddress}
            </span>
          </div>

          <div className="flex items-center gap-2 text-xs text-muted-foreground font-mono">
            <span>{node.region}</span>
            <span>•</span>
            <span className="text-foreground font-sans font-medium">{node.environment}</span>
          </div>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-center">
          {getStatusBadge()}
        </div>
      </div>

      {/* System Hardware & Architecture Specs */}
      <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-muted-foreground">
        <span className="px-2 py-0.5 rounded bg-background/80 border border-border/40">
          {node.os}
        </span>
        <span className="px-2 py-0.5 rounded bg-background/80 border border-border/40">
          {node.arch}
        </span>
        <span className="px-2 py-0.5 rounded bg-background/80 border border-border/40">
          {node.nodeVersion}
        </span>
        <span className="px-2 py-0.5 rounded bg-background/80 border border-border/40">
          {node.cpuCount} Cores • {Math.round(node.totalMemoryMb / 1024)}GB RAM
        </span>
      </div>

      {/* Real-time Telemetry Gauges (CPU, Memory, Heartbeat) */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {/* CPU Utilization */}
        <div className="p-3 rounded-xl bg-background/80 border border-border/40 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-muted-foreground font-mono">
            <span className="flex items-center gap-1 font-sans">
              <Cpu className="w-3.5 h-3.5 text-blue-400" />
              CPU Load
            </span>
            <span
              className={`font-bold ${
                cpuPercent > 80 ? 'text-rose-400' : cpuPercent > 50 ? 'text-amber-400' : 'text-foreground'
              }`}
            >
              {cpuPercent.toFixed(1)}%
            </span>
          </div>
          <div className="w-full h-1.5 rounded-full bg-muted/60 overflow-hidden">
            <div
              style={{ width: `${cpuPercent}%` }}
              className={`h-full rounded-full transition-all ${
                cpuPercent > 80 ? 'bg-rose-500' : cpuPercent > 50 ? 'bg-amber-500' : 'bg-blue-500'
              }`}
            />
          </div>
        </div>

        {/* Memory Utilization */}
        <div className="p-3 rounded-xl bg-background/80 border border-border/40 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-muted-foreground font-mono">
            <span className="flex items-center gap-1 font-sans">
              <HardDrive className="w-3.5 h-3.5 text-purple-400" />
              Memory
            </span>
            <span className="font-bold text-foreground">
              {(memoryUsedMb / 1024).toFixed(1)}GB
            </span>
          </div>
          <div className="w-full h-1.5 rounded-full bg-muted/60 overflow-hidden">
            <div
              style={{ width: `${memoryPercent}%` }}
              className="h-full rounded-full bg-purple-500 transition-all"
            />
          </div>
        </div>

        {/* Live Heartbeat Ping Delta */}
        <div className="p-3 rounded-xl bg-background/80 border border-border/40 space-y-1">
          <div className="flex items-center justify-between text-xs text-muted-foreground font-mono">
            <span className="flex items-center gap-1 font-sans">
              <Wifi className="w-3.5 h-3.5 text-emerald-400" />
              Heartbeat
            </span>
            <span
              className={`font-bold ${
                node.secondsSinceHeartbeat > 30 ? 'text-rose-400' : 'text-emerald-400'
              }`}
            >
              {node.secondsSinceHeartbeat < 60
                ? `${node.secondsSinceHeartbeat}s ago`
                : `${Math.round(node.secondsSinceHeartbeat / 60)}m ago`}
            </span>
          </div>
          <div className="text-[10px] text-muted-foreground font-mono truncate">
            Completed: {node.stats.totalJobsCompleted} jobs ({node.stats.uptimeHours}h uptime)
          </div>
        </div>
      </div>

      {/* Active Job Preview (If Busy) */}
      {isBusy && node.activeJob && (
        <div className="p-3.5 rounded-xl bg-blue-500/10 border border-blue-500/30 space-y-2 text-xs">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5 text-blue-300 font-semibold font-mono">
              <Play className="w-3.5 h-3.5 text-blue-400 animate-pulse" />
              <span>Active Job: {node.activeJob.jobId}</span>
            </div>
            <span className="font-mono text-blue-300 font-bold">
              {node.activeJob.progressPercent}%
            </span>
          </div>

          <div className="w-full h-1.5 rounded-full bg-background/80 overflow-hidden">
            <div
              style={{ width: `${node.activeJob.progressPercent}%` }}
              className="h-full rounded-full bg-blue-400 transition-all"
            />
          </div>

          <div className="flex items-center justify-between text-[11px] text-muted-foreground font-mono">
            <span className="truncate max-w-xs">{node.activeJob.targetName}</span>
            <span>{node.activeJob.currentStage}</span>
          </div>
        </div>
      )}

      {/* mTLS Attestation & Capability Tags */}
      <div className="pt-2 border-t border-border/40 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
        <div className="space-y-1.5">
          {/* Certificate / Keypair chip */}
          <div className="flex items-center gap-2 font-mono text-[11px]">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
            <span className="text-muted-foreground">mTLS Attestation:</span>
            <span className="text-foreground font-semibold">
              {node.publicKeyFingerprint || 'Ed25519 Verified'}
            </span>
            {node.certificate && (
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                Valid: {node.certificate.daysRemaining}d ({node.certificate.tlsVersion})
              </span>
            )}
          </div>

          {/* Capabilities */}
          <div className="flex flex-wrap items-center gap-1 text-[10px] font-mono">
            <Tag className="w-3 h-3 text-muted-foreground" />
            {node.capabilities.map((cap) => (
              <span
                key={cap}
                className="px-1.5 py-0.2 rounded bg-muted/60 text-muted-foreground border border-border/40"
              >
                {cap}
              </span>
            ))}
            {node.tags.map((tag) => (
              <span
                key={tag}
                className="px-1.5 py-0.2 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20"
              >
                #{tag}
              </span>
            ))}
          </div>
        </div>

        {/* Quick Action Buttons */}
        <div className="flex items-center gap-2 self-end sm:self-center shrink-0">
          <button
            type="button"
            onClick={() => onViewLeases(node)}
            className="flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-mono bg-background/80 hover:bg-background text-foreground border border-border/60 transition-colors"
          >
            <Clock className="w-3 h-3 text-muted-foreground" />
            <span>Job Leases</span>
          </button>

          {!isOffline && !isDraining && (
            <button
              type="button"
              onClick={handleDrainClick}
              disabled={drainingSuccess}
              className="flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-mono bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 transition-colors"
            >
              {drainingSuccess ? (
                <>
                  <CheckCircle className="w-3 h-3 text-emerald-400" />
                  <span className="text-emerald-400">Draining...</span>
                </>
              ) : (
                <>
                  <RotateCw className="w-3 h-3 text-amber-400" />
                  <span>Drain</span>
                </>
              )}
            </button>
          )}

          <button
            type="button"
            onClick={() => onRevoke(node)}
            className="flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-mono bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30 transition-colors"
          >
            <span>Revoke</span>
          </button>
        </div>
      </div>
    </div>
  );
};
