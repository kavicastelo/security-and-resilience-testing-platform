import React from 'react';
import {
  Zap,
  ShieldAlert,
  ShieldCheck,
  Play,
  Square,
  Gauge,
  WifiOff,
  Flame,
  Clock,
} from 'lucide-react';
import {
  ChaosInjectionConfig,
  PRESET_CHAOS_PROFILES,
} from '../../api/resilience.js';

interface ChaosControlPanelProps {
  config: ChaosInjectionConfig;
  onChangeConfig: (newConfig: ChaosInjectionConfig) => void;
  isRunning: boolean;
  onStartInjection: () => void;
  onStopInjection: () => void;
  isProductionTarget?: boolean;
}

export const ChaosControlPanel: React.FC<ChaosControlPanelProps> = ({
  config,
  onChangeConfig,
  isRunning,
  onStartInjection,
  onStopInjection,
  isProductionTarget = false,
}) => {
  const handlePresetSelect = (presetKey: string) => {
    const preset = PRESET_CHAOS_PROFILES[presetKey];
    if (preset) {
      onChangeConfig({
        ...preset,
      });
    }
  };

  const getLatencyColor = (ms: number) => {
    if (ms < 300) return 'text-cyan-400';
    if (ms < 1500) return 'text-amber-400';
    return 'text-red-400';
  };

  return (
    <div className="p-6 rounded-xl bg-card border border-border/80 shadow-lg space-y-6">
      {/* Header & Status Indicator */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border/60">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400">
            <Zap className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-foreground">
                Chaos MITM Proxy & Fault Injector
              </h3>
              <span
                className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase flex items-center gap-1 ${
                  isRunning
                    ? 'bg-red-500/20 text-red-300 border-red-500/40 animate-pulse'
                    : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                }`}
              >
                <span
                  className={`w-1.5 h-1.5 rounded-full ${
                    isRunning ? 'bg-red-400 animate-ping' : 'bg-emerald-400'
                  }`}
                />
                {isRunning ? 'INJECTING FAULTS' : 'PROXY IDLE (PASS-THROUGH)'}
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">
              Tune network latency, packet drops, synthetic 5xx errors, and circuit breaker tripping in real-time.
            </p>
          </div>
        </div>

        {/* Start / Stop Trigger */}
        <div className="flex items-center gap-2">
          {isRunning ? (
            <button
              type="button"
              onClick={onStopInjection}
              className="flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg bg-red-600 hover:bg-red-500 text-white transition-colors shadow-sm shadow-red-500/20"
            >
              <Square className="w-4 h-4 fill-white" />
              <span>Halt Fault Injection</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={onStartInjection}
              className="flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg bg-amber-600 hover:bg-amber-500 text-white transition-colors shadow-sm shadow-amber-500/20"
            >
              <Play className="w-4 h-4 fill-white" />
              <span>Start Chaos Injection</span>
            </button>
          )}
        </div>
      </div>

      {/* Preset Profiles */}
      <div className="space-y-2">
        <div className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground flex items-center justify-between">
          <span>Simulation Presets</span>
          <span className="text-[10px] font-mono lowercase">Click to load profile</span>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5">
          <button
            type="button"
            onClick={() => handlePresetSelect('slow_3g')}
            className={`p-3 rounded-lg border text-left transition-all ${
              config.activePreset === 'slow_3g'
                ? 'bg-amber-500/10 border-amber-500/60 ring-1 ring-amber-500/50'
                : 'bg-muted/20 border-border/60 hover:bg-muted/40'
            }`}
          >
            <div className="text-xs font-semibold text-foreground flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              Slow 3G Connection
            </div>
            <div className="text-[10px] font-mono text-muted-foreground mt-1">1800ms latency • 5% drops</div>
          </button>

          <button
            type="button"
            onClick={() => handlePresetSelect('db_brownout')}
            className={`p-3 rounded-lg border text-left transition-all ${
              config.activePreset === 'db_brownout'
                ? 'bg-amber-500/10 border-amber-500/60 ring-1 ring-amber-500/50'
                : 'bg-muted/20 border-border/60 hover:bg-muted/40'
            }`}
          >
            <div className="text-xs font-semibold text-foreground flex items-center gap-1.5">
              <Flame className="w-3.5 h-3.5 text-amber-400" />
              Database Brownout
            </div>
            <div className="text-[10px] font-mono text-muted-foreground mt-1">850ms latency • 40% 503s</div>
          </button>

          <button
            type="button"
            onClick={() => handlePresetSelect('dependency_outage')}
            className={`p-3 rounded-lg border text-left transition-all ${
              config.activePreset === 'dependency_outage'
                ? 'bg-amber-500/10 border-amber-500/60 ring-1 ring-amber-500/50'
                : 'bg-muted/20 border-border/60 hover:bg-muted/40'
            }`}
          >
            <div className="text-xs font-semibold text-foreground flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
              Dependency Outage
            </div>
            <div className="text-[10px] font-mono text-muted-foreground mt-1">75% 502 Bad Gateway</div>
          </button>

          <button
            type="button"
            onClick={() => handlePresetSelect('packet_loss')}
            className={`p-3 rounded-lg border text-left transition-all ${
              config.activePreset === 'packet_loss'
                ? 'bg-amber-500/10 border-amber-500/60 ring-1 ring-amber-500/50'
                : 'bg-muted/20 border-border/60 hover:bg-muted/40'
            }`}
          >
            <div className="text-xs font-semibold text-foreground flex items-center gap-1.5">
              <WifiOff className="w-3.5 h-3.5 text-purple-400" />
              Aggressive Packet Loss
            </div>
            <div className="text-[10px] font-mono text-muted-foreground mt-1">35% connection drops</div>
          </button>
        </div>
      </div>

      {/* Sliders Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 p-5 rounded-xl bg-slate-950/60 border border-border/70">
        {/* Latency Injection */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-foreground flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              Artificial Latency
            </span>
            <span className={`font-mono font-bold ${getLatencyColor(config.latencyMs)}`}>
              {config.latencyMs} ms
            </span>
          </div>
          <input
            type="range"
            min={0}
            max={5000}
            step={50}
            value={config.latencyMs}
            onChange={(e) =>
              onChangeConfig({
                ...config,
                latencyMs: Number(e.target.value),
                activePreset: 'custom',
              })
            }
            className="w-full accent-cyan-500 cursor-pointer"
          />
          <div className="flex justify-between text-[10px] font-mono text-muted-foreground">
            <span>0 ms (Native)</span>
            <span>2500 ms</span>
            <span>5000 ms</span>
          </div>
        </div>

        {/* Latency Jitter */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-foreground flex items-center gap-1.5">
              <Gauge className="w-3.5 h-3.5 text-blue-400" />
              Latency Jitter Window (±)
            </span>
            <span className="font-mono font-bold text-blue-400">±{config.jitterMs} ms</span>
          </div>
          <input
            type="range"
            min={0}
            max={1000}
            step={25}
            value={config.jitterMs}
            onChange={(e) =>
              onChangeConfig({
                ...config,
                jitterMs: Number(e.target.value),
                activePreset: 'custom',
              })
            }
            className="w-full accent-blue-500 cursor-pointer"
          />
          <div className="flex justify-between text-[10px] font-mono text-muted-foreground">
            <span>0 ms (Fixed)</span>
            <span>500 ms</span>
            <span>1000 ms</span>
          </div>
        </div>

        {/* Packet Drop Rate */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-foreground flex items-center gap-1.5">
              <WifiOff className="w-3.5 h-3.5 text-purple-400" />
              Packet Drop Rate (TCP Drop)
            </span>
            <span
              className={`font-mono font-bold ${
                config.packetDropRate > 20 ? 'text-red-400' : 'text-purple-400'
              }`}
            >
              {config.packetDropRate}%
            </span>
          </div>
          <input
            type="range"
            min={0}
            max={50}
            step={1}
            value={config.packetDropRate}
            onChange={(e) =>
              onChangeConfig({
                ...config,
                packetDropRate: Number(e.target.value),
                activePreset: 'custom',
              })
            }
            className="w-full accent-purple-500 cursor-pointer"
          />
          <div className="flex justify-between text-[10px] font-mono text-muted-foreground">
            <span>0% (No Drops)</span>
            <span>25%</span>
            <span>50% (Max Safety Cap)</span>
          </div>
        </div>

        {/* Error Injection Rate & Status Code */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-foreground flex items-center gap-1.5">
              <Flame className="w-3.5 h-3.5 text-amber-400" />
              Error Injection Rate
            </span>
            <span
              className={`font-mono font-bold ${
                config.errorInjectionRate > 50 ? 'text-red-400' : 'text-amber-400'
              }`}
            >
              {config.errorInjectionRate}%
            </span>
          </div>
          <input
            type="range"
            min={0}
            max={100}
            step={5}
            value={config.errorInjectionRate}
            onChange={(e) =>
              onChangeConfig({
                ...config,
                errorInjectionRate: Number(e.target.value),
                activePreset: 'custom',
              })
            }
            className="w-full accent-amber-500 cursor-pointer"
          />
          <div className="flex items-center justify-between pt-1">
            <span className="text-[10px] font-mono text-muted-foreground">HTTP Status to Inject:</span>
            <select
              value={config.errorStatusCode}
              onChange={(e) =>
                onChangeConfig({
                  ...config,
                  errorStatusCode: Number(e.target.value),
                  activePreset: 'custom',
                })
              }
              className="px-2 py-0.5 text-xs font-mono rounded bg-card border border-border text-foreground focus:outline-none"
            >
              <option value={503}>503 Service Unavailable</option>
              <option value={502}>502 Bad Gateway</option>
              <option value={500}>500 Internal Server Error</option>
              <option value={504}>504 Gateway Timeout</option>
              <option value={429}>429 Too Many Requests</option>
            </select>
          </div>
        </div>
      </div>

      {/* Circuit Breaker & Safety Invariant Controls */}
      <div className="p-4 rounded-xl bg-card border border-border/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-start gap-3">
          <div
            className={`p-2 rounded-lg border shrink-0 ${
              isProductionTarget || config.circuitBreakerEnabled
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                : 'bg-zinc-800 text-zinc-400 border-zinc-700'
            }`}
          >
            {isProductionTarget || config.circuitBreakerEnabled ? (
              <ShieldCheck className="w-5 h-5" />
            ) : (
              <ShieldAlert className="w-5 h-5" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-foreground">Safety Circuit Breaker</span>
              {isProductionTarget && (
                <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                  LOCKED ON (Production Target)
                </span>
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">
              Automatically trips to OPEN state and stops fault injection if consecutive errors exceed threshold, protecting target upstream stability.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4 shrink-0">
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground font-mono">Trip After:</span>
            <select
              value={config.circuitBreakerThreshold}
              onChange={(e) =>
                onChangeConfig({
                  ...config,
                  circuitBreakerThreshold: Number(e.target.value),
                })
              }
              className="px-2 py-1 text-xs font-mono rounded bg-background border border-border text-foreground"
            >
              <option value={3}>3 failures</option>
              <option value={5}>5 failures</option>
              <option value={10}>10 failures</option>
            </select>
          </div>

          <label className="relative inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={config.circuitBreakerEnabled || isProductionTarget}
              disabled={isProductionTarget}
              onChange={(e) =>
                onChangeConfig({
                  ...config,
                  circuitBreakerEnabled: e.target.checked,
                })
              }
              className="sr-only peer"
            />
            <div className="w-11 h-6 bg-zinc-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-emerald-600" />
          </label>
        </div>
      </div>
    </div>
  );
};
