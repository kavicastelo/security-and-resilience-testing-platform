import React from 'react';
import {
  X,
  Sliders,
  AlertTriangle,
  RotateCcw,
} from 'lucide-react';
import {
  usePlanStudioStore,
  REGISTERED_ENGINES,
} from '../../store/usePlanStudioStore.js';

export const EngineConfigDrawer: React.FC = () => {
  const {
    steps,
    activeConfigStepId,
    setActiveConfigStepId,
    updateStepOptions,
  } = usePlanStudioStore();

  const step = steps.find((s) => s.id === activeConfigStepId);
  if (!step) return null;

  const descriptor = REGISTERED_ENGINES.find((e) => e.id === step.engineId);
  const options = step.options || {};

  const handleOptionChange = (key: string, value: any) => {
    updateStepOptions(step.id, { [key]: value });
  };

  const resetToDefaults = () => {
    if (descriptor) {
      updateStepOptions(step.id, { ...descriptor.defaultOptions });
    }
  };

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full sm:w-96 bg-card/95 backdrop-blur-md border-l border-border shadow-2xl flex flex-col animate-slide-left">
      {/* Drawer Header */}
      <div className="p-4 border-b border-border/60 bg-accent/20 flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Sliders className="w-4 h-4 text-primary" />
          <div>
            <h3 className="text-xs font-semibold text-foreground">
              Configure {step.name}
            </h3>
            <span className="font-mono text-[10px] text-muted-foreground block">
              {step.engineId}
            </span>
          </div>
        </div>

        <button
          type="button"
          onClick={() => setActiveConfigStepId(null)}
          className="p-1 rounded text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Drawer Body Form */}
      <div className="flex-1 overflow-y-auto p-5 space-y-5 text-xs">
        {step.disruptive && (
          <div className="p-3 rounded-xl bg-rose-950/30 border border-rose-800/50 flex items-start gap-2.5 text-rose-300">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <p className="text-[11px] leading-relaxed">
              This engine performs active probing or stress testing. Verify target authorization before dispatch.
            </p>
          </div>
        )}

        {/* Tailored Form for k6 Load Generator */}
        {step.engineId === 'engine-worker-k6' && (
          <div className="space-y-4">
            <div>
              <div className="flex justify-between mb-1">
                <label className="text-muted-foreground">Virtual Users (VUs)</label>
                <span className="font-mono font-bold text-cyan-400">{options.vus || 10} VUs</span>
              </div>
              <input
                type="range"
                min={1}
                max={100}
                value={options.vus || 10}
                onChange={(e) => handleOptionChange('vus', parseInt(e.target.value, 10))}
                className="w-full"
              />
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <label className="text-muted-foreground">Test Duration (Seconds)</label>
                <span className="font-mono font-bold text-foreground">{options.durationSec || 15}s</span>
              </div>
              <input
                type="range"
                min={3}
                max={60}
                value={options.durationSec || 15}
                onChange={(e) => handleOptionChange('durationSec', parseInt(e.target.value, 10))}
                className="w-full"
              />
            </div>

            <div>
              <label className="block text-muted-foreground mb-1">P95 SLA Latency Threshold (ms)</label>
              <input
                type="number"
                min={50}
                max={5000}
                step={50}
                value={options.maxP95Ms || 500}
                onChange={(e) => handleOptionChange('maxP95Ms', parseInt(e.target.value, 10))}
                className="w-full px-3 py-1.5 rounded-lg bg-accent border border-border text-foreground font-mono"
              />
            </div>
          </div>
        )}

        {/* Tailored Form for GraphQL */}
        {step.engineId === 'engine-native-graphql' && (
          <div className="space-y-4">
            <div>
              <div className="flex justify-between mb-1">
                <label className="text-muted-foreground">Max Query Depth Ceiling</label>
                <span className="font-mono font-bold text-primary">{options.maxDepth || 6} Levels</span>
              </div>
              <input
                type="range"
                min={1}
                max={15}
                value={options.maxDepth || 6}
                onChange={(e) => handleOptionChange('maxDepth', parseInt(e.target.value, 10))}
                className="w-full"
              />
            </div>

            <label className="flex items-center space-x-2 cursor-pointer">
              <input
                type="checkbox"
                checked={options.testIntrospection ?? true}
                onChange={(e) => handleOptionChange('testIntrospection', e.target.checked)}
                className="rounded border-border text-primary"
              />
              <span className="text-foreground">Detect Introspection Exposure</span>
            </label>

            <label className="flex items-center space-x-2 cursor-pointer">
              <input
                type="checkbox"
                checked={options.testBatching ?? true}
                onChange={(e) => handleOptionChange('testBatching', e.target.checked)}
                className="rounded border-border text-primary"
              />
              <span className="text-foreground">Detect Batch Query Amplification</span>
            </label>
          </div>
        )}

        {/* Tailored Form for Injection Fuzzer */}
        {step.engineId === 'engine-native-fuzzer' && (
          <div className="space-y-4">
            <div>
              <label className="block text-muted-foreground mb-1">Wordlist Size</label>
              <select
                value={options.wordlistSize || 'standard'}
                onChange={(e) => handleOptionChange('wordlistSize', e.target.value)}
                className="w-full px-3 py-1.5 rounded-lg bg-accent border border-border text-foreground cursor-pointer"
              >
                <option value="minimal">Minimal (Top 10 High-Confidence Payloads)</option>
                <option value="standard">Standard (OWASP Recommended Suite)</option>
                <option value="extended">Extended (Deep Polyglot & Evasion Vectors)</option>
              </select>
            </div>

            <div>
              <label className="block text-muted-foreground mb-1">Inter-Request Throttle Delay (ms)</label>
              <input
                type="number"
                min={0}
                max={1000}
                step={25}
                value={options.delayMs ?? 50}
                onChange={(e) => handleOptionChange('delayMs', parseInt(e.target.value, 10))}
                className="w-full px-3 py-1.5 rounded-lg bg-accent border border-border text-foreground font-mono"
              />
            </div>
          </div>
        )}

        {/* Tailored Form for Chaos MITM */}
        {step.engineId === 'engine-native-chaos' && (
          <div className="space-y-4">
            <div>
              <div className="flex justify-between mb-1">
                <label className="text-muted-foreground">Injected Latency Jitter (ms)</label>
                <span className="font-mono font-bold text-rose-400">{options.latencyJitterMs || 200} ms</span>
              </div>
              <input
                type="range"
                min={0}
                max={1000}
                step={50}
                value={options.latencyJitterMs || 200}
                onChange={(e) => handleOptionChange('latencyJitterMs', parseInt(e.target.value, 10))}
                className="w-full"
              />
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <label className="text-muted-foreground">Simulated Packet Drop Rate</label>
                <span className="font-mono font-bold text-rose-400">
                  {Math.round((options.packetDropRate || 0.1) * 100)}%
                </span>
              </div>
              <input
                type="range"
                min={0}
                max={0.5}
                step={0.05}
                value={options.packetDropRate || 0.1}
                onChange={(e) => handleOptionChange('packetDropRate', parseFloat(e.target.value))}
                className="w-full"
              />
            </div>
          </div>
        )}

        {/* Tailored Form for HTTP Smuggling */}
        {step.engineId === 'engine-native-smuggling' && (
          <div className="space-y-3">
            <label className="block text-muted-foreground">Probe Request Desync Variants</label>
            <div className="space-y-1.5 font-mono text-[11px]">
              <span className="block px-2.5 py-1 rounded bg-accent border border-border">CL.TE (Content-Length / Transfer-Encoding)</span>
              <span className="block px-2.5 py-1 rounded bg-accent border border-border">TE.CL (Transfer-Encoding / Content-Length)</span>
            </div>
            <div>
              <label className="block text-muted-foreground mb-1">Socket Read Timeout (ms)</label>
              <input
                type="number"
                min={1000}
                max={15000}
                step={1000}
                value={options.timeoutMs || 5000}
                onChange={(e) => handleOptionChange('timeoutMs', parseInt(e.target.value, 10))}
                className="w-full px-3 py-1.5 rounded-lg bg-accent border border-border text-foreground font-mono"
              />
            </div>
          </div>
        )}

        {/* Generic Option Key/Value Pairs for Other Engines */}
        {!['engine-worker-k6', 'engine-native-graphql', 'engine-native-fuzzer', 'engine-native-chaos', 'engine-native-smuggling'].includes(step.engineId) && (
          <div className="space-y-3">
            <span className="text-muted-foreground block text-[11px] uppercase tracking-wider">
              Engine Parameters ({Object.keys(options).length})
            </span>
            {Object.entries(options).map(([key, value]) => {
              if (typeof value === 'boolean') {
                return (
                  <label key={key} className="flex items-center space-x-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={value}
                      onChange={(e) => handleOptionChange(key, e.target.checked)}
                      className="rounded border-border text-primary"
                    />
                    <span className="text-foreground capitalize">{key.replace(/([A-Z])/g, ' $1')}</span>
                  </label>
                );
              }
              return (
                <div key={key}>
                  <label className="block text-muted-foreground mb-1 capitalize">
                    {key.replace(/([A-Z])/g, ' $1')}
                  </label>
                  <input
                    type="text"
                    value={String(value)}
                    onChange={(e) => handleOptionChange(key, e.target.value)}
                    className="w-full px-3 py-1.5 rounded-lg bg-accent border border-border text-foreground font-mono"
                  />
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Drawer Footer */}
      <div className="p-4 border-t border-border/60 bg-accent/20 flex items-center justify-between">
        <button
          type="button"
          onClick={resetToDefaults}
          className="flex items-center space-x-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Reset Defaults</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveConfigStepId(null)}
          className="px-4 py-1.5 rounded-lg bg-primary hover:bg-primary/90 text-white font-medium text-xs transition-colors"
        >
          Apply Parameters
        </button>
      </div>
    </div>
  );
};
