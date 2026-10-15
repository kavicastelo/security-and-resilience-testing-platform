import React, { useState } from 'react';
import {
  Zap,
  ArrowRight,
  ShieldAlert,
  ShieldCheck,
  Binary,
  Code2,
  Layers,
  Clock,
  AlertTriangle,
} from 'lucide-react';
import { SmugglingWireSnapshot, SmugglingWireVariant } from '../../api/infra.js';

export interface HttpSmugglingWireTabProps {
  smugglingData: SmugglingWireSnapshot;
  className?: string;
}

export const HttpSmugglingWireTab: React.FC<HttpSmugglingWireTabProps> = ({
  smugglingData,
  className = '',
}) => {
  const [selectedVariantId, setSelectedVariantId] = useState<string>('var-cl-te-timing');
  const [viewMode, setViewMode] = useState<'text' | 'hexdump'>('text');
  const selectedVariant: SmugglingWireVariant | undefined =
    smugglingData.variants.find((v) => v.id === selectedVariantId) ?? smugglingData.variants[0];

  if (!selectedVariant) {
    return (
      <div className={`p-8 rounded-2xl bg-card/60 border border-border/60 text-center space-y-3 ${className}`}>
        <Zap className="w-10 h-10 text-muted-foreground mx-auto opacity-50" />
        <h4 className="text-base font-semibold text-foreground">No HTTP Smuggling Probes Executed</h4>
        <p className="text-xs text-muted-foreground max-w-md mx-auto">
          Specify a target URL and probe for RFC-7230/9112 Content-Length and Transfer-Encoding desync vectors (CL.TE, TE.CL, TE.TE).
        </p>
      </div>
    );
  }

  const isConfirmed = selectedVariant.vulnerabilityStatus === 'CONFIRMED';
  const isSafe = selectedVariant.vulnerabilityStatus === 'SAFE';

  return (
    <div className={`space-y-5 ${className}`}>
      {/* Header & Reverse Proxy Architecture Summary */}
      <div className="p-5 rounded-2xl bg-card/60 border border-border/60 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border/40">
          <div>
            <div className="flex items-center gap-2">
              <Zap className="w-5 h-5 text-amber-400" />
              <h3 className="font-semibold text-foreground text-sm tracking-wide">
                HTTP Request Smuggling Wire Protocol Inspector & Desync Analyzer
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 uppercase">
                RFC 9112 §6.3
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-0.5 font-mono">
              Target: {smugglingData.targetHost}:{smugglingData.targetPort} (TLS: {smugglingData.useTls ? 'Enabled' : 'Disabled'})
            </p>
          </div>

          {/* Architecture Pair Pills */}
          <div className="flex items-center gap-2 font-mono text-xs">
            <div className="px-3 py-1 rounded-xl bg-background/80 border border-border/50">
              <span className="text-muted-foreground block text-[10px] font-sans">Edge Proxy</span>
              <span className="text-cyan-400 font-semibold">{smugglingData.reverseProxyType}</span>
            </div>
            <ArrowRight className="w-3.5 h-3.5 text-muted-foreground" />
            <div className="px-3 py-1 rounded-xl bg-background/80 border border-border/50">
              <span className="text-muted-foreground block text-[10px] font-sans">Origin Server</span>
              <span className="text-blue-400 font-semibold">{smugglingData.backendServerType}</span>
            </div>
          </div>
        </div>

        {/* Smuggling Technique Variants Carousel / Pills */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1">
          {smugglingData.variants.map((v) => {
            const isSelected = v.id === selectedVariant.id;
            const isVuln = v.vulnerabilityStatus === 'CONFIRMED';

            return (
              <button
                key={v.id}
                type="button"
                onClick={() => setSelectedVariantId(v.id)}
                className={`flex items-center gap-2 px-3 py-2 rounded-xl border text-xs font-mono transition-all shrink-0 ${
                  isSelected
                    ? 'bg-amber-500/15 border-amber-500/50 text-foreground shadow-lg'
                    : 'bg-background/60 border-border/40 text-muted-foreground hover:text-foreground'
                }`}
              >
                <span
                  className={`w-2 h-2 rounded-full ${
                    isVuln ? 'bg-rose-500 animate-pulse' : 'bg-emerald-500'
                  }`}
                />
                <span className="font-bold">{v.technique}</span>
                <span className="text-[11px] opacity-80">{v.name.slice(0, 28)}...</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Desync Mechanism & Parser Asymmetry Visualizer */}
      <div className="p-5 rounded-2xl bg-card/60 border border-border/60 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-border/40">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-blue-400" />
            <h4 className="font-semibold text-foreground text-xs uppercase tracking-wider font-mono">
              Parser Asymmetry & Desynchronization Anatomy: {selectedVariant.name}
            </h4>
          </div>

          <div className="flex items-center gap-2">
            {isConfirmed ? (
              <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/40 text-xs font-mono font-bold animate-pulse">
                <ShieldAlert className="w-3.5 h-3.5" />
                Vulnerability Confirmed (Canary Reflected)
              </span>
            ) : isSafe ? (
              <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 text-xs font-mono font-bold">
                <ShieldCheck className="w-3.5 h-3.5" />
                Robust (400 Bad Request Enforced)
              </span>
            ) : (
              <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-500/15 text-amber-400 border border-amber-500/30 text-xs font-mono font-bold">
                <AlertTriangle className="w-3.5 h-3.5" />
                Suspected Timing Discrepancy
              </span>
            )}
          </div>
        </div>

        {/* Dual Parser Comparison Flow */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
          {/* Frontend Reverse Proxy Parser */}
          <div className="p-3.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 space-y-2">
            <div className="flex items-center justify-between text-cyan-400 font-semibold">
              <span>Frontend Reverse Proxy</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyan-500/20 border border-cyan-500/30">
                L7 Ingress
              </span>
            </div>
            <p className="text-muted-foreground text-[11px] leading-relaxed">
              {selectedVariant.frontendExpectation}
            </p>
          </div>

          {/* Backend Origin Server Parser */}
          <div className="p-3.5 rounded-xl bg-blue-500/10 border border-blue-500/30 space-y-2">
            <div className="flex items-center justify-between text-blue-400 font-semibold">
              <span>Backend Origin Server</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-blue-500/20 border border-blue-500/30">
                Application Worker
              </span>
            </div>
            <p className="text-muted-foreground text-[11px] leading-relaxed">
              {selectedVariant.backendExpectation}
            </p>
          </div>
        </div>

        {/* Root Cause Explanation */}
        <div className="p-3 rounded-xl bg-background/80 border border-border/40 text-xs leading-relaxed text-muted-foreground">
          <strong className="text-foreground">Desync Root Cause:</strong> {selectedVariant.desyncExplanation}
        </div>
      </div>

      {/* Raw Socket & Hex Dump Side-by-Side Dual Inspector */}
      <div className="p-5 rounded-2xl bg-card/60 border border-border/60 shadow-xl space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-border/40">
          <div className="flex items-center gap-2">
            <Binary className="w-4 h-4 text-purple-400" />
            <h4 className="font-semibold text-foreground text-xs uppercase tracking-wider font-mono">
              Raw Wire Socket Payload & Server Response Frame
            </h4>
          </div>

          {/* Text vs Hex Dump Toggle */}
          <div className="flex items-center gap-1 bg-background/80 p-1 rounded-xl border border-border/50 text-xs font-mono">
            <button
              type="button"
              onClick={() => setViewMode('text')}
              className={`flex items-center gap-1 px-2.5 py-1 rounded-lg transition-colors ${
                viewMode === 'text' ? 'bg-purple-500/20 text-purple-300' : 'text-muted-foreground'
              }`}
            >
              <Code2 className="w-3.5 h-3.5" />
              <span>Raw ASCII (CRLF)</span>
            </button>
            <button
              type="button"
              onClick={() => setViewMode('hexdump')}
              className={`flex items-center gap-1 px-2.5 py-1 rounded-lg transition-colors ${
                viewMode === 'hexdump' ? 'bg-purple-500/20 text-purple-300' : 'text-muted-foreground'
              }`}
            >
              <Binary className="w-3.5 h-3.5" />
              <span>Hex Dump</span>
            </button>
          </div>
        </div>

        {/* Side-by-Side Raw Frames */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Outbound Request Socket */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs font-mono text-muted-foreground">
              <span className="text-foreground font-semibold">Outbound Raw TCP Payload:</span>
              <span className="text-[10px]">Preserves exact \r\n byte delimiters</span>
            </div>

            <div className="p-3.5 rounded-xl bg-black/80 border border-border/60 font-mono text-[11px] text-emerald-400 overflow-x-auto max-h-[360px] whitespace-pre select-text">
              {viewMode === 'text'
                ? selectedVariant.rawSocketRequest
                : selectedVariant.requestHexDump}
            </div>
          </div>

          {/* Inbound Response Socket */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs font-mono text-muted-foreground">
              <span className="text-foreground font-semibold">Inbound Server Wire Response:</span>
              <div className="flex items-center gap-2 text-[10px]">
                <Clock className="w-3 h-3 text-muted-foreground" />
                <span>{selectedVariant.latencyMs}ms</span>
                <span className="font-bold text-foreground">Status: {selectedVariant.statusCode}</span>
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-black/80 border border-border/60 font-mono text-[11px] text-cyan-300 overflow-x-auto max-h-[360px] whitespace-pre select-text">
              {viewMode === 'text'
                ? selectedVariant.rawSocketResponse
                : selectedVariant.responseHexDump}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
