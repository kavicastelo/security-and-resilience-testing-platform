import React from 'react';
import { Box, Server, Lock, Layers, Zap } from 'lucide-react';

export const Overview: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* Hero Banner */}
      <div className="rounded-xl border border-border bg-gradient-to-br from-card to-accent/30 p-6">
        <div className="flex items-start justify-between">
          <div className="space-y-2 max-w-2xl">
            <span className="inline-flex items-center space-x-1.5 text-xs font-mono uppercase bg-emerald-950/60 text-emerald-400 border border-emerald-800/60 px-2.5 py-0.5 rounded-full">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>Foundation Initialized</span>
            </span>
            <h2 className="text-xl font-bold tracking-tight text-foreground">
              Security QA for Enterprise Applications
            </h2>
            <p className="text-sm text-muted-foreground leading-relaxed">
              A local-first security QA laboratory for applications and infrastructure owned or
              explicitly authorized to test. Built on a modular monolith with isolated execution
              runners.
            </p>
          </div>
        </div>
      </div>

      {/* Architecture Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl border border-border bg-card space-y-3">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-lg bg-blue-950/40 border border-blue-800/40 text-blue-400">
              <Server className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-semibold text-sm">Class A: Native Engines</h3>
              <p className="text-[11px] text-muted-foreground font-mono">In-process fast checks</p>
            </div>
          </div>
          <p className="text-xs text-muted-foreground leading-relaxed">
            Headers, TLS handshakes, CORS policies, authentication handshakes, and rate-limit baselines.
          </p>
          <div className="text-[10px] font-mono text-emerald-400 bg-emerald-950/30 px-2 py-1 rounded border border-emerald-800/30">
            Contract Boundary: packages/test-sdk
          </div>
        </div>

        <div className="p-4 rounded-xl border border-border bg-card space-y-3">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-lg bg-purple-950/40 border border-purple-800/40 text-purple-400">
              <Box className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-semibold text-sm">Class B: Container Scanners</h3>
              <p className="text-[11px] text-muted-foreground font-mono">Isolated ephemeral tools</p>
            </div>
          </div>
          <p className="text-xs text-muted-foreground leading-relaxed">
            External tooling such as OWASP ZAP and Trivy containerized with scoped authorization parameters.
          </p>
          <div className="text-[10px] font-mono text-amber-400 bg-amber-950/30 px-2 py-1 rounded border border-amber-800/30">
            Planned for Phase 2
          </div>
        </div>

        <div className="p-4 rounded-xl border border-border bg-card space-y-3">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-lg bg-indigo-950/40 border border-indigo-800/40 text-indigo-400">
              <Zap className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-semibold text-sm">Class C: Heavy Workers</h3>
              <p className="text-[11px] text-muted-foreground font-mono">Resilience & Performance</p>
            </div>
          </div>
          <p className="text-xs text-muted-foreground leading-relaxed">
            Load generation and resilience soak runs (k6, headless browser validation, chaos simulations).
          </p>
          <div className="text-[10px] font-mono text-amber-400 bg-amber-950/30 px-2 py-1 rounded border border-amber-800/30">
            Planned for Phase 2
          </div>
        </div>
      </div>

      {/* Execution Lifecycle Flow */}
      <div className="p-5 rounded-xl border border-border bg-card space-y-3">
        <h3 className="text-sm font-semibold flex items-center space-x-2">
          <Layers className="w-4 h-4 text-blue-400" />
          <span>Execution Lifecycle Pipeline</span>
        </h3>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {[
            'Target Scope',
            'Scope Validation',
            'Test Definition',
            'TestRun',
            'Engine Execution',
            'Normalization',
            'Immutable Evidence',
            'Finding Model',
            'Policy Evaluation',
            'Release Gate Verdict',
          ].map((stage, idx, arr) => (
            <React.Fragment key={stage}>
              <span className="px-2.5 py-1 rounded-md bg-accent/60 border border-border/80 text-foreground font-mono text-[11px]">
                {stage}
              </span>
              {idx < arr.length - 1 && (
                <span className="text-muted-foreground/60 text-xs">→</span>
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Safety Notice */}
      <div className="p-4 rounded-xl border border-blue-900/40 bg-blue-950/20 flex items-start space-x-3 text-xs text-blue-300">
        <Lock className="w-4 h-4 text-blue-400 mt-0.5 shrink-0" />
        <div className="space-y-1">
          <div className="font-semibold text-blue-200">Security Boundary Principle:</div>
          <p className="text-blue-300/80 leading-relaxed">
            All test executions strictly require explicit target scope registration, allowed host
            validation, and active scanning consent. Potentially disruptive testing requires
            explicit capability flags and safety threshold limits.
          </p>
        </div>
      </div>
    </div>
  );
};
