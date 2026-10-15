import React, { useState } from 'react';
import {
  Database,
  Lock,
  Unlock,
  Key,
  Activity,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Binary,
} from 'lucide-react';
import { DatabaseSecuritySnapshot, DatabaseProbeResult } from '../../api/infra.js';

export interface DatabaseProtocolTabProps {
  databaseData: DatabaseSecuritySnapshot;
  className?: string;
}

export const DatabaseProtocolTab: React.FC<DatabaseProtocolTabProps> = ({
  databaseData,
  className = '',
}) => {
  const [selectedDbId, setSelectedDbId] = useState<string>('db-postgres-prod');

  const selectedDb: DatabaseProbeResult | undefined =
    databaseData.probes.find((p) => p.id === selectedDbId) ?? databaseData.probes[0];

  if (!selectedDb) {
    return (
      <div className={`p-8 rounded-2xl bg-card/60 border border-border/60 text-center space-y-3 ${className}`}>
        <Database className="w-10 h-10 text-muted-foreground mx-auto opacity-50" />
        <h4 className="text-base font-semibold text-foreground">No Database Wire Probes Executed</h4>
        <p className="text-xs text-muted-foreground max-w-md mx-auto">
          Configure a database target to audit in-transit TLS enforcement, unauthenticated access, and connection saturation ceilings.
        </p>
      </div>
    );
  }

  const getEngineBadge = (type: DatabaseProbeResult['databaseType']) => {
    switch (type) {
      case 'POSTGRES':
        return (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/15 text-blue-400 border border-blue-500/30">
            PostgreSQL (5432)
          </span>
        );
      case 'MYSQL':
        return (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-orange-500/15 text-orange-400 border border-orange-500/30">
            MySQL (3306)
          </span>
        );
      case 'REDIS':
        return (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/15 text-rose-400 border border-rose-500/30">
            Redis RESP (6379)
          </span>
        );
    }
  };

  return (
    <div className={`space-y-5 ${className}`}>
      {/* Header & Target Databases Switcher */}
      <div className="p-5 rounded-2xl bg-card/60 border border-border/60 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border/40">
          <div>
            <div className="flex items-center gap-2">
              <Database className="w-5 h-5 text-emerald-400" />
              <h3 className="font-semibold text-foreground text-sm tracking-wide">
                Direct Database Wire Protocol Security & Saturation Console
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                Layer 4/7 Wire Probes
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">
              Audits raw database wire handshakes, TLS enforcement, default accounts, and connection pool saturation.
            </p>
          </div>

          <div className="flex items-center gap-3 font-mono text-xs">
            <div className="px-3 py-1.5 rounded-xl bg-background/80 border border-border/50 text-right">
              <span className="text-muted-foreground block text-[10px] font-sans">Probed Databases</span>
              <span className="text-foreground font-bold">{databaseData.totalDatabasesChecked}</span>
            </div>
            <div className="px-3 py-1.5 rounded-xl bg-background/80 border border-border/50 text-right">
              <span className="text-muted-foreground block text-[10px] font-sans">Cleartext / Open</span>
              <span
                className={`font-bold ${
                  databaseData.unencryptedCount > 0 || databaseData.unauthenticatedCount > 0
                    ? 'text-rose-400'
                    : 'text-emerald-400'
                }`}
              >
                {databaseData.unencryptedCount + databaseData.unauthenticatedCount}
              </span>
            </div>
          </div>
        </div>

        {/* Database Selector Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {databaseData.probes.map((probe) => {
            const isSelected = probe.id === selectedDb.id;
            const hasVuln =
              !probe.tlsMandated || probe.unauthenticatedAccessAllowed || probe.defaultCredentialsMatched;

            return (
              <div
                key={probe.id}
                onClick={() => setSelectedDbId(probe.id)}
                className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                  isSelected
                    ? 'bg-card/90 border-emerald-500/60 shadow-lg'
                    : 'bg-background/60 border-border/50 hover:border-border'
                }`}
              >
                <div className="flex items-center justify-between pb-1.5">
                  <div className="flex items-center gap-1.5">
                    {getEngineBadge(probe.databaseType)}
                  </div>
                  {hasVuln ? (
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-400 border border-rose-500/30">
                      Vulnerable
                    </span>
                  ) : (
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                      Hardened
                    </span>
                  )}
                </div>

                <div className="font-mono text-xs font-semibold text-foreground truncate mt-1">
                  {probe.host}:{probe.port}
                </div>
                <div className="text-[11px] text-muted-foreground font-mono mt-0.5 truncate">
                  {probe.serverVersion}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Selected Database Protocol Inspection & Stress Results */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Wire Protocol Checks (Left 6 Cols) */}
        <div className="lg:col-span-6 rounded-2xl bg-card/60 border border-border/60 shadow-xl p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-border/40">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-emerald-400" />
              <h4 className="font-semibold text-foreground text-xs uppercase tracking-wider font-mono">
                Wire Protocol Security Controls: {selectedDb.databaseType}
              </h4>
            </div>
          </div>

          <div className="space-y-3 text-xs font-mono">
            {/* TLS Wire Enforcement */}
            <div className="p-3 rounded-xl bg-background/80 border border-border/40 flex items-center justify-between">
              <div className="flex items-center gap-2">
                {selectedDb.tlsMandated ? (
                  <Lock className="w-4 h-4 text-emerald-400" />
                ) : (
                  <Unlock className="w-4 h-4 text-rose-400" />
                )}
                <div>
                  <span className="font-semibold text-foreground block">
                    TLS / SSL Wire Encryption
                  </span>
                  <span className="text-[11px] text-muted-foreground">
                    {selectedDb.tlsMandated
                      ? 'Server strictly rejects cleartext StartupMessage'
                      : 'Cleartext connections accepted over raw socket'}
                  </span>
                </div>
              </div>
              <span
                className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${
                  selectedDb.tlsMandated
                    ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                    : 'bg-rose-500/15 text-rose-400 border-rose-500/30 animate-pulse'
                }`}
              >
                {selectedDb.tlsMandated ? 'Enforced' : 'Cleartext Permitted'}
              </span>
            </div>

            {/* Authentication Gateway */}
            <div className="p-3 rounded-xl bg-background/80 border border-border/40 flex items-center justify-between">
              <div className="flex items-center gap-2">
                {selectedDb.unauthenticatedAccessAllowed ? (
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                ) : (
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                )}
                <div>
                  <span className="font-semibold text-foreground block">
                    Unauthenticated Access Check
                  </span>
                  <span className="text-[11px] text-muted-foreground">
                    {selectedDb.unauthenticatedAccessAllowed
                      ? 'Server executed commands without requiring AUTH'
                      : 'Authentication challenge required on wire'}
                  </span>
                </div>
              </div>
              <span
                className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${
                  selectedDb.unauthenticatedAccessAllowed
                    ? 'bg-rose-500/15 text-rose-400 border-rose-500/30 animate-pulse'
                    : 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                }`}
              >
                {selectedDb.unauthenticatedAccessAllowed ? 'Open Access' : 'Protected'}
              </span>
            </div>

            {/* Default Credentials */}
            <div className="p-3 rounded-xl bg-background/80 border border-border/40 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Key
                  className={`w-4 h-4 ${
                    selectedDb.defaultCredentialsMatched ? 'text-rose-400' : 'text-emerald-400'
                  }`}
                />
                <div>
                  <span className="font-semibold text-foreground block">
                    Default Credentials Audit
                  </span>
                  <span className="text-[11px] text-muted-foreground">
                    {selectedDb.defaultCredentialsMatched
                      ? `Matched default superuser: ${selectedDb.matchedCredentialUser}`
                      : 'No standard factory passwords matched'}
                  </span>
                </div>
              </div>
              <span
                className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${
                  selectedDb.defaultCredentialsMatched
                    ? 'bg-rose-500/15 text-rose-400 border-rose-500/30 animate-pulse'
                    : 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                }`}
              >
                {selectedDb.defaultCredentialsMatched ? 'Default Creds' : 'No Defaults'}
              </span>
            </div>

            {/* Raw Wire Handshake Banner */}
            {selectedDb.rawBannerHex && (
              <div className="p-3 rounded-xl bg-black/60 border border-border/40 space-y-1">
                <div className="flex items-center gap-1.5 text-muted-foreground text-[10px] font-sans">
                  <Binary className="w-3.5 h-3.5 text-blue-400" />
                  <span>Raw Protocol Greeting Banner (Hex):</span>
                </div>
                <div className="text-[11px] text-emerald-400 break-all select-text">
                  {selectedDb.rawBannerHex}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Connection Pool Saturation & Stress Analysis (Right 6 Cols) */}
        <div className="lg:col-span-6 rounded-2xl bg-card/60 border border-border/60 shadow-xl p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-border/40">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <h4 className="font-semibold text-foreground text-xs uppercase tracking-wider font-mono">
                Connection Pool Saturation & Resilience Stress
              </h4>
            </div>
            <span
              className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                selectedDb.saturation.serverGraceful
                  ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                  : 'bg-rose-500/15 text-rose-400 border-rose-500/30'
              }`}
            >
              {selectedDb.saturation.serverGraceful ? 'Graceful Rejection' : 'Socket Crash'}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-3 text-xs font-mono">
            <div className="p-3 rounded-xl bg-background/80 border border-border/40">
              <span className="text-muted-foreground block text-[10px] font-sans">
                Burst Connections
              </span>
              <span className="text-foreground font-bold text-base">
                {selectedDb.saturation.attemptedConnections} sockets
              </span>
            </div>

            <div className="p-3 rounded-xl bg-background/80 border border-border/40">
              <span className="text-muted-foreground block text-[10px] font-sans">
                Avg Connect Time
              </span>
              <span className="text-cyan-400 font-bold text-base">
                {selectedDb.saturation.avgConnectionTimeMs} ms
              </span>
            </div>

            <div className="p-3 rounded-xl bg-background/80 border border-border/40">
              <span className="text-muted-foreground block text-[10px] font-sans">
                Accepted Sockets
              </span>
              <span className="text-emerald-400 font-bold text-base">
                {selectedDb.saturation.successfulConnections}
              </span>
            </div>

            <div className="p-3 rounded-xl bg-background/80 border border-border/40">
              <span className="text-muted-foreground block text-[10px] font-sans">
                Rejected Sockets
              </span>
              <span
                className={`font-bold text-base ${
                  selectedDb.saturation.rejectedConnections > 0 ? 'text-amber-400' : 'text-foreground'
                }`}
              >
                {selectedDb.saturation.rejectedConnections}
              </span>
            </div>
          </div>

          {selectedDb.saturation.rejectionReason && (
            <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-xs font-mono text-amber-300">
              <strong>Saturation Invariant:</strong> {selectedDb.saturation.rejectionReason}
            </div>
          )}

          {/* Findings & Remediation */}
          <div className="space-y-2 pt-2">
            <span className="text-xs font-semibold text-foreground font-mono">
              Database Hardening Findings ({selectedDb.findings.length})
            </span>
            {selectedDb.findings.length === 0 ? (
              <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs flex items-center gap-2">
                <ShieldCheck className="w-4 h-4" />
                <span>Zero protocol vulnerabilities detected on this database instance.</span>
              </div>
            ) : (
              selectedDb.findings.map((f) => (
                <div
                  key={f.id}
                  className="p-3 rounded-xl bg-card border border-border/60 text-xs space-y-1.5 font-mono"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-foreground font-sans">{f.title}</span>
                    <span className="text-[10px] uppercase font-bold px-1.5 py-0.2 rounded bg-rose-500/15 text-rose-400 border border-rose-500/30">
                      {f.severity}
                    </span>
                  </div>
                  <p className="text-muted-foreground text-[11px] leading-relaxed font-sans">
                    {f.description}
                  </p>
                  <div className="flex items-start gap-1.5 text-[11px] text-blue-300 pt-1 border-t border-border/30">
                    <Terminal className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
                    <span>
                      <strong className="text-blue-400">Fix:</strong> {f.remediation}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
