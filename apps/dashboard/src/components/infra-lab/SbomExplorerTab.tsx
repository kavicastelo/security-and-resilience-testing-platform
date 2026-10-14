import React, { useState, useMemo } from 'react';
import {
  Boxes,
  Search,
  ExternalLink,
  ShieldAlert,
  ShieldCheck,
  Hash,
  ArrowRight,
  Filter,
} from 'lucide-react';
import { SbomGraphSnapshot } from '../../api/infra.js';

export interface SbomExplorerTabProps {
  sbomData: SbomGraphSnapshot;
  className?: string;
}

export const SbomExplorerTab: React.FC<SbomExplorerTabProps> = ({
  sbomData,
  className = '',
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [ecosystemFilter, setEcosystemFilter] = useState<string>('all');
  const [dependencyTypeFilter, setDependencyTypeFilter] = useState<'all' | 'direct' | 'transitive'>('all');
  const [vulnerabilityOnly, setVulnerabilityOnly] = useState(false);
  const [selectedComponentId, setSelectedComponentId] = useState<string | null>('comp-jsonwebtoken');

  // Sub-50ms instant filtering with useMemo
  const filteredComponents = useMemo(() => {
    return sbomData.components.filter((c) => {
      const query = searchQuery.trim().toLowerCase();
      const matchesSearch =
        query === '' ||
        c.name.toLowerCase().includes(query) ||
        c.purl.toLowerCase().includes(query) ||
        c.cveMatches.some((cve) => cve.id.toLowerCase().includes(query));

      const matchesEco = ecosystemFilter === 'all' || c.ecosystem === ecosystemFilter;
      const matchesDepType =
        dependencyTypeFilter === 'all' ||
        (dependencyTypeFilter === 'direct' && c.isDirect) ||
        (dependencyTypeFilter === 'transitive' && !c.isDirect);

      const matchesVuln = !vulnerabilityOnly || c.cveMatches.length > 0 || c.licenseRisk === 'CRITICAL';

      return matchesSearch && matchesEco && matchesDepType && matchesVuln;
    });
  }, [sbomData.components, searchQuery, ecosystemFilter, dependencyTypeFilter, vulnerabilityOnly]);

  const selectedComponent =
    sbomData.components.find((c) => c.id === selectedComponentId) ?? filteredComponents[0];

  const getCvssBadge = (score?: number, severity?: string) => {
    const isCritical = severity === 'critical' || (score !== undefined && score >= 9.0);
    const isHigh = severity === 'high' || (score !== undefined && score >= 7.0 && score < 9.0);

    return (
      <span
        className={`inline-flex items-center gap-1 font-mono text-[10px] font-bold px-2 py-0.5 rounded border ${
          isCritical
            ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse'
            : isHigh
            ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
            : 'bg-blue-500/20 text-blue-300 border-blue-500/40'
        }`}
      >
        <ShieldAlert className="w-3 h-3" />
        {score ? `CVSS ${score.toFixed(1)}` : severity?.toUpperCase()}
      </span>
    );
  };

  return (
    <div className={`space-y-5 ${className}`}>
      {/* Executive SBOM Header Bar */}
      <div className="p-5 rounded-2xl bg-card/60 border border-border/60 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border/40">
          <div>
            <div className="flex items-center gap-2">
              <Boxes className="w-5 h-5 text-purple-400" />
              <h3 className="font-semibold text-foreground text-sm tracking-wide">
                Software Bill of Materials (SBOM) & Supply Chain Lifecycle
              </h3>
              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
                {sbomData.format.replace('_', ' ')} v{sbomData.specVersion}
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-0.5 font-mono">
              Target: {sbomData.applicationName} v{sbomData.version} • Author: {sbomData.author}
            </p>
          </div>

          <div className="flex items-center gap-3 font-mono text-xs">
            <div className="px-3 py-1.5 rounded-xl bg-background/80 border border-border/50 text-right">
              <span className="text-muted-foreground block text-[10px] font-sans">Total Packages</span>
              <span className="text-foreground font-bold">{sbomData.totalComponents}</span>
            </div>
            <div className="px-3 py-1.5 rounded-xl bg-background/80 border border-border/50 text-right">
              <span className="text-muted-foreground block text-[10px] font-sans">Known CVEs</span>
              <span
                className={`font-bold ${
                  sbomData.criticalCveCount > 0 ? 'text-rose-400' : 'text-emerald-400'
                }`}
              >
                {sbomData.criticalCveCount + sbomData.highCveCount}
              </span>
            </div>
          </div>
        </div>

        {/* Search & Filter Controls */}
        <div className="flex flex-col md:flex-row items-center justify-between gap-3">
          {/* Real-time Sub-50ms Search Bar */}
          <div className="relative w-full md:w-80">
            <Search className="w-4 h-4 text-muted-foreground absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search component, PURL, CVE-ID..."
              className="w-full text-xs font-mono bg-background/80 border border-border/60 rounded-xl pl-9 pr-3 py-2 text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-purple-500"
            />
          </div>

          {/* Quick Filters */}
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            {/* Direct vs Transitive */}
            <div className="flex items-center gap-1 bg-background/80 p-1 rounded-xl border border-border/50 text-[11px]">
              <button
                type="button"
                onClick={() => setDependencyTypeFilter('all')}
                className={`px-2 py-0.5 rounded ${
                  dependencyTypeFilter === 'all' ? 'bg-muted text-foreground' : 'text-muted-foreground'
                }`}
              >
                All
              </button>
              <button
                type="button"
                onClick={() => setDependencyTypeFilter('direct')}
                className={`px-2 py-0.5 rounded ${
                  dependencyTypeFilter === 'direct' ? 'bg-purple-500/20 text-purple-300' : 'text-muted-foreground'
                }`}
              >
                Direct ({sbomData.directDependenciesCount})
              </button>
              <button
                type="button"
                onClick={() => setDependencyTypeFilter('transitive')}
                className={`px-2 py-0.5 rounded ${
                  dependencyTypeFilter === 'transitive' ? 'bg-purple-500/20 text-purple-300' : 'text-muted-foreground'
                }`}
              >
                Transitive ({sbomData.transitiveDependenciesCount})
              </button>
            </div>

            {/* Ecosystem Selector */}
            <select
              value={ecosystemFilter}
              onChange={(e) => setEcosystemFilter(e.target.value)}
              className="bg-background/80 border border-border/60 rounded-xl px-2.5 py-1.5 text-xs text-foreground focus:outline-none cursor-pointer"
            >
              <option value="all">All Ecosystems</option>
              <option value="npm">npm</option>
              <option value="pypi">pypi</option>
              <option value="golang">golang</option>
              <option value="maven">maven</option>
              <option value="cargo">cargo</option>
            </select>

            {/* Vulnerability Only Toggle */}
            <button
              type="button"
              onClick={() => setVulnerabilityOnly(!vulnerabilityOnly)}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl border transition-colors ${
                vulnerabilityOnly
                  ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                  : 'bg-background/80 text-muted-foreground border-border/60 hover:text-foreground'
              }`}
            >
              <Filter className="w-3 h-3" />
              <span>Vulnerable Only</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Grid: Component List & Component Detail Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Components Table (Left 7 Cols) */}
        <div className="lg:col-span-7 rounded-2xl bg-card/60 border border-border/60 shadow-xl overflow-hidden flex flex-col">
          <div className="p-3.5 bg-background/80 border-b border-border/40 text-xs font-mono text-muted-foreground flex items-center justify-between">
            <span>Showing {filteredComponents.length} packages</span>
            <span className="text-[11px] font-sans">Click row to inspect supply chain details</span>
          </div>

          <div className="overflow-x-auto max-h-[550px] overflow-y-auto divide-y divide-border/30">
            {filteredComponents.length === 0 ? (
              <div className="p-8 text-center text-muted-foreground text-xs font-mono">
                No components matched search filter &quot;{searchQuery}&quot;
              </div>
            ) : (
              filteredComponents.map((comp) => {
                const isSelected = selectedComponent?.id === comp.id;
                const hasCritical = comp.cveMatches.some((cve) => cve.severity === 'critical');
                const hasLicenseRisk = comp.licenseRisk === 'CRITICAL';

                return (
                  <div
                    key={comp.id}
                    onClick={() => setSelectedComponentId(comp.id)}
                    className={`p-3.5 flex items-center justify-between gap-3 cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-purple-500/10 border-l-4 border-l-purple-500'
                        : 'hover:bg-muted/30'
                    }`}
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-foreground text-xs font-mono">{comp.name}</span>
                        <span className="text-[11px] text-muted-foreground font-mono">v{comp.version}</span>
                        <span className="text-[9px] font-mono uppercase px-1.5 py-0.2 rounded bg-muted/60 text-muted-foreground border border-border/40">
                          {comp.ecosystem}
                        </span>
                        {comp.isDirect ? (
                          <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-purple-500/15 text-purple-400 border border-purple-500/30">
                            direct
                          </span>
                        ) : (
                          <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-muted/40 text-muted-foreground border border-border/30">
                            transitive
                          </span>
                        )}
                      </div>

                      <div className="text-[11px] text-muted-foreground font-mono truncate max-w-sm">
                        {comp.purl}
                      </div>
                    </div>

                    {/* Risk & Advisory Indicators */}
                    <div className="flex items-center gap-2 shrink-0">
                      {comp.cveMatches.length > 0 && (
                        <div className="flex items-center gap-1 font-mono text-[10px]">
                          {hasCritical ? (
                            <span className="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 animate-pulse font-bold">
                              {comp.cveMatches.length} CVEs
                            </span>
                          ) : (
                            <span className="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 font-bold">
                              {comp.cveMatches.length} CVE
                            </span>
                          )}
                        </div>
                      )}

                      {/* License Risk Tag */}
                      {hasLicenseRisk ? (
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-400 border border-rose-500/30">
                          {comp.licenses[0]} (Policy Breach)
                        </span>
                      ) : (
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          {comp.licenses.join(', ') || 'No license'}
                        </span>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Component Detail Inspector (Right 5 Cols) */}
        <div className="lg:col-span-5 rounded-2xl bg-card/60 border border-border/60 shadow-xl p-5 space-y-4">
          {selectedComponent ? (
            <>
              <div className="flex items-center justify-between pb-3 border-b border-border/40">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-foreground text-sm font-mono">
                      {selectedComponent.name}
                    </span>
                    <span className="text-xs text-muted-foreground font-mono">
                      v{selectedComponent.version}
                    </span>
                  </div>
                  <span className="text-[10px] text-muted-foreground font-mono">
                    {selectedComponent.ecosystem} ecosystem
                  </span>
                </div>

                {selectedComponent.cveMatches.length > 0 ? (
                  <span className="px-2 py-0.5 rounded bg-rose-500/15 text-rose-400 border border-rose-500/30 text-xs font-mono font-bold">
                    Vulnerable
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 text-xs font-mono font-bold">
                    Advisories Clean
                  </span>
                )}
              </div>

              {/* Package URL & Metadata */}
              <div className="p-3 rounded-xl bg-background/80 border border-border/40 space-y-2 text-xs font-mono">
                <div>
                  <span className="text-muted-foreground text-[10px] block font-sans">Package URL (PURL)</span>
                  <span className="text-foreground text-[11px] break-all">{selectedComponent.purl}</span>
                </div>
                <div>
                  <span className="text-muted-foreground text-[10px] block font-sans">License Concluded</span>
                  <span
                    className={`font-semibold ${
                      selectedComponent.licenseRisk === 'CRITICAL'
                        ? 'text-rose-400'
                        : 'text-emerald-400'
                    }`}
                  >
                    {selectedComponent.licenses.join(', ') || 'Unspecified'}
                  </span>
                  {selectedComponent.licenseViolationReason && (
                    <p className="text-[10px] text-rose-300 font-sans mt-0.5">
                      ⚠️ {selectedComponent.licenseViolationReason}
                    </p>
                  )}
                </div>
              </div>

              {/* Hashes & Integrity */}
              {selectedComponent.hashes && (
                <div className="space-y-1 text-xs font-mono">
                  <span className="text-muted-foreground text-[10px] flex items-center gap-1 font-sans">
                    <Hash className="w-3 h-3" />
                    Cryptographic Integrity Hashes
                  </span>
                  {Object.entries(selectedComponent.hashes).map(([algo, hash]) => (
                    <div
                      key={algo}
                      className="p-2 rounded-lg bg-black/40 border border-border/30 text-[10px] text-muted-foreground break-all"
                    >
                      <strong className="text-foreground uppercase">{algo}:</strong> {hash}
                    </div>
                  ))}
                </div>
              )}

              {/* Correlated CVE Advisory Matches */}
              <div className="space-y-2">
                <span className="text-xs font-semibold text-foreground flex items-center justify-between">
                  <span>Correlated Vulnerabilities ({selectedComponent.cveMatches.length})</span>
                  <span className="text-[10px] text-muted-foreground font-mono">Source: OSV / NVD</span>
                </span>

                {selectedComponent.cveMatches.length === 0 ? (
                  <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4" />
                    <span>No known CVE advisories affecting version {selectedComponent.version}.</span>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {selectedComponent.cveMatches.map((cve) => (
                      <div
                        key={cve.id}
                        className="p-3.5 rounded-xl bg-card border border-border/60 space-y-2 text-xs"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-bold text-foreground font-mono flex items-center gap-1.5">
                            {cve.id}
                            {cve.referenceUrls[0] && (
                              <a
                                href={cve.referenceUrls[0]}
                                target="_blank"
                                rel="noreferrer"
                                className="text-blue-400 hover:text-blue-300 inline-block"
                              >
                                <ExternalLink className="w-3 h-3" />
                              </a>
                            )}
                          </span>
                          {getCvssBadge(cve.cvssScore, cve.severity)}
                        </div>

                        <p className="text-muted-foreground text-[11px] leading-relaxed">
                          {cve.summary}
                        </p>

                        {/* Recommendation / Fixed Version */}
                        {cve.fixedVersion && (
                          <div className="flex items-center gap-1.5 pt-1 border-t border-border/30 text-[11px] font-mono text-emerald-400">
                            <ArrowRight className="w-3.5 h-3.5" />
                            <span>Remediation: Upgrade to &gt;= v{cve.fixedVersion}</span>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="p-8 text-center text-muted-foreground text-xs font-mono">
              Select a component to inspect supply chain details
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
