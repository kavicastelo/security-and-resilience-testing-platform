import React, { useState, useEffect } from 'react';
import {
  Boxes,
  Server,
  Zap,
  Database,
  Activity,
  Download,
  RotateCcw,
  Play,
  Globe,
} from 'lucide-react';
import {
  InfraStudioOverviewSnapshot,
  fetchInfraStudioOverview,
} from '../../api/infra.js';
import { KubernetesAuditTab } from './KubernetesAuditTab.js';
import { SbomExplorerTab } from './SbomExplorerTab.js';
import { HttpSmugglingWireTab } from './HttpSmugglingWireTab.js';
import { DatabaseProtocolTab } from './DatabaseProtocolTab.js';

export const InfraSupplyChainView: React.FC = () => {
  const [data, setData] = useState<InfraStudioOverviewSnapshot | null>(null);
  const [activeTab, setActiveTab] = useState<'k8s' | 'sbom' | 'smuggling' | 'db'>('k8s');
  const [isLoading, setIsLoading] = useState(true);
  const [isScanning, setIsScanning] = useState(false);

  useEffect(() => {
    const loadOverview = async () => {
      setIsLoading(true);
      const res = await fetchInfraStudioOverview();
      setData(res);
      setIsLoading(false);
    };

    loadOverview();
  }, []);

  const handleTriggerScan = () => {
    if (isScanning) return;
    setIsScanning(true);
    setTimeout(() => {
      setIsScanning(false);
    }, 1500);
  };

  const handleExportAudit = () => {
    if (!data) return;
    const reportData = {
      title: 'Infrastructure & Software Supply Chain Comprehensive Audit',
      timestamp: new Date().toISOString(),
      kubernetesAudit: {
        cluster: data.k8s.clusterName,
        complianceScore: `${data.k8s.overallComplianceScore}%`,
        workloads: data.k8s.workloads.length,
        pssDistribution: data.k8s.pssDistribution,
      },
      sbomSupplyChain: {
        application: data.sbom.applicationName,
        version: data.sbom.version,
        componentsCount: data.sbom.totalComponents,
        vulnerabilities: {
          critical: data.sbom.criticalCveCount,
          high: data.sbom.highCveCount,
        },
      },
      smugglingWireSecurity: {
        target: `${data.smuggling.targetHost}:${data.smuggling.targetPort}`,
        reverseProxy: data.smuggling.reverseProxyType,
        backendServer: data.smuggling.backendServerType,
        vulnerabilitiesDetected: data.smuggling.vulnerableCount,
      },
      databaseProtocolSecurity: {
        databasesProbed: data.database.totalDatabasesChecked,
        unencryptedWireCount: data.database.unencryptedCount,
        unauthenticatedCount: data.database.unauthenticatedCount,
      },
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `infra-supply-chain-audit-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (isLoading || !data) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] space-y-3">
        <Activity className="w-8 h-8 text-blue-400 animate-spin" />
        <p className="text-sm font-mono text-muted-foreground">
          Loading Infrastructure & Software Supply Chain Console...
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Console Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-2xl bg-card/60 border border-border/60 shadow-xl backdrop-blur-md">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20">
              <Boxes className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
                Infrastructure K8s & SBOM Supply Chain Studio
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-normal">
                  Phase UI-11
                </span>
              </h1>
              <div className="flex items-center gap-3 text-xs text-muted-foreground font-mono mt-0.5">
                <span className="flex items-center gap-1">
                  <Globe className="w-3.5 h-3.5 text-blue-400" />
                  Cluster: {data.k8s.clusterName.slice(0, 32)}...
                </span>
                <span>•</span>
                <span>4 Infrastructure Engines Integrated</span>
              </div>
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={handleTriggerScan}
            disabled={isScanning}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold shadow-lg transition-all ${
              isScanning
                ? 'bg-blue-500/20 text-blue-300 border border-blue-500/40 cursor-wait'
                : 'bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white shadow-blue-500/20'
            }`}
          >
            {isScanning ? (
              <>
                <RotateCcw className="w-3.5 h-3.5 animate-spin" />
                <span>Scanning Infrastructure...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                <span>Run Full Infra Audit</span>
              </>
            )}
          </button>

          <button
            type="button"
            onClick={handleExportAudit}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium bg-background/80 hover:bg-background text-foreground border border-border/60 transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-muted-foreground" />
            <span>Export Audit</span>
          </button>
        </div>
      </div>

      {/* Top Executive Summary Scorecards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* Kubernetes PSS Score */}
        <div className="p-4 rounded-2xl bg-card/60 border border-border/60 shadow-lg space-y-1">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>K8s PSS Posture</span>
            <Server className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">
            {data.k8s.overallComplianceScore}%{' '}
            <span className="text-xs font-normal text-muted-foreground">Restricted</span>
          </div>
          <p className="text-[11px] text-muted-foreground font-mono">
            {data.k8s.criticalFindingsCount} critical misconfigurations
          </p>
        </div>

        {/* SBOM Supply Chain */}
        <div className="p-4 rounded-2xl bg-card/60 border border-border/60 shadow-lg space-y-1">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Supply Chain Vulnerabilities</span>
            <Boxes className="w-4 h-4 text-purple-400" />
          </div>
          <div
            className={`text-2xl font-bold font-mono ${
              data.sbom.criticalCveCount > 0 ? 'text-rose-400' : 'text-emerald-400'
            }`}
          >
            {data.sbom.criticalCveCount}{' '}
            <span className="text-xs font-normal text-muted-foreground">Critical CVEs</span>
          </div>
          <p className="text-[11px] text-muted-foreground font-mono">
            Across {data.sbom.totalComponents} packages (1 license breach)
          </p>
        </div>

        {/* HTTP Smuggling Desync */}
        <div className="p-4 rounded-2xl bg-card/60 border border-border/60 shadow-lg space-y-1">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>HTTP Desync Risk</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div
            className={`text-2xl font-bold font-mono ${
              data.smuggling.vulnerableCount > 0 ? 'text-rose-400' : 'text-emerald-400'
            }`}
          >
            {data.smuggling.vulnerableCount}{' '}
            <span className="text-xs font-normal text-muted-foreground">Desync Flaws</span>
          </div>
          <p className="text-[11px] text-muted-foreground font-mono">
            CL.TE & TE.CL socket vectors confirmed
          </p>
        </div>

        {/* Database Protocols */}
        <div className="p-4 rounded-2xl bg-card/60 border border-border/60 shadow-lg space-y-1">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Database Wire Security</span>
            <Database className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-foreground">
            {data.database.totalDatabasesChecked}{' '}
            <span className="text-xs font-normal text-muted-foreground">Engines Probed</span>
          </div>
          <p className="text-[11px] text-muted-foreground font-mono">
            {data.database.unencryptedCount} cleartext, {data.database.unauthenticatedCount} open Redis
          </p>
        </div>
      </div>

      {/* Navigation Tab Bar */}
      <div className="flex items-center gap-2 border-b border-border/40 pb-2 text-xs font-medium overflow-x-auto">
        <button
          type="button"
          onClick={() => setActiveTab('k8s')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-colors shrink-0 ${
            activeTab === 'k8s'
              ? 'bg-blue-500/15 text-blue-300 border border-blue-500/30'
              : 'text-muted-foreground hover:text-foreground'
          }`}
        >
          <Server className="w-3.5 h-3.5" />
          <span>Kubernetes Workloads & PSS</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('sbom')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-colors shrink-0 ${
            activeTab === 'sbom'
              ? 'bg-purple-500/15 text-purple-300 border border-purple-500/30'
              : 'text-muted-foreground hover:text-foreground'
          }`}
        >
          <Boxes className="w-3.5 h-3.5" />
          <span>SBOM & Dependency Explorer</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('smuggling')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-colors shrink-0 ${
            activeTab === 'smuggling'
              ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
              : 'text-muted-foreground hover:text-foreground'
          }`}
        >
          <Zap className="w-3.5 h-3.5" />
          <span>HTTP Smuggling Wire Inspector</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('db')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-colors shrink-0 ${
            activeTab === 'db'
              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
              : 'text-muted-foreground hover:text-foreground'
          }`}
        >
          <Database className="w-3.5 h-3.5" />
          <span>Database Protocols & Saturation</span>
        </button>
      </div>

      {/* Active Tab View */}
      {activeTab === 'k8s' && <KubernetesAuditTab auditData={data.k8s} />}
      {activeTab === 'sbom' && <SbomExplorerTab sbomData={data.sbom} />}
      {activeTab === 'smuggling' && <HttpSmugglingWireTab smugglingData={data.smuggling} />}
      {activeTab === 'db' && <DatabaseProtocolTab databaseData={data.database} />}
    </div>
  );
};
