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
  Upload,
  FileCode,
  CheckCircle,
  AlertCircle,
  X,
  FileText,
} from 'lucide-react';
import {
  InfraStudioOverviewSnapshot,
  fetchInfraStudioOverview,
  auditKubernetesManifest,
  auditSbomDocument,
  probeHttpSmuggling,
  auditDatabaseSecurity,
  EXAMPLE_K8S_AUDIT,
  EXAMPLE_SBOM_GRAPH,
  EXAMPLE_SMUGGLING_SNAPSHOT,
  EXAMPLE_DATABASE_SECURITY,
  EMPTY_INFRA_OVERVIEW,
} from '../../api/infra.js';
import { KubernetesAuditTab } from './KubernetesAuditTab.js';
import { SbomExplorerTab } from './SbomExplorerTab.js';
import { HttpSmugglingWireTab } from './HttpSmugglingWireTab.js';
import { DatabaseProtocolTab } from './DatabaseProtocolTab.js';

const SAMPLE_K8S_YAML = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-gateway
  namespace: production-core
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: gateway
          image: nginx:1.25.0
          securityContext:
            privileged: true
            runAsRoot: true
          resources:
            limits:
              cpu: "1"
              memory: "512Mi"
`;

const SAMPLE_SBOM_JSON = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "component": {
      "name": "production-service",
      "version": "1.0.0"
    }
  },
  "components": [
    {
      "name": "jsonwebtoken",
      "version": "8.5.1",
      "purl": "pkg:npm/jsonwebtoken@8.5.1",
      "licenses": [{ "license": { "id": "MIT" } }]
    },
    {
      "name": "axios",
      "version": "1.6.0",
      "purl": "pkg:npm/axios@1.6.0",
      "licenses": [{ "license": { "id": "MIT" } }]
    },
    {
      "name": "internal-exporter-daemon",
      "version": "2.1.0",
      "purl": "pkg:npm/internal-exporter-daemon@2.1.0",
      "licenses": [{ "license": { "id": "AGPL-3.0-only" } }]
    }
  ]
}`;

export const InfraSupplyChainView: React.FC = () => {
  const [data, setData] = useState<InfraStudioOverviewSnapshot | null>(null);
  const [activeTab, setActiveTab] = useState<'k8s' | 'sbom' | 'smuggling' | 'db'>('k8s');
  const [isLoading, setIsLoading] = useState(true);
  const [isScanning, setIsScanning] = useState(false);
  const [showAuditModal, setShowAuditModal] = useState(false);
  const [modalTab, setModalTab] = useState<'k8s' | 'sbom' | 'smuggling' | 'db'>('k8s');

  // Modal form inputs
  const [k8sInput, setK8sInput] = useState('');
  const [sbomInput, setSbomInput] = useState('');
  const [targetUrlInput, setTargetUrlInput] = useState('http://localhost:3000');
  const [dbEngineInput, setDbEngineInput] = useState<'postgres' | 'mysql' | 'redis'>('postgres');
  const [dbConnInput, setDbConnInput] = useState('postgres://postgres:postgres@localhost:5432/security_lab');
  const [auditError, setAuditError] = useState<string | null>(null);

  useEffect(() => {
    const loadOverview = async () => {
      setIsLoading(true);
      const res = await fetchInfraStudioOverview();
      setData(res);
      setIsLoading(false);
    };

    loadOverview();
  }, []);

  const isCleanEmpty =
    !data ||
    (data.k8s.totalWorkloads === 0 &&
      data.sbom.totalComponents === 0 &&
      data.smuggling.testedVariantsCount === 0 &&
      data.database.totalDatabasesChecked === 0);

  const handleLoadDemoDataset = () => {
    setData({
      k8s: EXAMPLE_K8S_AUDIT,
      sbom: EXAMPLE_SBOM_GRAPH,
      smuggling: EXAMPLE_SMUGGLING_SNAPSHOT,
      database: EXAMPLE_DATABASE_SECURITY,
    });
  };

  const handleRunModalAudit = async () => {
    if (isScanning) return;
    setIsScanning(true);
    setAuditError(null);

    try {
      if (modalTab === 'k8s') {
        const result = await auditKubernetesManifest(k8sInput || SAMPLE_K8S_YAML);
        setData((prev) => ({
          ...(prev || EMPTY_INFRA_OVERVIEW),
          k8s: result,
        }));
        setActiveTab('k8s');
      } else if (modalTab === 'sbom') {
        const result = await auditSbomDocument(sbomInput || SAMPLE_SBOM_JSON, 'cyclonedx');
        setData((prev) => ({
          ...(prev || EMPTY_INFRA_OVERVIEW),
          sbom: result,
        }));
        setActiveTab('sbom');
      } else if (modalTab === 'smuggling') {
        const result = await probeHttpSmuggling(targetUrlInput, ['CL_TE', 'TE_CL', 'TE_TE']);
        setData((prev) => ({
          ...(prev || EMPTY_INFRA_OVERVIEW),
          smuggling: result,
        }));
        setActiveTab('smuggling');
      } else if (modalTab === 'db') {
        const result = await auditDatabaseSecurity({
          engine: dbEngineInput,
          connectionString: dbConnInput,
        });
        setData((prev) => ({
          ...(prev || EMPTY_INFRA_OVERVIEW),
          database: result,
        }));
        setActiveTab('db');
      }
      setShowAuditModal(false);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Audit execution failed';
      setAuditError(msg);
    } finally {
      setIsScanning(false);
    }
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
                  Production Engine
                </span>
              </h1>
              <div className="flex items-center gap-3 text-xs text-muted-foreground font-mono mt-0.5">
                <span className="flex items-center gap-1">
                  <Globe className="w-3.5 h-3.5 text-blue-400" />
                  Cluster: {data.k8s.clusterName.slice(0, 32)}
                </span>
                <span>•</span>
                <span>4 Native Infrastructure Engines Connected</span>
              </div>
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => {
              setModalTab(activeTab);
              setShowAuditModal(true);
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white shadow-lg shadow-blue-500/20 transition-all"
          >
            <Play className="w-3.5 h-3.5" />
            <span>Launch Audit / Probe</span>
          </button>

          {isCleanEmpty && (
            <button
              type="button"
              onClick={handleLoadDemoDataset}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium bg-purple-500/15 hover:bg-purple-500/25 text-purple-300 border border-purple-500/30 transition-colors"
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>Load Example Dataset</span>
            </button>
          )}

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

      {/* Clean Environment Banner if zero audits run */}
      {isCleanEmpty ? (
        <div className="p-8 rounded-2xl bg-card/60 border border-border/60 shadow-xl text-center space-y-4">
          <div className="p-3 w-12 h-12 rounded-2xl bg-blue-500/10 text-blue-400 border border-blue-500/20 mx-auto flex items-center justify-center">
            <Boxes className="w-6 h-6" />
          </div>
          <div className="space-y-1">
            <h3 className="text-base font-semibold text-foreground">No Infrastructure Audits Run Yet</h3>
            <p className="text-xs text-muted-foreground max-w-lg mx-auto">
              Your active workspace has 0 detected infrastructure defects. Upload a Kubernetes manifest, parse an SBOM, probe HTTP desync vectors, or test database transport security.
            </p>
          </div>
          <div className="flex items-center justify-center gap-3 pt-2">
            <button
              type="button"
              onClick={() => {
                setModalTab('k8s');
                setShowAuditModal(true);
              }}
              className="px-4 py-2 rounded-xl text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-500/20 transition-all flex items-center gap-1.5"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Audit Kubernetes Manifest</span>
            </button>
            <button
              type="button"
              onClick={handleLoadDemoDataset}
              className="px-4 py-2 rounded-xl text-xs font-medium bg-card hover:bg-card/80 text-foreground border border-border/60 transition-colors flex items-center gap-1.5"
            >
              <FileCode className="w-3.5 h-3.5 text-purple-400" />
              <span>Explore Example Dataset</span>
            </button>
          </div>
        </div>
      ) : (
        <>
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
                <span className="text-xs font-normal text-muted-foreground">
                  {data.k8s.totalWorkloads > 0 ? 'Restricted' : 'Clean'}
                </span>
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
                Across {data.sbom.totalComponents} packages ({data.sbom.licenseViolationsCount} license breaches)
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
                {data.smuggling.testedVariantsCount} wire variants probed
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
        </>
      )}

      {/* Modal Dialog for Launching Audits & Probes */}
      {showAuditModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="bg-card border border-border/80 rounded-2xl w-full max-w-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
            <div className="flex items-center justify-between p-4 border-b border-border/50">
              <div className="flex items-center gap-2">
                <Play className="w-4 h-4 text-blue-400" />
                <h3 className="font-semibold text-sm text-foreground">Launch Infrastructure Audit / Probe</h3>
              </div>
              <button
                type="button"
                onClick={() => setShowAuditModal(false)}
                className="text-muted-foreground hover:text-foreground"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Tabs */}
            <div className="flex border-b border-border/40 p-2 gap-2 text-xs font-medium bg-background/50">
              <button
                type="button"
                onClick={() => setModalTab('k8s')}
                className={`px-2.5 py-1 rounded-lg ${modalTab === 'k8s' ? 'bg-blue-500/15 text-blue-300 font-semibold' : 'text-muted-foreground'}`}
              >
                Kubernetes
              </button>
              <button
                type="button"
                onClick={() => setModalTab('sbom')}
                className={`px-2.5 py-1 rounded-lg ${modalTab === 'sbom' ? 'bg-purple-500/15 text-purple-300 font-semibold' : 'text-muted-foreground'}`}
              >
                SBOM
              </button>
              <button
                type="button"
                onClick={() => setModalTab('smuggling')}
                className={`px-2.5 py-1 rounded-lg ${modalTab === 'smuggling' ? 'bg-amber-500/15 text-amber-300 font-semibold' : 'text-muted-foreground'}`}
              >
                HTTP Smuggling
              </button>
              <button
                type="button"
                onClick={() => setModalTab('db')}
                className={`px-2.5 py-1 rounded-lg ${modalTab === 'db' ? 'bg-emerald-500/15 text-emerald-300 font-semibold' : 'text-muted-foreground'}`}
              >
                Database
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-4 space-y-3 overflow-y-auto flex-1">
              {auditError && (
                <div className="p-3 rounded-xl bg-rose-500/15 border border-rose-500/30 text-xs text-rose-300 flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  <span>{auditError}</span>
                </div>
              )}

              {modalTab === 'k8s' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground">Manifest YAML / Pod Spec</span>
                    <button
                      type="button"
                      onClick={() => setK8sInput(SAMPLE_K8S_YAML)}
                      className="text-blue-400 hover:text-blue-300 flex items-center gap-1 font-mono text-[11px]"
                    >
                      <FileText className="w-3 h-3" />
                      Load Example Kubernetes Manifest
                    </button>
                  </div>
                  <textarea
                    value={k8sInput}
                    onChange={(e) => setK8sInput(e.target.value)}
                    placeholder="Paste Kubernetes Deployment, Pod, or DaemonSet YAML..."
                    rows={8}
                    className="w-full p-2.5 rounded-xl bg-background border border-border/60 text-xs font-mono text-foreground focus:outline-none focus:border-blue-500 resize-none"
                  />
                </div>
              )}

              {modalTab === 'sbom' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground">CycloneDX / SPDX JSON</span>
                    <button
                      type="button"
                      onClick={() => setSbomInput(SAMPLE_SBOM_JSON)}
                      className="text-purple-400 hover:text-purple-300 flex items-center gap-1 font-mono text-[11px]"
                    >
                      <FileText className="w-3 h-3" />
                      Load Example CycloneDX SBOM
                    </button>
                  </div>
                  <textarea
                    value={sbomInput}
                    onChange={(e) => setSbomInput(e.target.value)}
                    placeholder="Paste CycloneDX or SPDX JSON document..."
                    rows={8}
                    className="w-full p-2.5 rounded-xl bg-background border border-border/60 text-xs font-mono text-foreground focus:outline-none focus:border-purple-500 resize-none"
                  />
                </div>
              )}

              {modalTab === 'smuggling' && (
                <div className="space-y-3 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Target URL</span>
                    <button
                      type="button"
                      onClick={() => setTargetUrlInput('http://localhost:3000')}
                      className="text-amber-400 hover:text-amber-300 font-mono text-[11px]"
                    >
                      Load Example Target
                    </button>
                  </div>
                  <input
                    type="text"
                    value={targetUrlInput}
                    onChange={(e) => setTargetUrlInput(e.target.value)}
                    placeholder="http://localhost:3000"
                    className="w-full p-2 rounded-xl bg-background border border-border/60 text-xs font-mono text-foreground"
                  />
                  <p className="text-[11px] text-muted-foreground">
                    Engine probes CL.TE, TE.CL, and TE.TE socket vectors and measures timing differential desyncs.
                  </p>
                </div>
              )}

              {modalTab === 'db' && (
                <div className="space-y-3 text-xs">
                  <div>
                    <label className="text-muted-foreground block mb-1">Database Engine</label>
                    <select
                      value={dbEngineInput}
                      onChange={(e) => setDbEngineInput(e.target.value as any)}
                      className="w-full p-2 rounded-xl bg-background border border-border/60 text-xs font-mono text-foreground"
                    >
                      <option value="postgres">PostgreSQL</option>
                      <option value="mysql">MySQL</option>
                      <option value="redis">Redis</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-muted-foreground block mb-1">Connection String / Target</label>
                    <input
                      type="text"
                      value={dbConnInput}
                      onChange={(e) => setDbConnInput(e.target.value)}
                      placeholder="postgres://user:pass@localhost:5432/db"
                      className="w-full p-2 rounded-xl bg-background border border-border/60 text-xs font-mono text-foreground"
                    />
                  </div>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-border/50 flex items-center justify-end gap-2 bg-background/50">
              <button
                type="button"
                onClick={() => setShowAuditModal(false)}
                className="px-3 py-1.5 rounded-xl text-xs font-medium bg-background text-foreground border border-border/60"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleRunModalAudit}
                disabled={isScanning}
                className="px-4 py-1.5 rounded-xl text-xs font-semibold bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white shadow-lg shadow-blue-500/20 disabled:opacity-50 flex items-center gap-1.5"
              >
                {isScanning ? (
                  <>
                    <RotateCcw className="w-3.5 h-3.5 animate-spin" />
                    <span>Executing Audit...</span>
                  </>
                ) : (
                  <>
                    <CheckCircle className="w-3.5 h-3.5" />
                    <span>Execute Audit</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
