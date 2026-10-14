import React, { useState, useEffect } from 'react';
import {
  FrameworkId,
  OverallComplianceReport,
  fetchComplianceAssessment,
  COMPLIANCE_DISCLAIMER,
} from '../../api/reports.js';
import { ComplianceRadarChart } from './ComplianceRadarChart.js';
import { FrameworkMappingTable } from './FrameworkMappingTable.js';
import { ReportGeneratorModal } from './ReportGeneratorModal.js';
import {
  ShieldCheck,
  ShieldAlert,
  FileSpreadsheet,
  Download,
  RefreshCw,
  Layers,
  Scale,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Info,
} from 'lucide-react';

export const ComplianceCenterView: React.FC = () => {
  const [selectedFramework, setSelectedFramework] = useState<FrameworkId>('OWASP_TOP_10_2021');
  const [selectedCategoryId, setSelectedCategoryId] = useState<string | undefined>();
  const [reportData, setReportData] = useState<OverallComplianceReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [selectedRunId, setSelectedRunId] = useState<string>('run-live-01');

  // Load compliance assessment on mount
  const loadData = async (runId?: string) => {
    setLoading(true);
    try {
      const data = await fetchComplianceAssessment(runId);
      setReportData(data);
    } catch {
      // Fallback handled in API client
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData(selectedRunId);
  }, [selectedRunId]);

  const activeAssessment = reportData?.frameworks[selectedFramework];

  const frameworksList: Array<{ id: FrameworkId; label: string; badge: string }> = [
    { id: 'OWASP_TOP_10_2021', label: 'OWASP Top 10 (2021)', badge: 'Web App' },
    { id: 'OWASP_API_2023', label: 'OWASP API Security', badge: 'API 2023' },
    { id: 'OWASP_ASVS_4_0', label: 'OWASP ASVS 4.0', badge: 'L1 - L3' },
    { id: 'PCI_DSS_4_0', label: 'PCI-DSS 4.0 (Req 6)', badge: 'Payment' },
  ];

  const getStatusBadge = (status: 'PASS' | 'FAIL' | 'NEEDS_REVIEW') => {
    switch (status) {
      case 'PASS':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-4 h-4" /> PASS
          </span>
        );
      case 'FAIL':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <ShieldAlert className="w-4 h-4" /> VIOLATIONS DETECTED
          </span>
        );
      case 'NEEDS_REVIEW':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-4 h-4" /> NEEDS REVIEW
          </span>
        );
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* View Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-border">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-primary/10 border border-primary/20 text-primary">
              <FileSpreadsheet className="w-5 h-5" />
            </div>
            <h1 className="text-xl font-bold tracking-tight text-foreground">
              Enterprise Compliance Center & Standards Mapping
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 font-mono">
              OWASP &bull; ASVS &bull; PCI-DSS
            </span>
          </div>
          <p className="text-xs text-muted-foreground max-w-3xl">
            Live compliance scorecards against OWASP Top 10, ASVS 4.0, and PCI-DSS 4.0. Generates zero-dependency executive PDFs, standalone offline HTML audits, and SARIF 2.1 scans.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          {/* Run Selector */}
          <div className="flex items-center gap-1.5 bg-card border border-border px-2.5 py-1.5 rounded-lg text-xs">
            <Activity className="w-3.5 h-3.5 text-muted-foreground" />
            <select
              value={selectedRunId}
              onChange={(e) => setSelectedRunId(e.target.value)}
              aria-label="Select Test Run Scope"
              className="bg-transparent border-none text-foreground font-mono text-xs focus:outline-none cursor-pointer"
            >
              <option value="run-live-01">Run: run-live-01 (Latest Scan)</option>
              <option value="run-prod-baseline">Run: run-prod-baseline (Nightly)</option>
              <option value="run-api-gateway">Run: run-api-gateway (Fuzzing)</option>
            </select>
          </div>

          <button
            type="button"
            onClick={() => loadData(selectedRunId)}
            className="p-2 rounded-lg bg-card border border-border text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
            title="Refresh Compliance Assessment"
            aria-label="Refresh Data"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-primary' : ''}`} />
          </button>

          <button
            type="button"
            onClick={() => setIsReportModalOpen(true)}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary hover:bg-primary/90 text-primary-foreground text-xs font-bold shadow-lg transition-all"
          >
            <Download className="w-4 h-4" />
            Generate & Export Report
          </button>
        </div>
      </div>

      {/* KPI Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Compliance Percentage Index */}
        <div className="p-4 rounded-xl bg-card border border-border shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-muted-foreground text-xs">
            <span className="font-semibold">Framework Posture</span>
            <Scale className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-3">
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold font-mono text-foreground">
                {activeAssessment ? `${activeAssessment.compliancePercentage}%` : '...'}
              </span>
              <span className="text-xs text-muted-foreground">compliant</span>
            </div>
            {/* Progress bar */}
            <div className="w-full h-1.5 bg-muted rounded-full mt-2 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-full transition-all duration-500"
                style={{ width: `${activeAssessment?.compliancePercentage || 0}%` }}
              />
            </div>
          </div>
        </div>

        {/* Evaluated Controls */}
        <div className="p-4 rounded-xl bg-card border border-border shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-muted-foreground text-xs">
            <span className="font-semibold">Evaluated Controls</span>
            <Layers className="w-4 h-4 text-primary" />
          </div>
          <div className="mt-3">
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold font-mono text-foreground">
                {activeAssessment
                  ? `${activeAssessment.compliantControlsCount} / ${activeAssessment.totalControlsEvaluated}`
                  : '...'}
              </span>
              <span className="text-xs text-emerald-400 font-medium">passed</span>
            </div>
            <p className="text-[11px] text-muted-foreground mt-1">
              Active verification rules applied
            </p>
          </div>
        </div>

        {/* Violations Count */}
        <div className="p-4 rounded-xl bg-card border border-border shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-muted-foreground text-xs">
            <span className="font-semibold">Active Violations</span>
            <ShieldAlert className="w-4 h-4 text-rose-500" />
          </div>
          <div className="mt-3">
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold font-mono text-rose-400">
                {activeAssessment ? activeAssessment.nonCompliantControlsCount : '0'}
              </span>
              <span className="text-xs text-muted-foreground">categories non-compliant</span>
            </div>
            <p className="text-[11px] text-muted-foreground mt-1">
              {reportData?.countsBySeverity.critical || 0} Critical &bull; {reportData?.countsBySeverity.high || 0} High
            </p>
          </div>
        </div>

        {/* Audit Readiness */}
        <div className="p-4 rounded-xl bg-card border border-border shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-muted-foreground text-xs">
            <span className="font-semibold">Audit Posture</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-3">
            <div>
              {activeAssessment ? getStatusBadge(activeAssessment.overallStatus) : '...'}
            </div>
            <p className="text-[11px] text-muted-foreground mt-2">
              {selectedFramework === 'OWASP_TOP_10_2021'
                ? 'Standard 2021 Revision'
                : selectedFramework === 'OWASP_API_2023'
                ? '2023 API Taxonomy'
                : selectedFramework === 'OWASP_ASVS_4_0'
                ? 'ASVS v4.0.3 Verification'
                : 'Section 6 Application Controls'}
            </p>
          </div>
        </div>
      </div>

      {/* Framework Selector Tabs */}
      <div className="flex items-center gap-2 border-b border-border overflow-x-auto pb-1">
        {frameworksList.map((fw) => {
          const isActive = selectedFramework === fw.id;
          return (
            <button
              key={fw.id}
              type="button"
              onClick={() => {
                setSelectedFramework(fw.id);
                setSelectedCategoryId(undefined);
              }}
              className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-all whitespace-nowrap border-b-2 ${
                isActive
                  ? 'border-primary text-foreground bg-card'
                  : 'border-transparent text-muted-foreground hover:text-foreground hover:bg-muted/40'
              }`}
            >
              <span>{fw.label}</span>
              <span
                className={`px-1.5 py-0.2 rounded text-[10px] font-mono ${
                  isActive
                    ? 'bg-primary/20 text-primary'
                    : 'bg-muted text-muted-foreground'
                }`}
              >
                {fw.badge}
              </span>
            </button>
          );
        })}
      </div>

      {/* Middle Section: Spider/Radar Chart & Category Progress Meter */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Radar Spider Chart */}
        <div className="lg:col-span-6 p-5 rounded-2xl bg-card border border-border shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between pb-3 border-b border-border">
            <div>
              <h3 className="text-xs font-bold text-foreground flex items-center gap-2">
                <Scale className="w-4 h-4 text-cyan-400" />
                Category Coverage Radar & Spider Graph
              </h3>
              <p className="text-[11px] text-muted-foreground mt-0.5">
                Multi-axis visual mapping of compliance density across all categories
              </p>
            </div>
            {selectedCategoryId && (
              <button
                type="button"
                onClick={() => setSelectedCategoryId(undefined)}
                className="text-[11px] text-cyan-400 hover:underline"
              >
                Reset Focus
              </button>
            )}
          </div>

          <div className="py-4 flex-1 flex items-center justify-center">
            {activeAssessment && (
              <ComplianceRadarChart
                categories={activeAssessment.categories}
                selectedCategoryId={selectedCategoryId}
                onSelectCategory={(id) => setSelectedCategoryId(id)}
              />
            )}
          </div>
        </div>

        {/* Right: Category Progress Bars List */}
        <div className="lg:col-span-6 p-5 rounded-2xl bg-card border border-border shadow-sm flex flex-col justify-between">
          <div className="pb-3 border-b border-border">
            <h3 className="text-xs font-bold text-foreground flex items-center gap-2">
              <Layers className="w-4 h-4 text-primary" />
              Category Control Posture Summary ({activeAssessment?.categories.length || 0})
            </h3>
            <p className="text-[11px] text-muted-foreground mt-0.5">
              Passing controls and active violation distribution per category
            </p>
          </div>

          <div className="divide-y divide-border/60 overflow-y-auto max-h-[360px] pr-1 py-1 space-y-2">
            {activeAssessment?.categories.map((cat) => {
              const isSelected = selectedCategoryId === cat.id;
              const isCompliant = cat.status === 'COMPLIANT';

              return (
                <div
                  key={cat.id}
                  onClick={() => setSelectedCategoryId(cat.id)}
                  className={`pt-2 pb-2 px-3 rounded-lg cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-cyan-500/10 border border-cyan-500/30'
                      : 'hover:bg-muted/30 border border-transparent'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs mb-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-primary text-[11px]">
                        {cat.id}
                      </span>
                      <span className="font-semibold text-foreground text-xs truncate max-w-[220px]">
                        {cat.name}
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      {isCompliant ? (
                        <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400">
                          100% Pass
                        </span>
                      ) : (
                        <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-400">
                          {cat.findingsCount} Violation(s)
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Progress bar */}
                  <div className="w-full h-1.5 bg-muted rounded-full overflow-hidden mt-1.5">
                    <div
                      className={`h-full rounded-full transition-all duration-300 ${
                        isCompliant ? 'bg-emerald-400' : 'bg-rose-500'
                      }`}
                      style={{
                        width: isCompliant ? '100%' : `${Math.max(25, 100 - cat.findingsCount * 25)}%`,
                      }}
                    />
                  </div>

                  <div className="flex items-center justify-between text-[10px] text-muted-foreground mt-1">
                    <span className="font-mono">Evidence: {cat.demonstrationLevel}</span>
                    <span>CWEs: {cat.cweList.slice(0, 2).join(', ')}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Bottom Section: Framework Mapping Drill-down Table */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold text-foreground">
              {activeAssessment?.frameworkName} Control Matrix Drilldown
            </h2>
            <p className="text-xs text-muted-foreground">
              Granular mapping between platform rules, verified CWEs, and standards requirements
            </p>
          </div>
        </div>

        {activeAssessment && (
          <FrameworkMappingTable
            categories={activeAssessment.categories}
            selectedCategoryId={selectedCategoryId}
            onSelectCategory={(id) => setSelectedCategoryId(id)}
            frameworkTitle={activeAssessment.frameworkName}
          />
        )}
      </div>

      {/* Persistent Legal Disclaimer Footnote */}
      <div className="text-[11px] text-muted-foreground border-t border-border pt-4 flex items-center justify-between">
        <span className="flex items-center gap-1.5">
          <Info className="w-3.5 h-3.5 text-slate-500" />
          {COMPLIANCE_DISCLAIMER}
        </span>
        <span className="font-mono">Security Lab Report Subsystem v1.4</span>
      </div>

      {/* Report Generator Modal */}
      <ReportGeneratorModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        testRunId={selectedRunId}
      />
    </div>
  );
};
