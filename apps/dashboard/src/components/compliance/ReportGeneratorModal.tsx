import React, { useState, useMemo } from 'react';
import {
  ReportFormat,
  ReportConfig,
  downloadReport,
  generateClientSyntheticHtml,
  generateClientSyntheticSarif,
  COMPLIANCE_DISCLAIMER,
} from '../../api/reports.js';
import {
  X,
  Download,
  FileText,
  FileCode,
  Shield,
  Eye,
  Settings,
  Copy,
  Check,
  Building2,
  Lock,
  UserCheck,
  CheckCircle2,
} from 'lucide-react';
import { useAppStore } from '../../store/useAppStore.js';

interface ReportGeneratorModalProps {
  isOpen: boolean;
  onClose: () => void;
  testRunId?: string;
}

export const ReportGeneratorModal: React.FC<ReportGeneratorModalProps> = ({
  isOpen,
  onClose,
  testRunId = 'run-live-01',
}) => {
  const { showToast } = useAppStore();
  const [activeTab, setActiveTab] = useState<'config' | 'preview'>('config');
  const [selectedFormat, setSelectedFormat] = useState<ReportFormat>('pdf');
  const [isExporting, setIsExporting] = useState(false);
  const [copied, setCopied] = useState(false);

  // Customization fields
  const [orgName, setOrgName] = useState('Enterprise Security Operations');
  const [confidentiality, setConfidentiality] = useState<ReportConfig['confidentialityNotice']>(
    'RESTRICTED / STRICTLY CONFIDENTIAL'
  );
  const [assessorName, setAssessorName] = useState('SecOps Automated Auditor');
  const [executiveNotes, setExecutiveNotes] = useState(
    'Automated continuous compliance verification against OWASP Top 10, ASVS 4.0, and PCI-DSS 4.0 standards. All findings require security team sign-off.'
  );
  const [includeDiff, setIncludeDiff] = useState(true);
  const [includeWire, setIncludeWire] = useState(false);

  const reportConfig: ReportConfig = useMemo(
    () => ({
      format: selectedFormat,
      organizationName: orgName,
      confidentialityNotice: confidentiality,
      executiveNotes,
      assessorName,
      scopeSummary: 'Target Environment: Production API Gateway',
      includeRemediationDiff: includeDiff,
      includeWireFrames: includeWire,
    }),
    [selectedFormat, orgName, confidentiality, executiveNotes, assessorName, includeDiff, includeWire]
  );

  // Generate live preview string based on format
  const previewContent = useMemo(() => {
    if (selectedFormat === 'html') {
      return generateClientSyntheticHtml(testRunId, reportConfig);
    } else if (selectedFormat === 'sarif') {
      return generateClientSyntheticSarif(testRunId, reportConfig);
    } else if (selectedFormat === 'json') {
      return JSON.stringify(
        {
          testRunId,
          evaluatedAt: new Date().toISOString(),
          organization: orgName,
          confidentiality,
          disclaimer: COMPLIANCE_DISCLAIMER,
          frameworks: {
            owaspTop10: { score: 85, status: 'PASS' },
            owaspApi: { score: 80, status: 'PASS' },
            asvs4: { score: 78, status: 'NEEDS_REVIEW' },
            pciDss6: { score: 90, status: 'PASS' },
          },
        },
        null,
        2
      );
    } else {
      // PDF document preview text representation
      return `======================================================================
EXECUTIVE SECURITY COMPLIANCE REPORT (PDF 1.4 VECTOR)
======================================================================
Classification: ${confidentiality}
Organization:   ${orgName}
Assessor:       ${assessorName}
Target Run:     ${testRunId}
Generated At:   ${new Date().toISOString()}

AUDIT DISCLAIMER (Product Requirement 24.4):
${COMPLIANCE_DISCLAIMER}

COMPLIANCE SUMMARY SCORECARDS:
  [OK] OWASP Top 10 (2021)     : 85% Compliance (PASS)
  [OK] OWASP API Security (2023): 80% Compliance (PASS)
  [!]  OWASP ASVS 4.0          : 78% Compliance (NEEDS_REVIEW)
  [OK] PCI-DSS 4.0 Section 6   : 90% Compliance (PASS)

EXECUTIVE REMARKS:
${executiveNotes}
======================================================================`;
    }
  }, [selectedFormat, testRunId, reportConfig, orgName, confidentiality, assessorName, executiveNotes]);

  if (!isOpen) return null;

  const handleDownload = async () => {
    setIsExporting(true);
    try {
      const res = await downloadReport(testRunId, selectedFormat, reportConfig);
      if (res.success) {
        showToast(`Report downloaded successfully: ${res.filename}`, 'success');
      }
    } catch {
      showToast('Failed to download report', 'error');
    } finally {
      setIsExporting(false);
    }
  };

  const handleCopyPreview = () => {
    navigator.clipboard.writeText(previewContent);
    setCopied(true);
    showToast('Report content copied to clipboard', 'info');
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-background/80 backdrop-blur-sm animate-in fade-in">
      <div className="relative w-full max-w-4xl max-h-[90vh] flex flex-col bg-card border border-border rounded-2xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border bg-muted/20">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-primary/10 border border-primary/20 text-primary">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-foreground">
                Enterprise Report Hub & Standards Export
              </h2>
              <p className="text-xs text-muted-foreground">
                Generate executive audit PDFs, offline interactive HTML, and CI/CD SARIF artifacts
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Tab Switcher */}
            <div className="flex items-center bg-muted/40 p-1 rounded-lg border border-border text-xs">
              <button
                type="button"
                onClick={() => setActiveTab('config')}
                className={`flex items-center gap-1.5 px-3 py-1 rounded-md transition-colors ${
                  activeTab === 'config'
                    ? 'bg-card text-foreground font-semibold shadow-sm'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                <Settings className="w-3.5 h-3.5" />
                Customize
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('preview')}
                className={`flex items-center gap-1.5 px-3 py-1 rounded-md transition-colors ${
                  activeTab === 'preview'
                    ? 'bg-card text-foreground font-semibold shadow-sm'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                <Eye className="w-3.5 h-3.5" />
                Live Preview
              </button>
            </div>

            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
              aria-label="Close Modal"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Body Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Format Selector Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {/* PDF Profile */}
            <div
              onClick={() => setSelectedFormat('pdf')}
              className={`cursor-pointer p-4 rounded-xl border transition-all ${
                selectedFormat === 'pdf'
                  ? 'bg-primary/10 border-primary ring-1 ring-primary/50'
                  : 'bg-card border-border hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <FileText className={`w-5 h-5 ${selectedFormat === 'pdf' ? 'text-primary' : 'text-muted-foreground'}`} />
                {selectedFormat === 'pdf' && <CheckCircle2 className="w-4 h-4 text-primary" />}
              </div>
              <h4 className="font-semibold text-xs text-foreground">Executive PDF (1.4)</h4>
              <p className="text-[11px] text-muted-foreground mt-1">
                Pure TypeScript zero-dependency PDF vector report with cover summary and scorecards.
              </p>
            </div>

            {/* Standalone HTML Profile */}
            <div
              onClick={() => setSelectedFormat('html')}
              className={`cursor-pointer p-4 rounded-xl border transition-all ${
                selectedFormat === 'html'
                  ? 'bg-cyan-500/10 border-cyan-500 ring-1 ring-cyan-500/50'
                  : 'bg-card border-border hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <FileCode className={`w-5 h-5 ${selectedFormat === 'html' ? 'text-cyan-400' : 'text-muted-foreground'}`} />
                {selectedFormat === 'html' && <CheckCircle2 className="w-4 h-4 text-cyan-400" />}
              </div>
              <h4 className="font-semibold text-xs text-foreground">Technical Audit (HTML)</h4>
              <p className="text-[11px] text-muted-foreground mt-1">
                Self-contained offline interactive report with embedded styles, SVG charts, and evidence.
              </p>
            </div>

            {/* SARIF Profile */}
            <div
              onClick={() => setSelectedFormat('sarif')}
              className={`cursor-pointer p-4 rounded-xl border transition-all ${
                selectedFormat === 'sarif'
                  ? 'bg-purple-500/10 border-purple-500 ring-1 ring-purple-500/50'
                  : 'bg-card border-border hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <FileCode className={`w-5 h-5 ${selectedFormat === 'sarif' ? 'text-purple-400' : 'text-muted-foreground'}`} />
                {selectedFormat === 'sarif' && <CheckCircle2 className="w-4 h-4 text-purple-400" />}
              </div>
              <h4 className="font-semibold text-xs text-foreground">CI/CD Artifact (SARIF 2.1)</h4>
              <p className="text-[11px] text-muted-foreground mt-1">
                GitHub Security tab compatible SARIF v2.1.0 JSON with embedded compliance taxonomies.
              </p>
            </div>
          </div>

          {activeTab === 'config' ? (
            /* Customization Form */
            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {/* Organization Name */}
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                    <Building2 className="w-3.5 h-3.5 text-muted-foreground" />
                    Organization / Enterprise Name
                  </label>
                  <input
                    type="text"
                    value={orgName}
                    onChange={(e) => setOrgName(e.target.value)}
                    className="w-full px-3 py-2 text-xs bg-muted/40 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                    placeholder="e.g. Acme FinTech Corp"
                  />
                </div>

                {/* Confidentiality Notice */}
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-muted-foreground" />
                    Confidentiality Classification
                  </label>
                  <select
                    value={confidentiality}
                    onChange={(e) =>
                      setConfidentiality(e.target.value as ReportConfig['confidentialityNotice'])
                    }
                    className="w-full px-3 py-2 text-xs bg-muted/40 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                  >
                    <option value="RESTRICTED / STRICTLY CONFIDENTIAL">
                      RESTRICTED / STRICTLY CONFIDENTIAL
                    </option>
                    <option value="CONFIDENTIAL">CONFIDENTIAL</option>
                    <option value="INTERNAL USE ONLY">INTERNAL USE ONLY</option>
                    <option value="PUBLIC / THIRD-PARTY AUDIT">PUBLIC / THIRD-PARTY AUDIT</option>
                  </select>
                </div>

                {/* Assessor Name */}
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                    <UserCheck className="w-3.5 h-3.5 text-muted-foreground" />
                    Auditor / Assessor Title
                  </label>
                  <input
                    type="text"
                    value={assessorName}
                    onChange={(e) => setAssessorName(e.target.value)}
                    className="w-full px-3 py-2 text-xs bg-muted/40 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                    placeholder="e.g. Principal AppSec Architect"
                  />
                </div>

                {/* Scope Target Run */}
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-foreground">Target Test Run Scope</label>
                  <div className="px-3 py-2 text-xs bg-muted/20 border border-border rounded-lg text-muted-foreground font-mono">
                    {testRunId}
                  </div>
                </div>
              </div>

              {/* Executive Notes */}
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-foreground">
                  Executive Scope Remarks & Compliance Notes
                </label>
                <textarea
                  rows={3}
                  value={executiveNotes}
                  onChange={(e) => setExecutiveNotes(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-muted/40 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                  placeholder="Enter custom scope remarks or release approval context..."
                />
              </div>

              {/* Optional Flags */}
              <div className="pt-2 flex flex-wrap items-center gap-6 text-xs text-muted-foreground">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={includeDiff}
                    onChange={(e) => setIncludeDiff(e.target.checked)}
                    className="rounded border-border text-primary focus:ring-primary"
                  />
                  <span>Include Run-over-Run Regression Diff</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={includeWire}
                    onChange={(e) => setIncludeWire(e.target.checked)}
                    className="rounded border-border text-primary focus:ring-primary"
                  />
                  <span>Attach Raw HTTP Forensic Socket Frames</span>
                </label>
              </div>
            </div>
          ) : (
            /* Live In-Browser Preview */
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span>Live Rendering Preview &bull; {selectedFormat.toUpperCase()}</span>
                <button
                  type="button"
                  onClick={handleCopyPreview}
                  className="flex items-center gap-1 px-2.5 py-1 rounded bg-muted hover:bg-muted/80 text-foreground transition-colors"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copied ? 'Copied!' : 'Copy Raw'}
                </button>
              </div>

              {selectedFormat === 'html' ? (
                <div className="w-full h-80 rounded-xl border border-border bg-slate-950 overflow-hidden shadow-inner">
                  <iframe
                    title="Live Report Preview"
                    srcDoc={previewContent}
                    className="w-full h-full border-none"
                    sandbox="allow-same-origin"
                  />
                </div>
              ) : (
                <pre className="w-full h-80 p-4 rounded-xl border border-border bg-slate-950 text-slate-300 font-mono text-xs overflow-auto select-text">
                  {previewContent}
                </pre>
              )}
            </div>
          )}

          {/* Product Requirement 24.4 Reminder Banner */}
          <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300 text-xs">
            <strong>Mandatory Product Invariant (Requirement 24.4):</strong> Generated exports explicitly state that results provide technical testing evidence of control efficacy and do not constitute formal regulatory certification sign-off.
          </div>
        </div>

        {/* Modal Footer Actions */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-border bg-muted/20">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold text-muted-foreground hover:text-foreground hover:bg-muted rounded-lg transition-colors"
          >
            Cancel
          </button>

          <button
            type="button"
            onClick={handleDownload}
            disabled={isExporting}
            className="inline-flex items-center gap-2 px-5 py-2 rounded-lg bg-primary hover:bg-primary/90 text-primary-foreground text-xs font-bold shadow-lg transition-all disabled:opacity-50"
          >
            <Download className="w-4 h-4" />
            {isExporting ? 'Generating Report...' : `Export ${selectedFormat.toUpperCase()}`}
          </button>
        </div>
      </div>
    </div>
  );
};
