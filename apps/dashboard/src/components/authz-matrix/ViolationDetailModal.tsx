import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  AlertTriangle,
  RotateCw,
  Copy,
  Check,
  Lock,
  Unlock,
  Terminal,
  FileCode,
  ShieldCheck,
} from 'lucide-react';
import { AuthzViolationEvidence, formatGithubIssueBody } from '../../api/authz.js';

interface ViolationDetailModalProps {
  evidence: AuthzViolationEvidence | null;
  onClose: () => void;
  onRetest?: (findingId: string) => Promise<void>;
}

export const ViolationDetailModal: React.FC<ViolationDetailModalProps> = ({
  evidence,
  onClose,
  onRetest,
}) => {
  const [copiedCurl, setCopiedCurl] = useState(false);
  const [copiedIssue, setCopiedIssue] = useState(false);
  const [isRetesting, setIsRetesting] = useState(false);
  const [retestOutcome, setRetestOutcome] = useState<{ success: boolean; message: string } | null>(null);

  if (!evidence) return null;

  const handleCopyCurl = async () => {
    try {
      await navigator.clipboard.writeText(evidence.curlCommand);
      setCopiedCurl(true);
      setTimeout(() => setCopiedCurl(false), 2000);
    } catch {
      // Fallback
    }
  };

  const handleCopyIssue = async () => {
    try {
      const issueBody = formatGithubIssueBody(evidence);
      await navigator.clipboard.writeText(issueBody);
      setCopiedIssue(true);
      setTimeout(() => setCopiedIssue(false), 2000);
    } catch {
      // Fallback
    }
  };

  const handleTriggerRetest = async () => {
    if (!onRetest) return;
    setIsRetesting(true);
    setRetestOutcome(null);
    try {
      await onRetest(evidence.findingId);
      setRetestOutcome({
        success: true,
        message: 'Retest executed: Target responded with HTTP 403 Forbidden. Vulnerability mitigated!',
      });
    } catch (err: any) {
      setRetestOutcome({
        success: false,
        message: err.message || 'Retest failed or server returned non-200 response.',
      });
    } finally {
      setIsRetesting(false);
    }
  };

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'HIGH':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      case 'MEDIUM':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40';
      default:
        return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
    }
  };

  const getViolationBadgeClass = (vType: string) => {
    switch (vType) {
      case 'BOLA_HORIZONTAL_IDOR':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      case 'BFLA_VERTICAL_ESCALATION':
        return 'bg-purple-500/20 text-purple-300 border-purple-500/40';
      default:
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-4xl max-h-[90vh] flex flex-col bg-card border border-border/80 rounded-xl shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border/60 bg-muted/20">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span
                  className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${getSeverityBadgeClass(
                    evidence.severity,
                  )}`}
                >
                  {evidence.severity}
                </span>
                <span
                  className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${getViolationBadgeClass(
                    evidence.violationType,
                  )}`}
                >
                  {evidence.violationType.replace(/_/g, ' ')}
                </span>
                <span className="text-xs font-mono text-muted-foreground">{evidence.findingId}</span>
              </div>
              <h2 className="text-base font-semibold text-foreground mt-0.5">{evidence.title}</h2>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 text-muted-foreground hover:text-foreground rounded-lg hover:bg-accent transition-colors"
            aria-label="Close dialog"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Security Outcome Banner */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-lg bg-emerald-950/20 border border-emerald-500/30 flex items-start gap-3">
              <div className="p-1.5 rounded-md bg-emerald-500/10 text-emerald-400 shrink-0">
                <Lock className="w-4 h-4" />
              </div>
              <div>
                <div className="text-[11px] font-bold uppercase tracking-wider text-emerald-400">
                  Expected Policy Enforcement
                </div>
                <div className="text-sm font-semibold text-emerald-200 mt-0.5">
                  HTTP {evidence.expectedStatusCode} (Forbidden / Denied)
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  Tenant boundaries should block cross-tenant resource queries without authorization.
                </div>
              </div>
            </div>

            <div className="p-4 rounded-lg bg-red-950/25 border border-red-500/40 flex items-start gap-3">
              <div className="p-1.5 rounded-md bg-red-500/10 text-red-400 shrink-0">
                <Unlock className="w-4 h-4" />
              </div>
              <div>
                <div className="text-[11px] font-bold uppercase tracking-wider text-red-400">
                  Actual Server Decision
                </div>
                <div className="text-sm font-semibold text-red-200 mt-0.5">
                  HTTP {evidence.actualStatusCode} (Unauthorized Access Granted)
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  Target returned private object data to an unauthorized caller across tenant borders.
                </div>
              </div>
            </div>
          </div>

          {/* Description & Tenancy Boundaries */}
          <div className="p-4 rounded-lg bg-muted/20 border border-border/60">
            <div className="text-xs font-semibold text-foreground mb-1">Observed Violation Summary</div>
            <p className="text-xs text-muted-foreground leading-relaxed">{evidence.description}</p>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4 pt-3 border-t border-border/40 text-xs font-mono">
              <div>
                <span className="text-muted-foreground block text-[10px] uppercase">Actor Identity</span>
                <span className="font-semibold text-foreground">{evidence.actorPersonaId}</span>
                <span className="text-[10px] text-muted-foreground block">({evidence.actorPersonaRole})</span>
              </div>
              <div>
                <span className="text-muted-foreground block text-[10px] uppercase">Actor Tenant</span>
                <span className="font-semibold text-cyan-400">{evidence.actorTenantId || 'N/A'}</span>
              </div>
              <div>
                <span className="text-muted-foreground block text-[10px] uppercase">Resource Owner</span>
                <span className="font-semibold text-foreground">{evidence.ownerPersonaId || 'N/A'}</span>
              </div>
              <div>
                <span className="text-muted-foreground block text-[10px] uppercase">Owner Tenant</span>
                <span className="font-semibold text-purple-400">{evidence.ownerTenantId || 'N/A'}</span>
              </div>
            </div>
          </div>

          {/* Side-by-side Request vs Leaked Response */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Request */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs font-semibold text-foreground">
                <span className="flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-blue-400" />
                  Adversary HTTP Request
                </span>
                <span className="font-mono text-[11px] text-muted-foreground">{evidence.method}</span>
              </div>
              <div className="p-3 bg-slate-950/80 rounded-lg border border-border/60 font-mono text-xs overflow-x-auto space-y-2 text-slate-300">
                <div className="text-cyan-400 break-all">{evidence.testedUrl}</div>
                <div className="pt-2 border-t border-slate-800 text-[11px] space-y-1">
                  {Object.entries(evidence.requestHeaders).map(([k, v]) => (
                    <div key={k} className="flex">
                      <span className="text-slate-500 w-32 shrink-0">{k}:</span>
                      <span className="text-slate-300 truncate">{v}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Response */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs font-semibold text-foreground">
                <span className="flex items-center gap-1.5">
                  <FileCode className="w-3.5 h-3.5 text-red-400" />
                  Leaked Sensitive Response
                </span>
                {evidence.leakedFields && evidence.leakedFields.length > 0 && (
                  <span className="text-[10px] font-mono text-red-400">
                    {evidence.leakedFields.length} Leaked Fields
                  </span>
                )}
              </div>
              <div className="p-3 bg-slate-950/80 rounded-lg border border-border/60 font-mono text-xs overflow-x-auto text-slate-300">
                {evidence.leakedFields && evidence.leakedFields.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mb-2 pb-2 border-b border-slate-800">
                    {evidence.leakedFields.map((field) => (
                      <span
                        key={field}
                        className="px-1.5 py-0.5 rounded text-[10px] bg-red-500/20 text-red-300 border border-red-500/30"
                      >
                        {field}
                      </span>
                    ))}
                  </div>
                )}
                <pre className="text-[11px] text-red-200/90 whitespace-pre font-mono">
                  {evidence.responseBody || '{"error": "No response body recorded"}'}
                </pre>
              </div>
            </div>
          </div>

          {/* cURL Reproduction Command */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs font-semibold text-foreground">
              <span>Automated cURL Reproduction</span>
              <button
                type="button"
                onClick={handleCopyCurl}
                className="flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground transition-colors"
              >
                {copiedCurl ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Copied cURL!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy Command</span>
                  </>
                )}
              </button>
            </div>
            <pre className="p-3 bg-slate-950/90 border border-border/60 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto">
              {evidence.curlCommand}
            </pre>
          </div>

          {/* Remediation Advice */}
          <div className="p-4 rounded-lg bg-blue-950/20 border border-blue-500/30 space-y-1.5">
            <div className="flex items-center gap-2 text-xs font-bold text-blue-400 uppercase tracking-wider">
              <ShieldCheck className="w-4 h-4" />
              Prescriptive Remediation Strategy
            </div>
            <p className="text-xs text-blue-200/90 leading-relaxed">{evidence.remediation}</p>
          </div>

          {/* Retest Status Banner */}
          {retestOutcome && (
            <div
              className={`p-3 rounded-lg border text-xs flex items-center gap-2 ${
                retestOutcome.success
                  ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300'
                  : 'bg-red-950/30 border-red-500/40 text-red-300'
              }`}
            >
              {retestOutcome.success ? (
                <ShieldCheck className="w-4 h-4 shrink-0 text-emerald-400" />
              ) : (
                <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
              )}
              <span>{retestOutcome.message}</span>
            </div>
          )}
        </div>

        {/* Footer Toolbar */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-border/60 bg-muted/20">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleTriggerRetest}
              disabled={isRetesting}
              className="flex items-center gap-2 px-3 py-1.5 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors disabled:opacity-50"
            >
              <RotateCw className={`w-3.5 h-3.5 ${isRetesting ? 'animate-spin' : ''}`} />
              <span>{isRetesting ? 'Executing Retest...' : 'Retest Finding'}</span>
            </button>
            <button
              type="button"
              onClick={handleCopyIssue}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-accent text-accent-foreground hover:bg-accent/80 border border-border/60 transition-colors"
            >
              {copiedIssue ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedIssue ? 'Copied Issue Template!' : 'Export Issue (GitHub/Jira)'}</span>
            </button>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 text-xs font-medium rounded-lg bg-muted text-muted-foreground hover:text-foreground transition-colors"
          >
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
};
