import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  Clock,
  Calendar,
  UserCheck,
  CheckCircle2,
  AlertTriangle,
  FileCheck2,
  Loader2,
  AlertOctagon,
} from 'lucide-react';
import { FindingItem, calculateWaiverCountdown } from '../../api/findings.js';

interface PolicyWaiverModalProps {
  isOpen: boolean;
  onClose: () => void;
  finding: FindingItem | null;
  onSubmitWaiver: (params: {
    finding: FindingItem;
    reason: string;
    approvedBy: string;
    days: number;
    riskTier: 'low' | 'medium' | 'high' | 'business_exception';
  }) => Promise<void>;
  isSubmitting?: boolean;
}

export const PolicyWaiverModal: React.FC<PolicyWaiverModalProps> = ({
  isOpen,
  onClose,
  finding,
  onSubmitWaiver,
  isSubmitting = false,
}) => {
  const [selectedDays, setSelectedDays] = useState<number>(30);
  const [customDays, setCustomDays] = useState<string>('');
  const [useCustom, setUseCustom] = useState(false);
  const [reason, setReason] = useState<string>('');
  const [approvedBy, setApprovedBy] = useState<string>('Lead Security Architect');
  const [riskTier, setRiskTier] = useState<'low' | 'medium' | 'high' | 'business_exception'>(
    'business_exception',
  );
  const [validationError, setValidationError] = useState<string | null>(null);

  if (!isOpen || !finding) return null;

  const effectiveDays = useCustom ? parseInt(customDays, 10) || 1 : selectedDays;
  const targetDate = new Date(Date.now() + effectiveDays * 86400000);
  const previewCountdown = calculateWaiverCountdown(targetDate.toISOString());

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reason.trim() || reason.trim().length < 15) {
      setValidationError('Mandatory business justification must be at least 15 characters long');
      return;
    }
    if (!approvedBy.trim()) {
      setValidationError('Authorized approver name is required');
      return;
    }
    if (effectiveDays < 1 || effectiveDays > 365) {
      setValidationError('Waiver duration must be between 1 and 365 days');
      return;
    }

    setValidationError(null);
    await onSubmitWaiver({
      finding,
      reason: reason.trim(),
      approvedBy: approvedBy.trim(),
      days: effectiveDays,
      riskTier,
    });
  };

  const presetOptions = [
    { label: '7 Days', days: 7, desc: 'Hotfix / Sprint' },
    { label: '30 Days', days: 30, desc: 'Standard Cycle' },
    { label: '90 Days', days: 90, desc: 'Quarterly Review' },
    { label: '365 Days', days: 365, desc: 'Architectural Waiver' },
  ];

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="bg-slate-900 border border-slate-700/80 rounded-xl shadow-2xl w-full max-w-xl max-h-[92vh] flex flex-col overflow-hidden text-slate-200">
        {/* Modal Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 bg-slate-900/90 flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-amber-500/20 border border-amber-500/40 text-amber-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[11px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                  Compliance SLA Policy Waiver
                </span>
              </div>
              <h3 className="text-lg font-bold text-white mt-0.5">
                Assign Timed Policy Waiver
              </h3>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
            aria-label="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Content */}
        <form onSubmit={handleSubmit} className="p-5 sm:p-6 overflow-y-auto space-y-5">
          {/* Target Finding Summary Card */}
          <div className="p-3.5 rounded-lg bg-slate-950/70 border border-slate-800 space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400 font-mono">Fingerprint:</span>
              <span className="font-mono text-slate-300 truncate max-w-[280px]">
                {finding.fingerprint || finding.id}
              </span>
            </div>
            <div className="text-sm font-semibold text-white truncate">
              {finding.title}
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span
                className={`px-2 py-0.5 rounded font-bold uppercase ${
                  finding.severity === 'critical'
                    ? 'bg-purple-950/60 text-purple-400 border border-purple-800'
                    : finding.severity === 'high'
                    ? 'bg-rose-950/60 text-rose-400 border border-rose-800'
                    : 'bg-amber-950/60 text-amber-400 border border-amber-800'
                }`}
              >
                {finding.severity}
              </span>
              <span className="text-slate-400 font-mono">{finding.category}</span>
            </div>
          </div>

          {/* Duration Selector */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-blue-400" />
              Waiver Duration & Expiration Window
            </label>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-2">
              {presetOptions.map((opt) => (
                <button
                  type="button"
                  key={opt.days}
                  onClick={() => {
                    setSelectedDays(opt.days);
                    setUseCustom(false);
                  }}
                  className={`p-2.5 rounded-lg border text-left transition-all ${
                    !useCustom && selectedDays === opt.days
                      ? 'bg-blue-600/20 border-blue-500 text-blue-300 shadow-sm'
                      : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                  }`}
                >
                  <div className="font-bold text-sm text-white">{opt.label}</div>
                  <div className="text-[10px] text-slate-500 leading-tight mt-0.5">{opt.desc}</div>
                </button>
              ))}
            </div>

            <div className="flex items-center gap-2 mt-2">
              <button
                type="button"
                onClick={() => setUseCustom(!useCustom)}
                className={`text-xs px-2.5 py-1 rounded border transition-colors ${
                  useCustom
                    ? 'bg-blue-600/20 border-blue-500 text-blue-300'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-300'
                }`}
              >
                Custom Days
              </button>
              {useCustom && (
                <div className="flex items-center gap-1.5">
                  <input
                    type="number"
                    min="1"
                    max="365"
                    value={customDays}
                    onChange={(e) => setCustomDays(e.target.value)}
                    placeholder="e.g. 14"
                    className="w-24 px-2.5 py-1 text-xs rounded bg-slate-950 border border-slate-700 text-white font-mono focus:border-blue-500 outline-none"
                  />
                  <span className="text-xs text-slate-400">days</span>
                </div>
              )}
            </div>

            {/* Live Expiration Preview Countdown */}
            <div className="mt-3 p-3 rounded-lg bg-blue-950/20 border border-blue-500/30 flex items-center justify-between text-xs text-blue-300">
              <div className="flex items-center gap-2">
                <Calendar className="w-4 h-4 text-blue-400 shrink-0" />
                <span>
                  Expires: <strong>{targetDate.toLocaleDateString()}</strong> ({targetDate.toLocaleTimeString()})
                </span>
              </div>
              <span className="px-2 py-0.5 rounded font-mono font-bold bg-blue-500/20 text-blue-200 border border-blue-500/40">
                {previewCountdown.label}
              </span>
            </div>
          </div>

          {/* Risk Tier Selection */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <AlertOctagon className="w-3.5 h-3.5 text-amber-400" />
              Risk Acceptance Tier
            </label>
            <select
              value={riskTier}
              onChange={(e) => setRiskTier(e.target.value as typeof riskTier)}
              className="w-full px-3 py-2 text-xs rounded-lg bg-slate-950 border border-slate-700 text-slate-200 focus:border-blue-500 outline-none"
            >
              <option value="low">Low Impact (Negligible Exploitability)</option>
              <option value="medium">Compensating Control Active (WAF / Network Isolation)</option>
              <option value="high">High Risk Temporary Exception (CISO Approved)</option>
              <option value="business_exception">Standard Business Cycle Exception</option>
            </select>
          </div>

          {/* Authorized Approver */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
              <UserCheck className="w-3.5 h-3.5 text-emerald-400" />
              Authorized Approver / Security Principal
            </label>
            <input
              type="text"
              value={approvedBy}
              onChange={(e) => setApprovedBy(e.target.value)}
              placeholder="e.g. Lead Security Architect"
              className="w-full px-3 py-2 text-xs rounded-lg bg-slate-950 border border-slate-700 text-white placeholder-slate-500 focus:border-blue-500 outline-none"
              required
            />
          </div>

          {/* Mandatory Business Justification */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                <FileCheck2 className="w-3.5 h-3.5 text-purple-400" />
                Mandatory Business Justification
              </label>
              <span
                className={`text-[11px] font-mono ${
                  reason.trim().length >= 15 ? 'text-emerald-400' : 'text-amber-400'
                }`}
              >
                {reason.trim().length}/15 min chars
              </span>
            </div>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={3}
              placeholder="Provide explicit business rationale, compensating controls, or Jira ticket ID justifying this temporary waiver..."
              className="w-full px-3 py-2 text-xs rounded-lg bg-slate-950 border border-slate-700 text-white placeholder-slate-500 focus:border-blue-500 outline-none resize-none"
              required
            />
          </div>

          {/* Validation Error Message */}
          {validationError && (
            <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-500/50 flex items-center gap-2 text-xs text-rose-300">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{validationError}</span>
            </div>
          )}

          {/* Compliance Audit Disclaimer */}
          <div className="p-3 rounded-lg bg-slate-950/50 border border-slate-800 text-[11px] text-slate-400 leading-relaxed">
            <strong className="text-slate-300">Compliance Invariant:</strong> Applying a policy
            waiver suppresses automated CI/CD release gate failures until expiration. Once the countdown
            reaches 0, the finding automatically reverts to an active violation. All waiver grants are
            tamper-evident and recorded in the tenant audit trail.
          </div>

          {/* Modal Actions */}
          <div className="pt-2 border-t border-slate-800 flex items-center justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              disabled={isSubmitting}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting || reason.trim().length < 15}
              className="px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-md shadow-amber-900/30"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Enforcing Policy Waiver…</span>
                </>
              ) : (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Confirm Waiver ({effectiveDays} Days)</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
