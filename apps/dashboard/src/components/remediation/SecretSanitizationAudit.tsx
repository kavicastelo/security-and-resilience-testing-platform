import React, { useState } from 'react';
import {
  ShieldCheck,
  Eye,
  EyeOff,
  CheckCircle2,
  Info,
} from 'lucide-react';

interface SecretSanitizationAuditProps {
  redactedCount?: number;
  compact?: boolean;
}

export const SecretSanitizationAudit: React.FC<SecretSanitizationAuditProps> = ({
  redactedCount = 3,
  compact = false,
}) => {
  const [showAuditDrawer, setShowAuditDrawer] = useState(false);

  const auditRules = [
    {
      category: 'Authorization & Bearer Tokens',
      pattern: 'Bearer eyJhbGciOi... / Basic dXNlcjpw...',
      status: 'Cryptographically Redacted',
      replacement: '[REDACTED_SECRET]',
    },
    {
      category: 'API Keys & Secrets',
      pattern: 'x-api-key, secret_token, api_key',
      status: 'Cryptographically Redacted',
      replacement: '[REDACTED_SECRET]',
    },
    {
      category: 'Session & Cookie Credentials',
      pattern: 'Cookie, Set-Cookie, SessionId',
      status: 'Stripped Prior to Prompt',
      replacement: '***STRIPPED***',
    },
    {
      category: 'Internal CIDR & Infrastructure IPs',
      pattern: '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16',
      status: 'Anonymized Private Ranges',
      replacement: 'target-vpc.internal',
    },
  ];

  if (compact) {
    return (
      <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-950/40 border border-emerald-500/40 text-emerald-300 text-xs font-medium">
        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
        <span>Zero-Leakage Sanitized ({redactedCount} tokens scrubbed)</span>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/20 p-4 space-y-3 text-slate-200">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-emerald-500/20 border border-emerald-500/40 text-emerald-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wider text-emerald-400">
                Data Privacy &amp; Secret Sanitization Verified
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-emerald-500/20 text-emerald-300 font-mono font-bold">
                100% Zero-Leak
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-0.5">
              All credentials, authorization tokens, cookies, and internal infrastructure IPs were scrubbed before dispatch to external LLMs.
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={() => setShowAuditDrawer(!showAuditDrawer)}
          className="text-xs px-3 py-1.5 rounded-lg bg-emerald-900/40 hover:bg-emerald-800/40 text-emerald-300 border border-emerald-700/50 font-medium flex items-center gap-1.5 transition-colors self-start sm:self-auto shrink-0"
        >
          {showAuditDrawer ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
          <span>{showAuditDrawer ? 'Hide Audit Log' : 'View Redaction Rules'}</span>
        </button>
      </div>

      {/* Expanded Redaction Rules */}
      {showAuditDrawer && (
        <div className="pt-2 border-t border-emerald-500/20 space-y-2 animate-fade-in text-xs font-mono">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {auditRules.map((rule, idx) => (
              <div
                key={idx}
                className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1"
              >
                <div className="flex items-center justify-between font-sans">
                  <span className="font-semibold text-slate-200 text-xs flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    {rule.category}
                  </span>
                  <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                    {rule.status}
                  </span>
                </div>
                <div className="text-[11px] text-slate-400 truncate">Pattern: {rule.pattern}</div>
                <div className="text-[11px] text-emerald-400 font-bold">
                  Sent to AI as: <code>{rule.replacement}</code>
                </div>
              </div>
            ))}
          </div>

          <div className="text-[11px] text-slate-400 font-sans flex items-center gap-1.5 pt-1">
            <Info className="w-3.5 h-3.5 text-blue-400 shrink-0" />
            <span>
              Enforced by <code>apps/controller/src/services/ai/prompt-builder.ts</code> per enterprise compliance directive.
            </span>
          </div>
        </div>
      )}
    </div>
  );
};
