import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ShieldCheck,
  ShieldAlert,
  Clock,
  Copy,
  Check,
  RefreshCw,
  X,
  ExternalLink,
  Globe,
  FileCode,
  AlertCircle,
  HelpCircle,
} from 'lucide-react';
import {
  targetsApi,
  Target,
  ChallengeInstructions,
  VerificationResult,
} from '../../api/targets.js';
import { useAppStore } from '../../store/useAppStore.js';

interface OwnershipWizardModalProps {
  target: Target;
  isOpen: boolean;
  onClose: () => void;
  onVerified?: () => void;
}

export const OwnershipWizardModal: React.FC<OwnershipWizardModalProps> = ({
  target,
  isOpen,
  onClose,
  onVerified,
}) => {
  const queryClient = useQueryClient();
  const { showToast } = useAppStore();
  const [activeTab, setActiveTab] = useState<'dns' | 'http'>('dns');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<VerificationResult | null>(null);

  // Fetch challenge instructions from backend
  const {
    data: challenge,
    isLoading: isLoadingChallenge,
    refetch: refetchChallenge,
  } = useQuery<ChallengeInstructions>({
    queryKey: ['target-challenge', target.id],
    queryFn: () => targetsApi.getChallenge(target.id),
    enabled: isOpen && Boolean(target.id),
  });

  // Verify mutation
  const verifyMutation = useMutation({
    mutationFn: (method: 'DNS_TXT' | 'HTTP_WELL_KNOWN' | 'AUTO') =>
      targetsApi.verifyOwnership(target.id, method),
    onSuccess: (result) => {
      setLastResult(result);
      if (result.verified) {
        showToast('Domain ownership verified successfully!', 'success');
        queryClient.invalidateQueries({ queryKey: ['targets'] });
        queryClient.invalidateQueries({ queryKey: ['target-challenge', target.id] });
        if (onVerified) onVerified();
      } else {
        showToast(result.message || 'Verification could not be confirmed', 'error');
      }
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      setLastResult({
        verified: false,
        status: 'FAILED',
        message: msg,
      });
      showToast(msg, 'error');
    },
  });

  if (!isOpen) return null;

  const copyToClipboard = (text: string, key: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    showToast(`Copied ${label} to clipboard`, 'info');
    setTimeout(() => {
      setCopiedKey((curr) => (curr === key ? null : curr));
    }, 2000);
  };

  const domain = (() => {
    try {
      return new URL(target.baseUrl).hostname;
    } catch {
      return target.baseUrl;
    }
  })();

  const isVerified =
    lastResult?.verified ??
    (challenge?.status === 'VERIFIED' || target.verificationStatus === 'VERIFIED');

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-md animate-fade-in">
      <div className="relative w-full max-w-2xl bg-card border border-border/80 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="p-6 border-b border-border/60 bg-gradient-to-r from-card to-accent/30 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div
              className={`p-2.5 rounded-xl border ${
                isVerified
                  ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-400'
                  : 'bg-amber-950/40 border-amber-800/60 text-amber-400'
              }`}
            >
              {isVerified ? (
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
              ) : (
                <Clock className="w-5 h-5 text-amber-400" />
              )}
            </div>
            <div>
              <h3 className="text-base font-semibold text-foreground flex items-center gap-2">
                <span>Cryptographic Ownership Verification</span>
                {isVerified && (
                  <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-emerald-950/60 text-emerald-400 border border-emerald-800/60">
                    Verified
                  </span>
                )}
              </h3>
              <p className="text-xs text-muted-foreground">
                Target: <span className="font-mono text-foreground">{target.name}</span> ({domain})
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent/60 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6">
          {/* Verification Status Banner */}
          {isVerified ? (
            <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-800/50 flex items-start gap-3">
              <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
              <div className="space-y-1 text-xs">
                <p className="font-semibold text-emerald-300">
                  Target Domain Ownership is Cryptographically Verified
                </p>
                <p className="text-emerald-400/80 leading-relaxed">
                  Active vulnerability scanning, fuzzing, and resilience execution are authorized on this target.
                  {challenge?.verifiedAt && (
                    <span className="block mt-1 text-[11px] font-mono text-emerald-400/60">
                      Verified At: {new Date(challenge.verifiedAt).toLocaleString()} via{' '}
                      {challenge.verificationMethod || 'DNS_TXT'}
                    </span>
                  )}
                </p>
              </div>
            </div>
          ) : (
            <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-800/50 flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
              <div className="space-y-1 text-xs">
                <p className="font-semibold text-amber-300">
                  Verification Required Before Active Scans
                </p>
                <p className="text-amber-400/80 leading-relaxed">
                  In compliance with RFC-1918 and anti-abuse policies, external domains must prove cryptographic control before active tests can run.
                </p>
              </div>
            </div>
          )}

          {/* Verification Challenge Loading State */}
          {isLoadingChallenge ? (
            <div className="py-8 flex flex-col items-center justify-center space-y-2 text-xs text-muted-foreground">
              <RefreshCw className="w-5 h-5 animate-spin text-primary" />
              <span>Retrieving cryptographic challenge token...</span>
            </div>
          ) : challenge ? (
            <div className="space-y-5">
              {/* Method Tabs */}
              <div className="flex border-b border-border/60">
                <button
                  type="button"
                  onClick={() => setActiveTab('dns')}
                  className={`flex items-center space-x-2 py-2.5 px-4 text-xs font-medium border-b-2 transition-colors ${
                    activeTab === 'dns'
                      ? 'border-primary text-primary'
                      : 'border-transparent text-muted-foreground hover:text-foreground'
                  }`}
                >
                  <Globe className="w-3.5 h-3.5" />
                  <span>Method 1: DNS TXT Record (Recommended)</span>
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab('http')}
                  className={`flex items-center space-x-2 py-2.5 px-4 text-xs font-medium border-b-2 transition-colors ${
                    activeTab === 'http'
                      ? 'border-primary text-primary'
                      : 'border-transparent text-muted-foreground hover:text-foreground'
                  }`}
                >
                  <FileCode className="w-3.5 h-3.5" />
                  <span>Method 2: HTTP .well-known Token</span>
                </button>
              </div>

              {/* Tab 1: DNS TXT */}
              {activeTab === 'dns' && (
                <div className="space-y-4 animate-fade-in text-xs">
                  <p className="text-muted-foreground leading-relaxed">
                    Add a DNS <code className="text-primary font-mono font-semibold">TXT</code> record with your DNS provider (e.g. Cloudflare, AWS Route 53, Google Cloud DNS).
                  </p>

                  <div className="space-y-3">
                    <div className="bg-accent/40 border border-border/80 rounded-xl p-3 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">
                          Primary Host / Name
                        </span>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(challenge.dns.recordName, 'dns-name', 'DNS Record Name')}
                          className="flex items-center space-x-1 text-[11px] text-primary hover:text-primary/80"
                        >
                          {copiedKey === 'dns-name' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedKey === 'dns-name' ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                      <code className="block font-mono text-foreground text-xs select-all break-all">
                        {challenge.dns.recordName}
                      </code>
                    </div>

                    <div className="bg-accent/40 border border-border/80 rounded-xl p-3 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">
                          Alternative Host / Root Domain
                        </span>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(challenge.dns.alternativeRecordName, 'dns-alt', 'Alternative Host')}
                          className="flex items-center space-x-1 text-[11px] text-primary hover:text-primary/80"
                        >
                          {copiedKey === 'dns-alt' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedKey === 'dns-alt' ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                      <code className="block font-mono text-foreground text-xs select-all break-all">
                        {challenge.dns.alternativeRecordName}
                      </code>
                    </div>

                    <div className="bg-accent/40 border border-border/80 rounded-xl p-3 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">
                          TXT Record Value / Content
                        </span>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(challenge.dns.recordValue, 'dns-val', 'Record Value')}
                          className="flex items-center space-x-1 text-[11px] text-primary hover:text-primary/80"
                        >
                          {copiedKey === 'dns-val' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedKey === 'dns-val' ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                      <code className="block font-mono text-primary text-xs select-all break-all font-semibold">
                        {challenge.dns.recordValue}
                      </code>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 p-3 bg-muted/30 border border-border/60 rounded-xl text-muted-foreground text-[11px]">
                    <HelpCircle className="w-4 h-4 shrink-0 text-primary" />
                    <span>
                      DNS TTL propagation typically takes 30 to 180 seconds. You can verify immediately or re-check at any time.
                    </span>
                  </div>
                </div>
              )}

              {/* Tab 2: HTTP .well-known */}
              {activeTab === 'http' && (
                <div className="space-y-4 animate-fade-in text-xs">
                  <p className="text-muted-foreground leading-relaxed">
                    Host a static file on your web server returning HTTP 200 with the exact challenge token.
                  </p>

                  <div className="space-y-3">
                    <div className="bg-accent/40 border border-border/80 rounded-xl p-3 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">
                          Target Verification URL
                        </span>
                        <div className="flex items-center space-x-2">
                          <a
                            href={challenge.http.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center space-x-1 text-[11px] text-muted-foreground hover:text-foreground"
                          >
                            <ExternalLink className="w-3 h-3" />
                            <span>Test URL</span>
                          </a>
                          <button
                            type="button"
                            onClick={() => copyToClipboard(challenge.http.url, 'http-url', 'Verification URL')}
                            className="flex items-center space-x-1 text-[11px] text-primary hover:text-primary/80"
                          >
                            {copiedKey === 'http-url' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                            <span>{copiedKey === 'http-url' ? 'Copied' : 'Copy'}</span>
                          </button>
                        </div>
                      </div>
                      <code className="block font-mono text-foreground text-xs select-all break-all">
                        {challenge.http.url}
                      </code>
                    </div>

                    <div className="bg-accent/40 border border-border/80 rounded-xl p-3 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">
                          Expected File Content
                        </span>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(challenge.http.expectedContent, 'http-content', 'Token')}
                          className="flex items-center space-x-1 text-[11px] text-primary hover:text-primary/80"
                        >
                          {copiedKey === 'http-content' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedKey === 'http-content' ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                      <code className="block font-mono text-primary text-xs select-all break-all font-semibold">
                        {challenge.http.expectedContent}
                      </code>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 p-3 bg-muted/30 border border-border/60 rounded-xl text-muted-foreground text-[11px]">
                    <HelpCircle className="w-4 h-4 shrink-0 text-primary" />
                    <span>
                      Server must return <code className="text-foreground">200 OK</code> and Content-Type <code className="text-foreground">text/plain</code>.
                    </span>
                  </div>
                </div>
              )}

              {/* Diagnostic Error from Last Run */}
              {lastResult && !lastResult.verified && (
                <div className="p-4 rounded-xl bg-red-950/30 border border-red-800/60 text-xs space-y-2 animate-fade-in">
                  <div className="flex items-center space-x-2 font-semibold text-red-300">
                    <ShieldAlert className="w-4 h-4 text-red-400" />
                    <span>Verification Attempt Failed</span>
                  </div>
                  <p className="text-red-300/90 leading-relaxed font-mono text-[11px]">
                    {lastResult.message}
                  </p>
                  {lastResult.details && (
                    <pre className="p-2.5 rounded-lg bg-black/40 border border-red-900/50 text-[10px] font-mono text-red-300/80 overflow-x-auto">
                      {JSON.stringify(lastResult.details, null, 2)}
                    </pre>
                  )}
                </div>
              )}
            </div>
          ) : null}
        </div>

        {/* Modal Footer */}
        <div className="p-5 border-t border-border/60 bg-accent/20 flex flex-wrap items-center justify-between gap-3">
          <button
            type="button"
            onClick={() => refetchChallenge()}
            className="flex items-center space-x-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh Challenge</span>
          </button>

          <div className="flex items-center space-x-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg text-xs font-medium text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
            >
              Close
            </button>
            <button
              type="button"
              onClick={() =>
                verifyMutation.mutate(
                  activeTab === 'dns' ? 'DNS_TXT' : 'HTTP_WELL_KNOWN',
                )
              }
              disabled={verifyMutation.isPending || isVerified}
              className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-primary hover:bg-primary/90 disabled:opacity-50 text-white font-medium text-xs shadow-md transition-all hover:glow-blue"
            >
              {verifyMutation.isPending ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Validating Proof...</span>
                </>
              ) : isVerified ? (
                <>
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>Ownership Confirmed</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>Verify Ownership Now</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
