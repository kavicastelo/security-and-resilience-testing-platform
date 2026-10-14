import React, { useState, useEffect } from 'react';
import {
  X,
  Sparkles,
  ShieldCheck,
  CheckCircle2,
  FileCode,
  GitPullRequest,
  Check,
  Copy,
  ExternalLink,
  Loader2,
  Layers,
  Activity,
  UserCheck,
  Cpu,
  Coins,
} from 'lucide-react';
import {
  AiRemediationProposal,
  RemediationRequest,
  VerifyRemediationResult,
  fetchRemediationsForFinding,
  generateFindingRemediation,
  getConfidenceTier,
  generateGitHubPrMarkdown,
} from '../../api/remediation.js';
import { CodeDiffViewer } from './CodeDiffViewer.js';
import { SecretSanitizationAudit } from './SecretSanitizationAudit.js';
import { PatchVerificationStepper } from './PatchVerificationStepper.js';
import { useAppStore } from '../../store/useAppStore.js';

interface FindingSummary {
  id: string;
  title: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description?: string;
  fingerprint?: string;
  targetId?: string;
  testDefinitionId?: string;
}

interface AiRemediationStudioModalProps {
  isOpen: boolean;
  onClose: () => void;
  finding: FindingSummary | null;
  onApplyPatch?: (proposal: AiRemediationProposal) => Promise<void>;
}

export const AiRemediationStudioModal: React.FC<AiRemediationStudioModalProps> = ({
  isOpen,
  onClose,
  finding,
  onApplyPatch,
}) => {
  const { showToast } = useAppStore();

  const [activeTab, setActiveTab] = useState<'diff' | 'root_cause' | 'verify' | 'privacy' | 'pr'>('diff');
  const [selectedProvider, setSelectedProvider] = useState<'anthropic' | 'openai' | 'ollama' | 'mock'>('mock');
  const [selectedModel, setSelectedModel] = useState<string>('Claude 3.5 Sonnet');
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [proposals, setProposals] = useState<AiRemediationProposal[]>([]);
  const [activeProposalIndex, setActiveProposalIndex] = useState<number>(0);
  const [latestVerification, setLatestVerification] = useState<VerifyRemediationResult | null>(null);
  const [isAccepting, setIsAccepting] = useState<boolean>(false);
  const [copiedPr, setCopiedPr] = useState<boolean>(false);

  // Load existing remediation proposals when opened
  useEffect(() => {
    if (isOpen && finding?.id) {
      fetchRemediationsForFinding(finding.id).then((list) => {
        if (list.length > 0) {
          setProposals(list);
          setActiveProposalIndex(0);
        } else {
          // Auto-trigger initial proposal generation
          handleSynthesizePatch();
        }
      });
    }
  }, [isOpen, finding?.id]);

  if (!isOpen || !finding) return null;

  const currentProposal: AiRemediationProposal | null = proposals[activeProposalIndex] || null;
  const confidence = currentProposal ? getConfidenceTier(currentProposal.confidenceScore) : null;

  const handleSynthesizePatch = async () => {
    if (!finding.id) return;
    setIsGenerating(true);
    try {
      const req: RemediationRequest = {
        provider: selectedProvider,
        model: selectedModel,
        optInConfirmed: true,
      };
      const newProposal = await generateFindingRemediation(finding.id, req);
      setProposals((prev) => [newProposal, ...prev]);
      setActiveProposalIndex(0);
      showToast('AI Remediation patch synthesized successfully', 'success');
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      showToast(`Patch generation failed: ${msg}`, 'error');
    } finally {
      setIsGenerating(false);
    }
  };

  const handleAcceptPatch = async () => {
    if (!currentProposal) return;
    setIsAccepting(true);
    try {
      if (onApplyPatch) {
        await onApplyPatch(currentProposal);
      }
      showToast('Patch accepted and recorded in audit ledger. Finding marked as in progress.', 'success');
      onClose();
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err), 'error');
    } finally {
      setIsAccepting(false);
    }
  };

  const prDraft = currentProposal
    ? generateGitHubPrMarkdown(finding, currentProposal, latestVerification)
    : { title: '', body: '' };

  const handleCopyPr = () => {
    navigator.clipboard.writeText(`${prDraft.title}\n\n${prDraft.body}`);
    setCopiedPr(true);
    showToast('Copied GitHub PR draft to clipboard', 'info');
    setTimeout(() => setCopiedPr(false), 2000);
  };

  // Mock token usage statistics
  const promptTokens = currentProposal?.promptTokens || 1240;
  const completionTokens = currentProposal?.completionTokens || 480;
  const estimatedCost = ((promptTokens * 3 + completionTokens * 15) / 1000000).toFixed(4);

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="ai-studio-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md animate-fade-in"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="bg-slate-900 border-2 border-purple-500/70 rounded-2xl shadow-2xl shadow-purple-950/40 w-full max-w-6xl max-h-[94vh] flex flex-col overflow-hidden text-slate-200">
        {/* Studio Top Banner & Attribution */}
        <div className="p-4 sm:p-5 border-b border-purple-500/30 bg-gradient-to-r from-purple-950/40 via-slate-900 to-slate-900 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="p-2.5 rounded-xl bg-purple-500/20 border border-purple-500/40 text-purple-300 shadow-md shadow-purple-900/30 shrink-0">
              <Sparkles className="w-6 h-6 animate-pulse text-purple-400" />
            </div>

            <div>
              <div className="flex flex-wrap items-center gap-2 mb-1">
                <span className="text-[11px] font-bold px-2 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/40 uppercase tracking-wider">
                  AI Remediation Studio
                </span>
                <span
                  className={`text-xs px-2.5 py-0.5 rounded-full font-bold uppercase ${
                    finding.severity === 'critical'
                      ? 'bg-purple-950 text-purple-400 border border-purple-800'
                      : finding.severity === 'high'
                      ? 'bg-rose-950 text-rose-400 border border-rose-800'
                      : 'bg-amber-950 text-amber-400 border border-amber-800'
                  }`}
                >
                  {finding.severity}
                </span>
                <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono">
                  {finding.category}
                </span>

                {confidence && (
                  <span
                    className={`text-[11px] px-2 py-0.5 rounded-full font-bold border ${confidence.badgeBg}`}
                    title={confidence.description}
                  >
                    Confidence: {confidence.tier} ({Math.round((currentProposal?.confidenceScore || 0.85) * 100)}%)
                  </span>
                )}
              </div>

              <h2 id="ai-studio-modal-title" className="text-lg sm:text-xl font-bold text-white truncate max-w-xl">
                {finding.title}
              </h2>
            </div>
          </div>

          {/* Model Attribution & Synthesis Trigger */}
          <div className="flex flex-wrap items-center gap-2 self-start lg:self-center">
            {/* Provider selection */}
            <select
              value={selectedProvider}
              onChange={(e) => {
                const prov = e.target.value as typeof selectedProvider;
                setSelectedProvider(prov);
                if (prov === 'anthropic') setSelectedModel('Claude 3.5 Sonnet');
                else if (prov === 'openai') setSelectedModel('GPT-4o');
                else if (prov === 'ollama') setSelectedModel('DeepSeek-R1 (Local)');
                else setSelectedModel('Deterministic Mock Engine');
              }}
              className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-purple-500/40 text-purple-200 text-xs font-medium outline-none cursor-pointer"
            >
              <option value="mock">Deterministic Mock Engine (Offline)</option>
              <option value="anthropic">Anthropic (Claude 3.5 Sonnet)</option>
              <option value="openai">OpenAI (GPT-4o)</option>
              <option value="ollama">Ollama (DeepSeek-R1 Local)</option>
            </select>

            <button
              type="button"
              onClick={handleSynthesizePatch}
              disabled={isGenerating}
              className="px-3.5 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-semibold text-xs flex items-center gap-1.5 transition-all disabled:opacity-50 shadow-md shadow-purple-900/30 cursor-pointer"
            >
              {isGenerating ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Synthesizing…</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Regenerate Patch</span>
                </>
              )}
            </button>

            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
              aria-label="Close"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Token Usage & Provider Telemetry Bar */}
        <div className="px-5 py-2 bg-slate-950/80 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-400 font-mono">
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1.5 text-purple-300">
              <Cpu className="w-3.5 h-3.5 text-purple-400" />
              <span>Model: {currentProposal?.model || selectedModel}</span>
            </span>
            <span className="flex items-center gap-1">
              <Coins className="w-3.5 h-3.5 text-amber-400" />
              <span>
                Tokens: {promptTokens} prompt + {completionTokens} comp (${estimatedCost})
              </span>
            </span>
          </div>

          {proposals.length > 1 && (
            <div className="flex items-center gap-1.5 font-sans">
              <span className="text-[11px] text-slate-400">Proposals:</span>
              <div className="flex items-center gap-1">
                {proposals.map((_, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => setActiveProposalIndex(idx)}
                    className={`w-5 h-5 rounded text-xs font-bold transition-colors ${
                      activeProposalIndex === idx
                        ? 'bg-purple-600 text-white'
                        : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                    }`}
                  >
                    {idx + 1}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1 px-4 sm:px-6 border-b border-slate-800 bg-slate-950/40 text-sm overflow-x-auto">
          <button
            type="button"
            onClick={() => setActiveTab('diff')}
            className={`py-3 px-3.5 border-b-2 font-medium flex items-center gap-2 whitespace-nowrap transition-colors ${
              activeTab === 'diff'
                ? 'border-purple-500 text-purple-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode className="w-4 h-4" />
            <span>Code Diff &amp; Patch</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('root_cause')}
            className={`py-3 px-3.5 border-b-2 font-medium flex items-center gap-2 whitespace-nowrap transition-colors ${
              activeTab === 'root_cause'
                ? 'border-purple-500 text-purple-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="w-4 h-4" />
            <span>Root Cause &amp; Checklist</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('verify')}
            className={`py-3 px-3.5 border-b-2 font-medium flex items-center gap-2 whitespace-nowrap transition-colors ${
              activeTab === 'verify'
                ? 'border-purple-500 text-purple-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldCheck className="w-4 h-4" />
            <span>Sandboxed Verification</span>
            {currentProposal && (
              <span
                className={`ml-1 text-[10px] px-1.5 py-0.5 rounded font-bold uppercase border ${
                  currentProposal.verifiedStatus === 'PASSED'
                    ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800'
                    : currentProposal.verifiedStatus === 'FAILED'
                    ? 'bg-rose-950/60 text-rose-400 border-rose-800'
                    : 'bg-amber-950/60 text-amber-400 border-amber-800'
                }`}
              >
                {currentProposal.verifiedStatus}
              </span>
            )}
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('privacy')}
            className={`py-3 px-3.5 border-b-2 font-medium flex items-center gap-2 whitespace-nowrap transition-colors ${
              activeTab === 'privacy'
                ? 'border-purple-500 text-purple-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>Secret Sanitization Audit</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('pr')}
            className={`py-3 px-3.5 border-b-2 font-medium flex items-center gap-2 whitespace-nowrap transition-colors ${
              activeTab === 'pr'
                ? 'border-purple-500 text-purple-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <GitPullRequest className="w-4 h-4" />
            <span>GitHub PR Draft</span>
          </button>
        </div>

        {/* Tab Content Body */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-6 bg-slate-950/60 space-y-5">
          {isGenerating ? (
            <div className="flex flex-col items-center justify-center py-20 text-slate-400 space-y-3">
              <Loader2 className="w-8 h-8 animate-spin text-purple-400" />
              <p className="text-sm font-medium text-slate-300">
                Synthesizing targeted security patch with {selectedModel}…
              </p>
              <p className="text-xs text-slate-500 max-w-sm text-center">
                Scrubbing sensitive tokens, constructing prompt context, and generating unified git diff.
              </p>
            </div>
          ) : !currentProposal ? (
            <div className="flex flex-col items-center justify-center py-16 text-slate-500 space-y-3">
              <Sparkles className="w-10 h-10 text-purple-500/50" />
              <p className="text-base font-medium text-slate-300">No Remediation Proposals Generated</p>
              <button
                type="button"
                onClick={handleSynthesizePatch}
                className="px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-semibold text-xs"
              >
                Synthesize Patch Proposal
              </button>
            </div>
          ) : (
            <>
              {/* TAB 1: CODE DIFF & PATCH */}
              {activeTab === 'diff' && (
                <div className="space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-slate-400">
                    <p>
                      Inspect unified git diff generated to mitigate this flaw. Use the split view toggle for side-by-side review.
                    </p>
                    <SecretSanitizationAudit compact />
                  </div>

                  <CodeDiffViewer
                    gitDiff={currentProposal.gitDiff}
                    modelAttribution={currentProposal.model || selectedModel}
                  />
                </div>
              )}

              {/* TAB 2: ROOT CAUSE & CHECKLIST */}
              {activeTab === 'root_cause' && (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
                  <div className="lg:col-span-2 space-y-4">
                    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
                      <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                        <Activity className="w-4 h-4 text-purple-400" />
                        Root Cause Analysis
                      </h3>
                      <div className="prose prose-invert prose-xs max-w-none text-slate-300 leading-relaxed space-y-2 whitespace-pre-wrap">
                        {currentProposal.explanation}
                      </div>
                    </div>
                  </div>

                  {/* Developer Checklist */}
                  <div className="space-y-4">
                    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
                      <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        Developer Remediation Checklist
                      </h3>

                      <div className="space-y-2 text-xs">
                        <label className="flex items-start gap-2.5 p-2 rounded bg-slate-950/60 border border-slate-800/80 cursor-pointer">
                          <input type="checkbox" defaultChecked className="mt-0.5 rounded border-slate-700" />
                          <span className="text-slate-300">
                            Apply parameter sanitization and parameterized query bindings
                          </span>
                        </label>
                        <label className="flex items-start gap-2.5 p-2 rounded bg-slate-950/60 border border-slate-800/80 cursor-pointer">
                          <input type="checkbox" defaultChecked className="mt-0.5 rounded border-slate-700" />
                          <span className="text-slate-300">
                            Configure standard defensive security response headers
                          </span>
                        </label>
                        <label className="flex items-start gap-2.5 p-2 rounded bg-slate-950/60 border border-slate-800/80 cursor-pointer">
                          <input type="checkbox" className="mt-0.5 rounded border-slate-700" />
                          <span className="text-slate-300">
                            Run automated patch verification loop in sandbox container
                          </span>
                        </label>
                        <label className="flex items-start gap-2.5 p-2 rounded bg-slate-950/60 border border-slate-800/80 cursor-pointer">
                          <input type="checkbox" className="mt-0.5 rounded border-slate-700" />
                          <span className="text-slate-300">
                            Export GitHub PR draft and submit for security code review
                          </span>
                        </label>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 3: SANDBOXED VERIFICATION */}
              {activeTab === 'verify' && (
                <div className="space-y-4">
                  <PatchVerificationStepper
                    remediationId={currentProposal.id}
                    initialStatus={currentProposal.verifiedStatus}
                    initialDetails={currentProposal.verificationOutput}
                    onVerificationComplete={(res) => {
                      setLatestVerification(res);
                      setProposals((prev) =>
                        prev.map((p) =>
                          p.id === currentProposal.id
                            ? {
                                ...p,
                                verifiedStatus: res.verifiedStatus,
                                verificationOutput: res.verificationDetails,
                              }
                            : p,
                        ),
                      );
                    }}
                  />
                </div>
              )}

              {/* TAB 4: SECRET SANITIZATION AUDIT */}
              {activeTab === 'privacy' && (
                <div className="space-y-4">
                  <SecretSanitizationAudit />
                </div>
              )}

              {/* TAB 5: GITHUB PR DRAFT */}
              {activeTab === 'pr' && (
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div>
                      <h3 className="text-sm font-bold text-white flex items-center gap-2">
                        <GitPullRequest className="w-4 h-4 text-purple-400" />
                        GitHub Pull Request Draft
                      </h3>
                      <p className="text-xs text-slate-400 mt-0.5">
                        Pre-formatted Pull Request body with finding details, verification status, and git diff.
                      </p>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={handleCopyPr}
                        className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium flex items-center gap-1.5 transition-colors"
                      >
                        {copiedPr ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copiedPr ? 'Copied' : 'Copy PR Markdown'}</span>
                      </button>

                      <a
                        href={`https://github.com/security-lab/platform/compare?quick_pull=1&title=${encodeURIComponent(
                          prDraft.title,
                        )}&body=${encodeURIComponent(prDraft.body)}`}
                        target="_blank"
                        rel="noreferrer"
                        className="px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors"
                      >
                        <span>Open PR on GitHub</span>
                        <ExternalLink className="w-3.5 h-3.5" />
                      </a>
                    </div>
                  </div>

                  {/* PR Title field */}
                  <div className="space-y-1">
                    <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                      Pull Request Title
                    </label>
                    <input
                      type="text"
                      readOnly
                      value={prDraft.title}
                      className="w-full px-3 py-2 text-xs font-mono rounded-lg bg-slate-950 border border-slate-800 text-slate-200 select-all"
                    />
                  </div>

                  {/* PR Body field */}
                  <div className="space-y-1">
                    <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                      Pull Request Description (Markdown)
                    </label>
                    <textarea
                      readOnly
                      rows={12}
                      value={prDraft.body}
                      className="w-full px-3 py-2 text-xs font-mono rounded-lg bg-slate-950 border border-slate-800 text-slate-200 resize-none select-all"
                    />
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Modal Footer with Human-in-the-Loop Actions */}
        <div className="p-4 border-t border-purple-500/30 bg-slate-950/90 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2 text-slate-400">
            <UserCheck className="w-4 h-4 text-purple-400 shrink-0" />
            <span>
              <strong>Mandatory Human Governance:</strong> AI proposals are assistive only and require explicit operator review.
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium transition-colors cursor-pointer"
            >
              Cancel
            </button>

            {currentProposal && (
              <button
                type="button"
                onClick={handleAcceptPatch}
                disabled={isAccepting}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold flex items-center gap-1.5 transition-colors shadow-md shadow-emerald-950/40 cursor-pointer disabled:opacity-50"
              >
                {isAccepting ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Recording Acceptance…</span>
                  </>
                ) : (
                  <>
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Review &amp; Accept Patch</span>
                  </>
                )}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
